//! nf_tables netlink — kernel-interface file (AGENTS.md §4.1).
//!
//! Pure-netlink nftables client: builds nfnetlink batches by hand and drives
//! them over a `NETLINK_NETFILTER` socket. No `nft` binary is ever executed.
//! Only the tiny subset the bridge NAT needs is implemented:
//!
//!   * per-container IPv4 tables (`table ip zerun-<id>`),
//!   * one base chain of type `nat` (POSTROUTING),
//!   * rules built from the expressions: payload, cmp, meta and masq.
//!
//! Only **egress masquerade** lives in the kernel here. Published ports (`-p`)
//! are served by a built-in userland TCP proxy (src/network.rs) instead of
//! kernel DNAT: DNAT-ing a 127.0.0.1-sourced local packet towards the bridge
//! fails at the post-DNAT route lookup (Linux treats 127.0.0.0/8 as a
//! loopback-only source), which is exactly why Docker excludes 127.0.0.0/8
//! from its OUTPUT DNAT and ships docker-proxy for host-loopback access.
//!
//! Layout notes (reverse-engineered from `nft` + verified against the kernel):
//!
//!   * A change set is one datagram: `NFNL_MSG_BATCH_BEGIN`, one or more
//!     `NFT_MSG_*` messages, `NFNL_MSG_BATCH_END`. The kernel commits the
//!     whole batch atomically and rolls it back on the first error.
//!   * The kernel only replies when something failed — a successful batch is
//!     silent. Error replies are `NLMSG_ERROR` carrying a negative errno.
//!   * nf_tables numeric attributes are **big-endian** (`be32`), including
//!     register numbers, hook priorities and verdicts. This is unusual for
//!     rtnetlink and easy to get wrong.
//!   * String compares load a whole 16-byte (IFNAMSIZ) zero-padded register,
//!     so a `meta iifname` / `meta oifname` compare pads its operand too.

use crate::error::ZResult;
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};
use std::io;
use std::net::Ipv4Addr;

// --- netlink / nfnetlink framing -------------------------------------------

const NLMSG_ERROR: u16 = 0x2;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_APPEND: u16 = 0x0800;
const NLA_F_NESTED: u16 = 0x8000;
const NLMSG_MIN_TYPE: u16 = 0x10;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE;
const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE + 1;
const NFPROTO_IPV4: u8 = 2;
/// Family used by nfgenmsg for the batch begin/end bookends.
const AF_UNSPEC: u8 = 0;

// --- nf_tables message types ------------------------------------------------

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;

// --- nf_tables attribute types (only the subset used here) -------------------

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

// --- expression attribute types ----------------------------------------------

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_DATA_VALUE: u16 = 1;

// --- expression / hook value constants ---------------------------------------

const NFT_REG_1: u32 = 1;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFT_META_OIFNAME: u32 = 7;

const NF_ACCEPT: u32 = 1;

/// Hook number of the IPv4 netfilter POSTROUTING hook (nat srcnat).
const NF_INET_POST_ROUTING: u32 = 4;
/// nft `priority srcnat` for nat chains.
const PRIO_SRCNAT: i32 = 100;

/// IP header offsets for payload matches.
const IP_SADDR_OFFSET: u32 = 12;
const IPV4_LEN: u32 = 4;

/// Per-container bridge NAT configuration.
pub struct NatConfig<'a> {
    /// nft table name (`zerun-<id>`).
    pub table: &'a str,
    /// Container IPv4 address (masquerade source guard).
    pub container_ip: Ipv4Addr,
}

/// Raw nfnetlink client. One socket, blocking, used from the host side only.
pub struct Nftables {
    sock: Socket,
}

impl Nftables {
    /// Open a NETLINK_NETFILTER socket in the *current* network namespace.
    pub fn new() -> ZResult<Self> {
        let mut sock = Socket::new(NETLINK_NETFILTER)
            .map_err(|e| crate::zerr!("open nfnetlink socket: {e}"))?;
        sock.bind(&SocketAddr::new(0, 0))
            .map_err(|e| crate::zerr!("bind nfnetlink socket: {e}"))?;
        sock.set_non_blocking(true)
            .map_err(|e| crate::zerr!("nfnetlink socket non-blocking: {e}"))?;
        Ok(Nftables { sock })
    }

    /// Install (or refresh) the per-container NAT table.
    ///
    /// Table + chains + rules are created in one atomic batch; a stale table
    /// left over from a crashed run is deleted first (best effort).
    pub fn install_nat(&self, cfg: &NatConfig) -> ZResult<()> {
        // Best-effort cleanup of a stale table from a crashed run.
        let _ = self.delete_table(cfg.table);

        let msgs: Vec<Vec<u8>> = vec![
            msg_new_table(cfg.table),
            msg_new_chain(cfg.table, "postrouting", NF_INET_POST_ROUTING, PRIO_SRCNAT),
            msg_new_rule(cfg.table, "postrouting", &masquerade_rule(cfg.container_ip)),
        ];
        self.send_batch(&msgs)
    }

    /// Delete the whole table `name` (with all chains and rules).
    ///
    /// Missing tables are tolerated (kernel ENOENT) so teardown is idempotent.
    /// Other errors are reported on stderr and ignored: cleanup is best-effort
    /// and must never fail an already-finished container run.
    pub fn remove_table(&self, name: &str) {
        if let Err(code) = self.delete_table(name) {
            if code != libc::ENOENT {
                eprintln!(
                    "zerun: warn: nft teardown for table {name}: {}",
                    io::Error::from_raw_os_error(code)
                );
            }
        }
    }

    /// Delete the whole table `name`; Err(errno) on kernel failure.
    pub fn delete_table(&self, name: &str) -> std::result::Result<(), i32> {
        let mut buf = Vec::new();
        buf.extend(batch_bookend(NFNL_MSG_BATCH_BEGIN));
        buf.extend(msg_del_table(name));
        buf.extend(batch_bookend(NFNL_MSG_BATCH_END));
        self.sock
            .send(&buf, 0)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.drain_errors()
    }

    /// Send one atomic batch and surface the first kernel error.
    fn send_batch(&self, msgs: &[Vec<u8>]) -> ZResult<()> {
        let mut buf = Vec::new();
        buf.extend(batch_bookend(NFNL_MSG_BATCH_BEGIN));
        for m in msgs {
            buf.extend_from_slice(m);
        }
        buf.extend(batch_bookend(NFNL_MSG_BATCH_END));

        self.sock
            .send(&buf, 0)
            .map_err(|e| crate::zerr!("send nftables batch: {e}"))?;
        self.drain_errors()
            .map_err(|code| crate::zerr!("nftables: {}", io::Error::from_raw_os_error(code)))
    }

    /// Read kernel error replies until the socket is drained.
    ///
    /// nfnetlink processing is synchronous with `send`, and a successful batch
    /// produces no reply at all, so the first non-blocking read either yields
    /// an `NLMSG_ERROR` (failure) or `WouldBlock` (success). Returns the
    /// positive errno of the first failure.
    fn drain_errors(&self) -> std::result::Result<(), i32> {
        let mut buf = vec![0u8; 16384];
        loop {
            match self.sock.recv(&mut buf, 0) {
                Ok(n) => {
                    if let Some(err) = parse_nlmsg_error(&buf[..n]) {
                        return Err(err);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => {
                    return Err(e.raw_os_error().unwrap_or(libc::EIO));
                }
            }
        }
    }
}

/// First `NLMSG_ERROR` in `buf`: returns the (negative) errno, if any.
fn parse_nlmsg_error(buf: &[u8]) -> Option<i32> {
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        let msg_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if msg_type == NLMSG_ERROR && off + 20 <= buf.len() {
            let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
            if err < 0 {
                return Some(-err);
            }
        }
        off += (len + 3) & !3;
    }
    None
}

// --- low-level encoders -------------------------------------------------------

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Encode one netlink attribute (nla_len includes the 4-byte header; payload
/// padded to 4 bytes).
fn nla(typ: u16, payload: &[u8]) -> Vec<u8> {
    let total = 4 + payload.len();
    let pad = (4 - (total % 4)) % 4;
    let mut out = Vec::with_capacity(total + pad);
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&typ.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(total + pad, 0);
    out
}

fn nla_nested(typ: u16, payload: &[u8]) -> Vec<u8> {
    nla(typ | NLA_F_NESTED, payload)
}

fn nla_str(typ: u16, s: &str) -> Vec<u8> {
    let mut payload = s.as_bytes().to_vec();
    payload.push(0);
    nla(typ, &payload)
}

fn nla_be32(typ: u16, v: u32) -> Vec<u8> {
    nla(typ, &be32(v))
}

/// One nlmsghdr + payload (nfgenmsg + attributes for nfnetlink messages).
fn nlmsg(msg_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&msg_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    out.extend_from_slice(payload);
    out
}

/// nfgenmsg: family, version, res_id (network byte order).
fn nfgenmsg(family: u8, res_id: u16) -> [u8; 4] {
    [family, 0, (res_id >> 8) as u8, (res_id & 0xff) as u8]
}

fn nft_msg(msg_type: u16, flags: u16, attrs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + attrs.len());
    payload.extend_from_slice(&nfgenmsg(NFPROTO_IPV4, 0));
    payload.extend_from_slice(attrs);
    nlmsg((NFNL_SUBSYS_NFTABLES << 8) | msg_type, flags, &payload)
}

/// The BATCH_BEGIN / BATCH_END bookends use family AF_UNSPEC and res_id =
/// NFNL_SUBSYS_NFTABLES (the subsystem the batch belongs to).
fn batch_bookend(msg_type: u16) -> Vec<u8> {
    nlmsg(
        msg_type,
        NLM_F_REQUEST,
        &nfgenmsg(AF_UNSPEC, NFNL_SUBSYS_NFTABLES),
    )
}

fn msg_new_table(name: &str) -> Vec<u8> {
    let mut attrs = nla_str(NFTA_TABLE_NAME, name);
    attrs.extend(nla_be32(NFTA_TABLE_FLAGS, 0));
    nft_msg(NFT_MSG_NEWTABLE, NLM_F_REQUEST | NLM_F_CREATE, &attrs)
}

fn msg_del_table(name: &str) -> Vec<u8> {
    let attrs = nla_str(NFTA_TABLE_NAME, name);
    nft_msg(NFT_MSG_DELTABLE, NLM_F_REQUEST, &attrs)
}

fn msg_new_chain(table: &str, chain: &str, hooknum: u32, priority: i32) -> Vec<u8> {
    let mut hook = nla_be32(NFTA_HOOK_HOOKNUM, hooknum);
    hook.extend(nla_be32(NFTA_HOOK_PRIORITY, priority as u32));
    let mut attrs = nla_str(NFTA_CHAIN_TABLE, table);
    attrs.extend(nla_str(NFTA_CHAIN_NAME, chain));
    attrs.extend(nla_be32(NFTA_CHAIN_POLICY, NF_ACCEPT));
    attrs.extend(nla_str(NFTA_CHAIN_TYPE, "nat"));
    attrs.extend(nla_nested(NFTA_CHAIN_HOOK, &hook));
    nft_msg(NFT_MSG_NEWCHAIN, NLM_F_REQUEST | NLM_F_CREATE, &attrs)
}

fn msg_new_rule(table: &str, chain: &str, expressions: &[u8]) -> Vec<u8> {
    let mut attrs = nla_str(NFTA_RULE_TABLE, table);
    attrs.extend(nla_str(NFTA_RULE_CHAIN, chain));
    attrs.extend(nla_nested(NFTA_RULE_EXPRESSIONS, expressions));
    nft_msg(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
        &attrs,
    )
}

// --- expression builders -------------------------------------------------------
//
// Every helper returns the raw bytes of one or more `NFTA_LIST_ELEM` entries,
// i.e. the payload expected inside `NFTA_RULE_EXPRESSIONS`.

/// Wrap expression `name` (e.g. "cmp") and its `data` payload as a list elem.
fn expr(name: &str, data: &[u8]) -> Vec<u8> {
    let mut inner = nla_str(NFTA_EXPR_NAME, name);
    inner.extend(nla_nested(NFTA_EXPR_DATA, data));
    nla_nested(NFTA_LIST_ELEM, &inner)
}

/// The `NFTA_DATA_VALUE` inside an immediate/cmp data nest.
fn data_value(raw: &[u8]) -> Vec<u8> {
    nla(NFTA_DATA_VALUE, raw)
}

/// cmp: `<reg> <op> <raw value>` (op: NFT_CMP_EQ / NFT_CMP_NEQ).
fn cmp_expr(reg: u32, op: u32, value: &[u8]) -> Vec<u8> {
    let mut data = nla_be32(NFTA_CMP_SREG, reg);
    data.extend(nla_be32(NFTA_CMP_OP, op));
    data.extend(nla_nested(NFTA_CMP_DATA, &data_value(value)));
    expr("cmp", &data)
}

/// payload: load `len` bytes at `base`+`offset` into `reg`.
fn payload_expr(reg: u32, base: u32, offset: u32, len: u32) -> Vec<u8> {
    let mut data = nla_be32(NFTA_PAYLOAD_DREG, reg);
    data.extend(nla_be32(NFTA_PAYLOAD_BASE, base));
    data.extend(nla_be32(NFTA_PAYLOAD_OFFSET, offset));
    data.extend(nla_be32(NFTA_PAYLOAD_LEN, len));
    expr("payload", &data)
}

/// meta: load the named key into `reg`.
fn meta_expr(reg: u32, key: u32) -> Vec<u8> {
    let mut data = nla_be32(NFTA_META_KEY, key);
    data.extend(nla_be32(NFTA_META_DREG, reg));
    expr("meta", &data)
}

/// masquerade (no flags).
fn masq_expr() -> Vec<u8> {
    expr("masq", &[])
}

/// `ip saddr <ip>` exact match.
fn ip_saddr_match(ip: Ipv4Addr) -> Vec<u8> {
    let mut out = payload_expr(
        NFT_REG_1,
        NFT_PAYLOAD_NETWORK_HEADER,
        IP_SADDR_OFFSET,
        IPV4_LEN,
    );
    out.extend(cmp_expr(NFT_REG_1, NFT_CMP_EQ, &ip.octets()));
    out
}

/// Interface-name strings are compared as zero-padded IFNAMSIZ (16) bytes.
fn ifname_value(name: &str) -> [u8; 16] {
    let mut raw = [0u8; 16];
    let n = name.len().min(16);
    raw[..n].copy_from_slice(&name.as_bytes()[..n]);
    raw
}

/// `oifname != <name>` meta compare (used to keep intra-bridge traffic
/// un-NATed, mirroring Docker's `! -o docker0` masquerade guard).
fn oifname_neq(name: &str) -> Vec<u8> {
    let mut out = meta_expr(NFT_REG_1, NFT_META_OIFNAME);
    out.extend(cmp_expr(NFT_REG_1, NFT_CMP_NEQ, &ifname_value(name)));
    out
}

/// postrouting masquerade for one container's traffic:
/// `ip saddr <ip> oifname != "zerun0" masquerade` — the oifname guard keeps
/// container-to-container (and container-to-gateway) traffic un-NATed, exactly
/// like Docker's `-s <subnet> ! -o docker0 -j MASQUERADE`.
fn masquerade_rule(ip: Ipv4Addr) -> Vec<u8> {
    let mut out = ip_saddr_match(ip);
    out.extend(oifname_neq("zerun0"));
    out.extend(masq_expr());
    out
}
