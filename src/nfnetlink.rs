//! nf_tables netlink — kernel-interface file (AGENTS.md §4.1).
//!
//! Pure-netlink nftables client: builds nfnetlink batches by hand and drives
//! them over a `NETLINK_NETFILTER` socket. No `nft` binary is ever executed.
//! Only the tiny subset the bridge NAT needs is implemented:
//!
//!   * one shared IPv4 table (`table ip zerun-nat`) for the managed bridge,
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
use std::time::{Duration, Instant};

// --- netlink / nfnetlink framing -------------------------------------------

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_APPEND: u16 = 0x0800;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
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
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;

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
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;

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
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

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

/// Stable marker on the rule owned by Zerun. `userdata` is an opaque binary
/// attribute, so it gives the idempotency check a unique identity without
/// relying on rule handles, which the kernel reassigns after every change.
const NAT_RULE_USERDATA: &[u8] = b"zerun:nat:v1";

/// How long to wait for a non-blocking nfnetlink dump to produce all replies.
const DUMP_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared bridge NAT configuration.
pub struct NatConfig<'a> {
    /// nft table name (`zerun-nat`).
    pub table: &'a str,
    /// Source network to masquerade when leaving the managed bridge.
    pub source_network: Ipv4Addr,
    /// Prefix length of `source_network`.
    pub prefix_len: u8,
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

    /// Install the shared bridge NAT table if it is not already present.
    ///
    /// Ensuring each layer separately lets a partially-created table heal
    /// without deleting a table that other containers may already be using.
    /// Rules carry a stable `userdata` marker. A dump lets us identify legacy
    /// unmarked rules and duplicate marked rules. The canonical rule is added
    /// first, then stale rules are removed in a separate atomic batch so NAT
    /// never has an empty-rule window.
    pub fn install_nat(&self, cfg: &NatConfig) -> ZResult<()> {
        self.ensure_object("table", &[msg_new_table(cfg.table)])?;
        self.ensure_object(
            "postrouting chain",
            &[msg_new_chain(
                cfg.table,
                "postrouting",
                NF_INET_POST_ROUTING,
                PRIO_SRCNAT,
            )],
        )?;

        let mut rules = self.dump_rules(cfg.table, "postrouting")?;
        rules.sort_by_key(|rule| rule.handle);

        let mut delete = Vec::new();
        let mut kept = false;
        for rule in rules {
            let marked = rule.userdata.as_deref() == Some(NAT_RULE_USERDATA);
            if marked && !kept {
                kept = true;
                continue;
            }
            let handle = rule.handle.ok_or_else(|| {
                crate::zerr!("nftables: rule in {} postrouting has no handle", cfg.table)
            })?;
            delete.push(msg_del_rule(cfg.table, "postrouting", handle));
        }

        if !kept {
            self.ensure_object(
                "NAT rule",
                &[msg_new_rule(
                    cfg.table,
                    "postrouting",
                    &masquerade_rule(cfg.source_network, cfg.prefix_len),
                    Some(NAT_RULE_USERDATA),
                )],
            )?;
        }

        if !delete.is_empty() {
            match self.send_batch_errno(&delete) {
                Ok(()) => {}
                Err(libc::ENOENT) => {
                    // Another Zerun process repaired the chain concurrently.
                    // Re-read it before failing: one canonical marked rule is
                    // all this installation promises.
                    if self.has_canonical_rule(cfg.table, "postrouting")? {
                        return Ok(());
                    }
                    return Err(nft_errno("remove stale NAT rules", libc::ENOENT));
                }
                Err(code) => return Err(nft_errno("remove stale NAT rules", code)),
            }
        }
        Ok(())
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
    fn send_batch_errno(&self, msgs: &[Vec<u8>]) -> std::result::Result<(), i32> {
        let mut buf = Vec::new();
        buf.extend(batch_bookend(NFNL_MSG_BATCH_BEGIN));
        for m in msgs {
            buf.extend_from_slice(m);
        }
        buf.extend(batch_bookend(NFNL_MSG_BATCH_END));

        self.sock
            .send(&buf, 0)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.drain_errors()
    }

    /// Create an object and treat `EEXIST` as success.
    fn ensure_object(&self, label: &str, msgs: &[Vec<u8>]) -> ZResult<()> {
        match self.send_batch_errno(msgs) {
            Ok(()) | Err(libc::EEXIST) => Ok(()),
            Err(code) => Err(nft_errno(label, code)),
        }
    }

    fn has_canonical_rule(&self, table: &str, chain: &str) -> ZResult<bool> {
        let rules = self.dump_rules(table, chain)?;
        Ok(rules
            .iter()
            .any(|rule| rule.userdata.as_deref() == Some(NAT_RULE_USERDATA)))
    }

    /// Dump rules for one chain. The kernel returns multipart `GETRULE`
    /// messages followed by `NLMSG_DONE`; parse only records that match the
    /// requested table and chain.
    fn dump_rules(&self, table: &str, chain: &str) -> ZResult<Vec<RuleRecord>> {
        let mut attrs = nla_str(NFTA_RULE_TABLE, table);
        attrs.extend(nla_str(NFTA_RULE_CHAIN, chain));
        let mut payload = nfgenmsg(NFPROTO_IPV4, 0).to_vec();
        payload.extend_from_slice(&attrs);
        let request = nlmsg(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE,
            NLM_F_REQUEST | NLM_F_DUMP,
            &payload,
        );
        self.sock
            .send(&request, 0)
            .map_err(|e| crate::zerr!("nftables dump request: {e}"))?;

        let deadline = Instant::now() + DUMP_TIMEOUT;
        let mut rules = Vec::new();
        let mut storage = vec![0u8; 65536];
        loop {
            let mut buf = &mut storage[..];
            match self.sock.recv(&mut buf, 0) {
                Ok(n) => {
                    if n == 0 {
                        return Err(crate::zerr!("nftables: truncated rule dump"));
                    }
                    if parse_rule_dump(&storage[..n], table, chain, &mut rules)? {
                        return Ok(rules);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(crate::zerr!("nftables: rule dump timed out"));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(crate::zerr!("nftables rule dump: {e}")),
            }
        }
    }

    /// Read kernel error replies until the socket is drained.
    ///
    /// nfnetlink processing is synchronous with `send`, and a successful batch
    /// produces no reply at all, so the first non-blocking read either yields
    /// an `NLMSG_ERROR` (failure) or `WouldBlock` (success). Returns the
    /// positive errno of the first failure.
    fn drain_errors(&self) -> std::result::Result<(), i32> {
        let mut storage = vec![0u8; 16384];
        loop {
            let mut buf = &mut storage[..];
            match self.sock.recv(&mut buf, 0) {
                Ok(n) => {
                    if let Some(err) = parse_nlmsg_error(&storage[..n]) {
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

struct RuleRecord {
    handle: Option<u64>,
    userdata: Option<Vec<u8>>,
}

/// Parse one nfnetlink datagram. Returns true when `NLMSG_DONE` was seen.
fn parse_rule_dump(
    buf: &[u8],
    table: &str,
    chain: &str,
    out: &mut Vec<RuleRecord>,
) -> ZResult<bool> {
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > buf.len() {
            return Err(crate::zerr!(
                "nftables: malformed rule dump header at offset {off}: len={len}, packet={}",
                buf.len()
            ));
        }
        let msg_type = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if msg_type == NLMSG_DONE {
            return Ok(true);
        }
        if msg_type == NLMSG_ERROR {
            if len < 20 {
                return Err(crate::zerr!("nftables: malformed rule dump error"));
            }
            let err = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
            if err != 0 {
                return Err(nft_errno("dump NAT rules", -err));
            }
        } else if len >= 20 {
            let attrs = parse_attrs(&buf[off + 20..off + len])?;
            let mut rule_table = None;
            let mut rule_chain = None;
            let mut handle = None;
            let mut userdata = None;
            for (kind, value) in attrs {
                match kind {
                    NFTA_RULE_TABLE => rule_table = parse_string(value),
                    NFTA_RULE_CHAIN => rule_chain = parse_string(value),
                    NFTA_RULE_HANDLE if value.len() == 8 => {
                        handle = Some(u64::from_be_bytes(value.try_into().unwrap()));
                    }
                    NFTA_RULE_USERDATA => userdata = Some(value.to_vec()),
                    _ => {}
                }
            }
            if rule_table.as_deref() == Some(table) && rule_chain.as_deref() == Some(chain) {
                out.push(RuleRecord { handle, userdata });
            }
        }
        off += (len + 3) & !3;
    }
    Ok(false)
}

fn nft_errno(context: &str, code: i32) -> crate::error::ZError {
    crate::zerr!("nftables {context}: {}", io::Error::from_raw_os_error(code))
}

fn parse_string(value: &[u8]) -> Option<String> {
    // nftables string attributes are NUL-terminated and may include alignment
    // padding. Stop at the first NUL rather than trimming only trailing NULs:
    // an embedded NUL must never become part of a table/chain identity.
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..end]).ok().map(str::to_owned)
}

fn parse_attrs(buf: &[u8]) -> ZResult<Vec<(u16, &[u8])>> {
    let mut attrs = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        if buf.len() - off < 4 {
            return Err(crate::zerr!("nftables: malformed attribute header"));
        }
        let len = u16::from_ne_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
        if len < 4 || off + len > buf.len() {
            return Err(crate::zerr!("nftables: malformed attribute"));
        }
        let aligned_len = (len + 3) & !3;
        if off + aligned_len > buf.len() {
            return Err(crate::zerr!("nftables: malformed attribute padding"));
        }
        let typ = u16::from_ne_bytes(buf[off + 2..off + 4].try_into().unwrap()) & NLA_TYPE_MASK;
        attrs.push((typ, &buf[off + 4..off + len]));
        off += aligned_len;
    }
    Ok(attrs)
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

fn msg_new_rule(table: &str, chain: &str, expressions: &[u8], userdata: Option<&[u8]>) -> Vec<u8> {
    let mut attrs = nla_str(NFTA_RULE_TABLE, table);
    attrs.extend(nla_str(NFTA_RULE_CHAIN, chain));
    attrs.extend(nla_nested(NFTA_RULE_EXPRESSIONS, expressions));
    if let Some(userdata) = userdata {
        attrs.extend(nla(NFTA_RULE_USERDATA, userdata));
    }
    nft_msg(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
        &attrs,
    )
}

fn msg_del_rule(table: &str, chain: &str, handle: u64) -> Vec<u8> {
    let mut attrs = nla_str(NFTA_RULE_TABLE, table);
    attrs.extend(nla_str(NFTA_RULE_CHAIN, chain));
    attrs.extend(nla(NFTA_RULE_HANDLE, &handle.to_be_bytes()));
    nft_msg(NFT_MSG_DELRULE, NLM_F_REQUEST, &attrs)
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

/// `ip saddr <ip>[/prefix]` match. Prefixes use an explicit bitwise AND.
fn ip_saddr_match(network: Ipv4Addr, prefix: u8) -> Vec<u8> {
    let mut out = payload_expr(
        NFT_REG_1,
        NFT_PAYLOAD_NETWORK_HEADER,
        IP_SADDR_OFFSET,
        IPV4_LEN,
    );
    if prefix < 32 {
        let mask = prefix_to_mask(prefix);
        out.extend(bitwise_and_expr(NFT_REG_1, IPV4_LEN, &mask));
        out.extend(cmp_expr(NFT_REG_1, NFT_CMP_EQ, &network.octets()));
    } else {
        out.extend(cmp_expr(NFT_REG_1, NFT_CMP_EQ, &network.octets()));
    }
    out
}

fn prefix_to_mask(prefix: u8) -> [u8; 4] {
    let value = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    value.to_be_bytes()
}

/// `reg = reg & mask` (used for CIDR source-address matches).
fn bitwise_and_expr(reg: u32, len: u32, mask: &[u8]) -> Vec<u8> {
    let mut data = nla_be32(NFTA_BITWISE_SREG, reg);
    data.extend(nla_be32(NFTA_BITWISE_DREG, reg));
    data.extend(nla_be32(NFTA_BITWISE_LEN, len));
    data.extend(nla_nested(NFTA_BITWISE_MASK, &data_value(mask)));
    data.extend(nla_nested(NFTA_BITWISE_XOR, &data_value(&[0; 4])));
    expr("bitwise", &data)
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

/// postrouting masquerade for the managed bridge subnet:
/// `ip saddr <network>/<prefix> oifname != "zerun0" masquerade` — the oifname
/// guard keeps container-to-container (and container-to-gateway) traffic
/// un-NATed, exactly like Docker's `-s <subnet> ! -o docker0 -j MASQUERADE`.
fn masquerade_rule(network: Ipv4Addr, prefix: u8) -> Vec<u8> {
    let mut out = ip_saddr_match(network, prefix);
    out.extend(oifname_neq("zerun0"));
    out.extend(masq_expr());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_masks_are_network_order() {
        assert_eq!(prefix_to_mask(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_mask(8), [255, 0, 0, 0]);
        assert_eq!(prefix_to_mask(24), [255, 255, 255, 0]);
        assert_eq!(prefix_to_mask(32), [255, 255, 255, 255]);
    }

    #[test]
    fn bridge_rule_masks_the_whole_managed_subnet() {
        let rule = masquerade_rule(Ipv4Addr::new(10, 88, 0, 0), 24);
        let text = String::from_utf8_lossy(&rule);
        assert!(text.contains("bitwise"));
        assert!(text.contains("masq"));
        // The network bytes and oifname payload are embedded in the TLV data.
        assert!(rule.windows(4).any(|w| w == [10, 88, 0, 0]));
        assert!(rule.windows(7).any(|w| w == *b"zerun0\x00"));
    }

    #[test]
    fn managed_rule_userdata_uses_the_wire_attribute() {
        let msg = msg_new_rule("zerun-nat", "postrouting", &[], Some(NAT_RULE_USERDATA));
        let attrs = parse_attrs(&msg[20..]).unwrap();
        assert!(attrs
            .iter()
            .any(|(kind, value)| *kind == NFTA_RULE_USERDATA && *value == NAT_RULE_USERDATA));
        assert!(!attrs.iter().any(|(kind, _)| *kind == 6));
    }

    #[test]
    fn rule_dump_parser_reads_every_message_in_a_datagram() {
        let mut datagram = msg_new_rule("zerun-nat", "postrouting", &[], Some(NAT_RULE_USERDATA));
        datagram.extend(msg_new_rule(
            "zerun-nat",
            "postrouting",
            &[],
            Some(b"legacy"),
        ));
        datagram.extend(msg_new_rule("other", "postrouting", &[], None));
        datagram.extend(nlmsg(NLMSG_DONE, 0, &[]));

        let mut rules = Vec::new();
        assert!(parse_rule_dump(&datagram, "zerun-nat", "postrouting", &mut rules).unwrap());
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].userdata.as_deref(), Some(NAT_RULE_USERDATA));
        assert_eq!(rules[1].userdata.as_deref(), Some(b"legacy".as_slice()));
    }

    #[test]
    fn parse_string_stops_at_the_first_nul() {
        assert_eq!(
            parse_string(b"postrouting\0padding"),
            Some("postrouting".to_owned())
        );
        assert_eq!(parse_string(b"\xff"), None);
    }

    #[test]
    fn parse_attrs_rejects_truncated_headers_and_padding() {
        assert!(parse_attrs(&[0, 0, 0]).is_err());
        // nla_len says five bytes, but the four-byte alignment needs eight.
        assert!(parse_attrs(&[5, 0, 1, 0, 1, 0, 0]).is_err());
    }

    #[test]
    fn delete_rule_encodes_a_network_order_handle() {
        let handle = 0x0102_0304_0506_0708;
        let msg = msg_del_rule("zerun-nat", "postrouting", handle);
        let attrs = parse_attrs(&msg[20..]).unwrap();
        let (_, value) = attrs
            .iter()
            .find(|(kind, _)| *kind == NFTA_RULE_HANDLE)
            .unwrap();
        assert_eq!(*value, handle.to_be_bytes());
    }
}
