//! Bridge networking (M4) orchestration.
//!
//! Topology for a rootful `run --net bridge`:
//!   host:   bridge `zerun0` 10.88.0.1/24  <-- veth `v<id>` (host end)
//!   child:  netns with `eth0` (peer `p<id>`, renamed by the child)
//!           10.88.0.x/24, default route via 10.88.0.1
//!
//! The parent owns host-side resources (bridge, veth host end) and configures
//! them before signalling the child over the net-ready pipe (see
//! `namespace.rs`).
//!
//! Outbound NAT lives in one shared nft table `zerun-nat`
//! (src/nfnetlink.rs, pure netlink — no `nft` binary): `ip saddr
//! 10.88.0.0/24 oifname != "zerun0" masquerade` lets containers reach the
//! outside world while container-to-container traffic keeps its source
//! addresses (Docker `-s <subnet> ! -o docker0` semantics). The table is
//! deterministic and persists across containers, avoiding a per-run netfilter
//! setup/teardown round trip.
//!
//! Published ports (`-p HOST:CONTAINER`) are NOT kernel-DNAT'd: DNAT-ing a
//! locally generated 127.0.0.1-sourced packet towards the bridge dies at the
//! post-DNAT route lookup (127.0.0.0/8 is loopback-only as a source), which is
//! exactly why Docker excludes 127.0.0.0/8 from OUTPUT DNAT and runs
//! docker-proxy for host-loopback access. Zerun ships that proxy built in:
//! `bind_port_proxies` opens one listener per published port on 0.0.0.0 and
//! forwards accepted TCP connections to the container IP. The listeners live
//! exactly as long as the parent (foreground CLI or detached reaper) waits on
//! the container, so they disappear with the run.
//!
//! IPv4 address allocation is deterministic from the container id (no daemon,
//! no shared state) and serialized in a file-based IPAM under
//! `<run>/net/ipam.json` guarded by an flock (M5): a container's deterministic
//! slot is tried first, occupied slots are skipped, and records are released
//! on exit — or reclaimed by `ps`/`rm` crash reconcile when the owner died.

use crate::error::ZResult;
use crate::netlink::Netlink;
use crate::nfnetlink::{NatConfig, Nftables};
use crate::trace;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;

/// Transport protocol for a published port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl PortProtocol {
    /// Lowercase label used in state records and CLI output.
    pub fn label(self) -> &'static str {
        match self {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
        }
    }
}

/// One port publish: host port -> container port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedPort {
    /// Address to bind on the host; unspecified means every IPv4 interface.
    pub host_ip: IpAddr,
    pub host: u16,
    pub container: u16,
    pub protocol: PortProtocol,
}

/// Host bridge every bridge-mode container shares (like Docker's docker0).
pub const BRIDGE_NAME: &str = "zerun0";
/// Gateway address of `BRIDGE_NAME` inside the 10.88.0.0/24 subnet.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
pub const SUBNET_PREFIX: u8 = 24;

/// What the parent created for one container; torn down after the run exits.
pub struct HostNet {
    veth_name: String,
    /// Legacy per-container nft table, when this run created one.
    table: Option<String>,
}

impl HostNet {
    /// veth host-end name (used for crash reconcile bookkeeping).
    pub fn veth_name(&self) -> &str {
        &self.veth_name
    }

    /// Legacy nft table name, if this container owns one.
    pub fn table(&self) -> Option<&str> {
        self.table.as_deref()
    }
}

/// One listening host port forwarded to the container (userland `-p` proxy).
/// Dropping the proxy closes the listener; pump threads are detached and die
/// with the owning process, which never outlives the container run.
pub struct PortProxy {
    _listener: ProxyListener,
}

enum ProxyListener {
    Tcp(#[allow(dead_code)] TcpListener),
    Udp(#[allow(dead_code)] UdpSocket),
}

impl PortProxy {
    /// Bind one listener/socket and spawn its receive loop.
    fn bind(
        host_ip: IpAddr,
        host: u16,
        container_ip: Ipv4Addr,
        container: u16,
        protocol: PortProtocol,
    ) -> ZResult<Self> {
        let host_label = host_ip_label(host_ip);
        match protocol {
            PortProtocol::Tcp => {
                let listener = TcpListener::bind((host_ip, host)).map_err(|e| {
                    crate::zerr!(
                        "cannot publish {host_label}:{host} -> {container_ip}:{container}/tcp: {e}"
                    )
                })?;
                let thread_listener = listener
                    .try_clone()
                    .map_err(|e| crate::zerr!("clone listener for {host_label}:{host}: {e}"))?;
                thread::spawn(move || accept_loop(thread_listener, container_ip, container));
                Ok(PortProxy {
                    _listener: ProxyListener::Tcp(listener),
                })
            }
            PortProtocol::Udp => {
                let listener = UdpSocket::bind((host_ip, host)).map_err(|e| {
                    crate::zerr!(
                        "cannot publish {host_label}:{host} -> {container_ip}:{container}/udp: {e}"
                    )
                })?;
                let thread_listener = listener
                    .try_clone()
                    .map_err(|e| crate::zerr!("clone UDP socket for {host_label}:{host}: {e}"))?;
                thread::spawn(move || udp_loop(thread_listener, container_ip, container));
                Ok(PortProxy {
                    _listener: ProxyListener::Udp(listener),
                })
            }
        }
    }
}
/// Bind one userland proxy per published port (Docker's docker-proxy, built
/// in). Fails fast so a port conflict aborts the run before any container
/// work happens.
pub fn bind_port_proxies(
    container_ip: Ipv4Addr,
    published: &[PublishedPort],
) -> ZResult<Vec<PortProxy>> {
    published
        .iter()
        .map(|p| PortProxy::bind(p.host_ip, p.host, container_ip, p.container, p.protocol))
        .collect()
}

/// Render a host address for CLI/error output (IPv6 needs brackets).
pub fn host_ip_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(ip) => format!("[{ip}]"),
        IpAddr::V4(ip) => ip.to_string(),
    }
}

/// Accept connections until the listener is dropped, then forward each one.
fn accept_loop(listener: TcpListener, container_ip: Ipv4Addr, container: u16) {
    for conn in listener.incoming() {
        let Ok(client) = conn else { break }; // listener closed -> shutdown
        thread::spawn(move || {
            let _ = forward(client, container_ip, container);
        });
    }
}

/// Receive datagrams from all clients and forward them to the container.
/// Replies are sent from a per-client connected socket so multiple clients can
/// use the same published host port independently.
fn udp_loop(listener: UdpSocket, container_ip: Ipv4Addr, container: u16) {
    let mut clients: HashMap<SocketAddr, UdpSocket> = HashMap::new();
    let mut buf = [0u8; 65535];
    while let Ok((len, client)) = listener.recv_from(&mut buf) {
        let upstream = if let Some(upstream) = clients.get(&client) {
            upstream
        } else {
            let (Ok(upstream), Ok(reply)) = (
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)),
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)),
            ) else {
                continue;
            };
            if upstream.connect((container_ip, container)).is_err()
                || reply.connect(client).is_err()
            {
                continue;
            }
            let Ok(registered) = upstream.try_clone() else {
                continue;
            };
            clients.insert(client, registered);
            thread::spawn(move || {
                let mut buf = [0u8; 65535];
                while let Ok(len) = upstream.recv(&mut buf) {
                    if reply.send(&buf[..len]).is_err() {
                        break;
                    }
                }
            });
            clients
                .get(&client)
                .expect("client UDP proxy was just inserted")
        };
        let _ = upstream.send(&buf[..len]);
    }
}

/// Pump bytes both ways between an accepted client and the container.
fn forward(mut client: TcpStream, container_ip: Ipv4Addr, container: u16) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect((container_ip, container))?;
    let mut c2u = client.try_clone()?;
    let mut u2c = upstream.try_clone()?;
    let a = thread::spawn(move || std::io::copy(&mut c2u, &mut upstream));
    let b = thread::spawn(move || std::io::copy(&mut u2c, &mut client));
    let _ = a.join();
    let _ = b.join();
    Ok(())
}

/// Host end of the veth pair (<= 15 chars, IFNAMSIZ-1).
pub fn veth_name(id: &str) -> String {
    format!("v{}", &id[..id.len().min(8)])
}

/// Peer end name while it still lives in the host netns; the child renames it
/// to `eth0` after the move.
pub fn peer_name(id: &str) -> String {
    format!("p{}", &id[..id.len().min(8)])
}

/// Shared nft table for all managed bridge containers (`table ip zerun-nat`).
pub const SHARED_NAT_TABLE: &str = "zerun-nat";

/// Deterministic container IPv4 address derived from the container id:
/// 10.88.0.2 ..= 10.88.0.254 (FNV-1a over the id string).
pub fn container_ip(id: &str) -> Ipv4Addr {
    let mut hash: u32 = 0x811c_9dc5;
    for b in id.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let host = 2 + (hash & 0x00ff_ffff) % 253;
    Ipv4Addr::new(10, 88, 0, host as u8)
}

// --- file-based IPAM (M5) ------------------------------------------------------
//
// Bridge addresses are handed out from a file under `<run>/net/ipam.json`,
// guarded by an flock on `<run>/net/ipam.lock`. The deterministic
// `container_ip` slot is tried first (so a single container keeps a stable,
// debuggable address); occupied slots are skipped. Concurrent `run`/`ps`
// invocations serialize on the lock; a crashed run leaves a stale record that
// `ps` reconcile / `doctor` reclaims (a record whose container id has no
// running state).

fn ipam_file(run_root: &Path) -> std::path::PathBuf {
    run_root.join("net").join("ipam.json")
}

fn ipam_lock(run_root: &Path) -> std::path::PathBuf {
    run_root.join("net").join("ipam.lock")
}

fn read_ipam(path: &Path) -> BTreeMap<String, Ipv4Addr> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn write_ipam(path: &Path, map: &BTreeMap<String, Ipv4Addr>) -> ZResult<()> {
    let json = serde_json::to_vec_pretty(map).map_err(|e| crate::zerr!("serialize ipam: {e}"))?;
    crate::fsutil::atomic_write(path, &json)
}

/// Acquire an exclusive advisory lock on the IPAM file (blocking).
fn lock_ipam(run_root: &Path) -> std::io::Result<std::fs::File> {
    let lock = ipam_lock(run_root);
    if let Some(dir) = lock.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock)?;
    // LOCK_EX on the whole file; released on drop/close.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(f)
}

/// Allocate this container's bridge IP (idempotent per id).
pub fn allocate_ip(run_root: &Path, id: &str) -> ZResult<Ipv4Addr> {
    let _guard = lock_ipam(run_root).map_err(|e| crate::zerr!("ipam lock: {e}"))?;
    let path = ipam_file(run_root);
    let mut map = read_ipam(&path);
    if let Some(ip) = map.get(id) {
        return Ok(*ip);
    }
    let preferred = container_ip(id);
    let taken: Vec<Ipv4Addr> = map.values().copied().collect();
    let ip = if !taken.contains(&preferred) {
        preferred
    } else {
        (2u16..=254)
            .map(|h| Ipv4Addr::new(10, 88, 0, h as u8))
            .find(|cand| !taken.contains(cand))
            .ok_or_else(|| crate::zerr!("bridge subnet 10.88.0.0/24 exhausted"))?
    };
    map.insert(id.to_string(), ip);
    write_ipam(&path, &map)?;
    Ok(ip)
}

/// Release this container's bridge IP (best effort; idempotent).
pub fn release_ip(run_root: &Path, id: &str) {
    let Ok(_guard) = lock_ipam(run_root) else {
        return;
    };
    let path = ipam_file(run_root);
    let mut map = read_ipam(&path);
    if map.remove(id).is_none() {
        return;
    }
    let _ = write_ipam(&path, &map);
}

/// Host side: ensure the bridge and shared NAT rule, create the veth peer
/// directly in the child's netns, then attach and bring up the host end.
pub fn setup_host_side(id: &str, child_pid: i32) -> ZResult<HostNet> {
    trace::mark("parent:net:begin");
    let nl = Netlink::new()?;
    trace::mark("parent:net:socket");
    let bridge = nl.ensure_bridge(BRIDGE_NAME)?;
    nl.ensure_address(bridge, GATEWAY_IP, SUBNET_PREFIX)?;
    trace::mark("parent:net:bridge");

    let host = veth_name(id);
    let peer = peer_name(id);
    if nl.link_index(&host)?.is_some() {
        return Err(crate::zerr!(
            "stale veth {host} already exists; remove it and retry"
        ));
    }
    trace::mark("parent:net:veth-create-begin");
    let netns = std::fs::File::open(format!("/proc/{child_pid}/ns/net"))
        .map_err(|e| crate::zerr!("open netns for pid {child_pid}: {e}"))?;
    nl.create_veth_peer_fd(&host, &peer, netns.as_raw_fd())?;
    trace::mark("parent:net:veth-created");
    let host_index = nl
        .link_index(&host)?
        .ok_or_else(|| crate::zerr!("veth {host} missing after create"))?;
    trace::mark("parent:net:veth-index");
    nl.set_master(host_index, bridge)?;
    trace::mark("parent:net:veth-master");
    nl.link_up(host_index)?;
    trace::mark("parent:net:veth");

    enable_ip_forward()?;
    let nft = Nftables::new()?;
    let cfg = NatConfig {
        table: SHARED_NAT_TABLE,
        source_network: Ipv4Addr::new(10, 88, 0, 0),
        prefix_len: SUBNET_PREFIX,
    };
    nft.install_nat(&cfg)?;
    trace::mark("parent:net:nat");

    Ok(HostNet {
        veth_name: host,
        table: None,
    })
}

/// Child side (inside the fresh netns, after the net-ready signal): rename the
/// peer to `eth0`, bring loopback and eth0 up, assign the address and default
/// route.
pub fn setup_container_side(id: &str, ip: Ipv4Addr) -> ZResult<()> {
    let nl = Netlink::new()?;
    let peer = peer_name(id);
    let idx = nl
        .link_index(&peer)?
        .ok_or_else(|| crate::zerr!("peer {peer} missing in container netns"))?;
    nl.rename(idx, "eth0")?;
    nl.link_up(idx)?;

    if let Some(lo) = nl.link_index("lo")? {
        nl.link_up(lo)?;
    }

    nl.ensure_address(idx, ip, SUBNET_PREFIX)?;
    nl.add_default_route(GATEWAY_IP, idx)?;
    Ok(())
}

/// Host side cleanup after the container exited: remove any legacy per-container
/// NAT table and any leftover veth host end.
///
/// When the child netns goes away the kernel removes the whole veth pair, so
/// usually there is nothing left to do; this only deletes a leftover host end
/// (e.g. after an unclean kill). Both steps are best-effort and never fail the
/// caller.
pub fn teardown_host_side(net: &HostNet) {
    teardown_named(&net.veth_name, net.table.as_deref());
}

/// Best-effort removal of a container's host-side leftovers by name. Used by
/// normal teardown and by crash reconcile (`ze ps`, `ze rm -f`) where the
/// reaper died before it could clean up.
pub fn teardown_named(veth: &str, table: Option<&str>) {
    trace::mark("teardown:begin");
    if let Some(table) = table {
        if let Ok(nft) = Nftables::new() {
            nft.remove_table(table);
        }
    }
    trace::mark("teardown:nft");
    let nl = match Netlink::new() {
        Ok(nl) => nl,
        Err(_) => return,
    };
    trace::mark("teardown:netlink");
    let index = match nl.link_index(veth) {
        Ok(Some(i)) => i,
        _ => return, // already gone with the container netns
    };
    if let Err(e) = nl.delete_link(index) {
        eprintln!("zerun: warn: failed to remove veth {veth} ({index}): {e}");
    }
}

/// Make sure the kernel forwards IPv4 between interfaces (required for bridge
/// egress / published ports). Docker does the same on bridge setup.
fn enable_ip_forward() -> ZResult<()> {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";
    match std::fs::read_to_string(PATH) {
        Ok(v) if v.trim() == "1" => return Ok(()),
        Ok(_) => {}
        Err(e) => {
            return Err(crate::zerr!(
                "--net bridge requires IPv4 forwarding: read {PATH}: {e}"
            ))
        }
    }
    std::fs::write(PATH, "1\n")
        .map_err(|e| crate::zerr!("--net bridge requires IPv4 forwarding: enable {PATH}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_stay_within_ifnamelen() {
        let id = "0123456789ab";
        assert!(veth_name(id).len() <= 15);
        assert!(peer_name(id).len() <= 15);
        assert_eq!(veth_name(id), "v01234567");
        assert_eq!(peer_name(id), "p01234567");
        assert_eq!(SHARED_NAT_TABLE, "zerun-nat");
    }

    #[test]
    fn container_ips_are_deterministic_and_in_range() {
        let ids = [
            "000000000001",
            "0123456789ab",
            "ffffffffffff",
            "deadbeefcafe",
        ];
        for id in &ids {
            let ip = container_ip(id);
            let last = ip.octets()[3];
            assert!((2..=254).contains(&last), "ip {ip} out of range for {id}");
            assert_eq!(ip.octets()[0..3], [10, 88, 0]);
            assert_eq!(container_ip(id), ip, "must be deterministic");
        }
        assert_ne!(container_ip("000000000001"), container_ip("000000000002"));
    }
}
