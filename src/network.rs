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
//! Outbound NAT lives in a per-container nft table `zerun-<id>`
//! (src/nfnetlink.rs, pure netlink — no `nft` binary): one postrouting
//! masquerade rule per container (`ip saddr <ip> oifname != "zerun0"
//! masquerade`) so the container reaches the outside world while
//! container-to-container traffic keeps its source addresses (Docker
//! `-s <subnet> ! -o docker0` semantics). The whole table is dropped
//! atomically when the container exits.
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
//! no shared state). A file-based IPAM bitmap is planned together with the M5
//! lifecycle work, where persistent state first exists.

use crate::error::ZResult;
use crate::netlink::Netlink;
use crate::nfnetlink::{NatConfig, Nftables};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;

/// One TCP port publish: host port -> container port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedPort {
    pub host: u16,
    pub container: u16,
}

/// Host bridge every bridge-mode container shares (like Docker's docker0).
pub const BRIDGE_NAME: &str = "zerun0";
/// Gateway address of `BRIDGE_NAME` inside the 10.88.0.0/24 subnet.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
pub const SUBNET_PREFIX: u8 = 24;

/// What the parent created for one container; torn down after the run exits.
pub struct HostNet {
    veth_name: String,
    /// nft table holding this container's NAT rules.
    table: String,
}

/// One listening host port forwarded to the container (userland `-p` proxy).
/// Dropping the proxy closes the listener; pump threads are detached and die
/// with the owning process, which never outlives the container run.
pub struct PortProxy {
    _listener: TcpListener,
}

impl PortProxy {
    /// Bind one listener and spawn its accept loop.
    fn bind(host: u16, container_ip: Ipv4Addr, container: u16) -> ZResult<Self> {
        let listener = TcpListener::bind(("0.0.0.0", host)).map_err(|e| {
            crate::zerr!("cannot publish 0.0.0.0:{host} -> {container_ip}:{container}: {e}")
        })?;
        let thread_listener = listener
            .try_clone()
            .map_err(|e| crate::zerr!("clone listener for 0.0.0.0:{host}: {e}"))?;
        thread::spawn(move || accept_loop(thread_listener, container_ip, container));
        Ok(PortProxy {
            _listener: listener,
        })
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
        .map(|p| PortProxy::bind(p.host, container_ip, p.container))
        .collect()
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

/// Per-container nft table name holding the NAT rules (`table ip zerun-<id>`).
pub fn nat_table(id: &str) -> String {
    format!("zerun-{}", &id[..id.len().min(16)])
}

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

/// Host side: ensure the bridge, create the veth pair, move the peer into the
/// child's netns, attach the host end to the bridge and install the
/// per-container egress-NAT table.
pub fn setup_host_side(id: &str, child_pid: i32) -> ZResult<HostNet> {
    let nl = Netlink::new()?;
    let bridge = nl.ensure_bridge(BRIDGE_NAME)?;
    nl.ensure_address(bridge, GATEWAY_IP, SUBNET_PREFIX)?;

    let host = veth_name(id);
    let peer = peer_name(id);
    if nl.link_index(&host)?.is_some() {
        return Err(crate::zerr!(
            "stale veth {host} already exists; remove it and retry"
        ));
    }
    nl.create_veth(&host, &peer)?;
    let host_index = nl
        .link_index(&host)?
        .ok_or_else(|| crate::zerr!("veth {host} missing after create"))?;
    nl.move_to_pid(&peer, child_pid as u32)?;
    nl.set_master(host_index, bridge)?;
    nl.link_up(host_index)?;

    enable_ip_forward()?;
    let table = nat_table(id);
    let nft = Nftables::new()?;
    let cfg = NatConfig {
        table: &table,
        container_ip: container_ip(id),
    };
    nft.install_nat(&cfg)?;

    Ok(HostNet {
        veth_name: host,
        table,
    })
}

/// Child side (inside the fresh netns, after the net-ready signal): rename the
/// peer to `eth0`, bring loopback and eth0 up, assign the address and default
/// route.
pub fn setup_container_side(id: &str) -> ZResult<()> {
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

    let ip = container_ip(id);
    nl.ensure_address(idx, ip, SUBNET_PREFIX)?;
    nl.add_default_route(GATEWAY_IP, idx)?;
    Ok(())
}

/// Host side cleanup after the container exited: drop the NAT table (atomic,
/// removes every rule of this container) and remove any leftover veth host end.
///
/// When the child netns goes away the kernel removes the whole veth pair, so
/// usually there is nothing left to do; this only deletes a leftover host end
/// (e.g. after an unclean kill). Both steps are best-effort and never fail the
/// caller.
pub fn teardown_host_side(net: &HostNet) {
    if let Ok(nft) = Nftables::new() {
        nft.remove_table(&net.table);
    }
    let nl = match Netlink::new() {
        Ok(nl) => nl,
        Err(_) => return,
    };
    let index = match nl.link_index(&net.veth_name) {
        Ok(Some(i)) => i,
        _ => return, // already gone with the container netns
    };
    if let Err(e) = nl.delete_link(index) {
        eprintln!(
            "zerun: warn: failed to remove veth {} ({}): {e}",
            net.veth_name, index
        );
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
        assert_eq!(nat_table(id), "zerun-0123456789ab");
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
