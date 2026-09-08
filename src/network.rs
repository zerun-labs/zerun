//! Bridge networking (M4) orchestration.
//!
//! Topology for a rootful `run --net bridge`:
//!   host:   bridge `zerun0` 10.88.0.1/24  <-- veth `v<id>` (host end)
//!   child:  netns with `eth0` (peer `p<id>`, renamed by the child)
//!           10.88.0.x/24, default route via 10.88.0.1
//!
//! The parent owns host-side resources (bridge, veth host end); the child
//! configures its own end once the parent signals the peer has been moved into
//! its netns (see the net-ready pipe in `namespace.rs`). NAT / port publishing
//! land in a later milestone step; until then the container reaches the bridge
//! gateway and sibling containers, but not the outside world.
//!
//! IPv4 address allocation is deterministic from the container id (no daemon,
//! no shared state). A file-based IPAM bitmap is planned together with the M5
//! lifecycle work, where persistent state first exists.

use crate::error::ZResult;
use crate::netlink::Netlink;
use std::net::Ipv4Addr;

/// Host bridge every bridge-mode container shares (like Docker's docker0).
pub const BRIDGE_NAME: &str = "zerun0";
/// Gateway address of `BRIDGE_NAME` inside the 10.88.0.0/24 subnet.
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
pub const SUBNET_PREFIX: u8 = 24;

/// What the parent created for one container; deleted after the run exits.
pub struct HostNet {
    veth_name: String,
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
/// child's netns and attach the host end to the bridge.
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

    Ok(HostNet { veth_name: host })
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

/// Host side cleanup after the container exited.
///
/// When the child netns goes away the kernel removes the whole veth pair, so
/// usually there is nothing left to do; this only deletes a leftover host end
/// (e.g. after an unclean kill). Best-effort, never fails the caller.
pub fn teardown_host_side(net: &HostNet) {
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
