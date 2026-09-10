//! Minimal rtnetlink wrapper — kernel-interface file (AGENTS.md §4.1).
//!
//! All rtnetlink traffic is concentrated here. The parent (host network
//! namespace) and the container child (its own fresh netns) both drive netlink
//! through this blocking API, so no caller has to touch async machinery.
//!
//! Methods are deliberately tiny: one request per call, with idempotent
//! "create-if-missing" helpers for shared host resources (the bridge).

use crate::error::ZResult;
use futures_util::StreamExt;
use rtnetlink::packet_route::{
    address::AddressAttribute,
    link::{InfoData, InfoKind, InfoVeth, LinkAttribute},
};
use std::net::Ipv4Addr;

pub struct Netlink {
    rt: tokio::runtime::Runtime,
    handle: rtnetlink::Handle,
}

impl Netlink {
    /// Open a netlink connection in the *current* network namespace. The child
    /// calls this again after clone, so it configures interfaces inside the
    /// container netns.
    pub fn new() -> ZResult<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| crate::zerr!("create netlink runtime: {e}"))?;
        // The rtnetlink socket must be created *inside* a runtime context
        // (netlink-sys registers it with the tokio reactor).
        let handle = rt.block_on(async {
            let (connection, handle, _events) = rtnetlink::new_connection()
                .map_err(|e| crate::zerr!("open rtnetlink socket: {e}"))?;
            rt.spawn(connection);
            Ok::<rtnetlink::Handle, crate::error::ZError>(handle)
        })?;
        Ok(Netlink { rt, handle })
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    /// ifindex of the link named `name` in this network namespace.
    pub fn link_index(&self, name: &str) -> ZResult<Option<u32>> {
        self.block_on(async {
            let mut stream = self.handle.link().get().execute();
            while let Some(msg) = stream.next().await {
                let msg = msg.map_err(|e| crate::zerr!("list links: {e}"))?;
                let lname = msg.attributes.iter().find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n.as_str()),
                    _ => None,
                });
                if lname == Some(name) {
                    return Ok(Some(msg.header.index));
                }
            }
            Ok(None)
        })
    }

    /// True when `index` already carries IPv4 address `ip`.
    pub fn has_address(&self, index: u32, ip: Ipv4Addr) -> ZResult<bool> {
        self.block_on(async {
            let mut stream = self.handle.address().get().execute();
            while let Some(msg) = stream.next().await {
                let msg = msg.map_err(|e| crate::zerr!("list addresses: {e}"))?;
                if msg.header.index != index {
                    continue;
                }
                for attr in &msg.attributes {
                    if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
                        if *a == ip {
                            return Ok(true);
                        }
                    }
                }
            }
            Ok(false)
        })
    }

    /// Create a bridge (ignore the error when it already exists).
    pub fn create_bridge(&self, name: &str) -> ZResult<()> {
        let req = self
            .handle
            .link()
            .add(rtnetlink::LinkBridge::new(name).build());
        self.block_on(req.execute())
            .map_err(|e| crate::zerr!("create bridge {name}: {e}"))
    }

    /// Bring a link up (`ip link set NAME up`).
    pub fn link_up(&self, index: u32) -> ZResult<()> {
        let msg = rtnetlink::LinkUnspec::new_with_index(index).up().build();
        self.block_on(self.handle.link().change(msg).execute())
            .map_err(|e| crate::zerr!("link {index} up: {e}"))
    }

    /// Enslave `index` to the bridge `master` (`ip link set NAME master BR`).
    pub fn set_master(&self, index: u32, master: u32) -> ZResult<()> {
        let msg = rtnetlink::LinkUnspec::new_with_index(index)
            .controller(master)
            .build();
        self.block_on(self.handle.link().change(msg).execute())
            .map_err(|e| crate::zerr!("attach link {index} to bridge {master}: {e}"))
    }

    /// Create a veth pair whose peer is born directly in the netns referenced
    /// by an open `/proc/<pid>/ns/net` descriptor.
    pub fn create_veth_peer_fd(
        &self,
        host: &str,
        peer: &str,
        fd: std::os::fd::RawFd,
    ) -> ZResult<()> {
        let mut peer_msg = rtnetlink::LinkMessageBuilder::<rtnetlink::LinkUnspec>::new()
            .name(peer)
            .build();
        peer_msg.attributes.push(LinkAttribute::NetNsFd(fd));
        let req = rtnetlink::LinkMessageBuilder::<rtnetlink::LinkVeth>::new_with_info_kind(
            InfoKind::Veth,
        )
        .name(host)
        .set_info_data(InfoData::Veth(InfoVeth::Peer(peer_msg)))
        .build();
        self.block_on(self.handle.link().add(req).execute())
            .map_err(|e| crate::zerr!("create veth pair {host}<->{peer}: {e}"))
    }

    /// Rename the link `index` to `name` (container-side: `p<id>` -> `eth0`).
    pub fn rename(&self, index: u32, name: &str) -> ZResult<()> {
        let msg = rtnetlink::LinkUnspec::new_with_index(index)
            .name(name)
            .build();
        self.block_on(self.handle.link().change(msg).execute())
            .map_err(|e| crate::zerr!("rename link {index} to {name}: {e}"))
    }

    /// Assign IPv4 `ip/prefix` to `index`.
    pub fn add_address(&self, index: u32, ip: Ipv4Addr, prefix: u8) -> ZResult<()> {
        let req = self
            .handle
            .address()
            .add(index, std::net::IpAddr::V4(ip), prefix);
        self.block_on(req.execute())
            .map_err(|e| crate::zerr!("add address {ip}/{prefix} to link {index}: {e}"))
    }

    /// Add the default IPv4 route via `gateway` out of `index`.
    pub fn add_default_route(&self, gateway: Ipv4Addr, index: u32) -> ZResult<()> {
        let msg = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(gateway)
            .output_interface(index)
            .build();
        self.block_on(self.handle.route().add(msg).execute())
            .map_err(|e| crate::zerr!("add default route via {gateway}: {e}"))
    }

    /// Delete the link `index` (removes a veth pair's host end on teardown).
    pub fn delete_link(&self, index: u32) -> ZResult<()> {
        self.block_on(self.handle.link().del(index).execute())
            .map_err(|e| crate::zerr!("delete link {index}: {e}"))
    }

    /// Ensure a bridge exists and is up; returns its ifindex.
    /// Races between concurrent runs are tolerated: a failed create is retried
    /// as a lookup, and a present bridge is reused as-is.
    pub fn ensure_bridge(&self, name: &str) -> ZResult<u32> {
        if let Some(idx) = self.link_index(name)? {
            return Ok(idx);
        }
        match self.create_bridge(name) {
            Ok(()) => {}
            Err(e) => {
                // Another process may have won the race; only proceed when the
                // bridge now exists.
                if self.link_index(name)?.is_none() {
                    return Err(e);
                }
            }
        }
        let idx = self
            .link_index(name)?
            .ok_or_else(|| crate::zerr!("bridge {name} missing after create"))?;
        self.link_up(idx)?;
        Ok(idx)
    }

    /// Assign `ip/prefix` to `index`, tolerating a concurrent identical add.
    pub fn ensure_address(&self, index: u32, ip: Ipv4Addr, prefix: u8) -> ZResult<()> {
        match self.add_address(index, ip, prefix) {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.has_address(index, ip)? {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Collect (ifindex, name) pairs — used by tests and `doctor`-style checks.
    #[allow(dead_code)]
    pub fn list_links(&self) -> ZResult<Vec<(u32, String)>> {
        self.block_on(async {
            let mut stream = self.handle.link().get().execute();
            let mut out = Vec::new();
            while let Some(msg) = stream.next().await {
                let msg = msg.map_err(|e| crate::zerr!("list links: {e}"))?;
                let name = msg
                    .attributes
                    .iter()
                    .find_map(|a| match a {
                        LinkAttribute::IfName(n) => Some(n.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                out.push((msg.header.index, name));
            }
            Ok(out)
        })
    }
}
