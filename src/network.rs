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
//! forwards accepted TCP connections to the container IP. Active TCP proxy
//! connections are bounded per container across all published ports so a
//! connection flood cannot create unbounded pump threads. Each proxy's
//! receive loop is stopped and joined before the next automatic restart
//! attempt, so a long-lived detached reaper can bind the same host ports again.
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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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

/// Address supplied by `--add-host NAME:ADDRESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostAliasAddress {
    Ip(IpAddr),
    /// Docker-compatible magic value resolved to the bridge gateway.
    HostGateway,
}

/// One operator-provided `/etc/hosts` entry, kept in parsed form so launch
/// metadata and generated services can reproduce the original flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAlias {
    name: String,
    address: HostAliasAddress,
}

/// A host alias with `host-gateway` resolved to a concrete address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub name: String,
    pub ip: IpAddr,
}

impl HostAlias {
    /// Parse Docker's `--add-host NAME:ADDRESS` form. IPv6 addresses are
    /// accepted without brackets because the separator is the first colon.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (name, address) = value
            .split_once(':')
            .ok_or_else(|| format!("--add-host '{value}' must be NAME:ADDRESS"))?;
        if !valid_host_alias_name(name) {
            return Err(format!(
                "--add-host '{value}' has an invalid host name (use ASCII letters, digits, '.', '_' or '-')"
            ));
        }
        let address = if address == "host-gateway" {
            HostAliasAddress::HostGateway
        } else {
            HostAliasAddress::Ip(
                address
                    .parse()
                    .map_err(|_| format!("--add-host '{value}' has an invalid IP address"))?,
            )
        };
        Ok(Self {
            name: name.to_string(),
            address,
        })
    }

    /// Canonical flag value retained in detached state and service units.
    pub fn render(&self) -> String {
        let address = match self.address {
            HostAliasAddress::Ip(ip) => ip.to_string(),
            HostAliasAddress::HostGateway => "host-gateway".to_string(),
        };
        format!("{}:{address}", self.name)
    }

    /// Resolve the alias for a concrete network mode. `gateway` is `Some` only
    /// for bridge mode; literal addresses work in every network mode.
    pub fn resolve(&self, gateway: Option<Ipv4Addr>) -> Result<HostEntry, String> {
        let ip = match self.address {
            HostAliasAddress::Ip(ip) => ip,
            HostAliasAddress::HostGateway => gateway.map(IpAddr::V4).ok_or_else(|| {
                format!(
                    "--add-host {}:host-gateway requires --net bridge",
                    self.name
                )
            })?,
        };
        Ok(HostEntry {
            name: self.name.clone(),
            ip,
        })
    }
}

/// Resolve every `--add-host` alias before cloning the container.
pub fn resolve_host_aliases(
    aliases: &[HostAlias],
    gateway: Option<Ipv4Addr>,
) -> Result<Vec<HostEntry>, String> {
    aliases.iter().map(|alias| alias.resolve(gateway)).collect()
}

fn valid_host_alias_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

/// What the parent created for one container; torn down after the run exits.
pub struct HostNet {
    veth_name: String,
    /// ifindex captured when the host end was created. Keeping it avoids a
    /// full rtnetlink link dump on the teardown path.
    veth_index: u32,
    /// rtnetlink connection used for setup and reused for teardown.
    netlink: Netlink,
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

const TCP_PROXY_CONNECTION_LIMIT: usize = 64;

/// One listening host port forwarded to the container (userland `-p` proxy).
///
/// Dropping the proxy stops its receive loop and joins it. A detached reaper
/// reuses the same process for automatic restart attempts, so listeners must
/// release their host ports between attempts instead of living until that
/// process exits.
pub struct PortProxy {
    _listener: ProxyListener,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Drop for PortProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
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
        tcp_connections: Arc<AtomicUsize>,
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
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = thread::Builder::new()
                    .name("zerun-port-tcp".to_string())
                    .spawn(move || {
                        accept_loop(
                            thread_listener,
                            container_ip,
                            container,
                            tcp_connections,
                            worker_stop,
                        )
                    })
                    .map_err(|e| {
                        crate::zerr!("spawn TCP port proxy for {host_label}:{host}: {e}")
                    })?;
                Ok(PortProxy {
                    _listener: ProxyListener::Tcp(listener),
                    stop,
                    worker: Some(worker),
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
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = thread::Builder::new()
                    .name("zerun-port-udp".to_string())
                    .spawn(move || udp_loop(thread_listener, container_ip, container, worker_stop))
                    .map_err(|e| {
                        crate::zerr!("spawn UDP port proxy for {host_label}:{host}: {e}")
                    })?;
                Ok(PortProxy {
                    _listener: ProxyListener::Udp(listener),
                    stop,
                    worker: Some(worker),
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
    let tcp_connections = Arc::new(AtomicUsize::new(0));
    published
        .iter()
        .map(|p| {
            PortProxy::bind(
                p.host_ip,
                p.host,
                container_ip,
                p.container,
                p.protocol,
                Arc::clone(&tcp_connections),
            )
        })
        .collect()
}

/// Render a host address for CLI/error output (IPv6 needs brackets).
pub fn host_ip_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(ip) => format!("[{ip}]"),
        IpAddr::V4(ip) => ip.to_string(),
    }
}

/// RAII slot held for the entire lifetime of one TCP proxy connection.
struct TcpProxySlot(Arc<AtomicUsize>);

impl Drop for TcpProxySlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_tcp_proxy_slot(connections: &Arc<AtomicUsize>) -> Option<TcpProxySlot> {
    connections
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < TCP_PROXY_CONNECTION_LIMIT).then_some(active + 1)
        })
        .ok()
        .map(|_| TcpProxySlot(Arc::clone(connections)))
}

/// Accept connections until the proxy is dropped, then forward each one.
fn accept_loop(
    listener: TcpListener,
    container_ip: Ipv4Addr,
    container: u16,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) {
    if let Err(error) = listener.set_nonblocking(true) {
        eprintln!("zerun: warn: configure TCP port proxy: {error}");
        return;
    }
    let mut warned_full = false;
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((client, _)) => {
                let Some(slot) = try_acquire_tcp_proxy_slot(&connections) else {
                    if !warned_full {
                        eprintln!(
                            "zerun: warn: TCP port proxy connection limit ({TCP_PROXY_CONNECTION_LIMIT}) reached; dropping new connections"
                        );
                        warned_full = true;
                    }
                    continue;
                };
                warned_full = false;
                if let Err(error) = thread::Builder::new()
                    .name("zerun-port-client".to_string())
                    .spawn(move || {
                        let _slot = slot;
                        let _ = forward(client, container_ip, container);
                    })
                {
                    eprintln!("zerun: warn: failed to spawn TCP port client proxy: {error}");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // A short poll keeps Drop latency below the restart backoff
                // while avoiding a permanently blocked accept thread.
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

const UDP_CLIENT_LIMIT: usize = 256;
const UDP_CLIENT_IDLE: Duration = Duration::from_secs(60);
const UDP_POLL_INTERVAL: Duration = Duration::from_secs(1);
const UDP_STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

struct UdpClient {
    upstream: UdpSocket,
    last_seen: Instant,
    stop: Arc<AtomicBool>,
    worker: thread::JoinHandle<()>,
}

fn stop_udp_client(client: UdpClient) {
    client.stop.store(true, Ordering::Release);
    // The worker polls the stop flag via a short socket read timeout. UDP
    // sockets have no shutdown(2), so joining waits at most one poll interval.
    let _ = client.worker.join();
}

fn prune_udp_clients(clients: &mut HashMap<SocketAddr, UdpClient>, now: Instant) {
    let stale: Vec<SocketAddr> = clients
        .iter()
        .filter_map(|(address, client)| {
            (now.duration_since(client.last_seen) >= UDP_CLIENT_IDLE).then_some(*address)
        })
        .collect();
    for address in stale {
        if let Some(client) = clients.remove(&address) {
            stop_udp_client(client);
        }
    }
}

/// Receive datagrams from all clients and forward them to the container.
/// Replies are sent through a clone of the published host socket so clients
/// observe the published host port as the source. Idle client mappings are
/// reclaimed, and a hard limit prevents a source-port flood from creating an
/// unbounded number of worker threads and sockets.
fn udp_loop(listener: UdpSocket, container_ip: Ipv4Addr, container: u16, stop: Arc<AtomicBool>) {
    let _ = listener.set_read_timeout(Some(UDP_STOP_POLL_INTERVAL));
    let mut clients: HashMap<SocketAddr, UdpClient> = HashMap::new();
    let mut warned_full = false;
    let mut next_prune = Instant::now() + UDP_POLL_INTERVAL;
    let mut buf = [0u8; 65535];

    while !stop.load(Ordering::Acquire) {
        let (len, client) = match listener.recv_from(&mut buf) {
            Ok(packet) => packet,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                let now = Instant::now();
                if now >= next_prune {
                    prune_udp_clients(&mut clients, now);
                    next_prune = now + UDP_POLL_INTERVAL;
                }
                continue;
            }
            Err(_) => break,
        };
        let now = Instant::now();
        prune_udp_clients(&mut clients, now);

        if let Some(existing) = clients.get_mut(&client) {
            existing.last_seen = now;
            if existing.upstream.send(&buf[..len]).is_err() {
                if let Some(dead) = clients.remove(&client) {
                    stop_udp_client(dead);
                }
            }
            continue;
        }

        if clients.len() >= UDP_CLIENT_LIMIT {
            if !warned_full {
                eprintln!(
                    "zerun: warn: UDP publish client limit ({UDP_CLIENT_LIMIT}) reached; dropping new clients"
                );
                warned_full = true;
            }
            continue;
        }
        warned_full = false;

        let Ok(upstream) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        let Ok(reply) = listener.try_clone() else {
            continue;
        };
        if upstream.connect((container_ip, container)).is_err()
            || upstream
                .set_read_timeout(Some(UDP_STOP_POLL_INTERVAL))
                .is_err()
        {
            continue;
        }
        let Ok(registered) = upstream.try_clone() else {
            continue;
        };
        let client_stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&client_stop);
        let worker = match thread::Builder::new()
            .name("zerun-port-udp-client".to_string())
            .spawn(move || {
                let mut buf = [0u8; 65535];
                while !worker_stop.load(Ordering::Acquire) {
                    match upstream.recv(&mut buf) {
                        Ok(len) => {
                            if reply.send_to(&buf[..len], client).is_err() {
                                break;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) => {}
                        Err(_) => break,
                    }
                }
            }) {
            Ok(worker) => worker,
            Err(error) => {
                eprintln!("zerun: warn: failed to spawn UDP port client proxy: {error}");
                continue;
            }
        };
        let _ = registered.send(&buf[..len]);
        clients.insert(
            client,
            UdpClient {
                upstream: registered,
                last_seen: now,
                stop: client_stop,
                worker,
            },
        );
    }

    for (_, client) in clients.drain() {
        stop_udp_client(client);
    }
}

/// Pump bytes both ways between an accepted client and the container.
fn forward(mut client: TcpStream, container_ip: Ipv4Addr, container: u16) -> std::io::Result<()> {
    let upstream_addr = SocketAddr::from((container_ip, container));
    let mut upstream = TcpStream::connect_timeout(&upstream_addr, Duration::from_secs(5))?;
    let mut c2u = client.try_clone()?;
    let mut u2c = upstream.try_clone()?;
    // Keep control descriptors so a failed second spawn can wake the first
    // pump even after the data streams have moved into their closures.
    let client_control = client.try_clone()?;
    let upstream_control = upstream.try_clone()?;
    let (finished_tx, finished_rx) = mpsc::channel();
    let client_to_upstream_tx = finished_tx.clone();
    let a = thread::Builder::new()
        .name("zerun-port-client-to-container".to_string())
        .spawn(move || {
            let result = std::io::copy(&mut c2u, &mut upstream);
            if result.is_ok() {
                // Preserve TCP half-close: let the container finish sending
                // its response after the client has shut down its write side.
                let _ = upstream.shutdown(Shutdown::Write);
            }
            let _ = client_to_upstream_tx.send(result);
        })
        .map_err(|e| std::io::Error::other(format!("spawn TCP pump: {e}")))?;
    let b = match thread::Builder::new()
        .name("zerun-port-container-to-client".to_string())
        .spawn(move || {
            let result = std::io::copy(&mut u2c, &mut client);
            if result.is_ok() {
                let _ = client.shutdown(Shutdown::Write);
            }
            let _ = finished_tx.send(result);
        }) {
        Ok(handle) => handle,
        Err(error) => {
            // The first pump owns cloned descriptors. Shut down the control
            // descriptors so its blocking copy wakes before we join it.
            let _ = client_control.shutdown(Shutdown::Both);
            let _ = upstream_control.shutdown(Shutdown::Both);
            let _ = a.join();
            return Err(std::io::Error::other(format!("spawn TCP pump: {error}")));
        }
    };

    // Wait for both directions. If either fails, shut down the control
    // descriptors so the opposite blocking copy cannot retain a proxy slot
    // indefinitely. Clean EOF is directional and must not cut off replies.
    let mut first_error = None;
    for _ in 0..2 {
        let Ok(result) = finished_rx.recv() else {
            break;
        };
        if let Err(error) = result {
            if first_error.is_none() {
                first_error = Some(error);
                let _ = client_control.shutdown(Shutdown::Both);
                let _ = upstream_control.shutdown(Shutdown::Both);
            }
        }
    }
    let _ = a.join();
    let _ = b.join();
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
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

/// Name used by pre-shared-NAT state records. New records leave `table` empty.
fn legacy_table_name(id: &str) -> String {
    format!("zerun-{id}")
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

fn read_ipam(path: &Path) -> ZResult<BTreeMap<String, Ipv4Addr>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(crate::zerr!("read IPAM state {}: {error}", path.display())),
    };
    let map: BTreeMap<String, Ipv4Addr> = serde_json::from_str(&text)
        .map_err(|error| crate::zerr!("parse IPAM state {}: {error}", path.display()))?;
    validate_ipam(&map)?;
    Ok(map)
}

fn validate_ipam_id(id: &str) -> ZResult<()> {
    if !(1..=64).contains(&id.len()) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::zerr!("invalid container id '{id}' in IPAM state"));
    }
    Ok(())
}

fn validate_ipam(map: &BTreeMap<String, Ipv4Addr>) -> ZResult<()> {
    let mut addresses = BTreeSet::new();
    for (id, ip) in map {
        validate_ipam_id(id)?;
        let octets = ip.octets();
        if octets[..3] != [10, 88, 0] || !(2..=254).contains(&octets[3]) {
            return Err(crate::zerr!(
                "IPAM address {ip} for {id} is outside 10.88.0.0/24"
            ));
        }
        if !addresses.insert(*ip) {
            return Err(crate::zerr!("duplicate IPAM address {ip}"));
        }
    }
    Ok(())
}

fn write_ipam(path: &Path, map: &BTreeMap<String, Ipv4Addr>) -> ZResult<()> {
    let json = serde_json::to_vec_pretty(map).map_err(|e| crate::zerr!("serialize ipam: {e}"))?;
    crate::fsutil::atomic_write(path, &json)
}

/// Validate the persisted IPAM state without creating runtime directories.
///
/// The doctor command uses this read-only probe to distinguish a missing state
/// file from a corrupted one before the next bridge run encounters it.
pub fn check_ipam_state(run_root: &Path) -> ZResult<bool> {
    let path = ipam_file(run_root);
    if !path.exists() {
        return Ok(false);
    }
    read_ipam(&path).map(|_| true)
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
    crate::syscalls::flock(f.as_raw_fd(), libc::LOCK_EX)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(f)
}

/// Allocate this container's bridge IP (idempotent per id).
pub fn allocate_ip(run_root: &Path, id: &str) -> ZResult<Ipv4Addr> {
    validate_ipam_id(id)?;
    let _guard = lock_ipam(run_root).map_err(|e| crate::zerr!("ipam lock: {e}"))?;
    let path = ipam_file(run_root);
    let mut map = read_ipam(&path)?;
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
    let _guard = match lock_ipam(run_root) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("zerun: warning: cannot lock IPAM state to release {id}: {error}");
            return;
        }
    };
    let path = ipam_file(run_root);
    let mut map = match read_ipam(&path) {
        Ok(map) => map,
        Err(error) => {
            eprintln!("zerun: warning: cannot release IPAM entry for {id}: {error}");
            return;
        }
    };
    if map.remove(id).is_none() {
        return;
    }
    if let Err(error) = write_ipam(&path, &map) {
        eprintln!("zerun: warning: cannot persist IPAM release for {id}: {error}");
    }
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
        veth_index: host_index,
        netlink: nl,
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
    trace::mark("teardown:begin");
    if let Some(table) = net.table.as_deref() {
        if let Ok(nft) = Nftables::new() {
            nft.remove_table(table);
        }
    }
    trace::mark("teardown:nft");
    // The veth peer lives in the container netns, so the kernel removes both
    // ends once that netns is gone. The sysfs probe avoids deleting a reused
    // ifindex in the small window between netns teardown and this call.
    if read_ifindex(&net.veth_name) != Some(net.veth_index) {
        return;
    }
    if let Err(e) = net.netlink.delete_link(net.veth_index) {
        eprintln!(
            "zerun: warn: failed to remove veth {} ({}): {e}",
            net.veth_name, net.veth_index
        );
    }
}

fn read_ifindex(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Best-effort removal of a container's host-side leftovers by name. Used by
/// normal teardown and by crash reconcile (`ze ps`, `ze rm -f`) where the
/// reaper died before it could clean up.
pub fn teardown_named(id: &str, veth: &str, table: Option<&str>) {
    let expected_veth = veth_name(id);
    if veth != expected_veth {
        eprintln!(
            "zerun: warn: refusing to remove unexpected veth {veth} for container {id} (expected {expected_veth})"
        );
        return;
    }
    trace::mark("teardown:begin");
    if let Some(table) = table {
        let expected_table = legacy_table_name(id);
        if table == expected_table {
            if let Ok(nft) = Nftables::new() {
                nft.remove_table(table);
            }
        } else {
            eprintln!(
                "zerun: warn: refusing to remove unexpected nft table {table} for container {id}"
            );
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
    fn host_aliases_parse_resolve_and_reject_unsafe_names() {
        let v4 = HostAlias::parse("host.example:192.0.2.7").unwrap();
        assert_eq!(v4.render(), "host.example:192.0.2.7");
        assert_eq!(
            v4.resolve(None).unwrap(),
            HostEntry {
                name: "host.example".to_string(),
                ip: "192.0.2.7".parse().unwrap(),
            }
        );

        let v6 = HostAlias::parse("v6.example:2001:db8::7").unwrap();
        assert_eq!(v6.render(), "v6.example:2001:db8::7");
        assert_eq!(
            v6.resolve(None).unwrap().ip,
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );

        let gateway = HostAlias::parse("host.zerun.internal:host-gateway").unwrap();
        assert_eq!(
            gateway.resolve(Some(GATEWAY_IP)).unwrap().ip,
            IpAddr::V4(GATEWAY_IP)
        );
        assert!(gateway.resolve(None).is_err());

        for invalid in [
            "missing-address",
            "bad name:192.0.2.1",
            "-leading:192.0.2.1",
            "trailing-:192.0.2.1",
            "host:not-an-ip",
            "host:",
        ] {
            assert!(HostAlias::parse(invalid).is_err(), "{invalid} was accepted");
        }
    }

    #[test]
    fn dropping_proxies_releases_published_ports() {
        for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            let port = match protocol {
                PortProtocol::Tcp => {
                    let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    let port = probe.local_addr().unwrap().port();
                    drop(probe);
                    port
                }
                PortProtocol::Udp => {
                    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    let port = probe.local_addr().unwrap().port();
                    drop(probe);
                    port
                }
            };

            let proxy = PortProxy::bind(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                Ipv4Addr::LOCALHOST,
                4242,
                protocol,
                Arc::new(AtomicUsize::new(0)),
            )
            .unwrap();
            let conflict = match protocol {
                PortProtocol::Tcp => TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map(drop),
                PortProtocol::Udp => UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).map(drop),
            };
            assert!(
                conflict.is_err(),
                "{protocol:?} listener did not own the port"
            );
            drop(proxy);

            match protocol {
                PortProtocol::Tcp => {
                    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                        .expect("TCP proxy did not release its port");
                }
                PortProtocol::Udp => {
                    UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
                        .expect("UDP proxy did not release its port");
                }
            }
        }
    }

    #[test]
    fn tcp_proxy_connection_slots_enforce_limit_and_release() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut slots: Vec<_> = (0..TCP_PROXY_CONNECTION_LIMIT)
            .map(|_| try_acquire_tcp_proxy_slot(&active).expect("slot within configured limit"))
            .collect();
        assert_eq!(active.load(Ordering::Acquire), TCP_PROXY_CONNECTION_LIMIT);
        assert!(try_acquire_tcp_proxy_slot(&active).is_none());

        drop(slots.pop());
        assert_eq!(
            active.load(Ordering::Acquire),
            TCP_PROXY_CONNECTION_LIMIT - 1
        );
        let replacement = try_acquire_tcp_proxy_slot(&active).expect("released slot is reusable");
        assert_eq!(active.load(Ordering::Acquire), TCP_PROXY_CONNECTION_LIMIT);
        drop(replacement);
        assert_eq!(
            active.load(Ordering::Acquire),
            TCP_PROXY_CONNECTION_LIMIT - 1
        );
    }

    #[test]
    fn tcp_proxy_preserves_half_close_and_returns_the_reply() {
        use std::io::{Read, Write};

        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = std::thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"reply").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let front = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let front_addr = front.local_addr().unwrap();
        let mut client = TcpStream::connect(front_addr).unwrap();
        let (proxy_client, _) = front.accept().unwrap();
        let proxy_thread = std::thread::spawn(move || {
            forward(proxy_client, Ipv4Addr::LOCALHOST, backend_addr.port()).unwrap();
        });

        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"reply");
        proxy_thread.join().unwrap();
        backend_thread.join().unwrap();
    }

    #[test]
    fn udp_client_expiry_signals_worker_stop() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut clients = HashMap::new();
        clients.insert(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            UdpClient {
                upstream: socket,
                last_seen: Instant::now() - UDP_CLIENT_IDLE,
                stop: Arc::clone(&stop),
                worker: std::thread::spawn(|| {}),
            },
        );

        prune_udp_clients(&mut clients, Instant::now());
        assert!(clients.is_empty());
        assert!(stop.load(Ordering::Acquire));
    }

    #[test]
    fn legacy_resource_names_are_container_specific() {
        assert_eq!(legacy_table_name("0123456789ab"), "zerun-0123456789ab");
        assert_ne!(legacy_table_name("0123456789ab"), SHARED_NAT_TABLE);
    }

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

    #[test]
    fn ipam_validation_rejects_corrupt_or_unsafe_state() {
        let mut valid = BTreeMap::new();
        valid.insert("0123456789ab".to_string(), Ipv4Addr::new(10, 88, 0, 42));
        assert!(validate_ipam(&valid).is_ok());

        let mut invalid_id = valid.clone();
        invalid_id.insert("not-a-container".to_string(), Ipv4Addr::new(10, 88, 0, 43));
        assert!(validate_ipam(&invalid_id).is_err());

        let mut invalid_subnet = valid.clone();
        invalid_subnet.insert("abcdef".to_string(), Ipv4Addr::new(10, 89, 0, 2));
        assert!(validate_ipam(&invalid_subnet).is_err());

        let mut duplicate = valid.clone();
        duplicate.insert("abcdef".to_string(), Ipv4Addr::new(10, 88, 0, 42));
        assert!(validate_ipam(&duplicate).is_err());
    }

    #[test]
    fn ipam_release_removes_the_recorded_address() {
        let root = std::env::temp_dir().join(format!(
            "zerun-network-ipam-release-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let id = "0123456789ab";
        let allocated = allocate_ip(&root, id).unwrap();
        assert_eq!(
            read_ipam(&ipam_file(&root)).unwrap().get(id),
            Some(&allocated)
        );
        release_ip(&root, id);
        assert!(read_ipam(&ipam_file(&root)).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ipam_probe_distinguishes_missing_and_invalid_state() {
        let root = std::env::temp_dir().join(format!(
            "zerun-network-ipam-probe-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let net = root.join("net");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&net).unwrap();
        assert!(!check_ipam_state(&root).unwrap());
        std::fs::write(net.join("ipam.json"), b"not json").unwrap();
        assert!(check_ipam_state(&root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
