//! Isolation orchestration.
//!
//! Parent: create cgroup -> fork a short-lived supervisor -> the supervisor
//! enters the requested namespaces and forks the workload -> attach the parked
//! worker to cgroup.procs and assemble host networking -> release the worker ->
//! forward signals -> wait. Worker: mount/pivot -> pseudo-fs -> (bridge:
//! container-side network config) -> security hardening -> execve (or run the
//! built-in mini-init first).
//!
//! For `--net bridge` a second pipe synchronizes networking between parent and
//! child: the parent builds the bridge/veth and moves the peer into the child's
//! netns, then signals the child over the net-ready pipe (0 = ready, 1 + text =
//! host-side failure). The child configures `eth0` only after the signal, so
//! networking is up before the workload starts.
//!
//! `run_container_with_report` exposes the moment the workload has exec'd
//! (`StartedInfo`) so the detached reaper (src/lifecycle.rs) can persist
//! "running" state and release the foreground CLI at exactly the right time,
//! and returns final cgroup metrics before cleanup.
use crate::cgroup::{CgroupV2, ResourceLimits};
use crate::error::ZResult;
use crate::mounts::{
    make_root_readonly, mount_extra_tmpfs, open_rootless_device_sources, setup_rootfs, BindMount,
    OverlayPaths, RootfsConfig, TmpfsMount,
};
use crate::pty::PtyPair;
use crate::seccomp::SeccompMode;
use crate::security;
use crate::state::{ContainerMetrics, NamespaceMode, NamespaceModes};
use crate::syscalls;
use crate::trace;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetMode {
    /// Fresh netns with loopback only.
    #[default]
    None,
    /// Rootful bridge networking: `zerun0` bridge + per-container veth pair.
    /// Requires CAP_NET_ADMIN in the host network namespace.
    Bridge,
    /// Share the host network.
    Host,
}

#[derive(Debug, Clone)]
pub struct RunSpec {
    pub rootfs: PathBuf,
    pub argv: Vec<String>,
    pub hostname: Option<String>,
    /// PID/IPC/UTS namespace sharing for this container.
    pub namespaces: NamespaceModes,
    pub net: NetMode,
    pub use_init: bool,
    pub limits: ResourceLimits,
    /// Per-process POSIX limits applied to the workload.
    pub ulimits: crate::rlimit::UlimitSet,
    pub seccomp: SeccompMode,
    /// Exact capability set left for the workload after security hardening.
    pub capabilities: security::CapabilitySet,
    /// Allocate a PTY for foreground container stdio (`run -t`).
    pub tty: bool,
    /// Forward host stdin to the container (`run -i`).
    pub interactive: bool,
    /// Per-container writable filesystem; None = pivot directly into `rootfs`.
    pub overlay: Option<OverlayPaths>,
    pub id: String,
    /// Lifecycle signal selected from `--stop-signal` or the image
    /// `config.StopSignal`. The parent translates an externally delivered
    /// SIGTERM into this signal, allowing an ordinary supervisor such as
    /// systemd to stop foreground containers with their intended policy.
    pub stop_signal: i32,
    /// Explicit container environment (image mode: KEY=VALUE pairs, fully
    /// replacing the inherited env). None = legacy `--rootfs` behavior
    /// (inherit host env + inject defaults).
    pub env: Option<Vec<(String, String)>>,
    /// Working directory inside the container (None = "/").
    pub cwd: Option<String>,
    /// Container user (`--user` or the image `config.User`), e.g. "nginx" or
    /// "1000:1000". None keeps the root user (mapped to the host user in
    /// rootless mode).
    pub user: Option<String>,
    /// Additional supplementary groups (`--group-add`), resolved inside the
    /// container mount namespace before hardening.
    pub group_add: Vec<String>,
    /// Remount the container root read-only before exec (`--read-only`);
    /// separate volume/tmpfs mounts stay writable.
    pub readonly: bool,
    /// Extra in-container tmpfs mounts (`--tmpfs PATH[:opts]`).
    pub tmpfs: Vec<TmpfsMount>,
    /// TCP ports published on the host (`-p HOST:CONTAINER`); only valid with
    /// `NetMode::Bridge`. Served by the built-in userland proxy in network.rs.
    pub ports: Vec<crate::network::PublishedPort>,
    /// Host bind mounts (simple file/directory volumes).
    pub volumes: Vec<BindMount>,
    /// Operator-provided names resolved into the container `/etc/hosts`.
    pub hosts: Vec<crate::network::HostEntry>,
    /// Bridge IPv4 assigned by the parent from the file IPAM (set before
    /// clone; consumed by both host-side NAT and the child's eth0 config).
    pub bridge_ip: Option<std::net::Ipv4Addr>,
    /// Runtime root of the active store (`/run/zerun` etc.), used by the
    /// parent for IPAM bookkeeping.
    pub run_root: PathBuf,
    /// Keep a cgroup for a detached container even when it has no resource
    /// limits, enabling lifecycle operations such as pause/unpause.
    pub lifecycle_cgroup: bool,
}

static TARGET_CHILD: AtomicI32 = AtomicI32::new(0);
static TARGET_STOP_SIGNAL: AtomicI32 = AtomicI32::new(crate::signal::DEFAULT_STOP_SIGNAL);

extern "C" fn forward_to_child(sig: libc::c_int) {
    let pid = TARGET_CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        crate::syscalls::signal_process(pid, forwarded_signal(sig));
    }
}

/// A supervisor convention: SIGTERM requests a graceful stop, so use the
/// container's resolved stop signal. Other terminal signals retain their
/// original meaning (Ctrl-C stays SIGINT, for example).
fn forwarded_signal(received: libc::c_int) -> libc::c_int {
    if received == libc::SIGTERM {
        TARGET_STOP_SIGNAL.load(Ordering::Relaxed)
    } else {
        received
    }
}

/// What the parent knows once the container workload has exec'd.
pub struct StartedInfo {
    pub pid: i32,
    /// `/proc/<pid>/stat` starttime, used to detect PID reuse in persisted state.
    pub pid_start_time: Option<u64>,
    /// Bridge IP of the container (net == bridge).
    pub ip: Option<std::net::Ipv4Addr>,
    /// Egress-NAT nft table name (crash reconcile).
    pub table: Option<String>,
    /// veth host-end name (crash reconcile).
    pub veth: Option<String>,
    /// cgroup v2 directory path (when limits were configured).
    pub cgroup: Option<String>,
}

/// Result of the parent's full run path.
pub struct RunExit {
    pub code: i32,
    /// Metrics captured just before the cgroup is cleaned up. `None` when no
    /// cgroup was created or the control files were unavailable.
    pub metrics: Option<ContainerMetrics>,
}

/// Full run path without a lifecycle hook. Returns the workload exit code.
pub fn run_container(spec: RunSpec) -> ZResult<i32> {
    Ok(run_container_with_report(spec, |_| Ok(()))?.code)
}

/// Full run path, returning both the exit code and final cgroup metrics. This
/// is the implementation used by `run_container` and the detached lifecycle
/// reaper. The callback runs after the workload has entered its final exec
/// path; a callback failure therefore aborts the workload and performs the
/// same host-side cleanup as any other setup failure.
pub fn run_container_with_report<F>(spec: RunSpec, on_started: F) -> ZResult<RunExit>
where
    F: FnOnce(&StartedInfo) -> ZResult<()>,
{
    trace::init();
    trace::mark("parent:begin");

    let rootless = crate::syscalls::effective_uid() != 0;

    // Create the cgroup on the parent side first (attach right after clone).
    // Detached containers keep one even without limits so pause/unpause can
    // freeze the whole process tree. Rootless hosts without delegation skip it.
    let has_limits = spec.limits.memory.is_some()
        || spec.limits.memory_reservation.is_some()
        || spec.limits.memory_swap.is_some()
        || spec.limits.cpus.is_some()
        || spec.limits.cpuset_cpus.is_some()
        || spec.limits.cpuset_mems.is_some()
        || spec.limits.pids.is_some()
        || spec.limits.oom_group
        || !spec.limits.io.is_empty();
    // Host PID sharing has no namespace-wide kill boundary. Keep a cgroup
    // where possible so runtime teardown and crash reconciliation can terminate
    // exec workers and other processes that did not descend from the workload.
    let needs_lifecycle_cgroup =
        spec.lifecycle_cgroup || matches!(spec.namespaces.pid, NamespaceMode::Host);
    let cg = if has_limits {
        Some(CgroupV2::create(&spec.id, &spec.limits)?)
    } else if needs_lifecycle_cgroup {
        match CgroupV2::create(&spec.id, &spec.limits) {
            Ok(cg) => Some(cg),
            Err(_) if rootless => {
                trace::mark("parent:cgroup:unavailable");
                None
            }
            Err(e) => {
                eprintln!(
                    "zerun: warning: lifecycle cgroup unavailable; \
                     process-tree cleanup and pause/unpause may be limited: {e}"
                );
                None
            }
        }
    } else {
        None
    };

    let mut pty_pair = if spec.tty {
        Some(PtyPair::open()?)
    } else {
        None
    };
    let mut err_pipe = syscalls::Pipe::new()?;

    // The worker must not begin mount or security setup until the parent has
    // attached it to the configured cgroup. This closes the race where a very
    // fast workload could run before its resource limits were effective.
    let mut start_gate = syscalls::Pipe::new()?;

    // Bridge mode needs a second pipe (parent -> child) so the child does not
    // exec before the veth peer has been moved into its netns. See module docs.
    let mut net_sync = if matches!(spec.net, NetMode::Bridge) {
        Some(syscalls::Pipe::new()?)
    } else {
        None
    };

    // Namespace flags: MNT/CGROUP are always private. PID/IPC/UTS/NET are private
    // unless the operator explicitly selected host sharing. Non-root
    // automatically adds NEWUSER (the kernel creates it first).
    if rootless && matches!(spec.net, NetMode::Bridge) {
        return Err(crate::zerr!(
            "--net bridge needs CAP_NET_ADMIN in the host network namespace; \
             run rootful, or use --net none / --net host"
        ));
    }
    let flags = namespace_flags(rootless, spec.namespaces, spec.net);
    if matches!(spec.namespaces.pid, NamespaceMode::Host) {
        // In a private PID namespace, killing the namespace init kills every
        // remaining task. With --pid host there is no such kernel boundary, so
        // make this runtime a subreaper and explicitly sweep descendants after
        // the top-level workload exits.
        syscalls::become_child_subreaper()?;
    }
    // Bridge mode: claim this container's IP from the file IPAM first (a
    // concurrent run may hold our deterministic slot), then bind the `-p`
    // userland proxies. Both happen before starting the child so that IP exhaustion or
    // a busy host port abort the run before any container work happens.
    let mut spec = spec;
    spec.bridge_ip = if matches!(spec.net, NetMode::Bridge) {
        Some(crate::network::allocate_ip(&spec.run_root, &spec.id)?)
    } else {
        None
    };
    let _port_proxies = if let (NetMode::Bridge, Some(ip)) = (spec.net, spec.bridge_ip) {
        if !spec.ports.is_empty() {
            match crate::network::bind_port_proxies(ip, &spec.ports) {
                Ok(proxies) => Some(proxies),
                Err(error) => {
                    release_bridge_ip(&spec);
                    return Err(error);
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    // The host euid/egid must be captured before entering the user namespace:
    // until the mapping is written, geteuid() reports 65534 (nobody).
    let host_euid = crate::syscalls::effective_uid();
    let host_egid = crate::syscalls::effective_gid();

    let slave = pty_pair.as_ref().map_or(-1, PtyPair::slave);
    let net_sync_fds = net_sync
        .as_ref()
        .map(|pipe| (pipe.read_fd(), pipe.write_fd()));
    let child_spec = spec.clone();
    let spawned = match spawn_namespaced_child(
        flags,
        child_spec,
        ChildIpc {
            err_w: err_pipe.write_fd(),
            err_r: err_pipe.read_fd(),
            start_gate_r: start_gate.read_fd(),
            start_gate_w: start_gate.write_fd(),
            net_sync: net_sync_fds,
            tty_slave: slave,
        },
        ChildIdentity {
            rootless,
            host_euid,
            host_egid,
        },
    ) {
        Ok(spawned) => spawned,
        Err(error) => {
            // The supervisor failed before creating a worker. The owned pipes,
            // PTY, cgroup, and port proxies now release their parent-side
            // resources as this stack frame unwinds.
            release_bridge_ip(&spec);
            return Err(error);
        }
    };
    let supervisor_pid = spawned.supervisor_pid;
    let pid = spawned.worker_pid;
    if let Some(pair) = &mut pty_pair {
        pair.release_slave();
    }
    trace::mark("parent:spawn:done");

    // The parent keeps neither the write end nor the child end of the error
    // pipe, nor the read end of the start gate.
    err_pipe.close_write();
    start_gate.close_read();
    TARGET_STOP_SIGNAL.store(spec.stop_signal, Ordering::Relaxed);
    TARGET_CHILD.store(pid, Ordering::Relaxed);

    // Attach the parked worker before it performs any workload setup. The
    // supervisor reports the worker PID immediately but the worker blocks on
    // the start gate until this succeeds.
    if let Some(cgroup) = &cg {
        if let Err(error) = cgroup.attach(pid) {
            start_gate.close_write();
            let _ = syscalls::kill(pid, libc::SIGKILL);
            let _ = wait_child(supervisor_pid);
            if let Err(cleanup_error) = cgroup.kill_all() {
                eprintln!("zerun: warning: terminate cgroup after attach failure: {cleanup_error}");
            }
            if let Some(cg) = cg {
                cg.cleanup();
            }
            release_bridge_ip(&spec);
            return Err(error);
        }
    }

    // Bridge mode: build the host side now. The child is parked on the net-ready
    // pipe, so the veth peer can be moved into its netns before it execs. On
    // failure the parent sends `1` + error text, which the child forwards over
    // the error pipe; on success it sends `0`.
    let mut host_net: Option<crate::network::HostNet> = None;
    if let Some(pipe) = net_sync.as_mut() {
        pipe.close_read(); // the parent never reads the net-ready pipe
        let msg = match crate::network::setup_host_side(&spec.id, pid) {
            Ok(net) => {
                host_net = Some(net);
                vec![0]
            }
            Err(e) => {
                let mut v = vec![1];
                v.extend_from_slice(e.to_string().as_bytes());
                v
            }
        };
        let _ = syscalls::write_all_fd(pipe.write_fd(), &msg); // EPIPE: child failed
        pipe.close_write();
    }

    // Forward terminal signals to the container PID 1.
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        if let Err(error) = install_forward(signal) {
            eprintln!("zerun: warning: install signal forwarder: {error}");
        }
    }

    // The worker is attached and any bridge setup result is queued. Let it
    // proceed into child setup and then wait for the error-pipe handshake.
    let start_result = syscalls::write_all_fd(start_gate.write_fd(), &[1]);
    start_gate.close_write();
    if let Err(error) = start_result {
        let _ = syscalls::kill(pid, libc::SIGKILL);
        let _ = wait_child(supervisor_pid);
        reap_host_pid_descendants(spec.namespaces);
        if let Some(net) = &host_net {
            crate::network::teardown_host_side(net);
        }
        if let Some(cg) = &cg {
            if let Err(cleanup_error) = cg.kill_all() {
                eprintln!(
                    "zerun: warning: terminate cgroup after start-gate failure: {cleanup_error}"
                );
            }
        }
        if let Some(cg) = cg {
            cg.cleanup();
        }
        release_bridge_ip(&spec);
        return Err(error);
    }

    // Block on the error pipe: EOF means the child successfully exec'd
    // (CLOEXEC closes the write end).
    let mut buf = [0u8; 2048];
    let n = read_all(err_pipe.read_fd(), &mut buf)?;
    err_pipe.close_read();
    if n > 0 {
        // The child failed before exec (this also reports bridge setup failures,
        // which the child relays over this pipe).
        let msg = String::from_utf8_lossy(&buf[..n]);
        eprintln!("zerun: container setup failed: {msg}");
        let _ = wait_child(supervisor_pid);
        reap_host_pid_descendants(spec.namespaces);
        if let Some(net) = &host_net {
            crate::network::teardown_host_side(net);
        }
        if let Some(cg) = cg {
            cg.cleanup();
        }
        release_bridge_ip(&spec);
        return Ok(RunExit {
            code: 1,
            metrics: None,
        });
    }
    trace::mark("parent:child-execved");

    // Lifecycle hook: the workload is up (or about to be); detached mode
    // persists "running" state and releases the `run -d` CLI here.
    let started = StartedInfo {
        pid,
        pid_start_time: crate::procinfo::process_start_time(pid),
        ip: spec.bridge_ip,
        table: host_net
            .as_ref()
            .and_then(|net| net.table().map(str::to_string)),
        veth: host_net.as_ref().map(|n| n.veth_name().to_string()),
        cgroup: cg.as_ref().map(|c| c.path().display().to_string()),
    };
    if let Err(error) = on_started(&started) {
        // The callback owns persistence of the detached "running" record. Do
        // not let a failed state write turn into a falsely successful `run -d`:
        // the workload is already running at this point, so terminate it and
        // release every host-side resource before returning the error.
        let _ = syscalls::kill(pid, libc::SIGKILL);
        let _ = wait_child(supervisor_pid);
        reap_host_pid_descendants(spec.namespaces);
        if let Some(net) = &host_net {
            crate::network::teardown_host_side(net);
        }
        if let Some(cg) = cg {
            cg.cleanup();
        }
        release_bridge_ip(&spec);
        return Err(error);
    }

    let pty_pump = if let Some(pair) = pty_pair.as_mut() {
        // Transfer master ownership to the pump for the wait period. It either
        // closes it on host-stdin EOF, or the short-lived CLI exits right after
        // the container closes the PTY.
        let master = pair.take_master();
        match crate::pty::attach(master, spec.tty && spec.interactive) {
            Ok(handle) => Some(handle),
            Err(error) => {
                // The pump never took ownership when thread creation failed;
                // close the master before following the failed-start cleanup.
                syscalls::close(master);
                // The workload is already running, so a failed pump startup
                // must follow the same cleanup path as a failed start hook.
                let _ = syscalls::kill(pid, libc::SIGKILL);
                let _ = wait_child(supervisor_pid);
                reap_host_pid_descendants(spec.namespaces);
                if let Some(net) = &host_net {
                    crate::network::teardown_host_side(net);
                }
                if let Some(cg) = cg {
                    cg.cleanup();
                }
                release_bridge_ip(&spec);
                return Err(error);
            }
        }
    } else {
        None
    };
    let code = match wait_child(supervisor_pid) {
        Ok(code) => code,
        Err(error) => {
            if let Some(cg) = &cg {
                if let Err(kill_error) = cg.kill_all() {
                    eprintln!("zerun: warning: terminate cgroup after wait failure: {kill_error}");
                }
            }
            reap_host_pid_descendants(spec.namespaces);
            if let Some(net) = &host_net {
                crate::network::teardown_host_side(net);
            }
            if let Some(cg) = cg {
                cg.cleanup();
            }
            release_bridge_ip(&spec);
            return Err(error);
        }
    };
    // The top-level process has exited. In a private PID namespace the kernel
    // already killed its namespace peers, but a host PID namespace has no such
    // boundary and exec workers are not necessarily descendants. Kill the
    // complete cgroup before reclaiming the rest of the run resources.
    if let Some(cg) = &cg {
        if let Err(error) = cg.kill_all() {
            eprintln!("zerun: warning: terminate container processes: {error}");
        }
    }
    reap_host_pid_descendants(spec.namespaces);
    if let Some(net) = &host_net {
        crate::network::teardown_host_side(net);
    }
    // Read metrics while the cgroup still exists; it is removed immediately
    // below and detached state needs the final snapshot for `stats`.
    let metrics = cg
        .as_ref()
        .filter(|cg| cg.path().exists())
        .map(|cg| ContainerMetrics::from_cgroup_path(cg.path()));
    if let Some(cg) = cg {
        cg.cleanup();
    }
    release_bridge_ip(&spec);
    if let Some(handle) = pty_pump {
        let _ = handle.join();
    }
    trace::mark("parent:end");
    Ok(RunExit { code, metrics })
}

/// Build the unshare(2) namespace mask for one container launch.
///
/// The PID namespace flag applies to the supervisor's next child: unshare(2)
/// creates the namespace but does not move the caller into it.
fn namespace_flags(rootless: bool, namespaces: NamespaceModes, net: NetMode) -> libc::c_int {
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP;
    if matches!(namespaces.pid, NamespaceMode::Private) {
        flags |= libc::CLONE_NEWPID;
    }
    if matches!(namespaces.uts, NamespaceMode::Private) {
        flags |= libc::CLONE_NEWUTS;
    }
    if matches!(namespaces.ipc, NamespaceMode::Private) {
        flags |= libc::CLONE_NEWIPC;
    }
    if !matches!(net, NetMode::Host) {
        flags |= libc::CLONE_NEWNET;
    }
    if rootless {
        flags |= libc::CLONE_NEWUSER;
    }
    flags
}

/// Kill and reap processes that were reparented to the runtime after a
/// `--pid host` workload's top-level process exited. The runtime is a child
/// subreaper in this mode, so each SIGKILL round exposes the next generation of
/// descendants as direct children. Private PID namespaces do not need this
/// sweep: the kernel kills every task when namespace init exits.
fn reap_host_pid_descendants(namespaces: NamespaceModes) {
    if !matches!(namespaces.pid, NamespaceMode::Host) {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let children = match crate::procinfo::direct_child_pids(crate::syscalls::process_id()) {
            Ok(children) => children,
            Err(error) => {
                eprintln!("zerun: warning: inspect --pid host descendants: {error}");
                return;
            }
        };
        if children.is_empty() {
            return;
        }
        for pid in children {
            crate::syscalls::signal_process(pid, libc::SIGKILL);
        }
        while matches!(crate::syscalls::wait_pid(-1, libc::WNOHANG), Ok(Some(_))) {}
        if Instant::now() >= deadline {
            eprintln!("zerun: warning: some --pid host descendants did not exit after SIGKILL");
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Best-effort release of a bridge IP back to the file IPAM.
fn release_bridge_ip(spec: &RunSpec) {
    if matches!(spec.net, NetMode::Bridge) {
        crate::network::release_ip(&spec.run_root, &spec.id);
    }
}

struct ChildIpc {
    err_w: RawFd,
    err_r: RawFd,
    /// Parent -> worker release gate. The worker remains parked until the
    /// parent has attached it to its cgroup and assembled host networking.
    start_gate_r: RawFd,
    start_gate_w: RawFd,
    net_sync: Option<(RawFd, RawFd)>,
    tty_slave: RawFd,
}

struct ChildIdentity {
    rootless: bool,
    host_euid: u32,
    host_egid: u32,
}

struct SpawnedChild {
    /// Intermediate process that owns the container's namespaces.
    supervisor_pid: i32,
    /// Workload process (PID 1 in a private PID namespace).
    worker_pid: i32,
}

const SUPERVISOR_SIGNALS: [libc::c_int; 7] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

/// Fork a single-threaded namespace supervisor and then the workload.
///
/// The runtime can be multithreaded here (detached logging and port proxies
/// are already active). Calling clone(2) with a Rust callback in that state is
/// unsafe because the child can inherit locks held by vanished threads. fork(2)
/// runs libc's atfork handling, and the supervisor immediately becomes
/// single-threaded before entering namespaces and forking the workload.
fn spawn_namespaced_child(
    flags: libc::c_int,
    spec: RunSpec,
    ipc: ChildIpc,
    identity: ChildIdentity,
) -> ZResult<SpawnedChild> {
    let (status_r, status_w) = syscalls::pipe2_cloexec()?;
    let supervisor_pid = match syscalls::fork_process() {
        Ok(pid) => pid,
        Err(error) => {
            syscalls::close(status_r);
            syscalls::close(status_w);
            return Err(error);
        }
    };
    if supervisor_pid == 0 {
        syscalls::close(status_r);
        supervisor_main(flags, spec, ipc, identity, status_w);
    }

    syscalls::close(status_w);
    let status = read_supervisor_status(status_r);
    syscalls::close(status_r);
    let status = match status {
        Ok(status) => status,
        Err(error) => {
            let _ = syscalls::kill_if_exists(supervisor_pid, libc::SIGKILL);
            let _ = wait_pid(supervisor_pid);
            return Err(error);
        }
    };
    match parse_supervisor_status(&status) {
        Ok(worker_pid) => Ok(SpawnedChild {
            supervisor_pid,
            worker_pid,
        }),
        Err(error) => {
            let _ = wait_pid(supervisor_pid);
            Err(error)
        }
    }
}

/// Body of the intermediate process. This function never returns.
fn supervisor_main(
    flags: libc::c_int,
    spec: RunSpec,
    ipc: ChildIpc,
    identity: ChildIdentity,
    status_w: RawFd,
) -> ! {
    for signal in SUPERVISOR_SIGNALS {
        if let Err(error) = syscalls::ignore_signal(signal) {
            supervisor_fail(status_w, &error);
        }
    }
    if let Err(error) = syscalls::unshare_namespaces(flags) {
        supervisor_fail(status_w, &error);
    }
    if identity.rootless {
        if let Err(error) = write_self_id_mapping(identity.host_euid, identity.host_egid) {
            supervisor_fail(status_w, &error);
        }
    }

    let worker_pid = match syscalls::fork_process() {
        Ok(pid) => pid,
        Err(error) => supervisor_fail(status_w, &error),
    };
    if worker_pid == 0 {
        syscalls::close(ipc.start_gate_w);
        syscalls::close(status_w);
        // The supervisor ignores terminal signals so it can outlive the
        // runtime parent's signal-forwarding window. The workload must not
        // inherit those ignored dispositions across execve.
        for signal in SUPERVISOR_SIGNALS {
            if let Err(error) = syscalls::reset_signal_handler(signal) {
                let msg = format!("{error}");
                let _ = syscalls::write_all_fd(ipc.err_w, msg.as_bytes());
                syscalls::close(ipc.err_w);
                syscalls::exit_process(1);
            }
        }
        match child_main(spec, ipc, identity) {
            Ok(()) => syscalls::exit_process(1),
            Err(error) => {
                eprintln!("zerun: child failed: {error}");
                syscalls::exit_process(1);
            }
        }
    }

    syscalls::close(ipc.start_gate_r);
    syscalls::close(ipc.start_gate_w);
    let status = format!("P{worker_pid}\n");
    if let Err(error) = syscalls::write_all_fd(status_w, status.as_bytes()) {
        eprintln!("zerun: report namespaced child: {error}");
        let _ = syscalls::kill(worker_pid, libc::SIGKILL);
        let _ = wait_pid(worker_pid);
        let _ = syscalls::close_fds_from(3);
        syscalls::exit_process(1);
    }
    // The supervisor must not retain lifecycle locks, log-pipe writers, image
    // leases, or the parent's ends of setup pipes for the container lifetime.
    let _ = syscalls::close_fds_from(3);
    let code = wait_pid(worker_pid).unwrap_or(1);
    syscalls::exit_process(code);
}

fn supervisor_fail(status_w: RawFd, error: &crate::error::ZError) -> ! {
    let message = error.to_string().replace('\n', " ");
    let status = format!("E{message}\n");
    let _ = syscalls::write_all_fd(status_w, status.as_bytes());
    syscalls::close(status_w);
    let _ = syscalls::close_fds_from(3);
    syscalls::exit_process(1)
}

fn read_supervisor_status(fd: RawFd) -> ZResult<String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = syscalls::read_fd(fd, &mut buf)? as usize;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.contains(&b'\n') {
            break;
        }
        if bytes.len() > 8192 {
            return Err(crate::zerr!("namespace supervisor status is too long"));
        }
    }
    if bytes.is_empty() {
        return Err(crate::zerr!(
            "namespace supervisor exited before reporting a workload PID"
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| crate::zerr!("namespace supervisor wrote non-UTF-8 status"))
}

fn parse_supervisor_status(status: &str) -> ZResult<i32> {
    let status = status.trim_end_matches(['\r', '\n']);
    match status.as_bytes().first() {
        Some(b'P') => {
            let pid = status[1..]
                .parse::<i32>()
                .map_err(|_| crate::zerr!("invalid namespace supervisor PID: {status:?}"))?;
            if pid <= 0 {
                return Err(crate::zerr!("invalid namespace supervisor PID: {pid}"));
            }
            Ok(pid)
        }
        Some(b'E') => Err(crate::zerr!("{}", &status[1..])),
        _ => Err(crate::zerr!(
            "invalid namespace supervisor status: {status:?}"
        )),
    }
}

fn child_main(spec: RunSpec, ipc: ChildIpc, identity: ChildIdentity) -> ZResult<()> {
    syscalls::close(ipc.err_r);
    // The net-ready pipe is parent -> child; the child never writes it.
    let net_r = ipc.net_sync.map(|(r, w)| {
        syscalls::close(w);
        r
    });

    // Report any failure to the parent over the pipe; the worker then exits 1.
    let result = child_stage(
        &spec,
        &identity,
        ipc.err_w,
        ipc.start_gate_r,
        net_r,
        ipc.tty_slave,
    );
    if let Err(e) = result {
        let msg = format!("{e}");
        let _ = syscalls::write_all_fd(ipc.err_w, msg.as_bytes());
        syscalls::close(ipc.err_w);
        return Err(e);
    }
    Ok(())
}

/// Prepare the process environment for exec. PTY workloads need a TERM value
/// even when the legacy `--rootfs` path inherited no one from the host.
fn exec_environment(spec: &RunSpec) -> Option<Vec<(String, String)>> {
    let mut env = spec.env.clone();
    if spec.tty {
        if let Some(pairs) = &mut env {
            if crate::workload::env_value(pairs, "TERM").is_none() {
                pairs.push(("TERM".to_string(), "xterm".to_string()));
            }
        } else if std::env::var_os("TERM").is_none() {
            // This runs only in the isolated child before Command inherits env.
            std::env::set_var("TERM", "xterm");
        }
    }
    env
}

fn child_stage(
    spec: &RunSpec,
    identity: &ChildIdentity,
    err_w: RawFd,
    start_gate_r: RawFd,
    net_r: Option<RawFd>,
    tty_slave: RawFd,
) -> ZResult<()> {
    // 0. Wait until the parent has attached this worker to its cgroup and
    // finished host-side launch preparation.
    wait_for_parent_start(start_gate_r)?;
    syscalls::close(start_gate_r);

    // Put the container on the requested PTY before other stages can emit
    // diagnostics; make it the session's controlling terminal so shells/signals
    // behave normally.
    if tty_slave >= 0 {
        syscalls::redirect_stdio(tty_slave)?;
        syscalls::new_session()?;
        syscalls::set_controlling_terminal(tty_slave)?;
        syscalls::close(tty_slave);
    } else if !spec.interactive {
        // Docker semantics: unless -i is requested, foreground containers do
        // not consume the caller's stdin. Detached runs already devnull stdin.
        syscalls::redirect_stdin_devnull()?;
    }

    // rootless: the user-namespace mapping was written by the single-
    // threaded supervisor before forking this worker, so this child already
    // has its in-namespace credentials.
    if identity.rootless && std::env::var_os("ZERUN_DEBUG").is_some() {
        let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        for l in st.lines().filter(|l| l.starts_with("Cap")) {
            eprintln!("[debug] {l}");
        }
    }

    // Open rootless device handles before pivot_root hides the host /dev.
    let device_sources = open_rootless_device_sources(identity.rootless);
    // Host IPC shares the host POSIX shared-memory directory as well as SysV
    // IPC. Clone the mount before pivot_root detaches the old root, then attach
    // it after the private /dev is built.
    let host_shm = if matches!(spec.namespaces.ipc, NamespaceMode::Host) {
        Some(crate::mounts::clone_host_shm_mount()?)
    } else {
        None
    };

    // 1. Root migration + pseudo-filesystems.
    let cfg = RootfsConfig {
        rootfs: &spec.rootfs,
        hostname: spec.hostname.as_deref(),
        set_hostname: matches!(spec.namespaces.uts, NamespaceMode::Private),
        rootless: identity.rootless,
        overlay: spec.overlay.as_ref(),
        volumes: &spec.volumes,
        device_sources: &device_sources,
        host_shm: host_shm.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
    };
    setup_rootfs(&cfg)?;

    // 1b. /etc/hosts: a container should resolve its own hostname and id.
    //     Written from inside the child because the bridge IP is only known
    //     once the parent's IPAM picked it, and the writable layer only exists
    //     after the overlay mount. Requires the per-run overlay: without one
    //     (--no-overlay) we would mutate the caller's rootfs, so we skip.
    write_etc_hosts(spec);

    // 1c. Extra `--tmpfs` mounts, after pivot: they are separate writable
    //     mounts that survive a `--read-only` root.
    mount_extra_tmpfs(identity.rootless, &spec.tmpfs)?;

    // 2. Network inside the container netns (before capability drop, which
    //    would remove the CAP_NET_ADMIN needed to configure eth0).
    match spec.net {
        NetMode::Bridge => {
            let fd = net_r.ok_or_else(|| crate::zerr!("bridge mode lost its net-ready pipe"))?;
            trace::mark("child:net:wait-begin");
            net_sync_wait(fd)?;
            trace::mark("child:net:ready");
            syscalls::close(fd);
            let ip = spec
                .bridge_ip
                .ok_or_else(|| crate::zerr!("bridge run lost its allocated IP"))?;
            crate::network::setup_container_side(&spec.id, ip)?;
        }
        NetMode::None => {
            // Bring loopback up so 127.0.0.1 works.
            syscalls::bring_loopback_up()?;
            if let Some(fd) = net_r {
                syscalls::close(fd);
            }
        }
        NetMode::Host => {
            if let Some(fd) = net_r {
                syscalls::close(fd);
            }
        }
    }

    // 2b. `--read-only`: remount the root read-only after every setup write
    //     (/etc/hosts, tmpfs mounts) but *before* the capability drop, which
    //     removes the CAP_SYS_ADMIN a remount needs. Separate volume/tmpfs
    //     mounts stay writable.
    if spec.readonly {
        make_root_readonly(identity.rootless)?;
    }

    // 2c. Apply per-process rlimits while the setup process still has the
    //     privileges needed to raise a hard limit up to the host ceiling.
    spec.ulimits.apply()?;
    trace::mark("child:ulimit:done");

    // 3. Security hardening: no_new_privs -> supplementary groups -> capability
    //    drop -> seccomp profile. Group names resolve against the container's
    //    own /etc/group after pivot_root.
    let supplementary_groups =
        security::resolve_group_additions(&spec.group_add, identity.rootless)?;
    security::harden(
        spec.seccomp,
        &spec.capabilities,
        identity.rootless,
        &supplementary_groups,
    )?;

    // 3a. Drop to the requested container user while CAP_SETUID/SETGID are still
    // effective (the capability set was trimmed but these two are retained).
    security::switch_user(spec.user.as_deref(), identity.rootless)?;

    // 3b. Move to the container working directory before the error pipe closes
    //     so a missing directory is reported to the parent as a setup failure.
    if let Some(cwd) = &spec.cwd {
        syscalls::chdir(cwd)?;
    }

    // 4. Start the workload.
    //    --init: do NOT re-exec our own binary (that would depend on
    //    /proc/self/exe being visible under the new root). Instead the container
    //    PID 1 directly runs the mini-init logic: it forks the workload (PID 2),
    //    reaps orphans, forwards signals, and _exit()s with the workload code.
    //    Setup has succeeded at this point, so close the error-pipe write end
    //    explicitly so the parent's blocking read gets EOF.
    //    (The direct-exec path relies on O_CLOEXEC; the --init path never execs,
    //    so it must close the write end manually, otherwise the parent would block
    //    forever on the sync read.)
    syscalls::close(err_w);
    trace::mark("child:exec:begin");
    let env = exec_environment(spec);
    let argv = crate::workload::resolve_argv(env.as_deref(), &spec.argv);
    if spec.use_init {
        let code =
            crate::mini_init::run(&argv, env.as_deref(), spec.hostname.as_deref(), &spec.id)?;
        crate::syscalls::exit_process(code);
    }

    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(argv.iter().skip(1));
    crate::workload::apply_env(&mut cmd, env.as_deref(), spec.hostname.as_deref(), &spec.id);
    let err = cmd.exec(); // only returns on failure
    Err(crate::zerr!("execve failed: {err}"))
}

/// Generate `/etc/hosts` for the container (Docker-style entries) and write it
/// into the container root. Best effort: failures are warned about and never
/// abort the run — a missing/odd image layout must not kill the container.
/// Host networking shares the host's /etc/hosts, so nothing is written there.
fn write_etc_hosts(spec: &RunSpec) {
    if matches!(spec.net, NetMode::Host) {
        return;
    }
    if spec.overlay.is_none() {
        eprintln!("zerun: warning: --no-overlay has no writable layer; /etc/hosts is not injected");
        return;
    }
    let host = spec.hostname.as_deref().unwrap_or(&spec.id);
    let content = render_etc_hosts(host, &spec.id, spec.bridge_ip, &spec.hosts);
    let etc = std::path::Path::new("/etc");
    if let Err(e) =
        std::fs::create_dir_all(etc).and_then(|_| std::fs::write(etc.join("hosts"), content))
    {
        eprintln!("zerun: warning: /etc/hosts injection: {e}");
    }
}

fn render_etc_hosts(
    hostname: &str,
    id: &str,
    bridge_ip: Option<std::net::Ipv4Addr>,
    aliases: &[crate::network::HostEntry],
) -> String {
    let self_entry = match bridge_ip {
        Some(ip) => format!("{ip}\t{hostname}\t{id}"),
        None => format!("127.0.0.1\t{hostname}"),
    };
    let mut content = format!(
        "127.0.0.1\tlocalhost\n\
         ::1\tlocalhost ip6-localhost ip6-loopback\n\
         fe00::0\tip6-localnet\n\
         ff00::0\tip6-mcastprefix\n\
         ff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n\
         \n{self_entry}\n"
    );
    for alias in aliases {
        content.push_str(&format!("{}\t{}\n", alias.ip, alias.name));
    }
    content
}

/// Unprivileged rootless: map uid/gid 0 inside the new user namespace to the host
/// euid/egid (single mapping; values captured before unshare).
/// setgroups must be denied before gid_map can be written.
fn write_self_id_mapping(host_euid: u32, host_egid: u32) -> ZResult<()> {
    // Kernels that pre-deny setgroups report EPERM, and older layouts may not
    // expose the file at all. Ignore only those expected cases; unexpected
    // failures should not be hidden before writing gid_map.
    if let Err(error) = std::fs::write("/proc/self/setgroups", "deny") {
        match error.raw_os_error() {
            Some(libc::EPERM) | Some(libc::ENOENT) => {}
            _ => return Err(crate::zerr!("write setgroups deny failed: {error}")),
        }
    }
    std::fs::write("/proc/self/uid_map", format!("0 {host_euid} 1"))
        .map_err(|e| crate::zerr!("write uid_map failed: {e}"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {host_egid} 1"))
        .map_err(|e| crate::zerr!("write gid_map failed: {e}"))?;
    Ok(())
}

/// Wait for the parent to release the worker start gate.
///
/// The parent writes one byte only after cgroup attachment and host-side
/// network setup. EOF means the parent abandoned startup before the worker was
/// allowed to touch the rootfs.
fn wait_for_parent_start(fd: RawFd) -> ZResult<()> {
    let mut release = [0u8; 1];
    let n = read_all(fd, &mut release)?;
    if n == 0 {
        return Err(crate::zerr!("runtime parent closed the worker start gate"));
    }
    if release[0] != 1 {
        return Err(crate::zerr!(
            "runtime parent sent an invalid worker start-gate byte"
        ));
    }
    Ok(())
}

/// Wait for the parent's net-ready signal over `fd`.
///
/// Protocol: a single `0` byte means the host side (bridge/veth) is ready; a
/// `1` byte is followed by the parent's error text. EOF without any byte means
/// the parent gave up without signalling (treated as a failure).
fn net_sync_wait(fd: RawFd) -> ZResult<()> {
    let mut first = [0u8; 1];
    let n = read_all(fd, &mut first)?;
    if n == 0 {
        return Err(crate::zerr!(
            "host network setup ended without signalling the container"
        ));
    }
    if first[0] == 0 {
        return Ok(());
    }
    let mut rest = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let m = syscalls::read_fd(fd, &mut buf)? as usize;
        if m == 0 {
            break;
        }
        rest.extend_from_slice(&buf[..m]);
    }
    let msg = String::from_utf8_lossy(&rest);
    let msg = msg.trim();
    if msg.is_empty() {
        Err(crate::zerr!("host network setup failed"))
    } else {
        Err(crate::zerr!("{msg}"))
    }
}

fn install_forward(sig: libc::c_int) -> ZResult<()> {
    syscalls::install_signal_handler(sig, forward_to_child)
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> ZResult<usize> {
    let mut total = 0;
    loop {
        let n = syscalls::read_fd(fd, &mut buf[total..])?; // EINTR is retried in syscalls.rs
        if n == 0 {
            return Ok(total); // EOF: the child successfully entered the workload
        }
        total += n as usize;
        if total == buf.len() {
            return Ok(total);
        }
    }
}

fn wait_pid(pid: i32) -> ZResult<i32> {
    let (_, status) =
        syscalls::wait_pid(pid, 0)?.ok_or_else(|| crate::zerr!("waitpid returned no child"))?;
    Ok(syscalls::wait_status_code(status).unwrap_or(1))
}

fn wait_child(pid: i32) -> ZResult<i32> {
    let result = wait_pid(pid);
    // Do not leave a stale PID in the async handler after the child has been
    // reaped; that PID may later be reused by an unrelated host process.
    TARGET_CHILD.store(0, Ordering::Relaxed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::HostEntry;
    use std::net::IpAddr;

    #[test]
    fn namespace_flags_create_private_namespaces_by_default() {
        let flags = namespace_flags(false, NamespaceModes::default(), NetMode::None);
        for namespace in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWNET,
        ] {
            assert_ne!(flags & namespace, 0);
        }
        assert_eq!(flags & libc::CLONE_NEWUSER, 0);
    }

    #[test]
    fn namespace_flags_honor_host_namespace_modes() {
        let modes = NamespaceModes {
            pid: NamespaceMode::Host,
            ipc: NamespaceMode::Host,
            uts: NamespaceMode::Host,
        };
        let flags = namespace_flags(true, modes, NetMode::Host);
        for namespace in [
            libc::CLONE_NEWPID,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWNET,
        ] {
            assert_eq!(flags & namespace, 0);
        }
        assert_ne!(flags & libc::CLONE_NEWNS, 0);
        assert_ne!(flags & libc::CLONE_NEWCGROUP, 0);
        assert_ne!(flags & libc::CLONE_NEWUSER, 0);
    }

    #[test]
    fn worker_start_gate_requires_an_explicit_release_byte() {
        let (read_fd, write_fd) = syscalls::pipe2_cloexec().unwrap();
        syscalls::write_all_fd(write_fd, &[1]).unwrap();
        syscalls::close(write_fd);
        assert!(wait_for_parent_start(read_fd).is_ok());
        syscalls::close(read_fd);

        let (read_fd, write_fd) = syscalls::pipe2_cloexec().unwrap();
        syscalls::write_all_fd(write_fd, &[2]).unwrap();
        syscalls::close(write_fd);
        assert!(wait_for_parent_start(read_fd).is_err());
        syscalls::close(read_fd);

        let (read_fd, write_fd) = syscalls::pipe2_cloexec().unwrap();
        syscalls::close(write_fd);
        assert!(wait_for_parent_start(read_fd).is_err());
        syscalls::close(read_fd);
    }

    #[test]
    fn supervisor_status_distinguishes_pid_and_setup_error() {
        assert_eq!(parse_supervisor_status("P4242\n").unwrap(), 4242);
        assert_eq!(
            parse_supervisor_status("Eunshare: permission denied\n")
                .unwrap_err()
                .to_string(),
            "unshare: permission denied"
        );
        assert!(parse_supervisor_status("P0\n").is_err());
        assert!(parse_supervisor_status("Pnot-a-pid\n").is_err());
        assert!(parse_supervisor_status("").is_err());
    }

    #[test]
    fn supervisor_term_uses_the_resolved_stop_signal() {
        TARGET_STOP_SIGNAL.store(libc::SIGUSR1, Ordering::Relaxed);
        assert_eq!(forwarded_signal(libc::SIGTERM), libc::SIGUSR1);
        assert_eq!(forwarded_signal(libc::SIGINT), libc::SIGINT);
        assert_eq!(forwarded_signal(libc::SIGHUP), libc::SIGHUP);
        TARGET_STOP_SIGNAL.store(crate::signal::DEFAULT_STOP_SIGNAL, Ordering::Relaxed);
    }

    #[test]
    fn generated_hosts_file_contains_identity_and_operator_aliases() {
        let content = render_etc_hosts(
            "web",
            "0123abcd",
            Some("10.88.0.42".parse().unwrap()),
            &[
                HostEntry {
                    name: "db.internal".to_string(),
                    ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
                },
                HostEntry {
                    name: "host.zerun.internal".to_string(),
                    ip: "10.88.0.1".parse::<IpAddr>().unwrap(),
                },
            ],
        );
        assert!(content.contains("10.88.0.42\tweb\t0123abcd\n"));
        assert!(content.contains("192.0.2.10\tdb.internal\n"));
        assert!(content.contains("10.88.0.1\thost.zerun.internal\n"));

        let loopback = render_etc_hosts("box", "0123abcd", None, &[]);
        assert!(loopback.contains("127.0.0.1\tbox\n"));
    }
}
