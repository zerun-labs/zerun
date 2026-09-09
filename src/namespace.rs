//! Isolation orchestration.
//!
//! Parent: create cgroup -> clone the child -> write cgroup.procs -> forward
//! signals -> wait. Child: mount/pivot -> pseudo-fs -> (bridge: net-ready sync
//! + container-side network config) -> security hardening -> execve (or run
//!   the built-in mini-init first).
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
use crate::mounts::{setup_rootfs, BindMount, OverlayPaths, RootfsConfig};
use crate::seccomp::SeccompMode;
use crate::security;
use crate::state::ContainerMetrics;
use crate::syscalls;
use crate::trace;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

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
    pub net: NetMode,
    pub use_init: bool,
    pub limits: ResourceLimits,
    pub seccomp: SeccompMode,
    /// Allocate a PTY for foreground container stdio (`run -t`).
    pub tty: bool,
    /// Forward host stdin to the container (`run -i`).
    pub interactive: bool,
    /// Per-container writable filesystem; None = pivot directly into `rootfs`.
    pub overlay: Option<OverlayPaths>,
    pub id: String,
    /// Explicit container environment (image mode: KEY=VALUE pairs, fully
    /// replacing the inherited env). None = legacy `--rootfs` behavior
    /// (inherit host env + inject defaults).
    pub env: Option<Vec<(String, String)>>,
    /// Working directory inside the container (None = "/").
    pub cwd: Option<String>,
    /// TCP ports published on the host (`-p HOST:CONTAINER`); only valid with
    /// `NetMode::Bridge`. Served by the built-in userland proxy in network.rs.
    pub ports: Vec<crate::network::PublishedPort>,
    /// Host bind mounts (simple file/directory volumes).
    pub volumes: Vec<BindMount>,
    /// Bridge IPv4 assigned by the parent from the file IPAM (set before
    /// clone; consumed by both host-side NAT and the child's eth0 config).
    pub bridge_ip: Option<std::net::Ipv4Addr>,
    /// Runtime root of the active store (`/run/zerun` etc.), used by the
    /// parent for IPAM bookkeeping.
    pub run_root: PathBuf,
}

static TARGET_CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_to_child(sig: libc::c_int) {
    let pid = TARGET_CHILD.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// What the parent knows once the container workload has exec'd.
pub struct StartedInfo {
    pub pid: i32,
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
    Ok(run_container_with_report(spec, |_| {})?.code)
}

/// Full run path, returning both the exit code and final cgroup metrics. This
/// is the implementation used by `run_container` and `run_container_with_hook`.
pub fn run_container_with_report<F>(spec: RunSpec, on_started: F) -> ZResult<RunExit>
where
    F: FnOnce(&StartedInfo),
{
    trace::init();
    trace::mark("parent:begin");

    // Create the cgroup on the parent side first (attach right after clone).
    // Skipped when no limits are set (typical rootless without delegation).
    let has_limits = spec.limits.memory.is_some()
        || spec.limits.memory_reservation.is_some()
        || spec.limits.cpus.is_some()
        || spec.limits.pids.is_some()
        || spec.limits.oom_group
        || !spec.limits.io.is_empty();
    let cg = if has_limits {
        Some(CgroupV2::create(&spec.id, &spec.limits)?)
    } else {
        None
    };

    let (err_r, err_w) = syscalls::pipe2_cloexec()?;
    let mut pty_pair = if spec.tty {
        Some(PtyPair::open()?)
    } else {
        None
    };

    // Bridge mode needs a second pipe (parent -> child) so the child does not
    // exec before the veth peer has been moved into its netns. See module docs.
    let net_sync = if matches!(spec.net, NetMode::Bridge) {
        Some(syscalls::pipe2_cloexec()?)
    } else {
        None
    };

    // clone flags: PID/MNT/UTS/IPC/CGROUP on by default; NEWNET additionally
    // for --net none and --net bridge. Non-root automatically adds NEWUSER (the
    // kernel guarantees the user namespace is created first).
    let rootless = unsafe { libc::geteuid() } != 0;
    if rootless && matches!(spec.net, NetMode::Bridge) {
        return Err(crate::zerr!(
            "--net bridge needs CAP_NET_ADMIN in the host network namespace; \
             run rootful, or use --net none / --net host"
        ));
    }
    // Bridge mode: claim this container's IP from the file IPAM first (a
    // concurrent run may hold our deterministic slot), then bind the `-p`
    // userland proxies. Both happen before the clone so that IP exhaustion or
    // a busy host port abort the run before any container work happens.
    let mut spec = spec;
    spec.bridge_ip = if matches!(spec.net, NetMode::Bridge) {
        Some(crate::network::allocate_ip(&spec.run_root, &spec.id)?)
    } else {
        None
    };
    let _port_proxies = if let (NetMode::Bridge, Some(ip)) = (spec.net, spec.bridge_ip) {
        if !spec.ports.is_empty() {
            Some(crate::network::bind_port_proxies(ip, &spec.ports)?)
        } else {
            None
        }
    } else {
        None
    };
    let mut flags = libc::CLONE_NEWPID
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWCGROUP
        | libc::SIGCHLD;
    if !matches!(spec.net, NetMode::Host) {
        flags |= libc::CLONE_NEWNET;
    }
    if rootless {
        flags |= libc::CLONE_NEWUSER;
    }
    // The host euid/egid must be captured before clone: once the child is inside
    // the new user namespace and before the mapping is written, geteuid() reports
    // 65534 (nobody).
    let host_euid = unsafe { libc::geteuid() };
    let host_egid = unsafe { libc::getegid() };

    let slave = pty_pair.as_ref().map_or(-1, |p| p.slave);
    let child_spec = spec.clone();
    let pid = syscalls::clone_into(flags, move || {
        child_main(
            child_spec,
            ChildIpc {
                err_w,
                err_r,
                net_sync,
                tty_slave: slave,
            },
            ChildIdentity {
                rootless,
                host_euid,
                host_egid,
            },
        )
    })?;
    if let Some(pair) = &mut pty_pair {
        pair.release_slave();
    }
    trace::mark("parent:clone:done");

    // The parent keeps neither the write end nor the child end of the error pipe.
    syscalls::close(err_w);
    TARGET_CHILD.store(pid, Ordering::Relaxed);

    // Bridge mode: build the host side now. The child is parked on the net-ready
    // pipe, so the veth peer can be moved into its netns before it execs. On
    // failure the parent sends `1` + error text, which the child forwards over
    // the error pipe; on success it sends `0`.
    let mut host_net: Option<crate::network::HostNet> = None;
    if let Some((net_r, net_w)) = net_sync {
        syscalls::close(net_r); // the parent never reads the net-ready pipe
        let msg = match crate::network::setup_host_side(&spec.id, pid, spec.bridge_ip.unwrap()) {
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
        syscalls::write_fd(net_w, &msg); // EPIPE: child already failed
        syscalls::close(net_w);
    }

    // Write cgroup.procs (the child may already have exited; attach ignores ESRCH).
    if let Some(cg) = &cg {
        cg.attach(pid)?;
    }

    // Forward terminal signals to the container PID 1.
    install_forward(libc::SIGINT);
    install_forward(libc::SIGTERM);
    install_forward(libc::SIGHUP);

    // Block on the error pipe: EOF means the child successfully exec'd
    // (CLOEXEC closes the write end).
    let mut buf = [0u8; 2048];
    let n = read_all(err_r, &mut buf)?;
    syscalls::close(err_r);
    if n > 0 {
        // The child failed before exec (this also reports bridge setup failures,
        // which the child relays over this pipe).
        let msg = String::from_utf8_lossy(&buf[..n]);
        eprintln!("zerun: container setup failed: {msg}");
        let _ = wait_pid(pid);
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
        ip: spec.bridge_ip,
        table: host_net.as_ref().map(|n| n.table().to_string()),
        veth: host_net.as_ref().map(|n| n.veth_name().to_string()),
        cgroup: cg.as_ref().map(|c| c.path().display().to_string()),
    };
    on_started(&started);

    let pty_pump = pty_pair.as_mut().map(|pair| {
        // Transfer master ownership to the pump for the wait period. It either
        // closes it on host-stdin EOF, or the short-lived CLI exits right after
        // the container closes the PTY.
        let master = pair.take_master();
        crate::pty::attach(master, spec.tty && spec.interactive)
    });
    let code = wait_pid(pid)?;
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

/// Best-effort release of a bridge IP back to the file IPAM.
fn release_bridge_ip(spec: &RunSpec) {
    if matches!(spec.net, NetMode::Bridge) {
        crate::network::release_ip(&spec.run_root, &spec.id);
    }
}

struct ChildIpc {
    err_w: RawFd,
    err_r: RawFd,
    net_sync: Option<(RawFd, RawFd)>,
    tty_slave: RawFd,
}

struct ChildIdentity {
    rootless: bool,
    host_euid: u32,
    host_egid: u32,
}

fn child_main(spec: RunSpec, ipc: ChildIpc, identity: ChildIdentity) -> ZResult<()> {
    syscalls::close(ipc.err_r);
    // The net-ready pipe is parent -> child; the child never writes it.
    let net_r = ipc.net_sync.map(|(r, w)| {
        syscalls::close(w);
        r
    });

    // Report any failure to the parent over the pipe; the trampoline then exits 1.
    let result = child_stage(&spec, &identity, ipc.err_w, net_r, ipc.tty_slave);
    if let Err(e) = result {
        let msg = format!("{e}");
        syscalls::write_fd(ipc.err_w, msg.as_bytes());
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
    net_r: Option<RawFd>,
    tty_slave: RawFd,
) -> ZResult<()> {
    // 0. Put the container on the requested PTY before other stages can emit
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

    // 0. rootless: write the uid/gid mapping before doing any mounts.
    if identity.rootless {
        write_self_id_mapping(identity.host_euid, identity.host_egid)?;
        if std::env::var_os("ZERUN_DEBUG").is_some() {
            let st = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            for l in st.lines().filter(|l| l.starts_with("Cap")) {
                eprintln!("[debug] {l}");
            }
        }
    }

    // 1. Root migration + pseudo-filesystems.
    let cfg = RootfsConfig {
        rootfs: &spec.rootfs,
        hostname: spec.hostname.as_deref(),
        rootless: identity.rootless,
        overlay: spec.overlay.as_ref(),
        volumes: &spec.volumes,
    };
    setup_rootfs(&cfg)?;

    // 1b. /etc/hosts: a container should resolve its own hostname and id.
    //     Written from inside the child because the bridge IP is only known
    //     once the parent's IPAM picked it, and the writable layer only exists
    //     after the overlay mount. Requires the per-run overlay: without one
    //     (--no-overlay) we would mutate the caller's rootfs, so we skip.
    write_etc_hosts(spec);

    // 2. Network inside the container netns (before capability drop, which
    //    would remove the CAP_NET_ADMIN needed to configure eth0).
    match spec.net {
        NetMode::Bridge => {
            let fd = net_r.ok_or_else(|| crate::zerr!("bridge mode lost its net-ready pipe"))?;
            net_sync_wait(fd)?;
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

    // 3. Security hardening: no_new_privs -> capability drop -> seccomp profile.
    security::harden(spec.seccomp)?;

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
        unsafe { libc::_exit(code) };
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
    let self_entry = match spec.bridge_ip {
        Some(ip) => format!("{ip}\t{host}\t{}", spec.id),
        None => format!("127.0.0.1\t{host}"),
    };
    let content = format!(
        "127.0.0.1\tlocalhost\n\
         ::1\tlocalhost ip6-localhost ip6-loopback\n\
         fe00::0\tip6-localnet\n\
         ff00::0\tip6-mcastprefix\n\
         ff02::1\tip6-allnodes\n\
         ff02::2\tip6-allrouters\n\
         \n{self_entry}\n"
    );
    let etc = std::path::Path::new("/etc");
    if let Err(e) =
        std::fs::create_dir_all(etc).and_then(|_| std::fs::write(etc.join("hosts"), content))
    {
        eprintln!("zerun: warning: /etc/hosts injection: {e}");
    }
}

/// Unprivileged rootless: map uid/gid 0 inside the new user namespace to the host
/// euid/egid (single mapping; values captured by the parent before clone).
/// setgroups must be denied before gid_map can be written.
fn write_self_id_mapping(host_euid: u32, host_egid: u32) -> ZResult<()> {
    // Ignore setgroups write failures (some kernels deny it by default already).
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    std::fs::write("/proc/self/uid_map", format!("0 {host_euid} 1"))
        .map_err(|e| crate::zerr!("write uid_map failed: {e}"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {host_egid} 1"))
        .map_err(|e| crate::zerr!("write gid_map failed: {e}"))?;
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

fn install_forward(sig: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_to_child as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
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

/// Owns the parent-side ends of a PTY during clone/setup.
struct PtyPair {
    master: Option<RawFd>,
    slave: RawFd,
    child_owns_slave: bool,
}

impl PtyPair {
    fn open() -> ZResult<Self> {
        let (master, slave) = syscalls::open_pty()?;
        Ok(Self {
            master: Some(master),
            slave,
            child_owns_slave: false,
        })
    }

    /// After a successful clone the parent must release the slave so the
    /// container's exit can close the last slave-side descriptors.
    fn release_slave(&mut self) {
        syscalls::close(self.slave);
        self.child_owns_slave = true;
    }

    fn take_master(&mut self) -> RawFd {
        self.master.take().unwrap_or(-1)
    }
}

impl Drop for PtyPair {
    fn drop(&mut self) {
        if let Some(master) = self.master.take() {
            syscalls::close(master);
        }
        if !self.child_owns_slave {
            syscalls::close(self.slave);
        }
    }
}

fn wait_pid(pid: i32) -> ZResult<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e.into());
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128 + libc::WTERMSIG(status));
        }
    }
}
