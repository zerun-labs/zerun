//! zerun — daemonless, single-binary Linux container runtime.
//!
//! Command surface (Docker-compatible top 20%):
//!   zerun run [opts] IMAGE [CMD...]       run a container from an OCI image
//!   zerun run --rootfs DIR [opts] -- CMD  legacy: run from an unpacked rootfs
//!   zerun run -d [--name N] [opts] IMAGE  run detached (state under /run/zerun)
//!   zerun ps [-a] / stop / rm / logs / exec   detached-container lifecycle (M5)
//!   zerun pull / images / rmi             OCI image lifecycle (M3)
//!   zerun doctor                          environment diagnostics
mod cgroup;
mod error;
mod execc;
mod fsutil;
mod image;
mod lifecycle;
mod mini_init;
mod mounts;
mod namespace;
mod netlink;
mod network;
mod nfnetlink;
mod pty;
mod seccomp;
mod security;
mod service;
mod state;
mod store;
mod syscalls;
mod trace;
mod workload;

use cgroup::ResourceLimits;
use image::name::Reference;
use image::PullOptions;
use mounts::OverlayPaths;
use namespace::{NetMode, RunSpec};
use seccomp::SeccompMode;
use state::ContainerState;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use store::Store;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[2..]),
        Some("ps") => cmd_ps(&args[2..]),
        Some("stop") => cmd_stop(&args[2..]),
        Some("restart") => cmd_restart(&args[2..]),
        Some("rm") => cmd_rm(&args[2..]),
        Some("logs") => cmd_logs(&args[2..]),
        Some("exec") => cmd_exec(&args[2..]),
        Some("pull") => cmd_pull(&args[2..]),
        Some("images") => cmd_images(&args[2..]),
        Some("rmi") => cmd_rmi(&args[2..]),
        Some("commit") => cmd_commit(&args[2..]),
        Some("generate-service") => cmd_generate_service(&args[2..]),
        Some("doctor") => cmd_doctor(),
        Some("__init") => {
            // Internal re-exec entry: __init [--] <cmd...>
            let pos = args.iter().position(|a| a == "--");
            let business: Vec<String> = pos.map(|p| args[p + 1..].to_vec()).unwrap_or_default();
            match mini_init::run(&business, None, None, "") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("zerun-init: {e}");
                    1
                }
            }
        }
        Some("-h") | Some("--help") | None => {
            print_help();
            0
        }
        Some(other) => {
            eprintln!("zerun: unknown subcommand '{other}'");
            print_help();
            2
        }
    };
    exit(code);
}

#[derive(Default)]
struct RunArgs {
    rootfs: Option<String>,
    image: Option<String>,
    memory: Option<String>,
    cpus: Option<f64>,
    pids: Option<i64>,
    hostname: Option<String>,
    net: NetMode,
    /// True after the operator explicitly selected `--net`.
    net_specified: bool,
    use_init: bool,
    seccomp: SeccompMode,
    no_overlay: bool,
    platform: Option<String>,
    env: Vec<String>,
    ports: Vec<network::PublishedPort>,
    dns: Vec<String>,
    argv: Vec<String>,
    /// `-i/--interactive`: keep stdin attached (foreground runs).
    interactive: bool,
    /// `-t/--tty`: allocate a PTY for the container (foreground runs).
    tty: bool,
    /// `-d/--detach`: fork a reaper and return after the container starts.
    detach: bool,
    /// `--name NAME`: assign a human-friendly name (ps/stop/rm/logs/exec).
    name: Option<String>,
    /// `--rm`: remove state + overlay automatically when the container exits.
    rm: bool,
}

/// Parse `run` arguments. Two invocation styles:
///   legacy:  run --rootfs DIR [opts] [--] CMD [ARGS...]  (first positional = CMD)
///   image:   run [opts] IMAGE [CMD [ARGS...]]            (first positional = IMAGE)
fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut a = RunArgs::default();
    let mut i = 0;
    while i < args.len() {
        let s = &args[i];
        match s.as_str() {
            "--rootfs" => {
                a.rootfs = Some(next_value(args, &mut i, "--rootfs")?);
            }
            "--memory" | "-m" => {
                a.memory = Some(next_value(args, &mut i, s)?);
            }
            "--cpus" => {
                let v = next_value(args, &mut i, "--cpus")?;
                a.cpus = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --cpus value '{v}'"))?,
                );
            }
            "--pids" => {
                let v = next_value(args, &mut i, "--pids")?;
                a.pids = Some(
                    v.parse()
                        .map_err(|_| format!("invalid --pids value '{v}'"))?,
                );
            }
            "--hostname" | "-h" => {
                a.hostname = Some(next_value(args, &mut i, s)?);
            }
            "--net" => {
                let v = next_value(args, &mut i, "--net")?;
                a.net_specified = true;
                a.net = match v.as_str() {
                    "bridge" => NetMode::Bridge,
                    "host" => NetMode::Host,
                    "none" => NetMode::None,
                    other => {
                        return Err(format!("invalid --net value '{other}' (bridge|host|none)"))
                    }
                };
            }
            "-i" | "--interactive" => {
                a.interactive = true;
                i += 1;
            }
            "-t" | "--tty" => {
                a.tty = true;
                i += 1;
            }
            "-it" | "-ti" => {
                a.interactive = true;
                a.tty = true;
                i += 1;
            }
            "--init" => {
                a.use_init = true;
                i += 1;
            }
            "--seccomp" => {
                let v = next_value(args, &mut i, "--seccomp")?;
                a.seccomp = match v.as_str() {
                    "unconfined" => SeccompMode::Unconfined,
                    "default" => SeccompMode::Default,
                    other => return Err(format!("invalid --seccomp value '{other}'")),
                };
            }
            "--no-overlay" => {
                a.no_overlay = true;
                i += 1;
            }
            "--platform" => {
                a.platform = Some(next_value(args, &mut i, "--platform")?);
            }
            "--env" | "-e" => {
                a.env.push(next_value(args, &mut i, s)?);
            }
            "--publish" | "-p" => {
                let v = next_value(args, &mut i, s)?;
                a.ports.push(parse_publish(&v)?);
            }
            "--dns" => {
                let v = next_value(args, &mut i, "--dns")?;
                v.parse::<std::net::IpAddr>()
                    .map_err(|_| format!("invalid --dns address '{v}'"))?;
                a.dns.push(v);
            }
            "--detach" | "-d" => {
                a.detach = true;
                i += 1;
            }
            "--name" => {
                a.name = Some(next_value(args, &mut i, "--name")?);
            }
            "--rm" => {
                a.rm = true;
                i += 1;
            }
            "--" => {
                // Option terminator. Remaining tokens:
                //   legacy: the command; image: first token is IMAGE if none yet.
                let rest = &args[i + 1..];
                if a.rootfs.is_some() || a.image.is_some() {
                    a.argv = rest.to_vec();
                } else if let Some(first) = rest.first() {
                    a.image = Some(first.clone());
                    a.argv = rest[1..].to_vec();
                }
                i = args.len();
            }
            other if other.starts_with("--") && other.len() > 2 => {
                return Err(format!("unknown option {other}"));
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"));
            }
            _ => {
                // First positional token.
                if a.rootfs.is_some() {
                    // Legacy: everything from here is the command.
                    a.argv = args[i..].to_vec();
                } else if a.image.is_none() {
                    a.image = Some(s.clone());
                    // Docker-style: `run IMAGE [--] CMD...`; a `--` right after
                    // the image is an explicit command separator, not a program.
                    let rest = &args[i + 1..];
                    a.argv = match rest.first().map(|x| x.as_str()) {
                        Some("--") => rest[1..].to_vec(),
                        _ => rest.to_vec(),
                    };
                } else {
                    a.argv = args[i..].to_vec();
                }
                i = args.len();
            }
        }
    }
    Ok(a)
}

/// Parse `-p`/`--publish` values. Supported forms (TCP only):
///   HOST:CONTAINER   publish container port on the given host port
///   CONTAINER        shorthand for CONTAINER:CONTAINER
/// Bind addresses (`127.0.0.1:8080:80`) and UDP are rejected with a clear
/// error until user-space forwarding lands.
fn parse_publish(v: &str) -> Result<network::PublishedPort, String> {
    fn parse_port(s: &str) -> Result<u16, String> {
        s.parse::<u16>()
            .map_err(|_| format!("invalid port '{s}' (expected 1-65535)"))
            .and_then(|p| {
                if p == 0 {
                    Err(format!("invalid port '{s}' (expected 1-65535)"))
                } else {
                    Ok(p)
                }
            })
    }
    if v.ends_with("/udp") {
        return Err("-p: UDP publishing is not supported yet (TCP only)".to_string());
    }
    if let Some((host, container)) = v.split_once(':') {
        if container.contains(':') {
            return Err(format!(
                "-p: binding to a host address ('{v}') is not supported yet; use HOST:CONTAINER"
            ));
        }
        Ok(network::PublishedPort {
            host: parse_port(host)?,
            container: parse_port(container)?,
        })
    } else {
        let p = parse_port(v)?;
        Ok(network::PublishedPort {
            host: p,
            container: p,
        })
    }
}

fn next_value(args: &[String], i: &mut usize, opt: &str) -> Result<String, String> {
    let v = args
        .get(*i + 1)
        .ok_or_else(|| format!("option {opt} requires a value"))?;
    *i += 2;
    Ok(v.clone())
}

/// Docker-style networking defaults: rootful runs use the managed bridge;
/// rootless stays on an isolated loopback namespace until user-mode NAT lands.
fn default_net(euid: u32) -> NetMode {
    if euid == 0 {
        NetMode::Bridge
    } else {
        NetMode::None
    }
}

fn cmd_run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help") {
        print_run_usage();
        return 0;
    }
    let mut a = match parse_run_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zerun run: {e}");
            return 2;
        }
    };
    if !a.net_specified {
        a.net = default_net(unsafe { libc::geteuid() });
    }
    if !a.ports.is_empty() && a.net != NetMode::Bridge {
        eprintln!("zerun run: -p/--publish requires --net bridge");
        return 2;
    }
    if a.tty && a.detach {
        eprintln!("zerun run: -t/--tty cannot be used with -d/--detach yet");
        return 2;
    }
    if a.interactive && a.detach {
        eprintln!("zerun: warning: -i has no effect with -d (detached stdin is /dev/null)");
    }
    if !a.dns.is_empty() && a.net != NetMode::Bridge {
        eprintln!("zerun: warning: --dns only applies to --net bridge; ignoring");
    }
    if a.rootfs.is_none() && a.image.is_none() {
        eprintln!("zerun run: an IMAGE (or --rootfs DIR for legacy mode) is required");
        print_run_usage();
        return 2;
    }

    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    if let Err(e) = store.ensure_dirs() {
        eprintln!("zerun: {e}");
        return 1;
    }

    // One id per run: used for the HOSTNAME default, the per-run overlay, the
    // nft table/veth names and the lifecycle state directory.
    let id = short_id();

    // Resolve the container root filesystem and, for image mode, the process
    // environment / working directory / default command from the OCI config.
    let (rootfs, env, cwd, argv) = if let Some(rootfs_str) = &a.rootfs {
        if !a.env.is_empty() {
            eprintln!("zerun run: -e/--env requires image mode (drop --rootfs)");
            return 2;
        }
        let rootfs = PathBuf::from(rootfs_str);
        if !rootfs.is_dir() {
            eprintln!(
                "zerun: rootfs directory does not exist: {}",
                rootfs.display()
            );
            return 2;
        }
        let mut argv = a.argv.clone();
        if argv.is_empty() {
            argv = vec!["/bin/sh".to_string()];
        }
        (rootfs, None, None, argv)
    } else {
        let image = a.image.as_deref().expect("image required");
        let reference = match Reference::parse(image) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("zerun run: invalid image reference '{image}': {e}");
                return 2;
            }
        };
        match resolve_run_image(&store, &reference, a.platform.as_deref()) {
            Ok((rootfs, cfg)) => {
                let env =
                    build_image_env(&cfg.config.env, &a.env, a.hostname.as_deref(), &id, a.tty);
                let argv = resolve_image_argv(&cfg, &a.argv);
                let cwd = if cfg.config.working_dir.is_empty() {
                    None
                } else {
                    Some(cfg.config.working_dir.clone())
                };
                (rootfs, Some(env), cwd, argv)
            }
            Err(e) => {
                eprintln!("zerun: {e}");
                return 1;
            }
        }
    };

    let container_fs = if a.no_overlay {
        None
    } else {
        match store.prepare_container_fs(&id, &rootfs) {
            Ok(fs) => Some(fs),
            Err(e) => {
                eprintln!("zerun: {e}");
                return 1;
            }
        }
    };
    inject_resolv_conf(a.net, a.dns.as_slice(), container_fs.as_ref());
    let (pivot_root, overlay) = match &container_fs {
        Some(fs) => (
            fs.root().to_path_buf(),
            Some(OverlayPaths {
                lower: fs.lower.clone(),
                upper: fs.upper.clone(),
                work: fs.work.clone(),
                merged: fs.merged.clone(),
            }),
        ),
        None => (rootfs.clone(), None),
    };

    let launch_args = if a.detach {
        detached_launch_args(&a, &rootfs)
    } else {
        Vec::new()
    };

    let image_desc = match &a.image {
        Some(i) => i.clone(),
        None => format!("rootfs:{}", rootfs.display()),
    };

    // Where the container actually pivoted to (overlay merged dir or the raw
    // rootfs), recorded in lifecycle state so `ze exec` can chroot there.
    let state_rootfs = match &container_fs {
        Some(fs) => fs.root().display().to_string(),
        None => fsutil::canonical_or_self(&rootfs).display().to_string(),
    };

    let spec = RunSpec {
        rootfs: pivot_root,
        argv,
        hostname: a.hostname,
        net: a.net,
        use_init: a.use_init,
        limits: ResourceLimits {
            memory: a.memory,
            cpus: a.cpus,
            pids: a.pids,
        },
        seccomp: a.seccomp,
        tty: a.tty,
        interactive: a.interactive,
        overlay,
        id,
        env,
        cwd,
        ports: a.ports,
        // Allocated from the file IPAM inside run_container (bridge mode).
        bridge_ip: None,
        run_root: store.run_root().to_path_buf(),
    };

    if a.detach {
        return run_detached(
            &store,
            spec,
            container_fs,
            &image_desc,
            &state_rootfs,
            DetachedInfo {
                launch_args,
                name: a.name,
                rm: a.rm,
            },
        );
    }

    // Foreground: this CLI is the parent and waits for the container.
    let result = namespace::run_container(spec);
    if let Some(fs) = container_fs {
        store.cleanup_container_fs(&fs);
    }
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zerun: {e}");
            1
        }
    }
}

/// `zerun run -d`: fork a per-container reaper, print the container id once
/// the workload is up, and exit. Everything container-shaped (clone, wait,
/// host-resource teardown, overlay cleanup, state updates) happens in the
/// reaper child (src/lifecycle.rs); it writes `0` / `1:<error>` over the
/// started pipe so the CLI never reports success for a container that failed
/// to start.
struct DetachedInfo {
    launch_args: Vec<String>,
    name: Option<String>,
    rm: bool,
}

fn run_detached(
    store: &Store,
    spec: RunSpec,
    container_fs: Option<store::ContainerFs>,
    image_desc: &str,
    state_rootfs: &str,
    info: DetachedInfo,
) -> i32 {
    use std::os::unix::io::AsRawFd;

    let id = spec.id.clone();
    if let Some(n) = &info.name {
        if state::list(store)
            .iter()
            .any(|c| c.name.as_deref() == Some(n))
        {
            eprintln!("zerun run: name '{n}' is already in use by another container");
            return 1;
        }
    }

    let sdir = state::ContainerState::dir(store, &id);
    if let Err(e) = fsutil::mkdir_p(&sdir) {
        eprintln!("zerun: {e}");
        return 1;
    }
    let log_path = sdir.join("console.log");
    let log_fd = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("zerun: open {}: {e}", log_path.display());
            return 1;
        }
    };
    let env: Vec<String> = spec
        .env
        .as_ref()
        .map(|pairs| pairs.iter().map(|(k, v)| format!("{k}={v}")).collect())
        .unwrap_or_default();
    let st = state::ContainerState {
        version: 1,
        id: id.clone(),
        name: info.name,
        image: image_desc.to_string(),
        pid: None,
        status: state::Status::Created,
        exit_code: None,
        created: state::now_rfc3339(),
        started: None,
        finished: None,
        rootless: unsafe { libc::geteuid() } != 0,
        net: net_label(spec.net),
        ports: spec.ports.iter().map(|p| (p.host, p.container)).collect(),
        ip: None,
        cmd: spec.argv.clone(),
        env,
        cwd: spec.cwd.clone(),
        log: log_path.display().to_string(),
        rootfs: state_rootfs.to_string(),
        overlay: container_fs
            .as_ref()
            .map(|fs| fs.dir().display().to_string()),
        launch_args: Some(info.launch_args),
        table: None,
        veth: None,
        cgroup: None,
    };
    if let Err(e) = st.save() {
        eprintln!("zerun: {e}");
        return 1;
    }

    let (started_r, started_w) = match syscalls::pipe2_cloexec() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };

    // Double purpose of the fork: the reaper becomes the container's parent and
    // survives this CLI; setsid() detaches it from the terminal so closing the
    // terminal cannot kill the container.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("zerun: fork: {}", std::io::Error::last_os_error());
            1
        }
        0 => {
            // --- reaper child ---
            syscalls::close(started_r);
            unsafe {
                libc::setsid();
            }
            let code = lifecycle::run_detached(
                store.clone(),
                spec,
                container_fs,
                info.rm,
                started_w,
                &log_path,
                log_fd.as_raw_fd(),
            );
            unsafe { libc::_exit(code) }
        }
        _ => {
            // --- foreground CLI: wait for the start signal ---
            drop(log_fd);
            syscalls::close(started_w);
            let mut msg = Vec::new();
            let mut buf = [0u8; 256];
            // Read one newline-terminated status line. EOF without a newline
            // (reaper died before signalling) is treated as the end of the
            // message. We must not wait for EOF: with --init the container
            // child never execs, so the write end of this pipe survives in the
            // container and EOF would only arrive when the container exits.
            while let Ok(n) = syscalls::read_fd(started_r, &mut buf) {
                if n == 0 {
                    break;
                }
                msg.extend_from_slice(&buf[..n as usize]);
                if msg.contains(&b'\n') {
                    break;
                }
            }
            syscalls::close(started_r);
            let text = String::from_utf8_lossy(&msg);
            if text.starts_with("0") {
                println!("{id}");
                0
            } else {
                let err = text.strip_prefix("1:").unwrap_or(&text).trim();
                if !err.is_empty() {
                    eprintln!("zerun: {err}");
                } else {
                    eprintln!(
                        "zerun: container failed to start (see {})",
                        log_path.display()
                    );
                }
                1
            }
        }
    }
}

/// Canonical arguments used to recreate a detached container. Capturing the
/// resolved options makes `restart` deterministic even if the caller's working
/// directory or shell aliases have changed.
fn detached_launch_args(a: &RunArgs, rootfs: &Path) -> Vec<String> {
    let mut args = vec!["-d".to_string()];
    if let Some(name) = &a.name {
        args.extend(["--name".to_string(), name.clone()]);
    }
    if let Some(v) = &a.memory {
        args.extend(["--memory".to_string(), v.clone()]);
    }
    if let Some(v) = a.cpus {
        args.extend(["--cpus".to_string(), v.to_string()]);
    }
    if let Some(v) = a.pids {
        args.extend(["--pids".to_string(), v.to_string()]);
    }
    if let Some(v) = &a.hostname {
        args.extend(["--hostname".to_string(), v.clone()]);
    }
    args.extend(["--net".to_string(), net_label(a.net)]);
    if a.use_init {
        args.push("--init".to_string());
    }
    if matches!(a.seccomp, SeccompMode::Unconfined) {
        args.extend(["--seccomp".to_string(), "unconfined".to_string()]);
    }
    if a.no_overlay {
        args.push("--no-overlay".to_string());
    }
    if let Some(v) = &a.platform {
        args.extend(["--platform".to_string(), v.clone()]);
    }
    for v in &a.env {
        args.extend(["--env".to_string(), v.clone()]);
    }
    for p in &a.ports {
        args.extend([
            "--publish".to_string(),
            format!("{}:{}", p.host, p.container),
        ]);
    }
    for v in &a.dns {
        args.extend(["--dns".to_string(), v.clone()]);
    }
    if a.rm {
        args.push("--rm".to_string());
    }
    if a.rootfs.is_some() {
        args.extend(["--rootfs".to_string(), rootfs.display().to_string()]);
    } else if let Some(image) = &a.image {
        args.push(image.clone());
    }
    if !a.argv.is_empty() {
        args.push("--".to_string());
        args.extend(a.argv.iter().cloned());
    }
    args
}

fn cmd_restart(args: &[String]) -> i32 {
    let mut timeout_secs: u64 = 10;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-t" | "--time" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(n) => timeout_secs = n,
                    Err(_) => {
                        eprintln!("zerun restart: invalid --time value '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun restart: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun restart [--time SECONDS] CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun restart: unknown option {other}");
                return 2;
            }
            _ => {
                targets.push(args[i].clone());
                i += 1;
            }
        }
    }
    if targets.is_empty() {
        eprintln!("zerun restart: at least one CONTAINER is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut failed = false;
    for target in targets {
        let launch_args = match state::resolve(&store, &target) {
            Ok(st) => match st.launch_args.clone() {
                Some(args) if args.first().map(String::as_str) == Some("-d") => args,
                _ => {
                    eprintln!(
                        "zerun restart: container {} predates restart metadata and cannot be restarted",
                        display_name(&st)
                    );
                    failed = true;
                    continue;
                }
            },
            Err(e) => {
                eprintln!("zerun restart: {e}");
                failed = true;
                continue;
            }
        };
        if let Err(e) = stop_one(&store, &target, timeout_secs) {
            eprintln!("zerun restart: {e}");
            failed = true;
            continue;
        }
        if let Ok(st) = state::resolve(&store, &target) {
            fsutil::remove_dir_all_quiet(&state::ContainerState::dir(&store, &st.id));
        }
        let code = cmd_run(&launch_args);
        if code != 0 {
            failed = true;
        }
    }
    if failed {
        1
    } else {
        0
    }
}

fn cmd_commit(args: &[String]) -> i32 {
    let mut message: Option<String> = None;
    let mut author: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-m" | "--message" => match next_value(args, &mut i, arg) {
                Ok(v) => message = Some(v),
                Err(e) => {
                    eprintln!("zerun commit: {e}");
                    return 2;
                }
            },
            "--author" => match next_value(args, &mut i, arg) {
                Ok(v) => author = Some(v),
                Err(e) => {
                    eprintln!("zerun commit: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!(
                    "usage: zerun commit [-m MESSAGE] [--author AUTHOR] CONTAINER IMAGE[:TAG]"
                );
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun commit: unknown option {other}");
                return 2;
            }
            _ => {
                positional.push(args[i].clone());
                i += 1;
            }
        }
    }
    let [container, target] = positional.as_slice() else {
        eprintln!("zerun commit: CONTAINER and IMAGE[:TAG] are required");
        return 2;
    };

    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let st = match state::resolve(&store, container) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun commit: {e}");
            return 1;
        }
    };
    let imgstore = match image::store::ImageStore::open(&store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };

    if st.status == state::Status::Running {
        eprintln!("zerun: warning: committing a running container; filesystem changes in progress may be inconsistent");
    }

    // A live container can archive its mounted merged rootfs directly. After
    // exit that mount is gone, so reconstruct the rootfs from the image lower
    // layer plus the persisted overlay upper layer.
    let mut rebuilt: Option<std::path::PathBuf> = None;
    let rootfs = match (
        st.overlay.as_deref(),
        matches!(st.status, state::Status::Running),
    ) {
        (Some(overlay), false) => {
            let upper = std::path::Path::new(overlay).join("upper");
            let staging = imgstore.blob_tmp("commit-source");
            match committable_lower_rootfs(&imgstore, &st) {
                Ok(lower) => {
                    let root = match image::commit::rebuild_rootfs(&lower, &upper, &staging) {
                        Ok(p) => p,
                        Err(e) => {
                            fsutil::remove_dir_all_quiet(&staging);
                            eprintln!("zerun commit: rebuild exited container rootfs: {e}");
                            return 1;
                        }
                    };
                    rebuilt = Some(root.clone());
                    root
                }
                Err(e) => {
                    fsutil::remove_dir_all_quiet(&staging);
                    eprintln!("zerun commit: {e}");
                    return 1;
                }
            }
        }
        _ => std::path::PathBuf::from(&st.rootfs),
    };
    if !rootfs.is_dir() {
        if let Some(path) = &rebuilt {
            fsutil::remove_dir_all_quiet(path);
        }
        eprintln!(
            "zerun commit: container filesystem is gone (removed or created by an older zerun): {}",
            rootfs.display()
        );
        return 1;
    }
    let options = image::commit::CommitOptions {
        env: st.env.clone(),
        cmd: st.cmd.clone(),
        working_dir: st.cwd.clone().unwrap_or_else(|| "/".to_string()),
        comment: message,
        author,
    };
    let result = image::commit::commit_image(&imgstore, &rootfs, target, options);
    if let Some(path) = &rebuilt {
        fsutil::remove_dir_all_quiet(path);
    }
    match result {
        Ok(record) => {
            println!(
                "sha256:{}",
                record
                    .manifest
                    .strip_prefix("sha256:")
                    .unwrap_or(&record.manifest)
            );
            0
        }
        Err(e) => {
            eprintln!("zerun commit: {e}");
            1
        }
    }
}

/// Resolve the lower rootfs backing a detached container's overlay.
fn committable_lower_rootfs(
    imgstore: &image::store::ImageStore,
    st: &state::ContainerState,
) -> Result<std::path::PathBuf, String> {
    if let Some(path) = st.image.strip_prefix("rootfs:") {
        return Ok(std::path::PathBuf::from(path));
    }
    let reference = Reference::parse(&st.image).map_err(|e| e.to_string())?;
    image::local_image(imgstore, &reference)
        .map_err(|e| e.to_string())?
        .map(|(rootfs, _)| rootfs)
        .ok_or_else(|| {
            format!(
                "base image '{}' is missing; it is needed to commit this exited container",
                st.image
            )
        })
}

fn net_label(net: NetMode) -> String {
    match net {
        NetMode::None => "none".to_string(),
        NetMode::Host => "host".to_string(),
        NetMode::Bridge => "bridge".to_string(),
    }
}

/// Give bridge-mode containers a working `/etc/resolv.conf`.
///
/// Docker semantics: explicit `--dns` wins; otherwise the host's nameservers
/// are inherited. The file is written into the per-run overlay `upper` on the
/// host side, so it appears in the container's `/etc` once the overlay is
/// mounted — no bind mounts across the pivot are needed.
fn inject_resolv_conf(
    net: NetMode,
    explicit: &[String],
    container_fs: Option<&store::ContainerFs>,
) {
    if net != NetMode::Bridge {
        return;
    }
    let Some(fs) = container_fs else {
        eprintln!("zerun: warning: --no-overlay has no writable layer; DNS is not injected");
        return;
    };
    let servers = if !explicit.is_empty() {
        explicit.to_vec()
    } else {
        host_nameservers()
    };
    if servers.is_empty() {
        return; // no nameserver available; keep the image's resolv.conf
    }
    let content = servers
        .iter()
        .map(|s| {
            format!(
                "nameserver {s}
"
            )
        })
        .collect::<String>();
    let etc = fs.upper.join("etc");
    if let Err(e) = fsutil::mkdir_p(&etc) {
        eprintln!("zerun: warning: DNS injection: {e}");
        return;
    }
    if let Err(e) = fsutil::atomic_write(&etc.join("resolv.conf"), content.as_bytes()) {
        eprintln!("zerun: warning: DNS injection: {e}");
    }
}

/// Nameserver IPs from the host's `/etc/resolv.conf`.
///
/// Loopback servers (systemd-resolved's 127.0.0.53) are useless inside a
/// container netns, so they are skipped; when nothing usable is left we fall
/// back to public resolvers so `--net bridge` containers get DNS out of the
/// box even on stub-resolver hosts.
fn host_nameservers() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver") {
                if let Some(ip) = it.next() {
                    if !ip.starts_with("127.") && !ip.starts_with("::1") {
                        out.push(ip.to_string());
                    }
                }
            }
        }
    }
    if out.is_empty() {
        out.push("1.1.1.1".to_string());
        out.push("8.8.8.8".to_string());
    }
    out
}

/// Resolve an image for `run`: find it locally or pull it. Returns the
/// read-only rootfs path plus the parsed image config.
fn resolve_run_image(
    store: &Store,
    reference: &Reference,
    platform: Option<&str>,
) -> Result<(PathBuf, image::config::ImageConfig), error::ZError> {
    let imgstore = image::store::ImageStore::open(store)?;
    if let Some(found) = image::local_image(&imgstore, reference)? {
        return Ok(found);
    }
    eprintln!(
        "zerun: image {} not found locally, pulling...",
        reference.canonical()
    );
    let mut client = image::registry::RegistryClient::new();
    let opts = PullOptions {
        platform: platform.map(str::to_string),
    };
    let pulled = image::pull_image(&imgstore, &mut client, reference, &opts)?;
    eprintln!(
        "zerun: pulled {} ({}), rootfs ready",
        reference.canonical(),
        fsutil::human_size(pulled.size_bytes)
    );
    Ok((pulled.rootfs, pulled.config))
}

/// Build the container environment from the image config + `-e` overrides.
/// The environment is fully specified (image mode clears the host env), so
/// PATH/HOME/HOSTNAME defaults are guaranteed here.
fn build_image_env(
    cfg_env: &[String],
    overrides: &[String],
    hostname: Option<&str>,
    id: &str,
    tty: bool,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    for entry in cfg_env {
        if let Some((k, v)) = entry.split_once('=') {
            upsert_env(&mut env, k.to_string(), v.to_string());
        }
    }
    if workload::env_value(&env, "PATH").is_none() {
        env.push(("PATH".to_string(), workload::DEFAULT_PATH.to_string()));
    }
    if workload::env_value(&env, "HOME").is_none() {
        env.push(("HOME".to_string(), "/root".to_string()));
    }
    for o in overrides {
        match o.split_once('=') {
            Some((k, v)) => upsert_env(&mut env, k.to_string(), v.to_string()),
            None => {
                // `-e NAME` passes the host value through (docker semantics).
                match std::env::var(o) {
                    Ok(v) => upsert_env(&mut env, o.to_string(), v),
                    Err(_) => eprintln!(
                        "zerun: warning: -e {o}: variable is not set in the host environment, skipping"
                    ),
                }
            }
        }
    }
    if workload::env_value(&env, "HOSTNAME").is_none() {
        env.push(("HOSTNAME".to_string(), hostname.unwrap_or(id).to_string()));
    }
    if tty && workload::env_value(&env, "TERM").is_none() {
        env.push(("TERM".to_string(), "xterm".to_string()));
    }
    env
}

fn upsert_env(env: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        env.push((key, value));
    }
}

/// Combine image Entrypoint/Cmd with CLI arguments (docker semantics):
/// CLI args replace Cmd but never Entrypoint; no CLI args run Entrypoint+Cmd.
fn resolve_image_argv(cfg: &image::config::ImageConfig, cli: &[String]) -> Vec<String> {
    let entry = &cfg.config.entrypoint;
    let cmd = &cfg.config.cmd;
    let mut argv: Vec<String> = Vec::new();
    if !cli.is_empty() {
        argv.extend(entry.iter().cloned());
        argv.extend(cli.iter().cloned());
    } else if !entry.is_empty() {
        argv.extend(entry.iter().cloned());
        argv.extend(cmd.iter().cloned());
    } else {
        argv.extend(cmd.iter().cloned());
    }
    if argv.is_empty() {
        argv.push("/bin/sh".to_string());
    }
    argv
}

fn cmd_pull(args: &[String]) -> i32 {
    let mut platform: Option<String> = None;
    let mut refs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--platform" => match next_value(args, &mut i, "--platform") {
                Ok(v) => platform = Some(v),
                Err(e) => {
                    eprintln!("zerun pull: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun pull [--platform os/arch[/variant]] IMAGE...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun pull: unknown option {other}");
                return 2;
            }
            _ => {
                refs.push(args[i].clone());
                i += 1;
            }
        }
    }
    if refs.is_empty() {
        eprintln!("zerun pull: at least one IMAGE is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    if let Err(e) = store.ensure_dirs() {
        eprintln!("zerun: {e}");
        return 1;
    }
    let imgstore = match image::store::ImageStore::open(&store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut client = image::registry::RegistryClient::new();
    let opts = PullOptions {
        platform: platform.clone(),
    };
    let mut failed = false;
    for r in &refs {
        let reference = match Reference::parse(r) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("zerun pull: invalid reference '{r}': {e}");
                failed = true;
                continue;
            }
        };
        println!("{}: pulling...", reference.canonical());
        match image::pull_image(&imgstore, &mut client, &reference, &opts) {
            Ok(img) => {
                println!(
                    "{}: pull complete ({} layers, {})",
                    reference.canonical(),
                    img.config.rootfs.diff_ids.len(),
                    fsutil::human_size(img.size_bytes)
                );
            }
            Err(e) => {
                eprintln!("zerun pull: {}: {e}", reference.canonical());
                failed = true;
            }
        }
    }
    if failed {
        1
    } else {
        0
    }
}

fn cmd_images(_args: &[String]) -> i32 {
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let imgstore = match image::store::ImageStore::open(&store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut records = match imgstore.records() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    records.sort_by(|a, b| a.name.cmp(&b.name).then(a.tag.cmp(&b.tag)));
    println!("{:<40} {:<16} {:<14} SIZE", "REPOSITORY", "TAG", "IMAGE ID");
    for r in &records {
        let tag = r.tag.as_deref().unwrap_or("<none>");
        let id = image::store::digest_hex(&r.manifest)
            .map(|h| h[..12.min(h.len())].to_string())
            .unwrap_or_else(|_| "?".to_string());
        println!(
            "{:<40} {:<16} {:<14} {}",
            r.name,
            tag,
            id,
            fsutil::human_size(r.size_bytes)
        );
    }
    0
}

fn cmd_rmi(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("zerun rmi: at least one IMAGE is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let imgstore = match image::store::ImageStore::open(&store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut failed = false;
    let mut removed_any = false;
    for r in args {
        let reference = match Reference::parse(r) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("zerun rmi: invalid reference '{r}': {e}");
                failed = true;
                continue;
            }
        };
        let name = format!("{}/{}", reference.registry, reference.repository);
        match imgstore.remove_record(&name, reference.tag.as_deref(), reference.digest.as_deref()) {
            Ok(Some(rec)) => {
                removed_any = true;
                let tag = rec.tag.as_deref().unwrap_or("<none>");
                println!("Untagged: {name}:{tag}");
            }
            Ok(None) => {
                eprintln!("zerun rmi: No such image: {r}");
                failed = true;
            }
            Err(e) => {
                eprintln!("zerun rmi: {e}");
                failed = true;
            }
        }
    }
    if removed_any {
        if let Err(e) = imgstore.gc() {
            eprintln!("zerun rmi: garbage collection: {e}");
        }
    }
    if failed {
        1
    } else {
        0
    }
}

fn cmd_generate_service(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help") {
        service::print_usage();
        return 0;
    }
    let mut a = match parse_run_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zerun generate-service: {e}");
            return 2;
        }
    };
    // Keep the generated command explicit so behavior does not depend on the
    // effective UID of the systemd service versus the generating user.
    if !a.net_specified {
        a.net = default_net(unsafe { libc::geteuid() });
    }
    match service::generate(&a, &mut std::io::stdout().lock()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("zerun generate-service: {e}");
            1
        }
    }
}

fn cmd_doctor() -> i32 {
    println!("== Zerun environment doctor ==");
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let rel = syscalls::cstr_to_string(u.release.as_ptr());
            println!("kernel release : {rel}  (baseline recommendation >= 5.10 LTS)");
        }
    }
    match cgroup::detect_cgroup2_root() {
        Ok(root) => {
            let ctrl = std::fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
            println!(
                "cgroup v2      : OK at {}  controllers: {}",
                root.display(),
                ctrl.trim()
            );
        }
        Err(e) => println!("cgroup v2      : MISSING ({e})"),
    }
    match std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        Ok(v) => println!("user namespaces: max = {}", v.trim()),
        Err(_) => println!("user namespaces: unknown"),
    }
    match std::fs::read_to_string("/proc/filesystems") {
        Ok(fs) => println!(
            "overlayfs      : {}",
            if fs.lines().any(|l| l.contains("overlay")) {
                "available (used from M2)"
            } else {
                "NOT available"
            }
        ),
        Err(_) => println!("overlayfs      : unknown"),
    }
    println!("cap_last_cap   : {}", syscalls::cap_last_cap());
    let data = Store::detect()
        .map(|s| s.data_root().display().to_string())
        .unwrap_or_else(|e| format!("<error: {e}>"));
    println!("data root      : {data}");
    println!(
        "uid            : {} (rootful isolation needs uid=0; non-root goes rootless via NEWUSER)",
        unsafe { libc::geteuid() }
    );
    0
}

// ---------------------------------------------------------------------------
// M5 detached-container lifecycle commands: ps / stop / rm / logs / exec
// ---------------------------------------------------------------------------

fn cmd_ps(args: &[String]) -> i32 {
    let mut all = false;
    for a in args {
        match a.as_str() {
            "-a" | "--all" => all = true,
            "-h" | "--help" => {
                println!("usage: zerun ps [-a]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun ps: unknown option {other}");
                return 2;
            }
            other => {
                eprintln!("zerun ps: unexpected argument '{other}'");
                return 2;
            }
        }
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    for mut st in state::list(&store) {
        // Crash reconcile: a record that says Running for a dead PID belongs
        // to a reaper that never got to clean up; mark it exited and reclaim
        // its host-side resources (nft table, veth, cgroup, IPAM, overlay).
        if lifecycle::reconcile_stale(&store, &mut st) {
            let _ = st.save();
        }
        if !all && st.status != state::Status::Running {
            continue;
        }
        rows.push(ps_row(&st));
    }
    if rows.is_empty() {
        return 0;
    }
    let headers = [
        "CONTAINER ID".to_string(),
        "IMAGE".to_string(),
        "COMMAND".to_string(),
        "CREATED".to_string(),
        "STATUS".to_string(),
        "PORTS".to_string(),
        "NAMES".to_string(),
    ];
    print!("{}", render_table(&headers, &rows));
    0
}

fn ps_row(st: &ContainerState) -> Vec<String> {
    vec![
        st.id.clone(),
        st.image.clone(),
        truncate(&one_line(&st.cmd), 30),
        format!("{} ago", elapsed_str(&st.created)),
        ps_status(st),
        ports_label(&st.ports),
        st.name.clone().unwrap_or_default(),
    ]
}

fn ps_status(st: &ContainerState) -> String {
    match st.status {
        state::Status::Running => match &st.started {
            Some(t) => format!("Up {}", elapsed_str(t)),
            None => "Up".to_string(),
        },
        state::Status::Exited => {
            let code = st.exit_code.unwrap_or(-1);
            match &st.finished {
                Some(t) => format!("Exited ({code}) {} ago", elapsed_str(t)),
                None => format!("Exited ({code})"),
            }
        }
        state::Status::Created => "Created".to_string(),
    }
}

fn ports_label(ports: &[(u16, u16)]) -> String {
    ports
        .iter()
        .map(|(h, c)| format!("0.0.0.0:{h}->{c}/tcp"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn cmd_stop(args: &[String]) -> i32 {
    let mut timeout_secs: u64 = 10;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-t" | "--time" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(n) => timeout_secs = n,
                    Err(_) => {
                        eprintln!("zerun stop: invalid --time value '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun stop: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun stop [--time SECONDS] CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun stop: unknown option {other}");
                return 2;
            }
            _ => {
                targets.push(args[i].clone());
                i += 1;
            }
        }
    }
    if targets.is_empty() {
        eprintln!("zerun stop: at least one CONTAINER is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut failed = false;
    for t in targets {
        match stop_one(&store, &t, timeout_secs) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun stop: {e}");
                failed = true;
            }
        }
    }
    if failed {
        1
    } else {
        0
    }
}

/// Docker semantics: SIGTERM, wait up to `--time`, then SIGKILL. The per-run
/// reaper observes the death and persists the exit itself; when it is gone
/// (crash) the stale record is reconciled instead.
fn stop_one(store: &Store, target: &str, timeout_secs: u64) -> Result<String, String> {
    let st = state::resolve(store, target)?;
    let name = display_name(&st);
    match st.status {
        state::Status::Exited | state::Status::Created => return Ok(name), // nothing to signal
        state::Status::Running => {}
    }
    if !st.pid_alive() {
        let mut s = st.clone();
        if lifecycle::reconcile_stale(store, &mut s) {
            let _ = s.save();
        }
        return Ok(name);
    }
    let pid = st
        .pid
        .ok_or_else(|| format!("container {} has no PID", st.id))?;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    if !wait_pid_gone(pid, Duration::from_secs(timeout_secs)) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        wait_pid_gone(pid, Duration::from_secs(5));
    }
    lifecycle::settle_exit(store, &st.id);
    Ok(name)
}

fn cmd_rm(args: &[String]) -> i32 {
    let mut force = false;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => {
                force = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!("usage: zerun rm [-f] CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun rm: unknown option {other}");
                return 2;
            }
            _ => {
                targets.push(args[i].clone());
                i += 1;
            }
        }
    }
    if targets.is_empty() {
        eprintln!("zerun rm: at least one CONTAINER is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut failed = false;
    for t in targets {
        match rm_one(&store, &t, force) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun rm: {e}");
                failed = true;
            }
        }
    }
    if failed {
        1
    } else {
        0
    }
}

fn rm_one(store: &Store, target: &str, force: bool) -> Result<String, String> {
    let mut st = state::resolve(store, target)?;
    let name = display_name(&st);
    if st.status == state::Status::Running {
        if !force {
            return Err(format!(
                "cannot remove a running container {name} - stop it first or use -f"
            ));
        }
        if let Some(pid) = st.pid.filter(|p| *p > 0) {
            if pid_alive(pid) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                wait_pid_gone(pid, Duration::from_secs(5));
            }
        }
        // Let the reaper record the exit (or reconcile when it is gone), so the
        // state directory is not deleted underneath a reaper that is about to
        // write its final record.
        lifecycle::settle_exit(store, &st.id);
        if let Some(fresh) = state::ContainerState::load(store, &st.id) {
            st = fresh;
        }
    }
    // Reclaim any host-side leftovers still recorded (best effort; the normal
    // reaper path already cleaned them up).
    lifecycle::reclaim_resources(store, &st);
    if let Some(ov) = &st.overlay {
        fsutil::remove_dir_all_quiet(Path::new(ov));
    }
    let dir = state::ContainerState::dir(store, &st.id);
    fsutil::remove_dir_all_quiet(&dir);
    Ok(name)
}

fn cmd_logs(args: &[String]) -> i32 {
    let mut tail: Option<usize> = None;
    let mut follow = false;
    let mut timestamps = false;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-n" | "--tail" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<usize>() {
                    Ok(n) => tail = Some(n),
                    Err(_) => {
                        eprintln!("zerun logs: invalid --tail value '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun logs: {e}");
                    return 2;
                }
            },
            "-f" | "--follow" => {
                follow = true;
                i += 1;
            }
            "-t" | "--timestamps" => {
                timestamps = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!("usage: zerun logs [--tail N] [-f] [-t|--timestamps] CONTAINER");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun logs: unknown option {other}");
                return 2;
            }
            _ => {
                targets.push(args[i].clone());
                i += 1;
            }
        }
    }
    if targets.len() != 1 {
        eprintln!("zerun logs: exactly one CONTAINER is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let st = match state::resolve(&store, &targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun logs: {e}");
            return 1;
        }
    };
    let path = PathBuf::from(&st.log);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "zerun logs: cannot read {} for container {}: {e}",
                path.display(),
                display_name(&st)
            );
            return 1;
        }
    };
    let shown = tail_bytes(&bytes, tail.unwrap_or(usize::MAX));
    write_log_output(shown, timestamps);
    if follow {
        follow_log(&store, &st, &path, shown.len() as u64, timestamps);
    }
    0
}

/// Print data appended to `console.log` until the container exits.
fn follow_log(store: &Store, st: &ContainerState, path: &Path, mut pos: u64, timestamps: bool) {
    while container_observable(store, st) {
        std::thread::sleep(Duration::from_millis(200));
        pos = drain_log(path, pos, timestamps);
    }
    drain_log(path, pos, timestamps);
}

fn drain_log(path: &Path, pos: u64, timestamps: bool) -> u64 {
    use std::io::{Read, Seek};
    let Ok(mut f) = std::fs::File::open(path) else {
        return pos;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return pos;
    };
    if len <= pos {
        return pos;
    }
    if f.seek(std::io::SeekFrom::Start(pos)).is_err() {
        return pos;
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_ok() {
        write_log_output(&buf, timestamps);
    }
    len
}

fn container_observable(store: &Store, st: &ContainerState) -> bool {
    match state::ContainerState::load(store, &st.id) {
        Some(s) => s.status == state::Status::Running && s.pid_alive(),
        None => false, // --rm removed the record; stop following
    }
}

fn cmd_exec(args: &[String]) -> i32 {
    let mut env_extra: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-e" | "--env" => match next_value(args, &mut i, a) {
                Ok(v) => env_extra.push(v),
                Err(e) => {
                    eprintln!("zerun exec: {e}");
                    return 2;
                }
            },
            "-w" | "--workdir" => match next_value(args, &mut i, a) {
                Ok(v) => workdir = Some(v),
                Err(e) => {
                    eprintln!("zerun exec: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun exec [-e NAME=VAL] [-w DIR] CONTAINER CMD [ARG...]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun exec: unknown option {other}");
                return 2;
            }
            _ => {
                let container = args[i].clone();
                let cmd = args[i + 1..].to_vec();
                if cmd.is_empty() {
                    eprintln!("zerun exec: a command is required after CONTAINER");
                    return 2;
                }
                let store = match Store::detect() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("zerun: {e}");
                        return 1;
                    }
                };
                let st = match state::resolve(&store, &container) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("zerun exec: {e}");
                        return 1;
                    }
                };
                return match execc::run(&st, &env_extra, workdir.as_deref(), &cmd) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("zerun exec: {e}");
                        1
                    }
                };
            }
        }
    }
    eprintln!("zerun exec: CONTAINER and COMMAND are required");
    2
}

// --- shared helpers for the lifecycle commands -------------------------------

fn display_name(st: &ContainerState) -> String {
    st.name.clone().unwrap_or_else(|| st.id.clone())
}

fn one_line(cmd: &[String]) -> String {
    cmd.join(" ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

fn render_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut w: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < w.len() {
                w[i] = w[i].max(c.chars().count());
            }
        }
    }
    let mut out = String::new();
    push_row(&mut out, headers, &w);
    for r in rows {
        push_row(&mut out, r, &w);
    }
    out
}

fn push_row(out: &mut String, cells: &[String], w: &[usize]) {
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(c);
        if i + 1 < w.len() {
            let pad = w[i].saturating_sub(c.chars().count());
            for _ in 0..pad {
                out.push(' ');
            }
        }
    }
    out.push('\n');
}

fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn wait_pid_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !pid_alive(pid)
}

/// `console.log` stores timestamps at capture time. Docker-style default
/// output omits them, while `-t` displays the recorded timestamps verbatim.
/// Legacy logs without the known prefix pass through unchanged.
fn write_log_output(data: &[u8], timestamps: bool) {
    if timestamps {
        write_stdout(data);
    } else {
        write_stdout(&strip_log_timestamps(data));
    }
}

fn strip_log_timestamps(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut start = 0;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| start + p + 1)
            .unwrap_or(data.len());
        let line = &data[start..end];
        if let Some(content) = timestamp_prefix(line) {
            out.extend_from_slice(content);
        } else {
            out.extend_from_slice(line);
        }
        start = end;
    }
    out
}

/// Return the line content after an RFC3339 nanosecond timestamp + TAB.
fn timestamp_prefix(line: &[u8]) -> Option<&[u8]> {
    const TS_LEN: usize = 30; // 2026-01-01T00:00:00.000000000Z
    if line.len() <= TS_LEN + 1 || line[TS_LEN] != b'\t' || !is_utc_rfc3339(&line[..TS_LEN]) {
        return None;
    }
    Some(&line[TS_LEN + 1..])
}

fn is_utc_rfc3339(b: &[u8]) -> bool {
    const SEPARATORS: [u8; 30] = *b"YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ";
    b.len() == 30
        && b.iter().zip(SEPARATORS).all(|(got, want)| match want {
            b'Y' | b'M' | b'D' | b'H' | b'S' | b'N' => got.is_ascii_digit(),
            _ => *got == want,
        })
}

/// Keep only the last `n` lines of `data` (newline-terminated lines; a
/// trailing newline does not produce an extra empty line).
fn tail_bytes(data: &[u8], n: usize) -> &[u8] {
    if n == 0 || data.is_empty() {
        return &[];
    }
    let mut line_starts = vec![0usize];
    for (i, b) in data.iter().enumerate() {
        if *b == b'\n' && i + 1 < data.len() {
            line_starts.push(i + 1);
        }
    }
    if line_starts.len() > n {
        &data[line_starts[line_starts.len() - n]..]
    } else {
        data
    }
}

fn write_stdout(data: &[u8]) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(data);
    let _ = out.flush();
}

/// Human-friendly age of an RFC3339 UTC timestamp ("5 minutes").
fn elapsed_str(rfc: &str) -> String {
    let Some(then) = epoch_of_rfc3339(rfc) else {
        return "unknown".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = (now - then).max(0);
    if secs < 60 {
        plural(secs, "second")
    } else if secs < 3600 {
        plural(secs / 60, "minute")
    } else if secs < 86400 {
        plural(secs / 3600, "hour")
    } else {
        plural(secs / 86400, "day")
    }
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

/// Parse the fixed-width "YYYY-MM-DDTHH:MM:SSZ" records state.rs writes.
fn epoch_of_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        std::str::from_utf8(&b[r]).ok()?.parse().ok()
    };
    let y = num(0..4)?;
    let mo = num(5..7)?;
    let d = num(8..10)?;
    let h = num(11..13)?;
    let mi = num(14..16)?;
    let se = num(17..19)?;
    Some(days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Howard Hinnant's days_from_civil (inverse of the algorithm in state.rs).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (u64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos & 0xffff_ffff_ffff)
}

fn print_run_usage() {
    println!(
        "usage:\n  \
         zerun run [OPTIONS] IMAGE [CMD [ARGS...]]\n  \
         zerun run -d [--name NAME] [OPTIONS] IMAGE [CMD [ARGS...]]   (detached)\n  \
         zerun run --rootfs DIR [OPTIONS] [--] CMD [ARGS...]   (legacy)"
    );
}

fn print_help() {
    println!(
        "zerun — daemonless single-binary container runtime\n\
\n\
USAGE:\n  \
  zerun run [opts] IMAGE [CMD...]        run a container from an OCI image\n  \
  zerun run -d [--name N] [opts] IMAGE [CMD...]\n  \
                                        run detached (logs/ps/stop/rm/exec)\n  \
  zerun ps [-a]                         list containers (detached)\n  \
  zerun stop [--time S] CONTAINER...    SIGTERM, then SIGKILL after the timeout\n  \
  zerun restart [--time S] CONTAINER... restart detached containers\n  \
  zerun rm [-f] CONTAINER...            remove stopped containers (-f: kill first)\n  \
  zerun logs [--tail N] [-f] [-t] CONTAINER  show a container's console.log\n  \
  zerun exec [-e K=V] [-w DIR] CONTAINER CMD [ARG...]\n  \
                                        run a command in a running container\n  \
  zerun pull [--platform ...] IMAGE...   pull OCI images (Docker Hub, mirrors)\n  \
  zerun images                           list local images\n  \
  zerun rmi IMAGE...                     remove local images\n  \
  zerun commit [-m MSG] CONTAINER IMAGE[:TAG]  save a container as an image\n  \
  zerun generate-service [opts] IMAGE    write a systemd unit to stdout\n  \
  zerun doctor                           environment diagnostics\n\
\n\
RUN OPTIONS:\n  \
  --rootfs DIR    run from an unpacked rootfs dir instead of an image (legacy)\n  \
  -d, --detach    run in the background; print the container id once started\n  \
  --name NAME     assign a name (ps/stop/rm/logs/exec address it by name)\n  \
  --rm            remove state and the writable layer when the container exits\n  \
  -m, --memory 64M    cgroup v2 memory.max (K/M/G suffixes)\n  \
  --cpus 0.5          cgroup v2 cpu.max (cores)\n  \
  --pids 256          cgroup v2 pids.max\n  \
  -h, --hostname H    container hostname (new UTS namespace)\n  \
  --net none|host|bridge\n  \
                      none = fresh netns + loopback; host = share host net;\n  \
                      bridge = zerun0 bridge + NAT (needs CAP_NET_ADMIN;\n  \
                      rootful default; rootless default is none)\n  \
  -i, --interactive      keep stdin attached (foreground runs)\n  \
  -t, --tty              allocate a PTY (foreground runs; combine with -i)\n  \
  -p, --publish HOST:CONTAINER  publish a TCP port on the host (requires --net bridge)\n  \
  --dns IP            container DNS server (repeatable; bridge mode; defaults to the host's)\n  \
  --init              run the built-in mini-init (reap orphans + forward signals)\n  \
  --seccomp default|unconfined\n  \
  --platform os/arch[/variant]  pull/run a specific platform\n  \
  -e, --env NAME[=VALUE]  set a container environment variable (image mode)\n  \
  --no-overlay        pivot directly into the rootfs (no writable upper layer)\n\
\n\
ENV:\n  \
  ZERUN_TRACE=1   print per-stage nanosecond timings to stderr (bench harness)\n  \
  ZERUN_REGISTRY_MIRRORS=...  comma-separated Docker Hub mirrors"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_launch_args_capture_resolved_options() {
        let mut a = parse_run_args(&["alpine".to_string(), "sleep".to_string(), "1".to_string()])
            .expect("valid run args");
        a.detach = true;
        a.name = Some("web".to_string());
        a.net = NetMode::Bridge;
        a.memory = Some("64M".to_string());
        a.ports.push(network::PublishedPort {
            host: 8080,
            container: 80,
        });
        let args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert_eq!(
            args,
            vec![
                "-d",
                "--name",
                "web",
                "--memory",
                "64M",
                "--net",
                "bridge",
                "--publish",
                "8080:80",
                "alpine",
                "--",
                "sleep",
                "1"
            ]
        );
    }

    #[test]
    fn parses_interactive_and_tty_flags() {
        let args: Vec<_> = ["-it", "alpine", "echo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("combined flags");
        assert!(a.interactive);
        assert!(a.tty);

        let args: Vec<_> = ["--interactive", "--tty", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("long flags");
        assert!(a.interactive);
        assert!(a.tty);
    }

    #[test]
    fn image_tty_gets_default_term() {
        let env = build_image_env(&[], &[], None, "abc123", true);
        assert_eq!(workload::env_value(&env, "TERM"), Some("xterm"));
    }

    #[test]
    fn rootful_defaults_to_bridge_and_rootless_to_none() {
        assert_eq!(default_net(0), NetMode::Bridge);
        assert_eq!(default_net(1000), NetMode::None);
    }

    #[test]
    fn log_timestamps_are_hidden_by_default_and_shown_on_request() {
        const RAW: &[u8] = b"2026-01-01T00:00:00.123456789Z\thello\nlegacy\npartial";
        assert_eq!(strip_log_timestamps(RAW), b"hello\nlegacy\npartial");
        assert_eq!(timestamp_prefix(RAW), Some(&b"hello\nlegacy\npartial"[..]));
        let first_line_end = RAW.iter().position(|&b| b == b'\n').unwrap() + 1;
        assert_eq!(
            timestamp_prefix(&RAW[..first_line_end]),
            Some(&b"hello\n"[..])
        );
    }
}
