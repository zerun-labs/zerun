//! zerun — daemonless, single-binary Linux container runtime.
//!
//! Command surface (Docker-compatible top 20%):
//!   zerun run [opts] IMAGE [CMD...]       run a container from an OCI image
//!   zerun run --rootfs DIR [opts] -- CMD  legacy: run from an unpacked rootfs
//!   zerun run -d [--name N] [opts] IMAGE  run detached (state under /run/zerun)
//!   zerun ps / wait / stop / rm / logs / exec   detached lifecycle (M5)
//!   zerun login / logout / pull / images / rmi   image lifecycle (M3)
//!   zerun doctor                          environment diagnostics
mod cgroup;
mod containerdiff;
mod error;
mod events;
mod execc;
mod fsutil;
mod image;
mod lifecycle;
mod logs;
mod mini_init;
mod mounts;
mod namespace;
mod netlink;
mod network;
mod nfnetlink;
mod procinfo;
mod prompt;
mod psfilter;
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
use image::auth::{normalize_registry, Credential, CredentialStore};
use image::name::Reference;
use image::registry::RegistryClient;
use image::PullOptions;
use logs::LogTimeFilter;
use mounts::OverlayPaths;
use namespace::{NetMode, RunSpec};
use psfilter::PsFilter;
use seccomp::SeccompMode;
use state::ContainerState;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use store::Store;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[2..]),
        Some("ps") => cmd_ps(&args[2..]),
        Some("wait") => cmd_wait(&args[2..]),
        Some("stop") => cmd_stop(&args[2..]),
        Some("kill") => cmd_kill(&args[2..]),
        Some("restart") => cmd_restart(&args[2..]),
        Some("rm") => cmd_rm(&args[2..]),
        Some("logs") => cmd_logs(&args[2..]),
        Some("stats") => cmd_stats(&args[2..]),
        Some("update") => cmd_update(&args[2..]),
        Some("inspect") => cmd_inspect(&args[2..]),
        Some("port") => cmd_port(&args[2..]),
        Some("rename") => cmd_rename(&args[2..]),
        Some("top") => cmd_top(&args[2..]),
        Some("diff") => cmd_diff(&args[2..]),
        Some("cp") => cmd_cp(&args[2..]),
        Some("export") => cmd_export(&args[2..]),
        Some("import") => cmd_import(&args[2..]),
        Some("events") => cmd_events(&args[2..]),
        Some("attach") => cmd_attach(&args[2..]),
        Some("exec") => cmd_exec(&args[2..]),
        Some("login") => cmd_login(&args[2..]),
        Some("logout") => cmd_logout(&args[2..]),
        Some("pull") => cmd_pull(&args[2..]),
        Some("images") => cmd_images(&args[2..]),
        Some("tag") => cmd_tag(&args[2..]),
        Some("rmi") => cmd_rmi(&args[2..]),
        Some("system") => cmd_system(&args[2..]),
        Some("prune") => cmd_prune(&args[2..]),
        Some("push") => cmd_push(&args[2..]),
        Some("save") => cmd_save(&args[2..]),
        Some("load") => cmd_load(&args[2..]),
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
    memory_reservation: Option<String>,
    /// Docker-style total memory+swap; -1/unlimited.
    memory_swap: Option<i64>,
    cpus: Option<f64>,
    cpuset_cpus: Option<String>,
    cpuset_mems: Option<String>,
    pids: Option<i64>,
    oom_group: bool,
    device_read_bps: Vec<cgroup::IoLimit>,
    device_write_bps: Vec<cgroup::IoLimit>,
    device_read_iops: Vec<cgroup::IoLimit>,
    device_write_iops: Vec<cgroup::IoLimit>,
    hostname: Option<String>,
    /// Container user (`--user USER[:GROUP]`; image `config.User` wins when no
    /// explicit flag is given).
    user: Option<String>,
    net: NetMode,
    /// True after the operator explicitly selected `--net`.
    net_specified: bool,
    use_init: bool,
    seccomp: SeccompMode,
    no_overlay: bool,
    tmpfs_upper: bool,
    /// `--read-only`: remount the container root read-only before exec.
    readonly: bool,
    /// `--tmpfs PATH[:opts]`: extra in-container tmpfs mounts.
    tmpfs: Vec<mounts::TmpfsMount>,
    platform: Option<String>,
    env: Vec<String>,
    ports: Vec<network::PublishedPort>,
    volumes: Vec<mounts::BindMount>,
    dns: Vec<String>,
    labels: BTreeMap<String, String>,
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
            "--memory-reservation" => {
                a.memory_reservation = Some(next_value(args, &mut i, s)?);
            }
            "--memory-swap" => {
                let v = next_value(args, &mut i, "--memory-swap")?;
                a.memory_swap = Some(cgroup::parse_memory_swap(&v).map_err(|e| e.to_string())?);
            }
            "--oom-group" => {
                a.oom_group = true;
                i += 1;
            }
            "--cpus" => {
                let v = next_value(args, &mut i, "--cpus")?;
                a.cpus = Some(
                    v.parse::<f64>()
                        .ok()
                        .filter(|c| *c > 0.0)
                        .ok_or_else(|| format!("invalid --cpus value '{v}'"))?,
                );
            }
            "--cpuset-cpus" => {
                let v = next_value(args, &mut i, "--cpuset-cpus")?;
                a.cpuset_cpus = Some(cgroup::parse_cpuset(&v).map_err(|e| e.to_string())?);
            }
            "--cpuset-mems" => {
                let v = next_value(args, &mut i, "--cpuset-mems")?;
                a.cpuset_mems = Some(cgroup::parse_cpuset(&v).map_err(|e| e.to_string())?);
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
            "--user" | "-u" => {
                a.user = Some(next_value(args, &mut i, "--user")?);
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
            "--tmpfs-upper" => {
                a.tmpfs_upper = true;
                i += 1;
            }
            "--read-only" => {
                a.readonly = true;
                i += 1;
            }
            "--tmpfs" => {
                let v = next_value(args, &mut i, "--tmpfs")?;
                a.tmpfs.push(mounts::parse_tmpfs(&v)?);
            }
            "--platform" => {
                a.platform = Some(next_value(args, &mut i, "--platform")?);
            }
            "--env" | "-e" => {
                a.env.push(next_value(args, &mut i, s)?);
            }
            "--volume" | "-v" => {
                let v = next_value(args, &mut i, s)?;
                a.volumes
                    .push(mounts::parse_bind(&v).map_err(|e| e.to_string())?);
            }
            "--publish" | "-p" => {
                let v = next_value(args, &mut i, s)?;
                a.ports.push(parse_publish(&v)?);
            }
            "--device-read-bps" => {
                let v = next_value(args, &mut i, s)?;
                a.device_read_bps.push(
                    cgroup::parse_io_limit("device-read-bps", &v).map_err(|e| e.to_string())?,
                );
            }
            "--device-write-bps" => {
                let v = next_value(args, &mut i, s)?;
                a.device_write_bps.push(
                    cgroup::parse_io_limit("device-write-bps", &v).map_err(|e| e.to_string())?,
                );
            }
            "--device-read-iops" => {
                let v = next_value(args, &mut i, s)?;
                a.device_read_iops.push(
                    cgroup::parse_io_limit("device-read-iops", &v).map_err(|e| e.to_string())?,
                );
            }
            "--device-write-iops" => {
                let v = next_value(args, &mut i, s)?;
                a.device_write_iops.push(
                    cgroup::parse_io_limit("device-write-iops", &v).map_err(|e| e.to_string())?,
                );
            }
            "--dns" => {
                let v = next_value(args, &mut i, "--dns")?;
                v.parse::<std::net::IpAddr>()
                    .map_err(|_| format!("invalid --dns address '{v}'"))?;
                a.dns.push(v);
            }
            "--label" => {
                let (k, v) = parse_label(&next_value(args, &mut i, "--label")?)?;
                a.labels.insert(k, v);
            }
            "--detach" | "-d" => {
                a.detach = true;
                i += 1;
            }
            "--name" => {
                let v = next_value(args, &mut i, "--name")?;
                if !state::valid_name(&v) {
                    return Err(format!(
                        "invalid --name '{v}' (allowed: [a-zA-Z0-9][a-zA-Z0-9_.-]*)"
                    ));
                }
                a.name = Some(v);
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

/// Parse `-p`/`--publish` values. Supported forms:
///   HOST[:CONTAINER][/tcp|/udp]
///   ADDRESS:HOST[:CONTAINER][/tcp|/udp]
/// IPv6 addresses are bracketed (`[::1]:8080:80`).
fn parse_publish(v: &str) -> Result<network::PublishedPort, String> {
    use std::net::IpAddr;

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

    let (v, protocol) = if let Some(v) = v.strip_suffix("/udp") {
        (v, network::PortProtocol::Udp)
    } else if let Some(v) = v.strip_suffix("/tcp") {
        (v, network::PortProtocol::Tcp)
    } else {
        (v, network::PortProtocol::Tcp)
    };
    if v.is_empty() {
        return Err(format!("-p: invalid port publish '{v}'"));
    }

    let (host_ip, rest) = if let Some(rest) = v.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| format!("-p: missing ']' in IPv6 publish '{v}'"))?;
        let ip: IpAddr = rest[..close]
            .parse()
            .map_err(|_| format!("-p: invalid host address in '{v}'"))?;
        let rest = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| format!("-p: invalid port publish '{v}'"))?;
        (ip, rest)
    } else {
        match v.matches(':').count() {
            0 => (std::net::Ipv4Addr::UNSPECIFIED.into(), v),
            1 => {
                let (first, second) = v.split_once(':').expect("one colon was counted");
                match first.parse::<IpAddr>() {
                    Ok(ip) => (ip, second),
                    Err(_) => (std::net::Ipv4Addr::UNSPECIFIED.into(), v),
                }
            }
            2 => {
                let ip: IpAddr = v
                    .split(':')
                    .next()
                    .expect("two colons were counted")
                    .parse()
                    .map_err(|_| format!("-p: invalid host address in '{v}'"))?;
                (ip, &v[v.find(':').expect("two colons were counted") + 1..])
            }
            _ => return Err(
                "-p: bracket IPv6 addresses ('[::1]:HOST:CONTAINER'); use ADDRESS:HOST:CONTAINER"
                    .to_string(),
            ),
        }
    };

    let (host, container) = match rest.split_once(':') {
        Some((host, container)) => (parse_port(host)?, parse_port(container)?),
        None => {
            let host = parse_port(rest)?;
            (host, host)
        }
    };
    Ok(network::PublishedPort {
        host_ip,
        host,
        container,
        protocol,
    })
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
    if a.no_overlay && a.tmpfs_upper {
        eprintln!("zerun run: --tmpfs-upper requires the writable overlay; remove --no-overlay");
        return 2;
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
    let (rootfs, env, cwd, user, argv, labels) = if let Some(rootfs_str) = &a.rootfs {
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
        (rootfs, None, None, None, argv, a.labels.clone())
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
                let mut labels = cfg.config.labels.clone();
                labels.extend(a.labels.clone());
                let cwd = if cfg.config.working_dir.is_empty() {
                    None
                } else {
                    Some(cfg.config.working_dir.clone())
                };
                let rootless = unsafe { libc::geteuid() } != 0;
                let image_user = if cfg.config.user.is_empty() {
                    None
                } else {
                    Some(cfg.config.user.as_str())
                };
                let (user, user_warning) =
                    resolve_image_user(a.user.as_deref(), image_user, rootless);
                if let Some(w) = &user_warning {
                    eprintln!("{w}");
                }
                (rootfs, Some(env), cwd, user, argv, labels)
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
        match store.prepare_container_fs(&id, &rootfs, a.tmpfs_upper) {
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
                tmpfs_upper: fs.tmpfs_upper,
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
            memory_reservation: a.memory_reservation,
            memory_swap: a.memory_swap,
            cpus: a.cpus,
            cpuset_cpus: a.cpuset_cpus,
            cpuset_mems: a.cpuset_mems,
            pids: a.pids,
            oom_group: a.oom_group,
            io: [
                a.device_read_bps,
                a.device_write_bps,
                a.device_read_iops,
                a.device_write_iops,
            ]
            .concat(),
        },
        seccomp: a.seccomp,
        tty: a.tty,
        interactive: a.interactive,
        overlay,
        id,
        env,
        cwd,
        user,
        ports: a.ports,
        volumes: a.volumes,
        readonly: a.readonly,
        tmpfs: a.tmpfs,
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
                labels,
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
    labels: BTreeMap<String, String>,
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
        port_protocols: if spec.ports.is_empty() {
            None
        } else {
            Some(
                spec.ports
                    .iter()
                    .map(|p| p.protocol.label().to_string())
                    .collect(),
            )
        },
        port_ips: if spec.ports.is_empty() {
            None
        } else {
            Some(spec.ports.iter().map(|p| p.host_ip.to_string()).collect())
        },
        ip: None,
        cmd: spec.argv.clone(),
        env,
        cwd: spec.cwd.clone(),
        user: spec.user.clone(),
        labels: info.labels,
        log: log_path.display().to_string(),
        rootfs: state_rootfs.to_string(),
        overlay: container_fs
            .as_ref()
            .map(|fs| fs.dir().display().to_string()),
        tmpfs_upper: container_fs.as_ref().is_some_and(|fs| fs.tmpfs_upper),
        launch_args: Some(info.launch_args),
        table: None,
        veth: None,
        cgroup: None,
        metrics: None,
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
    if let Some(v) = &a.memory_reservation {
        args.extend(["--memory-reservation".to_string(), v.clone()]);
    }
    if let Some(v) = a.memory_swap {
        let value = if v < 0 {
            "-1".to_string()
        } else {
            v.to_string()
        };
        args.extend(["--memory-swap".to_string(), value]);
    }
    if let Some(v) = a.cpus {
        args.extend(["--cpus".to_string(), v.to_string()]);
    }
    if let Some(v) = &a.cpuset_cpus {
        args.extend(["--cpuset-cpus".to_string(), v.clone()]);
    }
    if let Some(v) = &a.cpuset_mems {
        args.extend(["--cpuset-mems".to_string(), v.clone()]);
    }
    if let Some(v) = a.pids {
        args.extend(["--pids".to_string(), v.to_string()]);
    }
    if a.oom_group {
        args.push("--oom-group".to_string());
    }
    for v in &a.device_read_bps {
        if let Some(limit) = v.read_bps {
            args.extend([
                "--device-read-bps".to_string(),
                format!("{}:{}", v.device, limit),
            ]);
        }
    }
    for v in &a.device_write_bps {
        if let Some(limit) = v.write_bps {
            args.extend([
                "--device-write-bps".to_string(),
                format!("{}:{}", v.device, limit),
            ]);
        }
    }
    for v in &a.device_read_iops {
        if let Some(limit) = v.read_iops {
            args.extend([
                "--device-read-iops".to_string(),
                format!("{}:{}", v.device, limit),
            ]);
        }
    }
    for v in &a.device_write_iops {
        if let Some(limit) = v.write_iops {
            args.extend([
                "--device-write-iops".to_string(),
                format!("{}:{}", v.device, limit),
            ]);
        }
    }
    if let Some(v) = &a.hostname {
        args.extend(["--hostname".to_string(), v.clone()]);
    }
    if let Some(v) = &a.user {
        args.extend(["--user".to_string(), v.clone()]);
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
    if a.tmpfs_upper {
        args.push("--tmpfs-upper".to_string());
    }
    if a.readonly {
        args.push("--read-only".to_string());
    }
    for t in &a.tmpfs {
        args.extend(["--tmpfs".to_string(), t.raw.clone()]);
    }
    if let Some(v) = &a.platform {
        args.extend(["--platform".to_string(), v.clone()]);
    }
    for v in &a.env {
        args.extend(["--env".to_string(), v.clone()]);
    }
    for p in &a.ports {
        let base = format!(
            "{}:{}:{}",
            network::host_ip_label(p.host_ip),
            p.host,
            p.container
        );
        let publish = match p.protocol {
            network::PortProtocol::Tcp => base,
            network::PortProtocol::Udp => format!("{base}/udp"),
        };
        args.extend(["--publish".to_string(), publish]);
    }
    for v in &a.volumes {
        let mode = if v.readonly { "ro" } else { "rw" };
        args.extend([
            "--volume".to_string(),
            format!("{}:{}:{}", v.source.display(), v.target.display(), mode),
        ]);
    }
    for v in &a.dns {
        args.extend(["--dns".to_string(), v.clone()]);
    }
    for (k, v) in &a.labels {
        args.extend(["--label".to_string(), format!("{k}={v}")]);
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

    if st.tmpfs_upper {
        eprintln!(
            "zerun commit: a --tmpfs-upper container has no persisted writable layer to commit"
        );
        return 1;
    }
    if st.status == state::Status::Running {
        eprintln!("zerun: warning: committing a running container; filesystem changes in progress may be inconsistent");
    }

    // A live container's overlay is mounted inside its own mount namespace; the
    // host only sees the empty mount-point directory. Archive the live root via
    // /proc/<pid>/root instead. After exit that mount is gone, so reconstruct
    // the rootfs from the image lower layer plus the persisted overlay upper.
    let mut rebuilt: Option<std::path::PathBuf> = None;
    let rootfs = if matches!(st.status, state::Status::Running) {
        match st.pid.filter(|p| *p > 0 && st.pid_alive()) {
            Some(pid) => {
                let live = std::path::PathBuf::from(format!("/proc/{pid}/root"));
                if !live.is_dir() {
                    eprintln!(
                        "zerun commit: cannot read container {} root at {}",
                        display_name(&st),
                        live.display()
                    );
                    return 1;
                }
                live
            }
            None => {
                eprintln!(
                    "zerun commit: container {} is recorded as running but has no live PID",
                    display_name(&st)
                );
                return 1;
            }
        }
    } else {
        match st.overlay.as_deref() {
            Some(overlay) => {
                let upper = std::path::Path::new(overlay).join("upper");
                let staging = imgstore.blob_tmp("commit-source");
                match lower_rootfs(&store, &st) {
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
            None => std::path::PathBuf::from(&st.rootfs),
        }
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
        user: st.user.clone(),
        labels: st.labels.clone(),
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
/// Decide the container user for image mode. An explicit `--user` always wins;
/// otherwise the image `config.User` applies. Rootless user namespaces map only
/// uid/gid 0 (the host user), so an image user that is not trivially root
/// cannot be honored there: warn and degrade to root (the behavior before
/// `--user` existed) instead of failing a run the operator never constrained.
fn resolve_image_user(
    explicit: Option<&str>,
    image: Option<&str>,
    rootless: bool,
) -> (Option<String>, Option<String>) {
    let Some(user) = explicit
        .map(str::to_string)
        .or_else(|| image.map(str::to_string))
    else {
        return (None, None);
    };
    if rootless && explicit.is_none() && !user_is_mappable_rootless(&user) {
        (
            None,
            Some(format!(
                "zerun: warning: image user '{user}' is not mappable rootless (only uid 0 is); running as uid 0"
            )),
        )
    } else {
        (Some(user), None)
    }
}

/// True when a user spec can be satisfied by a rootless user namespace, which
/// maps only uid/gid 0 (the host user). Names other than "root" are assumed
/// unmappable — resolving them needs the container /etc/passwd.
fn user_is_mappable_rootless(spec: &str) -> bool {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let root_user = user == "0" || user == "root";
    let root_group = group.is_none_or(|g| g == "0" || g == "root");
    root_user && root_group
}

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

fn parse_label(raw: &str) -> Result<(String, String), String> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(format!("invalid --label '{raw}' (expected KEY=VALUE)"));
    };
    if key.is_empty() {
        return Err(format!("invalid --label '{raw}' (empty KEY)"));
    }
    Ok((key.to_string(), value.to_string()))
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

fn cmd_login(args: &[String]) -> i32 {
    let mut registry = "docker.io".to_string();
    let mut username: Option<String> = None;
    let mut password_stdin = false;
    let mut positional = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--username" => match next_value(args, &mut i, "--username") {
                Ok(v) => username = Some(v),
                Err(e) => {
                    eprintln!("zerun login: {e}");
                    return 2;
                }
            },
            "--username=" => {
                username = Some(args[i]["--username=".len()..].to_string());
                i += 1;
            }
            other if other.starts_with("--username=") => {
                username = Some(other["--username=".len()..].to_string());
                i += 1;
            }
            "--password-stdin" => {
                password_stdin = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!("usage: zerun login [REGISTRY] [-u USERNAME] [--password-stdin]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun login: unknown option {other}");
                return 2;
            }
            _ => {
                positional += 1;
                if positional > 1 {
                    eprintln!("zerun login: only one REGISTRY may be given");
                    return 2;
                }
                registry = args[i].clone();
                i += 1;
            }
        }
    }

    let registry = match normalize_registry(&registry) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun login: {e}");
            return 2;
        }
    };
    let username = match prompt::username(username) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("zerun login: {e}");
            return 1;
        }
    };
    let password = if password_stdin {
        prompt::password_from_stdin()
    } else {
        prompt::password_interactive()
    };
    let password = match password {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zerun login: {e}");
            return 1;
        }
    };
    let credential = Credential { username, password };
    let mut client = RegistryClient::new();
    if let Err(e) = client.verify_login(&registry, &credential) {
        eprintln!("zerun login: {e}");
        return 1;
    }
    let store = match CredentialStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun login: {e}");
            return 1;
        }
    };
    if let Err(e) = store.set(&registry, &credential) {
        eprintln!("zerun login: {e}");
        return 1;
    }
    println!("Login Succeeded for {registry}");
    0
}

fn cmd_logout(args: &[String]) -> i32 {
    let mut registry = "docker.io".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("usage: zerun logout [REGISTRY]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun logout: unknown option {other}");
                return 2;
            }
            _ => {
                if i > 0 {
                    eprintln!("zerun logout: only one REGISTRY may be given");
                    return 2;
                }
                registry = args[i].clone();
                i += 1;
            }
        }
    }
    let registry = match normalize_registry(&registry) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun logout: {e}");
            return 2;
        }
    };
    let store = match CredentialStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun logout: {e}");
            return 1;
        }
    };
    match store.remove(&registry) {
        Ok(true) => {
            println!("Removing login for {registry}");
            0
        }
        Ok(false) => {
            eprintln!("zerun logout: not logged in to {registry}");
            1
        }
        Err(e) => {
            eprintln!("zerun logout: {e}");
            1
        }
    }
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

fn cmd_tag(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: zerun tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]");
        return 0;
    }
    if args.len() != 2 {
        eprintln!("zerun tag: SOURCE_IMAGE and TARGET_IMAGE are required");
        return 2;
    }
    let source = match Reference::parse(&args[0]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun tag: invalid source '{}': {e}", args[0]);
            return 2;
        }
    };
    let target = match Reference::parse(&args[1]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun tag: invalid target '{}': {e}", args[1]);
            return 2;
        }
    };
    if target.digest.is_some() {
        eprintln!(
            "zerun tag: target '{}' must be REPOSITORY[:TAG], not a digest reference",
            args[1]
        );
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
    let source_name = format!("{}/{}", source.registry, source.repository);
    let target_name = format!("{}/{}", target.registry, target.repository);
    match imgstore.tag_record(
        &source_name,
        source.tag.as_deref(),
        source.digest.as_deref(),
        &target_name,
        target.tag.as_deref(),
    ) {
        Ok(record) => {
            println!("{} -> {}", record.manifest, target.canonical());
            0
        }
        Err(e) => {
            eprintln!("zerun tag: {e}");
            1
        }
    }
}

fn cmd_push(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: zerun push IMAGE[:TAG]");
        return 0;
    }
    if args.len() != 1 {
        eprintln!("zerun push: exactly one IMAGE[:TAG] is required");
        return 2;
    }
    let raw = &args[0];
    let reference = match Reference::parse(raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun push: invalid reference '{raw}': {e}");
            return 2;
        }
    };
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
    let mut client = RegistryClient::new();
    println!("{}: pushing...", reference.canonical());
    match image::push::push_image(&imgstore, &mut client, &reference) {
        Ok(image) => {
            println!("{}: digest: {}", reference.canonical(), image.digest);
            0
        }
        Err(e) => {
            eprintln!("zerun push: {}: {e}", reference.canonical());
            1
        }
    }
}

fn cmd_save(args: &[String]) -> i32 {
    let mut output: Option<PathBuf> = None;
    let mut images = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => match next_value(args, &mut i, "-o") {
                Ok(v) => output = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("zerun save: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun save -o FILE.tar IMAGE[:TAG]...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun save: unknown option {other}");
                return 2;
            }
            _ => {
                images.push(args[i].clone());
                i += 1;
            }
        }
    }
    let output = match output {
        Some(p) => p,
        None => {
            eprintln!("zerun save: -o FILE.tar is required");
            return 2;
        }
    };
    if images.is_empty() {
        eprintln!("zerun save: at least one IMAGE is required");
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
    match image::archive::save_images(&imgstore, &images, &output) {
        Ok(records) => {
            println!("Saved {} image(s) to {}", records.len(), output.display());
            for r in &records {
                let tag = r.tag.as_deref().unwrap_or("<none>");
                println!("  {}:{} {}", r.name, tag, r.manifest);
            }
            0
        }
        Err(e) => {
            eprintln!("zerun save: {e}");
            1
        }
    }
}

fn cmd_load(args: &[String]) -> i32 {
    let mut input: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--input" => match next_value(args, &mut i, "-i") {
                Ok(v) => input = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("zerun load: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun load -i FILE.tar");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun load: unknown option {other}");
                return 2;
            }
            other => {
                eprintln!("zerun load: unexpected argument '{other}'");
                return 2;
            }
        }
    }
    let input = match input {
        Some(p) => p,
        None => {
            eprintln!("zerun load: -i FILE.tar is required");
            return 2;
        }
    };
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
    match image::archive::load_archive(&imgstore, &input) {
        Ok(records) => {
            println!("Loaded image(s) from {}", input.display());
            for r in &records {
                let tag = r.tag.as_deref().unwrap_or("<none>");
                println!("  {}:{} {}", r.name, tag, r.manifest);
            }
            0
        }
        Err(e) => {
            eprintln!("zerun load: {e}");
            1
        }
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
    let mut quiet = false;
    let mut format = "table";
    let mut filter = PsFilter::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-a" | "--all" => {
                all = true;
                i += 1;
            }
            "-f" | "--filter" => {
                let value = match next_value(args, &mut i, "--filter") {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("zerun ps: {e}");
                        return 2;
                    }
                };
                let Some((key, value)) = value.split_once('=') else {
                    eprintln!("zerun ps: invalid --filter '{value}' (expected KEY=VALUE)");
                    return 2;
                };
                if let Err(e) = filter.set(key, value) {
                    eprintln!("zerun ps: {e}");
                    return 2;
                }
            }
            "-q" | "--quiet" => {
                quiet = true;
                i += 1;
            }
            "--format" => {
                let value = match next_value(args, &mut i, "--format") {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("zerun ps: {e}");
                        return 2;
                    }
                };
                format = match value.as_str() {
                    "table" => "table",
                    "json" => "json",
                    other => {
                        eprintln!("zerun ps: invalid --format '{other}' (expected table or json)");
                        return 2;
                    }
                };
            }
            "-h" | "--help" => {
                println!(
                    "usage: zerun ps [-a] [-q] [--format table|json] [-f|--filter KEY=VALUE]..."
                );
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
    if quiet && format != "table" {
        eprintln!("zerun ps: --quiet cannot be combined with --format");
        return 2;
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut json: Vec<ContainerState> = Vec::new();
    for mut st in state::list(&store) {
        // Crash reconcile: a record that says Running for a dead PID belongs
        // to a reaper that never got to clean up; mark it exited and reclaim
        // its host-side resources (nft table, veth, cgroup, IPAM, overlay).
        if lifecycle::reconcile_stale(&store, &mut st) {
            let _ = st.save();
        }
        if !all && !filter.widens_status() && st.status != state::Status::Running {
            continue;
        }
        if !filter.matches(&st) {
            continue;
        }
        if quiet {
            println!("{}", st.id);
        } else if format == "json" {
            json.push(st.clone());
        } else {
            rows.push(ps_row(&st));
        }
    }
    if format == "json" {
        match serde_json::to_string_pretty(&json) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("zerun ps: render JSON: {e}");
                return 1;
            }
        }
        return 0;
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
        ports_label(
            &st.ports,
            st.port_ips.as_deref(),
            st.port_protocols.as_deref(),
        ),
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

fn ports_label(
    ports: &[(u16, u16)],
    ips: Option<&[String]>,
    protocols: Option<&[String]>,
) -> String {
    ports
        .iter()
        .enumerate()
        .map(|(i, (h, c))| {
            let ip = ips
                .and_then(|values| values.get(i))
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
            let protocol = protocols
                .and_then(|values| values.get(i).map(String::as_str))
                .unwrap_or("tcp");
            format!("{}:{h}->{c}/{protocol}", network::host_ip_label(ip))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn cmd_wait(args: &[String]) -> i32 {
    let mut targets: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun wait CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun wait: unknown option {other}");
                return 2;
            }
            _ => targets.push(a.clone()),
        }
    }
    if targets.is_empty() {
        eprintln!("zerun wait: at least one CONTAINER is required");
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
        match wait_one(&store, &target) {
            Ok(code) => {
                println!("{code}");
                if code != 0 {
                    failed = true;
                }
            }
            Err(e) => {
                eprintln!("zerun wait: {e}");
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

/// Block until a detached container's final state is visible. This is most
/// useful for containers that retain their state after exit (`--rm` records
/// are intentionally removed as soon as the reaper persists their exit).
fn wait_one(store: &Store, target: &str) -> Result<i32, String> {
    let st = state::resolve(store, target)?;
    let name = display_name(&st);
    let id = st.id.clone();
    if st.status == state::Status::Created {
        return Err(format!("container {name} was created but never started"));
    }
    loop {
        let Some(mut st) = state::ContainerState::load(store, &id) else {
            return Err(format!(
                "container {name} state disappeared before its exit code was recorded (is it --rm?)"
            ));
        };
        if st.status == state::Status::Exited {
            return Ok(st.exit_code.unwrap_or(-1));
        }
        if st.status == state::Status::Running && !st.pid_alive() {
            if lifecycle::reconcile_stale(store, &mut st) {
                let _ = st.save();
            }
            if st.status == state::Status::Exited {
                return Ok(st.exit_code.unwrap_or(-1));
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
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

fn cmd_kill(args: &[String]) -> i32 {
    let mut signal: libc::c_int = libc::SIGKILL;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-s" | "--signal" => match next_value(args, &mut i, a) {
                Ok(v) => match signal_number(&v) {
                    Some(sig) => signal = sig,
                    None => {
                        eprintln!("zerun kill: invalid signal '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun kill: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun kill [--signal SIGNAL] CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun kill: unknown option {other}");
                return 2;
            }
            _ => {
                targets.push(args[i].clone());
                i += 1;
            }
        }
    }
    if targets.is_empty() {
        eprintln!("zerun kill: at least one CONTAINER is required");
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
        match kill_one(&store, &target, signal) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun kill: {e}");
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

/// Accept Docker's signal names (with or without the `SIG` prefix) and numeric
/// Linux signal numbers. Signal 0 is deliberately not exposed because `kill`
/// is a lifecycle command, not a PID liveness probe.
fn signal_number(input: &str) -> Option<libc::c_int> {
    if let Ok(value) = input.parse::<libc::c_int>() {
        return (1..=64).contains(&value).then_some(value);
    }
    let upper = input.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let name = name.strip_prefix('-').unwrap_or(name);
    let signal = match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "TRAP" => libc::SIGTRAP,
        "ABRT" => libc::SIGABRT,
        "BUS" => libc::SIGBUS,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "SEGV" => libc::SIGSEGV,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "STKFLT" => libc::SIGSTKFLT,
        "CHLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "TTIN" => libc::SIGTTIN,
        "TTOU" => libc::SIGTTOU,
        "URG" => libc::SIGURG,
        "XCPU" => libc::SIGXCPU,
        "XFSZ" => libc::SIGXFSZ,
        "VTALRM" => libc::SIGVTALRM,
        "PROF" => libc::SIGPROF,
        "WINCH" => libc::SIGWINCH,
        "IO" => libc::SIGIO,
        "PWR" => libc::SIGPWR,
        "SYS" => libc::SIGSYS,
        _ => return None,
    };
    Some(signal)
}

/// Send one signal to a detached container's PID 1. Unlike `stop`, this does
/// not impose a grace period; if the signal terminates the container, wait
/// briefly for the reaper to persist its final state.
fn kill_one(store: &Store, target: &str, signal: libc::c_int) -> Result<String, String> {
    let mut st = state::resolve(store, target)?;
    let name = display_name(&st);
    match st.status {
        state::Status::Exited | state::Status::Created => return Ok(name),
        state::Status::Running => {}
    }
    if !st.pid_alive() {
        if lifecycle::reconcile_stale(store, &mut st) {
            let _ = st.save();
        }
        return Ok(name);
    }
    let pid = st
        .pid
        .ok_or_else(|| format!("container {} has no PID", st.id))?;
    let rc = unsafe { libc::kill(pid, signal) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("signal container {name}: {e}"));
    }
    // Give a terminating signal a brief chance to take effect, without making
    // control signals such as STOP/CONT feel like `stop`.
    if wait_pid_gone(pid, Duration::from_millis(500)) {
        lifecycle::settle_exit(store, &st.id);
    }
    Ok(name)
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

/// `zerun system` — top-level system diagnostics. Currently only `df`.
fn cmd_system(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("df") => cmd_system_df(&args[1..]),
        Some("-h" | "--help") | None => {
            println!("usage: zerun system df");
            0
        }
        Some(other) => {
            eprintln!("zerun system: unknown subcommand '{other}'");
            println!("usage: zerun system df");
            2
        }
    }
}

/// `zerun system df` — summarize disk held by the image store and detached
/// container records. Image usage is the real content-addressed blob and
/// materialized-rootfs size. Container usage includes persisted state/log and
/// any retained overlay; stopped records are considered reclaimable.
fn cmd_system_df(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: zerun system df");
        return 0;
    }
    if !args.is_empty() {
        eprintln!("zerun system df: no options or arguments are accepted");
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
            eprintln!("zerun system df: {e}");
            return 1;
        }
    };
    let image_records = match imgstore.records() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun system df: {e}");
            return 1;
        }
    };
    let image_bytes = fsutil::dir_size(&store.data_root().join("blobs"))
        + fsutil::dir_size(&store.data_root().join("rootfs"));

    let mut containers = 0;
    let mut container_bytes = 0;
    let mut reclaimable_bytes = 0;
    for mut st in state::list(&store) {
        if lifecycle::reconcile_stale(&store, &mut st) {
            let _ = st.save();
        }
        let state_dir = state::ContainerState::dir(&store, &st.id);
        let overlay_bytes = st
            .overlay
            .as_deref()
            .map(|dir| fsutil::dir_size(Path::new(dir)))
            .unwrap_or(0);
        let bytes = fsutil::dir_size(&state_dir) + overlay_bytes;
        containers += 1;
        container_bytes += bytes;
        if st.status != state::Status::Running {
            reclaimable_bytes += bytes;
        }
    }

    println!(
        "{:<12} {:>7} {:>14} {:>14}",
        "TYPE", "COUNT", "DISK USAGE", "RECLAIMABLE"
    );
    println!(
        "{:<12} {:>7} {:>14} {:>14}",
        "Images",
        image_records.len(),
        fsutil::human_size(image_bytes),
        "0 B"
    );
    println!(
        "{:<12} {:>7} {:>14} {:>14}",
        "Containers",
        containers,
        fsutil::human_size(container_bytes),
        fsutil::human_size(reclaimable_bytes)
    );
    0
}

/// `zerun prune` — remove every retained exited container. Stale Running
/// records are reconciled first, so this is also the bulk crash-recovery path.
/// Live containers are deliberately never touched.
fn cmd_prune(args: &[String]) -> i32 {
    let mut force = false;
    for a in args {
        match a.as_str() {
            "-f" | "--force" => force = true,
            "-h" | "--help" => {
                println!("usage: zerun prune [-f|--force]");
                return 0;
            }
            other => {
                eprintln!(
                    "zerun prune: unknown option {other}; no positional arguments are accepted"
                );
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

    // Reconcile before selection so a dead reaper's Running record is treated
    // like the Exited record it logically represents.
    let states = state::list(&store);
    let mut targets = Vec::new();
    for mut st in states {
        if st.status == state::Status::Running
            && !st.pid_alive()
            && lifecycle::reconcile_stale(&store, &mut st)
        {
            let _ = st.save();
        }
        if st.status == state::Status::Exited {
            targets.push((st.id.clone(), display_name(&st)));
        }
    }
    if targets.is_empty() {
        println!("No exited containers to prune");
        return 0;
    }

    let prompt = format!(
        "Remove {} exited container(s)? This deletes their writable layers. [y/N] ",
        targets.len()
    );
    match prompt::confirm(&prompt, force) {
        Ok(true) => {}
        Ok(false) => return 0,
        Err(e) => {
            eprintln!("zerun prune: {e}");
            return 2;
        }
    }

    println!("Deleted Containers:");
    let mut removed = 0;
    let mut failed = false;
    for (id, label) in targets {
        match rm_one(&store, &id, true) {
            Ok(_) => {
                println!("{label}");
                removed += 1;
            }
            Err(e) => {
                eprintln!("zerun prune: {e}");
                failed = true;
            }
        }
    }
    println!("Total removed containers: {removed}");
    if failed {
        1
    } else {
        0
    }
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
    let mut since = None;
    let mut until = None;
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
            "--since" | "--until" => {
                let is_since = a == "--since";
                match next_value(args, &mut i, a) {
                    Ok(v) => {
                        if is_since {
                            since = Some(v);
                        } else {
                            until = Some(v);
                        }
                    }
                    Err(e) => {
                        eprintln!("zerun logs: {e}");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                println!(
                    "usage: zerun logs [--tail N] [--since TIME] [--until TIME] [-f] [-t] CONTAINER"
                );
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
    let filter = match LogTimeFilter::parse(since.as_deref(), until.as_deref()) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("zerun logs: {e}");
            return 2;
        }
    };
    // Tail selects raw log lines first, then time bounds narrow that window.
    // This keeps `--tail 0` cheap and makes both options independently useful.
    let shown = tail_bytes(&bytes, tail.unwrap_or(usize::MAX));
    // Follow resumes at the raw byte consumed by this snapshot. Filtered
    // output can be shorter than that tail when old lines are omitted.
    let followed_from = shown.len() as u64;
    let shown = logs::filter_log_lines(shown, Some(&filter));
    write_log_output(&shown, timestamps);
    // A fixed --until is an end boundary: future times still follow until the
    // wall clock reaches them; a past time only shows the historical window.
    if follow {
        follow_log(&store, &st, &path, followed_from, timestamps, Some(&filter));
    }
    0
}

/// Print data appended to `console.log` until the container exits.
fn follow_log(
    store: &Store,
    st: &ContainerState,
    path: &Path,
    mut pos: u64,
    timestamps: bool,
    filter: Option<&LogTimeFilter>,
) {
    loop {
        if filter.is_some_and(LogTimeFilter::until_reached) {
            break;
        }
        if !container_observable(store, st) {
            drain_log(path, pos, timestamps, filter);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        pos = drain_log(path, pos, timestamps, filter);
    }
}

fn drain_log(path: &Path, pos: u64, timestamps: bool, filter: Option<&LogTimeFilter>) -> u64 {
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
        let shown = logs::filter_log_lines(&buf, filter);
        write_log_output(&shown, timestamps);
    }
    len
}

fn container_observable(store: &Store, st: &ContainerState) -> bool {
    match state::ContainerState::load(store, &st.id) {
        Some(s) => s.status == state::Status::Running && s.pid_alive(),
        None => false, // --rm removed the record; stop following
    }
}

fn cmd_stats(args: &[String]) -> i32 {
    let mut all = false;
    let mut targets: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "-a" | "--all" => all = true,
            // Docker-compatible spelling for a single sample. This command is
            // intentionally one-shot; it never tails the control files.
            "--no-stream" => {}
            "-h" | "--help" => {
                println!("usage: zerun stats [-a] [--no-stream] [CONTAINER...]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun stats: unknown option {other}");
                return 2;
            }
            other => targets.push(other.to_string()),
        }
    }
    if !all && targets.is_empty() {
        eprintln!("zerun stats: specify at least one CONTAINER or use -a for all containers");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut states: Vec<state::ContainerState> = Vec::new();
    if all {
        for mut st in state::list(&store) {
            if lifecycle::reconcile_stale(&store, &mut st) {
                let _ = st.save();
            }
            states.push(st);
        }
    } else {
        for target in &targets {
            match state::resolve(&store, target) {
                Ok(mut st) => {
                    if lifecycle::reconcile_stale(&store, &mut st) {
                        let _ = st.save();
                    }
                    states.push(st);
                }
                Err(e) => {
                    eprintln!("zerun stats: {e}");
                    return 1;
                }
            }
        }
    }

    let headers = [
        "NAME".to_string(),
        "CPU TIME".to_string(),
        "MEM USAGE".to_string(),
        "MEM PEAK".to_string(),
        "PIDS".to_string(),
        "BLOCK I/O".to_string(),
    ];
    let rows: Vec<Vec<String>> = states
        .iter()
        .map(|st| {
            let metrics = if st.status == state::Status::Running {
                st.cgroup
                    .as_deref()
                    .map(Path::new)
                    .filter(|p| p.exists())
                    .map(state::ContainerMetrics::from_cgroup_path)
                    .or(st.metrics)
            } else {
                st.metrics
            };
            stats_row(display_name(st), metrics)
        })
        .collect();
    print!("{}", render_table(&headers, &rows));
    0
}

fn stats_row(name: String, metrics: Option<state::ContainerMetrics>) -> Vec<String> {
    let m = metrics.unwrap_or_default();
    vec![
        name,
        m.cpu_usage_usec
            .map(human_duration)
            .unwrap_or_else(|| "-".into()),
        m.memory_bytes
            .map(fsutil::human_size)
            .unwrap_or_else(|| "-".into()),
        m.memory_peak_bytes
            .map(fsutil::human_size)
            .unwrap_or_else(|| "-".into()),
        m.pids.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        match (m.io_read_bytes, m.io_write_bytes) {
            (Some(read), Some(write)) => format!(
                "{} / {}",
                fsutil::human_size(read),
                fsutil::human_size(write)
            ),
            (None, Some(write)) => format!("- / {}", fsutil::human_size(write)),
            (Some(read), None) => format!("{} / -", fsutil::human_size(read)),
            (None, None) => "-".to_string(),
        },
    ]
}

/// Render cumulative microseconds compactly for CLI tables.
fn human_duration(usec: u64) -> String {
    let secs_f = usec as f64 / 1_000_000.0;
    if secs_f < 1.0 {
        format!("{usec}us")
    } else if secs_f < 60.0 {
        format!("{secs_f:.2}s")
    } else {
        let mins = (secs_f / 60.0).floor() as u64;
        let secs = secs_f - mins as f64 * 60.0;
        format!("{mins}m{secs:04.1}s")
    }
}

/// `zerun update [opts] CONTAINER` — change cgroup v2 limits of a running
/// container in place (memory, CPU, cpuset, pids, oom-group).
///
/// The container must have been started with at least one resource flag so
/// its cgroup exists; otherwise there is nothing to update and `restart`
/// with the desired flags is the safe path. I/O ceilings are not yet
/// updatable (io.max merges device state), and `restart` reverts to the
/// launch-time limits captured in `launch_args`.
fn cmd_update(args: &[String]) -> i32 {
    let mut limits = cgroup::ResourceLimits::default();
    let mut targets: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => {
                println!(
                    "usage: zerun update [--memory SIZE] [--memory-reservation SIZE] \
                     [--memory-swap SIZE] [--cpuset-cpus LIST] [--cpuset-mems LIST] \
                     [--pids N] \
                     [--oom-group] CONTAINER"
                );
                return 0;
            }
            "-m" | "--memory" => match next_value(args, &mut i, a) {
                Ok(v) => {
                    limits.memory = Some(v);
                    continue;
                }
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--memory-reservation" => match next_value(args, &mut i, a) {
                Ok(v) => {
                    limits.memory_reservation = Some(v);
                    continue;
                }
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--memory-swap" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_memory_swap(&v) {
                    Ok(swap) => {
                        limits.memory_swap = Some(swap);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --memory-swap '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--cpus" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<f64>() {
                    Ok(c) if c > 0.0 => {
                        limits.cpus = Some(c);
                        continue;
                    }
                    _ => {
                        eprintln!("zerun update: --cpus expects a positive number, got '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--cpuset-cpus" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_cpuset(&v) {
                    Ok(list) => {
                        limits.cpuset_cpus = Some(list);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --cpuset-cpus '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--cpuset-mems" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_cpuset(&v) {
                    Ok(list) => {
                        limits.cpuset_mems = Some(list);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --cpuset-mems '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--pids" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<i64>() {
                    Ok(p) if p > 0 => {
                        limits.pids = Some(p);
                        continue;
                    }
                    _ => {
                        eprintln!("zerun update: --pids expects a positive integer, got '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--oom-group" => {
                limits.oom_group = true;
                i += 1;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun update: unknown option {other}");
                return 2;
            }
            other => {
                targets.push(other);
                i += 1;
            }
        }
    }
    if targets.len() != 1 {
        eprintln!("usage: zerun update [opts] CONTAINER");
        return 2;
    }
    if limits.memory.is_none()
        && limits.memory_reservation.is_none()
        && limits.memory_swap.is_none()
        && limits.cpus.is_none()
        && limits.cpuset_cpus.is_none()
        && limits.cpuset_mems.is_none()
        && limits.pids.is_none()
        && !limits.oom_group
    {
        eprintln!("zerun update: provide at least one limit to change");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun update: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!(
            "zerun update: container {} is not running",
            display_name(&st)
        );
        return 1;
    }
    let Some(cgroup_path) = st.cgroup.clone() else {
        eprintln!(
            "zerun update: container {} has no cgroup (started without resource limits); \
             restart it with the desired flags instead",
            display_name(&st)
        );
        return 1;
    };
    let cg = match cgroup::CgroupV2::open(Path::new(&cgroup_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zerun update: {e}");
            return 1;
        }
    };
    // The parent zerun cgroup is required by the io controller check inside
    // apply; recompute it from the cgroup v2 root.
    let parent = match cgroup::detect_cgroup2_root() {
        Ok(root) => root.join("zerun"),
        Err(e) => {
            eprintln!("zerun update: {e}");
            return 1;
        }
    };
    if let Err(e) = cg.apply_limits(&parent, &limits) {
        eprintln!("zerun update: {e}");
        return 1;
    }
    0
}

/// `zerun inspect CONTAINER...` — dump state records as pretty JSON.
///
/// The output is the raw on-disk `state.json` (plus crash reconciliation),
/// so scripts can rely on the persisted schema rather than a second view.
fn cmd_inspect(args: &[String]) -> i32 {
    let mut targets: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun inspect CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun inspect: unknown option {other}");
                return 2;
            }
            other => targets.push(other),
        }
    }
    if targets.is_empty() {
        eprintln!("zerun inspect: at least one CONTAINER is required");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    for target in targets {
        let mut st = match state::resolve(&store, target) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zerun inspect: {e}");
                return 1;
            }
        };
        if lifecycle::reconcile_stale(&store, &mut st) {
            let _ = st.save();
        }
        match serde_json::to_string_pretty(&st) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("zerun inspect: serialize {}: {e}", st.id);
                return 1;
            }
        }
    }
    0
}

/// `zerun port CONTAINER` — list published port mappings.
fn cmd_port(args: &[String]) -> i32 {
    let mut targets: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun port CONTAINER");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun port: unknown option {other}");
                return 2;
            }
            other => targets.push(other),
        }
    }
    if targets.len() != 1 {
        eprintln!("usage: zerun port CONTAINER");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun port: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    for (i, (host, container)) in st.ports.iter().enumerate() {
        let protocol = st
            .port_protocols
            .as_deref()
            .and_then(|v| v.get(i).map(String::as_str))
            .unwrap_or("tcp");
        let ip = st
            .port_ips
            .as_deref()
            .and_then(|values| values.get(i))
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
        println!(
            "{container}/{protocol} -> {}:{host}",
            network::host_ip_label(ip)
        );
    }
    0
}

/// `zerun rename OLD NEW` — re-point a state record at a new name.
///
/// The detached reaper load-modify-saves its own copy at start/exit, so a
/// rename racing one of those writes can be lost (the same tiny window any
/// lockless state edit has); everything else observes the new name.
fn cmd_rename(args: &[String]) -> i32 {
    let mut positional: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun rename OLD NEW");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun rename: unknown option {other}");
                return 2;
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        eprintln!("usage: zerun rename OLD NEW");
        return 2;
    }
    let (old, new) = (positional[0], positional[1]);
    if !state::valid_name(new) {
        eprintln!(
            "zerun rename: invalid container name '{new}' (allowed: [a-zA-Z0-9][a-zA-Z0-9_.-]*)"
        );
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, old) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun rename: {e}");
            return 1;
        }
    };
    if st.name.as_deref() == Some(new) {
        return 0;
    }
    if state::list(&store)
        .iter()
        .any(|other| other.id != st.id && other.name.as_deref() == Some(new))
    {
        eprintln!("zerun rename: name '{new}' is already in use");
        return 1;
    }
    st.name = Some(new.to_string());
    if let Err(e) = st.save() {
        eprintln!("zerun rename: {e}");
        return 1;
    }
    0
}

/// `zerun top CONTAINER` — host-side view of a container's processes.
///
/// PID-namespace membership is derived from /proc, so no setns and no
/// in-container helper are needed; the view matches the host's clock for
/// CPU time and never runs arbitrary code in the container.
fn cmd_top(args: &[String]) -> i32 {
    let mut positional: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun top CONTAINER");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun top: unknown option {other} (ps arguments are not supported)");
                return 2;
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 1 {
        eprintln!("usage: zerun top CONTAINER");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, positional[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun top: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!("zerun top: container {} is not running", display_name(&st));
        return 1;
    }
    let init_pid = st.pid.unwrap_or(0);
    let procs = match procinfo::list_pid_namespace(init_pid) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zerun top: {e}");
            return 1;
        }
    };
    println!(
        "{:<8} {:>7} {:>7} {:<8} {:>8} CMD",
        "UID", "PID", "PPID", "TTY", "TIME"
    );
    for p in procs {
        println!(
            "{:<8} {:>7} {:>7} {:<8} {:>8} {}",
            p.uid, p.pid, p.ppid, p.tty, p.cpu_time, p.cmd
        );
    }
    0
}

/// One endpoint of `zerun cp`: a host path or `CONTAINER:PATH`.
#[derive(Debug)]
enum CpEndpoint {
    Host(PathBuf),
    Container { target: String, path: String },
}

/// Parse one `cp` endpoint. Container paths are joined under the live
/// container's `/proc/<pid>/root`, so `..` components are rejected up front
/// (path-walking `..` on that root dentry lands in the *host* overlay dir).
fn parse_cp_endpoint(arg: &str) -> Result<CpEndpoint, String> {
    let Some((target, path)) = arg.split_once(':') else {
        return Ok(CpEndpoint::Host(PathBuf::from(arg)));
    };
    if target.is_empty() || path.is_empty() {
        return Err(format!(
            "invalid endpoint '{arg}' (expected CONTAINER:PATH or a host path)"
        ));
    }
    if path.split('/').any(|c| c == "..") {
        return Err(format!("'..' is not allowed in container path '{arg}'"));
    }
    Ok(CpEndpoint::Container {
        target: target.to_string(),
        path: path.trim_start_matches('/').to_string(),
    })
}

/// `zerun cp SRC DST` — copy between the host and a running container.
///
/// The container side is addressed through `/proc/<pid>/root`, which VFS
/// resolves with the container as the root (absolute symlinks inside the
/// container stay inside it). Exited containers have no live root mount,
/// so they are rejected instead of copying from an empty merged dir.
fn cmd_cp(args: &[String]) -> i32 {
    let mut positional: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun cp SRC DST   (one side: CONTAINER:PATH)");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun cp: unknown option {other}");
                return 2;
            }
            other => positional.push(other),
        }
    }
    if positional.len() != 2 {
        eprintln!("usage: zerun cp SRC DST   (one side: CONTAINER:PATH)");
        return 2;
    }
    let (src, dst) = match (
        parse_cp_endpoint(positional[0]),
        parse_cp_endpoint(positional[1]),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("zerun cp: {e}");
            return 2;
        }
    };
    // Direction: true = host -> container.
    let host_to_container = match (&src, &dst) {
        (CpEndpoint::Host(_), CpEndpoint::Container { .. }) => true,
        (CpEndpoint::Container { .. }, CpEndpoint::Host(_)) => false,
        _ => {
            eprintln!("zerun cp: exactly one of SRC/DST must be CONTAINER:PATH");
            return 2;
        }
    };
    let (host_endpoint, container_endpoint) = if host_to_container {
        (src, dst)
    } else {
        (dst, src)
    };
    let CpEndpoint::Container { target, path } = container_endpoint else {
        unreachable!("checked direction above")
    };
    let CpEndpoint::Host(host_path) = host_endpoint else {
        unreachable!("checked direction above")
    };
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, &target) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun cp: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!(
            "zerun cp: container {} is not running (cp needs a live container root)",
            display_name(&st)
        );
        return 1;
    }
    let pid = st.pid.unwrap_or(0);
    let container_root = PathBuf::from(format!("/proc/{pid}/root"));
    let result = if host_to_container {
        // Host -> container.
        let base = container_root.join(path);
        let dst_is_dir = base.is_dir();
        let Some(name) = host_path.file_name() else {
            eprintln!("zerun cp: invalid source path '{}'", host_path.display());
            return 2;
        };
        let to = if dst_is_dir { base.join(name) } else { base };
        copy_between(&host_path, &to)
    } else {
        // Container -> host.
        let from = container_root.join(&path);
        let dst_is_dir = host_path.ends_with("/") || host_path.is_dir();
        let Some(name) = from.file_name() else {
            eprintln!("zerun cp: invalid container path '{path}'");
            return 2;
        };
        let to = if dst_is_dir {
            host_path.join(name)
        } else {
            host_path.clone()
        };
        copy_between(&from, &to)
    };
    if let Err(e) = result {
        eprintln!("zerun cp: {e}");
        return 1;
    }
    0
}

/// Copy a file, directory, or symlink, preserving modes (reuses the
/// overlay-robust `copy_dir_all` for trees).
fn copy_between(src: &Path, dst: &Path) -> crate::error::ZResult<()> {
    if let Some(parent) = dst.parent() {
        fsutil::mkdir_p(parent)?;
    }
    let meta =
        std::fs::symlink_metadata(src).map_err(|e| crate::zerr!("stat {}: {e}", src.display()))?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(src)?;
        std::os::unix::fs::symlink(&target, dst)
            .map_err(|e| crate::zerr!("symlink {} -> {}: {e}", dst.display(), target.display()))
    } else if meta.is_dir() {
        fsutil::copy_dir_all(src, dst)
    } else {
        std::fs::copy(src, dst)
            .map_err(|e| crate::zerr!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dst,
            std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777),
        )
        .map_err(|e| crate::zerr!("chmod {}: {e}", dst.display()))
    }
}

/// `zerun diff CONTAINER` — show the container's filesystem changes.
///
/// The writable OverlayFS upper is compared directly with the image's
/// materialized lower root. This works for both running and retained exited
/// containers without needing to inspect mounts inside the container.
fn cmd_diff(args: &[String]) -> i32 {
    let mut targets: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun diff CONTAINER");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun diff: unknown option {other}");
                return 2;
            }
            other => targets.push(other),
        }
    }
    let [target] = targets.as_slice() else {
        eprintln!("usage: zerun diff CONTAINER");
        return 2;
    };

    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let st = match state::resolve(&store, target) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun diff: {e}");
            return 1;
        }
    };
    if st.tmpfs_upper {
        eprintln!("zerun diff: a --tmpfs-upper container has no persisted writable layer");
        return 1;
    }
    let Some(overlay) = &st.overlay else {
        eprintln!(
            "zerun diff: container {} has no writable overlay",
            display_name(&st)
        );
        return 1;
    };
    let upper = Path::new(overlay).join("upper");
    let lower = match lower_rootfs(&store, &st) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("zerun diff: {e}");
            return 1;
        }
    };
    let changes = match containerdiff::diff_roots(&lower, &upper) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zerun diff: {e}");
            return 1;
        }
    };
    for change in changes {
        println!("{} {}", change.kind.label(), change.path.display());
    }
    0
}

/// Locate the base rootfs for a container. This intentionally shares commit's
/// semantics: image-backed containers use the materialized lower root, while
/// legacy `rootfs:` containers use their original unpacked directory.
fn lower_rootfs(store: &Store, st: &state::ContainerState) -> Result<PathBuf, String> {
    if let Some(path) = st.image.strip_prefix("rootfs:") {
        return Ok(PathBuf::from(path));
    }
    let reference = Reference::parse(&st.image).map_err(|e| e.to_string())?;
    let imgstore = image::store::ImageStore::open(store).map_err(|e| e.to_string())?;
    image::local_image(&imgstore, &reference)
        .map_err(|e| e.to_string())?
        .map(|(rootfs, _)| rootfs)
        .ok_or_else(|| {
            format!(
                "base image '{}' is missing; it is needed to diff this container",
                st.image
            )
        })
}

/// `zerun export [-o FILE] CONTAINER` — stream the live container rootfs
/// as an uncompressed tar.
///
/// The tree is read through `/proc/<pid>/root`, so the container keeps
/// running while its filesystem is exported (consistency is the caller's
/// concern, like `docker export`). Mount points inside the container
/// (/proc, /sys, /dev, tmpfs, bind volumes) are recorded as empty
/// directories: their contents belong to the kernel or the host, not to
/// the container's filesystem layer.
fn cmd_export(args: &[String]) -> i32 {
    let mut output: Option<PathBuf> = None;
    let mut targets: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => {
                println!("usage: zerun export [-o FILE] CONTAINER");
                return 0;
            }
            "-o" | "--output" => match next_value(args, &mut i, a) {
                // next_value already advanced past the value.
                Ok(v) => {
                    output = Some(PathBuf::from(v));
                    continue;
                }
                Err(e) => {
                    eprintln!("zerun export: {e}");
                    return 2;
                }
            },
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun export: unknown option {other}");
                return 2;
            }
            other => targets.push(other),
        }
        i += 1;
    }
    if targets.len() != 1 {
        eprintln!("usage: zerun export [-o FILE] CONTAINER");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun export: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!(
            "zerun export: container {} is not running (export needs a live container root)",
            display_name(&st)
        );
        return 1;
    }
    let pid = st.pid.unwrap_or(0);
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let mounts = match read_mount_points(pid) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("zerun export: read mountinfo: {e}");
            return 1;
        }
    };
    use std::io::Write as _;
    let result = if let Some(path) = output {
        std::fs::File::create(&path)
            .map_err(|e| crate::zerr!("create {}: {e}", path.display()))
            .and_then(|mut f| {
                archive_tree(&mut f, &root, &mounts)?;
                f.flush()
                    .map_err(|e| crate::zerr!("flush {}: {e}", path.display()))
            })
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        archive_tree(&mut lock, &root, &mounts)
            .and_then(|()| lock.flush().map_err(|e| crate::zerr!("flush stdout: {e}")))
    };
    if let Err(e) = result {
        eprintln!("zerun export: {e}");
        return 1;
    }
    0
}

/// Mount points below the container root, read from `/proc/<pid>/mountinfo`.
fn read_mount_points(pid: i32) -> std::io::Result<std::collections::HashSet<PathBuf>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
    Ok(parse_mount_points(&text))
}

/// Parse `/proc/<pid>/mountinfo` into mount-point paths (field 4 of each
/// line), excluding the root itself. Paths are stored relative to the
/// container root (no leading `/`) to match archive entry paths.
fn parse_mount_points(text: &str) -> std::collections::HashSet<PathBuf> {
    text.lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .map(|p| p.trim_start_matches('/'))
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Recursively append `root` to the tar, skipping recursion below mount
/// points. `mounts` holds absolute container paths such as `/proc`.
fn archive_tree<W: std::io::Write>(
    builder_out: &mut W,
    root: &Path,
    mounts: &std::collections::HashSet<PathBuf>,
) -> crate::error::ZResult<()> {
    let mut builder = tar::Builder::new(builder_out);
    builder.follow_symlinks(false);
    archive_dir(&mut builder, root, Path::new(""), mounts)?;
    builder
        .finish()
        .map_err(|e| crate::zerr!("finish export tar: {e}"))
}

/// Append one directory's entries into the archive. `rel` is the archive
/// path of `dir` ("" for the root, which is not emitted itself).
fn archive_dir<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    dir: &Path,
    rel: &Path,
    mounts: &std::collections::HashSet<PathBuf>,
) -> crate::error::ZResult<()> {
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(dir)
        .map_err(|e| crate::zerr!("read_dir {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    // Deterministic archives make diffing exports tractable.
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let dest = rel.join(&name);
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| crate::zerr!("stat {}: {e}", path.display()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(&path)?;
            let mut header = tar::Header::new_gnu();
            // A bare new_gnu header has NUL-filled numeric fields; set the
            // basics so append_link can checksum it.
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            builder
                .append_link(&mut header, &dest, &target)
                .map_err(|e| crate::zerr!("tar link {}: {e}", path.display()))?;
        } else if ft.is_dir() {
            builder
                .append_dir(&dest, &path)
                .map_err(|e| crate::zerr!("tar dir {}: {e}", path.display()))?;
            // Mount points (proc/sys/dev/tmpfs/volumes) are archived as
            // empty directories; their contents are not container data.
            if !mounts.contains(&dest) {
                archive_dir(builder, &path, &dest, mounts)?;
            }
        } else if ft.is_file() {
            builder
                .append_file(&dest, &mut std::fs::File::open(&path)?)
                .map_err(|e| crate::zerr!("tar file {}: {e}", path.display()))?;
        } else {
            // Char/block/fifo devices keep their metadata but no data.
            let mut header = tar::Header::new_gnu();
            header.set_metadata(&meta);
            header.set_size(0);
            builder
                .append(&header, std::io::empty())
                .map_err(|e| crate::zerr!("tar device {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// `zerun import [-m MSG] FILE|- TARGET[:TAG]` — create a local image from
/// a rootfs tar (the inverse of `export`; plain/gzip/zstd accepted, `-`
/// reads stdin).
fn cmd_import(args: &[String]) -> i32 {
    let mut message: Option<String> = None;
    let mut author: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-m" | "--message" => match next_value(args, &mut i, arg) {
                // next_value already advanced past the value.
                Ok(v) => {
                    message = Some(v);
                    continue;
                }
                Err(e) => {
                    eprintln!("zerun import: {e}");
                    return 2;
                }
            },
            "--author" => match next_value(args, &mut i, arg) {
                Ok(v) => {
                    author = Some(v);
                    continue;
                }
                Err(e) => {
                    eprintln!("zerun import: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun import [-m MSG] FILE|- TARGET[:TAG]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun import: unknown option {other}");
                return 2;
            }
            _ => {
                positional.push(args[i].clone());
                i += 1;
            }
        }
    }
    let [file, target] = positional.as_slice() else {
        eprintln!("usage: zerun import [-m MSG] FILE|- TARGET[:TAG]");
        return 2;
    };
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
    match image::import::import_image(
        &imgstore,
        Path::new(file),
        target,
        image::import::ImportOptions {
            comment: message,
            author,
        },
    ) {
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
            eprintln!("zerun import: {e}");
            1
        }
    }
}

/// `zerun events` — stream container lifecycle events until interrupted.
///
/// Read-only polling of the persisted state records (no daemon, no inotify
/// dependency): transitions are diffed every 200 ms and anchored to the
/// states' own timestamps. The first snapshot is silent, like
/// `docker events` live mode.
fn cmd_events(args: &[String]) -> i32 {
    let mut filters: Vec<events::EventFilter> = Vec::new();
    let mut since = None;
    let mut until = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("usage: zerun events [--filter KEY=VALUE] [--since TIME] [--until TIME]");
                return 0;
            }
            "--filter" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    eprintln!("zerun events: --filter requires KEY=VALUE");
                    return 2;
                };
                let Some((key, selector)) = value.split_once('=') else {
                    eprintln!("zerun events: --filter requires KEY=VALUE");
                    return 2;
                };
                let mut filter = events::EventFilter::default();
                if let Err(e) = filter.set(key, selector) {
                    eprintln!("zerun events: {e}");
                    return 2;
                }
                filters.push(filter);
            }
            "--since" | "--until" => {
                let is_since = args[i] == "--since";
                i += 1;
                let Some(value) = args.get(i) else {
                    eprintln!("zerun events: {} requires an RFC3339 time", args[i - 1]);
                    return 2;
                };
                if is_since {
                    since = Some(value.as_str());
                } else {
                    until = Some(value.as_str());
                }
            }
            other => {
                eprintln!("zerun events: unknown option {other}");
                return 2;
            }
        }
        i += 1;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut previous = state::list(&store);
    if since.is_some() || until.is_some() {
        // Time-bounded output is deliberately replayable: reconstruct the
        // history of the current records before entering live-follow mode.
        previous = Vec::new();
    }
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let current = state::list(&store);
        for event in events::diff_events(&previous, &current) {
            let event = events::select_events(vec![event], &filters, since, until);
            let Some(event) = event.first() else {
                continue;
            };
            let _ = writeln!(out, "{}", events::format_event(event));
        }
        let _ = out.flush();
        previous = current;
    }
}

/// `zerun attach CONTAINER` — stream a detached container's live output.
///
/// Connects to the reaper's per-container unix socket and prints captured
/// output as it happens. The final control frame is runtime metadata, not
/// workload output; attach uses it to propagate the container's exit code.
/// Stdin is not forwarded in this version; use `exec` for interactive input.
fn cmd_attach(args: &[String]) -> i32 {
    let mut targets: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun attach CONTAINER");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun attach: unknown option {other}");
                return 2;
            }
            other => targets.push(other),
        }
    }
    if targets.len() != 1 {
        eprintln!("usage: zerun attach CONTAINER");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let mut st = match state::resolve(&store, targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun attach: {e}");
            return 1;
        }
    };
    if lifecycle::reconcile_stale(&store, &mut st) {
        let _ = st.save();
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!(
            "zerun attach: container {} is not running",
            display_name(&st)
        );
        return 1;
    }
    let Some(sock_path) = Path::new(&st.log)
        .parent()
        .map(|dir| dir.join("attach.sock"))
    else {
        eprintln!("zerun attach: container {} has no state directory", st.id);
        return 1;
    };
    if !sock_path.exists() {
        eprintln!(
            "zerun attach: container {} has no attach socket (older reaper or not running)",
            display_name(&st)
        );
        return 1;
    }
    let mut stream = match std::os::unix::net::UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun attach: connect {}: {e}", sock_path.display());
            return 1;
        }
    };
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        match lifecycle::read_attach_frame(&mut stream) {
            Ok(Some(chunk)) => {
                if out.write_all(&chunk).is_err() {
                    break;
                }
                let _ = out.flush();
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    // If EOF raced the control frame, fall back to the persisted state.
    match state::ContainerState::load(&store, &st.id) {
        Some(final_state) => final_state.exit_code.unwrap_or(0),
        // `--rm` removed the state; treat a clean EOF as success.
        None => 0,
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
        write_stdout(&logs::strip_log_timestamps(data));
    }
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
  zerun ps [-a] [-q] [-f KEY=VALUE]...  list filtered containers (detached)\n  \
  zerun wait CONTAINER...               block for detached containers to exit\n  \
  zerun stop [--time S] CONTAINER...    SIGTERM, then SIGKILL after the timeout\n  \
  zerun kill [--signal SIG] CONTAINER... signal detached containers (default KILL)\n  \
  zerun restart [--time S] CONTAINER... restart detached containers\n  \
  zerun rm [-f] CONTAINER...            remove stopped containers (-f: kill first)\n  \
  zerun logs [--tail N] [--since TIME] [--until TIME] [-f] [-t] CONTAINER\n  \
  zerun stats [-a] [CONTAINER...]        one-shot resource metrics\n  \
  zerun update [opts] CONTAINER          change live resource limits\n  \
  zerun inspect CONTAINER...             dump container state as JSON\n  \
  zerun port CONTAINER                   list published port mappings\n  \
  zerun rename OLD NEW                   rename a container\n  \
  zerun top CONTAINER                    list a container's processes\n  \
  zerun diff CONTAINER                   list changed, added, and deleted paths\n  \
  zerun cp SRC DST                       copy files to/from a running container\n  \
  zerun export [-o FILE] CONTAINER       export a container rootfs as tar\n  \
  zerun import [-m MSG] FILE|- TARGET    import a rootfs tar as a local image\n  \
  zerun events [--filter KEY=VALUE] [--since TIME] [--until TIME]\n  \
                                         stream/replay container lifecycle events\n  \
  zerun attach CONTAINER                 stream a detached container's output\n  \
  zerun exec [-e K=V] [-w DIR] CONTAINER CMD [ARG...]\n  \
                                        run a command in a running container\n  \
  zerun pull [--platform ...] IMAGE...   pull OCI images (Docker Hub, mirrors)\n  \
  zerun login [REGISTRY] [-u USER] [--password-stdin]\n  \
                                        log in to a private registry\n  \
  zerun logout [REGISTRY]               remove stored registry credentials\n  \
  zerun images                           list local images\n  \
  zerun rmi IMAGE...                     remove local images\n  \
  zerun system df                        summarize image/container disk usage\n  \
  zerun tag SOURCE TARGET[:TAG]          add a local tag to an image\n  \
  zerun push IMAGE[:TAG]                 push a local image to a registry\n  \
  zerun save -o FILE.tar IMAGE...        export images as an OCI archive\n  \
  zerun load -i FILE.tar                import images from an OCI archive\n  \
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
  --memory-reservation 64M    cgroup v2 memory.high soft limit\n  \
  --memory-swap 128M  total memory+swap ceiling (-1 = unlimited)\n  \
  --cpus 0.5          cgroup v2 cpu.max (cores)\n  \
  --cpuset-cpus 0-3   pin CPUs (cgroups v2 cpuset.cpus)\n  \
  --cpuset-mems 0     pin memory nodes (cgroups v2 cpuset.mems)\n  \
  --pids 256          cgroup v2 pids.max\n  \
  --oom-group         kill the whole cgroup on OOM (memory.oom.group)\n  \
  --device-read-bps DEV:BYTES    cgroup v2 io.max read rate (repeatable)\n  \
  --device-write-bps DEV:BYTES   cgroup v2 io.max write rate (repeatable)\n  \
  --device-read-iops DEV:COUNT   cgroup v2 io.max read IOPS (repeatable)\n  \
  --device-write-iops DEV:COUNT  cgroup v2 io.max write IOPS (repeatable)\n  \
  -h, --hostname H    container hostname (new UTS namespace)\n  \
  -u, --user USER[:GROUP]  run as container user (numeric or /etc/passwd name)\n  \
  --net none|host|bridge\n  \
                      none = fresh netns + loopback; host = share host net;\n  \
                      bridge = zerun0 bridge + NAT (needs CAP_NET_ADMIN;\n  \
                      rootful default; rootless default is none)\n  \
  -i, --interactive      keep stdin attached (foreground runs)\n  \
  -t, --tty              allocate a PTY (foreground runs; combine with -i)\n  \
  -p, --publish [ADDR:]HOST[:CONTAINER][/proto]\n  \
                                      publish a TCP/UDP port (requires --net bridge)\n  \
  -v, --volume HOST:CONTAINER[:ro]  bind-mount a host file or directory\n  \
  --dns IP            container DNS server (repeatable; bridge mode; defaults to the host's)\n  \
  --init              run the built-in mini-init (reap orphans + forward signals)\n  \
  --seccomp default|unconfined\n  \
  --platform os/arch[/variant]  pull/run a specific platform\n  \
  -e, --env NAME[=VALUE]  set a container environment variable (image mode)\n  \
  --no-overlay        pivot directly into the rootfs (no writable upper layer)\n  \
  --tmpfs-upper       keep the overlay writable layer in tmpfs (not committable)\n  \
  --read-only         remount the container root read-only before exec\n  \
  --tmpfs PATH[:opts]  mount an in-container tmpfs (size=/mode=/ro, repeatable)\n\
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
    fn export_archives_tree_and_skips_mounts() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-export-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root/proc/self")).unwrap();
        std::fs::create_dir_all(dir.join("root/etc/sub")).unwrap();
        std::fs::write(dir.join("root/etc/hosts"), b"content").unwrap();
        std::fs::write(dir.join("root/proc/hidden"), b"must-not-appear").unwrap();
        std::os::unix::fs::symlink("../etc/hosts", dir.join("root/etc/link")).unwrap();
        let mut mounts = std::collections::HashSet::new();
        mounts.insert(PathBuf::from("proc"));
        let mut out = Vec::new();
        archive_tree(&mut out, &dir.join("root"), &mounts).unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let mut names: Vec<(String, String)> = Vec::new(); // (name, kind)
        for entry in ar.entries().unwrap() {
            let e = entry.unwrap();
            let kind = if e.header().entry_type().is_symlink() {
                "link".to_string()
            } else if e.header().entry_type().is_dir() {
                "dir".to_string()
            } else {
                "file".to_string()
            };
            names.push((e.path().unwrap().display().to_string(), kind));
        }
        assert_eq!(
            names,
            vec![
                ("etc".to_string(), "dir".to_string()),
                ("etc/hosts".to_string(), "file".to_string()),
                ("etc/link".to_string(), "link".to_string()),
                ("etc/sub".to_string(), "dir".to_string()),
                ("proc".to_string(), "dir".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_mount_points_reads_field_four() {
        let text = "36 35 98:0 /mnt1 /proc rw - proc proc\n\
                    40 35 0:40 / /sys ro,nosuid - sysfs sysfs rw\n\
                    42 35 0:41 / / rw - overlay overlay rw\n";
        let mounts = parse_mount_points(text);
        assert!(mounts.contains(&PathBuf::from("proc")));
        assert!(mounts.contains(&PathBuf::from("sys")));
        // The root is not a skip target; everything below it is.
        assert_eq!(mounts.len(), 2);
        assert_eq!(parse_mount_points("").len(), 0);
    }

    #[test]
    fn cp_endpoint_parsing_and_safety() {
        let host = parse_cp_endpoint("/tmp/data").unwrap();
        assert!(matches!(host, CpEndpoint::Host(_)));
        let c = parse_cp_endpoint("web:/etc/hosts").unwrap();
        match c {
            CpEndpoint::Container { target, path } => {
                assert_eq!(target, "web");
                assert_eq!(path, "etc/hosts");
            }
            _ => panic!("expected container endpoint"),
        }
        // Leading slashes are container-relative; ".." never reaches the
        // /proc root join.
        let abs = parse_cp_endpoint("web:///tmp/x/../y").unwrap_err();
        assert!(abs.contains(".."));
        assert!(parse_cp_endpoint("web:").is_err());
        assert!(parse_cp_endpoint(":/tmp").is_err());
    }

    #[test]
    fn detached_launch_args_capture_resolved_options() {
        let mut a = parse_run_args(&["alpine".to_string(), "sleep".to_string(), "1".to_string()])
            .expect("valid run args");
        a.detach = true;
        a.name = Some("web".to_string());
        a.net = NetMode::Bridge;
        a.memory = Some("64M".to_string());
        a.ports.push(network::PublishedPort {
            host_ip: std::net::Ipv4Addr::UNSPECIFIED.into(),
            host: 8080,
            container: 80,
            protocol: network::PortProtocol::Tcp,
        });
        a.labels.insert("tier".to_string(), "prod".to_string());
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
                "0.0.0.0:8080:80",
                "--label",
                "tier=prod",
                "alpine",
                "--",
                "sleep",
                "1"
            ]
        );
    }

    #[test]
    fn captures_memory_swap() {
        for (raw, parsed) in [("268435456", 256 * 1024 * 1024), ("-1", -1)] {
            let args: Vec<_> = ["--memory-swap", raw, "alpine", "true"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let a = parse_run_args(&args).expect("valid memory swap");
            assert_eq!(a.memory_swap, Some(parsed));
            let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
            assert!(launch.contains(&"--memory-swap".to_string()));
            assert!(launch.contains(&raw.to_string()));
        }
        let args: Vec<_> = ["--memory-swap", "bad", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&args).is_err());
    }

    #[test]
    fn captures_memory_reservation_and_oom_group() {
        let args: Vec<_> = [
            "--memory",
            "64M",
            "--memory-reservation",
            "48M",
            "--oom-group",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("memory controls");
        assert_eq!(a.memory_reservation.as_deref(), Some("48M"));
        assert!(a.oom_group);
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch_args.contains(&"--memory-reservation".to_string()));
        assert!(launch_args.contains(&"48M".to_string()));
        assert!(launch_args.contains(&"--oom-group".to_string()));
    }

    #[test]
    fn image_user_resolution_honors_explicit_and_degrades_rootless() {
        // Explicit --user always wins (and rootless keeps the clear child error).
        let (u, w) = resolve_image_user(Some("1000:1000"), Some("101"), true);
        assert_eq!(u.as_deref(), Some("1000:1000"));
        assert!(w.is_none());
        // Rootful: image config.User applies when no flag is given.
        let (u, w) = resolve_image_user(None, Some("101"), false);
        assert_eq!(u.as_deref(), Some("101"));
        assert!(w.is_none());
        // Rootless auto image user that is not uid 0: warn and degrade to root.
        let (u, w) = resolve_image_user(None, Some("101"), true);
        assert!(u.is_none());
        assert!(w.unwrap().contains("not mappable rootless"));
        // Rootless trivial-root image users still apply (no warning).
        let (u, w) = resolve_image_user(None, Some("0"), true);
        assert_eq!(u.as_deref(), Some("0"));
        assert!(w.is_none());
        let (u, w) = resolve_image_user(None, Some("root:root"), true);
        assert_eq!(u.as_deref(), Some("root:root"));
        assert!(w.is_none());
    }

    #[test]
    fn parses_and_captures_readonly_and_tmpfs_flags() {
        let args: Vec<_> = [
            "--read-only",
            "--tmpfs",
            "/scratch:size=16m",
            "--tmpfs",
            "/run/shm:ro",
            "alpine",
            "sh",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("flags");
        assert!(a.readonly);
        assert_eq!(a.tmpfs.len(), 2);
        assert_eq!(a.tmpfs[0].data, "size=16m");
        assert!(a.tmpfs[1].readonly);
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch.contains(&"--read-only".to_string()));
        assert!(launch.contains(&"/scratch:size=16m".to_string()));
        assert!(launch.contains(&"/run/shm:ro".to_string()));
    }

    #[test]
    fn parses_and_captures_user_flag() {
        let args: Vec<_> = ["--user", "1000:1000", "alpine", "id"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("--user");
        assert_eq!(a.user.as_deref(), Some("1000:1000"));
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch_args.contains(&"--user".to_string()));
        assert!(launch_args.contains(&"1000:1000".to_string()));
    }

    #[test]
    fn parses_tcp_and_udp_publishes() {
        let args: Vec<_> = ["-p", "53:53/udp", "-p", "8080:80", "alpine", "echo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("publish flags");
        assert_eq!(
            a.ports,
            vec![
                network::PublishedPort {
                    host_ip: std::net::Ipv4Addr::UNSPECIFIED.into(),
                    host: 53,
                    container: 53,
                    protocol: network::PortProtocol::Udp,
                },
                network::PublishedPort {
                    host_ip: std::net::Ipv4Addr::UNSPECIFIED.into(),
                    host: 8080,
                    container: 80,
                    protocol: network::PortProtocol::Tcp,
                },
            ]
        );
        assert!(parse_publish("/udp").is_err());
    }

    #[test]
    fn parses_bound_publish_addresses() {
        let tcp = parse_publish("127.0.0.1:8080:80").unwrap();
        assert_eq!(tcp.host_ip, std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(tcp.host, 8080);
        assert_eq!(tcp.container, 80);

        let short_tcp = parse_publish("127.0.0.1:8080").unwrap();
        assert_eq!(short_tcp.host, 8080);
        assert_eq!(short_tcp.container, 8080);

        let udp = parse_publish("[::1]:5353:53/udp").unwrap();
        assert_eq!(
            udp.host_ip,
            std::net::IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(udp.host, 5353);
        assert_eq!(udp.container, 53);
        assert_eq!(udp.protocol, network::PortProtocol::Udp);

        assert!(parse_publish("not-an-address:8080:80").is_err());
        assert!(parse_publish("::1:8080:80").is_err());
    }

    #[test]
    fn port_labels_include_address_transport_and_default_to_tcp() {
        let ports = [(53, 53), (8080, 80)];
        let ips = Some(vec![
            "127.0.0.1".to_string(),
            std::net::Ipv6Addr::LOCALHOST.to_string(),
        ]);
        assert_eq!(
            ports_label(
                &ports,
                ips.as_deref(),
                Some(&["udp".to_string(), "tcp".to_string()])
            ),
            "127.0.0.1:53->53/udp, [::1]:8080->80/tcp"
        );
        assert_eq!(
            ports_label(&ports, None, None),
            "0.0.0.0:53->53/tcp, 0.0.0.0:8080->80/tcp"
        );
    }

    #[test]
    fn parses_and_overrides_labels() {
        let args: Vec<_> = [
            "--label",
            "tier=prod",
            "--label",
            "tier=dev",
            "--label",
            "only=",
            "alpine",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid labels");
        assert_eq!(a.labels.get("tier").map(String::as_str), Some("dev"));
        assert_eq!(a.labels.get("only").map(String::as_str), Some(""));
        assert!(parse_label("novalue").is_err());
        assert!(parse_label("=value").is_err());
    }

    #[test]
    fn parses_canonical_device_io_limits() {
        let args: Vec<_> = [
            "--device-read-bps",
            "8:48:1m",
            "--device-write-bps",
            "8:48:10mb",
            "--device-read-iops",
            "8:48:100",
            "--device-write-iops",
            "8:48:200",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("device I/O flags");
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch_args.contains(&"--device-read-bps".to_string()));
        assert!(launch_args.contains(&"8:48:1048576".to_string()));
        assert!(launch_args.contains(&"--device-write-bps".to_string()));
        assert!(launch_args.contains(&"8:48:10485760".to_string()));
        assert!(launch_args.contains(&"--device-read-iops".to_string()));
        assert!(launch_args.contains(&"8:48:100".to_string()));
        assert!(launch_args.contains(&"--device-write-iops".to_string()));
        assert!(launch_args.contains(&"8:48:200".to_string()));

        assert!(cgroup::parse_io_limit("device-read-bps", "8:48:0").is_err());
        assert!(cgroup::parse_io_limit("device-read-iops", "bad:1").is_err());
    }

    #[test]
    fn parses_and_launches_cpuset_limits() {
        let args: Vec<_> = [
            "--cpus",
            "0.5",
            "--cpuset-cpus",
            "0-3,8",
            "--cpuset-mems",
            "0",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid cpuset flags");
        assert_eq!(a.cpus, Some(0.5));
        assert_eq!(a.cpuset_cpus.as_deref(), Some("0-3,8"));
        assert_eq!(a.cpuset_mems.as_deref(), Some("0"));
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch_args.contains(&"--cpus".to_string()));
        assert!(launch_args.contains(&"0.5".to_string()));
        assert!(launch_args.contains(&"--cpuset-cpus".to_string()));
        assert!(launch_args.contains(&"0-3,8".to_string()));
        assert!(launch_args.contains(&"--cpuset-mems".to_string()));
        assert!(launch_args.contains(&"0".to_string()));
        assert!(cgroup::parse_cpuset("4-2").is_err());
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
    fn kill_signal_input_accepts_names_and_numbers() {
        assert_eq!(signal_number("KILL"), Some(libc::SIGKILL));
        assert_eq!(signal_number("sig-term"), Some(libc::SIGTERM));
        assert_eq!(signal_number("15"), Some(15));
        assert_eq!(signal_number("65"), None);
        assert_eq!(signal_number("0"), None);
        assert_eq!(signal_number("not-a-signal"), None);
    }
}
