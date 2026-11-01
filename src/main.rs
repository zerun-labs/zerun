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
mod cidfile;
mod containerdiff;
mod device_cgroup;
mod error;
mod events;
mod execc;
mod fsutil;
mod health;
mod image;
mod labels;
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
mod resolv;
mod restart;
mod rlimit;
mod seccomp;
mod security;
mod service;
mod signal;
mod state;
mod store;
mod syscalls;
mod sysctl;
mod trace;
mod units;
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
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use store::Store;

static EXPORT_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[2..]),
        Some("ps") => cmd_ps(&args[2..]),
        Some("wait") => cmd_wait(&args[2..]),
        Some("start") => cmd_start(&args[2..]),
        Some("pause") => cmd_pause(&args[2..]),
        Some("unpause") => cmd_unpause(&args[2..]),
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
        Some("version") | Some("-V") | Some("--version") => {
            println!("{}", version_string());
            0
        }
        Some("doctor") => cmd_doctor(&args[2..]),
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
    /// `--cidfile FILE`: write the new container id without overwriting.
    cidfile: Option<String>,
    memory: Option<String>,
    memory_reservation: Option<String>,
    /// Docker-style total memory+swap; -1/unlimited.
    memory_swap: Option<i64>,
    cpus: Option<f64>,
    /// Docker-compatible relative CPU weight (`--cpu-shares`).
    cpu_shares: Option<u64>,
    cpuset_cpus: Option<String>,
    cpuset_mems: Option<String>,
    pids: Option<i64>,
    oom_group: bool,
    device_read_bps: Vec<cgroup::IoLimit>,
    device_write_bps: Vec<cgroup::IoLimit>,
    device_read_iops: Vec<cgroup::IoLimit>,
    device_write_iops: Vec<cgroup::IoLimit>,
    /// Process-level POSIX limits (`--ulimit TYPE=SOFT[:HARD]`).
    ulimits: rlimit::UlimitSet,
    hostname: Option<String>,
    /// PID/IPC/UTS namespace sharing selected for this run.
    namespaces: state::NamespaceModes,
    /// Container user (`--user USER[:GROUP]`; image `config.User` wins when no
    /// explicit flag is given).
    user: Option<String>,
    /// Additional container groups (`--group-add NAME|GID`).
    group_add: Vec<String>,
    /// Signal used by `stop`/`restart` (`--stop-signal`); an image
    /// `config.StopSignal` is used when this is absent.
    stop_signal: Option<i32>,
    /// Grace period used by `stop`/`restart` before SIGKILL.
    stop_timeout: Option<u64>,
    /// Docker-compatible detached healthcheck overrides.
    health: health::CliOptions,
    /// Detached automatic restart policy (`--restart`).
    restart: Option<restart::RestartPolicy>,
    net: NetMode,
    /// True after the operator explicitly selected `--net`.
    net_specified: bool,
    use_init: bool,
    seccomp: SeccompMode,
    /// Canonical capability names added to the secure default set.
    cap_add: BTreeSet<String>,
    /// Canonical capability names removed from the secure default set.
    cap_drop: BTreeSet<String>,
    no_overlay: bool,
    tmpfs_upper: bool,
    /// `--read-only`: remount the container root read-only before exec.
    readonly: bool,
    /// `--tmpfs PATH[:opts]`: extra in-container tmpfs mounts.
    tmpfs: Vec<mounts::TmpfsMount>,
    /// `--shm-size SIZE`: size of the private `/dev/shm` tmpfs.
    shm_size: Option<u64>,
    platform: Option<String>,
    /// Override the image `ENTRYPOINT`; an empty string resets it.
    entrypoint: Option<String>,
    /// Override the image `WorkingDir`.
    workdir: Option<String>,
    /// Whether `run IMAGE` may use a local image or must contact the registry.
    pull: PullPolicy,
    /// Detached console-log rotation policy.
    log: logs::LogOptions,
    /// True when either log rotation flag was explicitly supplied.
    log_options_set: bool,
    env: Vec<String>,
    /// `--env-file FILE`: ordered image-mode environment files.
    env_files: Vec<String>,
    /// Ports declared with `--expose` and inherited from an image.
    exposed_ports: BTreeSet<network::ExposedPort>,
    /// `-P`/`--publish-all`: map every exposed port to a random host port.
    publish_all: bool,
    ports: Vec<network::PublishedPort>,
    volumes: Vec<mounts::BindMount>,
    /// `--device HOST[:CONTAINER[:rwm]]` explicit device passthrough.
    devices: Vec<mounts::DeviceMount>,
    dns: Vec<String>,
    /// `--dns-search DOMAIN`: bridge-mode resolver search domains.
    dns_search: Vec<String>,
    /// `--dns-option OPTION`: bridge-mode resolver options.
    dns_options: Vec<String>,
    /// `--add-host NAME:ADDRESS` entries written to the container `/etc/hosts`.
    add_hosts: Vec<network::HostAlias>,
    /// Namespaced kernel settings (`--sysctl KEY=VALUE`).
    sysctls: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
    argv: Vec<String>,
    /// `-i/--interactive`: keep stdin attached (foreground runs).
    interactive: bool,
    /// `-t/--tty`: allocate a PTY for foreground or detached output.
    tty: bool,
    /// `-d/--detach`: fork a reaper and return after the container starts.
    detach: bool,
    /// `--name NAME`: assign a human-friendly name (ps/stop/rm/logs/exec).
    name: Option<String>,
    /// `--rm`: remove state + overlay automatically when the container exits.
    rm: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PullPolicy {
    /// Use a local image when present, otherwise pull it.
    #[default]
    Missing,
    /// Always resolve the tag and refresh the local image.
    Always,
    /// Never contact a registry.
    Never,
}

impl PullPolicy {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "missing" => Ok(Self::Missing),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "invalid --pull value '{other}' (missing|always|never)"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

fn parse_seccomp_mode(flag: &str, value: &str) -> Result<SeccompMode, String> {
    match value {
        "unconfined" => Ok(SeccompMode::Unconfined),
        "default" => Ok(SeccompMode::Default),
        other => Err(format!(
            "invalid {flag} value '{other}' (default|unconfined)"
        )),
    }
}

/// Translate the Docker-compatible security options Zerun can enforce.
///
/// `no_new_privs` is a non-negotiable runtime invariant rather than a switch,
/// so accepting its Docker spelling is safe but disabling it is not. A custom
/// seccomp profile would require a complete profile loader; map the built-in
/// modes instead of pretending an unsupported file was applied.
fn apply_security_opt(value: &str, seccomp: &mut SeccompMode) -> Result<(), String> {
    if let Some(mode) = value.strip_prefix("seccomp=") {
        *seccomp = parse_seccomp_mode("--security-opt seccomp", mode)?;
        return Ok(());
    }
    match value {
        "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true" => Ok(()),
        "no-new-privileges=false" | "no-new-privileges:false" => Err(
            "--security-opt cannot disable no-new-privileges; Zerun always enables it".to_string(),
        ),
        other => Err(format!(
            "unsupported --security-opt '{other}' \
             (supported: seccomp=default|unconfined, no-new-privileges)"
        )),
    }
}

/// Parse a combined short `run` flag such as `-dt`, `-dit`, or `-dP`.
///
/// Docker commonly combines boolean run flags in one token. Every other short
/// flag keeps its ordinary single-token parsing path.
fn parse_combined_run_flags(value: &str) -> Option<(bool, bool, bool, bool)> {
    let flags = value.strip_prefix('-')?;
    if flags.starts_with('-') || flags.chars().count() < 2 {
        return None;
    }
    let mut detach = false;
    let mut interactive = false;
    let mut tty = false;
    let mut publish_all = false;
    for flag in flags.chars() {
        match flag {
            'd' => detach = true,
            'i' => interactive = true,
            't' => tty = true,
            'P' => publish_all = true,
            _ => return None,
        }
    }
    Some((detach, interactive, tty, publish_all))
}

/// Parse `run` arguments. Two invocation styles:
///   legacy:  run --rootfs DIR [opts] [--] CMD [ARGS...]  (first positional = CMD)
///   image:   run [opts] IMAGE [CMD [ARGS...]]            (first positional = IMAGE)
fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut a = RunArgs::default();
    let mut i = 0;
    while i < args.len() {
        let s = &args[i];
        if let Some((detach, interactive, tty, publish_all)) = parse_combined_run_flags(s) {
            a.detach |= detach;
            a.interactive |= interactive;
            a.tty |= tty;
            a.publish_all |= publish_all;
            i += 1;
            continue;
        }
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
            "--ulimit" => {
                let value = next_value(args, &mut i, "--ulimit")?;
                a.ulimits
                    .insert_spec(&value)
                    .map_err(|error| format!("--ulimit: {error}"))?;
            }
            "--group-add" => {
                let value = next_value(args, &mut i, "--group-add")?;
                append_group_additions(&mut a.group_add, &value)?;
            }
            "--cpus" => {
                let v = next_value(args, &mut i, "--cpus")?;
                a.cpus = Some(cgroup::parse_cpus(&v).map_err(|e| e.to_string())?);
            }
            "--cpu-shares" => {
                let v = next_value(args, &mut i, "--cpu-shares")?;
                a.cpu_shares = Some(cgroup::parse_cpu_shares(&v).map_err(|e| e.to_string())?);
            }
            "--cpuset-cpus" => {
                let v = next_value(args, &mut i, "--cpuset-cpus")?;
                a.cpuset_cpus = Some(cgroup::parse_cpuset(&v).map_err(|e| e.to_string())?);
            }
            "--cpuset-mems" => {
                let v = next_value(args, &mut i, "--cpuset-mems")?;
                a.cpuset_mems = Some(cgroup::parse_cpuset(&v).map_err(|e| e.to_string())?);
            }
            "--pids" | "--pids-limit" => {
                let v = next_value(args, &mut i, s)?;
                a.pids = Some(parse_pids_limit(s, &v)?);
            }
            "--hostname" | "-h" => {
                a.hostname = Some(next_value(args, &mut i, s)?);
            }
            "--pid" => {
                let value = next_value(args, &mut i, "--pid")?;
                a.namespaces.pid = state::NamespaceMode::parse("--pid", &value)?;
            }
            "--ipc" => {
                let value = next_value(args, &mut i, "--ipc")?;
                a.namespaces.ipc = state::IpcMode::parse(&value)?;
            }
            "--uts" => {
                let value = next_value(args, &mut i, "--uts")?;
                a.namespaces.uts = state::NamespaceMode::parse("--uts", &value)?;
            }
            "--user" | "-u" => {
                a.user = Some(next_value(args, &mut i, "--user")?);
            }
            "--stop-signal" => {
                let v = next_value(args, &mut i, "--stop-signal")?;
                a.stop_signal = Some(signal::parse(&v)?);
            }
            "--stop-timeout" => {
                let v = next_value(args, &mut i, "--stop-timeout")?;
                a.stop_timeout = Some(parse_seconds(&v, "--stop-timeout")?);
            }
            "--health-cmd" => {
                let value = next_value(args, &mut i, "--health-cmd")?;
                validate_health_command(&value)?;
                a.health.cmd = Some(value);
            }
            "--health-interval" => {
                let value = next_value(args, &mut i, "--health-interval")?;
                a.health.interval_ns = Some(parse_health_duration("--health-interval", &value)?);
            }
            "--health-timeout" => {
                let value = next_value(args, &mut i, "--health-timeout")?;
                a.health.timeout_ns = Some(parse_health_duration("--health-timeout", &value)?);
            }
            "--health-start-period" => {
                let value = next_value(args, &mut i, "--health-start-period")?;
                a.health.start_period_ns =
                    Some(parse_health_duration("--health-start-period", &value)?);
            }
            "--health-start-interval" => {
                let value = next_value(args, &mut i, "--health-start-interval")?;
                a.health.start_interval_ns =
                    Some(parse_health_duration("--health-start-interval", &value)?);
            }
            "--health-retries" => {
                let value = next_value(args, &mut i, "--health-retries")?;
                a.health.retries = Some(parse_health_retries(&value)?);
            }
            "--no-healthcheck" => {
                a.health.disabled = true;
                i += 1;
            }
            "--restart" => {
                let v = next_value(args, &mut i, "--restart")?;
                a.restart = Some(v.parse()?);
            }
            "--net" | "--network" => {
                let v = next_value(args, &mut i, s)?;
                a.net_specified = true;
                a.net = parse_net_mode(s, &v)?;
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
                a.seccomp = parse_seccomp_mode("--seccomp", &v)?;
            }
            "--security-opt" => {
                let v = next_value(args, &mut i, "--security-opt")?;
                apply_security_opt(&v, &mut a.seccomp)?;
            }
            "--cap-add" => {
                let v = next_value(args, &mut i, "--cap-add")?;
                a.cap_add.extend(security::parse_capability_list(&v)?);
            }
            "--cap-drop" => {
                let v = next_value(args, &mut i, "--cap-drop")?;
                a.cap_drop.extend(security::parse_capability_list(&v)?);
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
            "--shm-size" => {
                let v = next_value(args, &mut i, "--shm-size")?;
                a.shm_size = Some(
                    units::parse_size(&v).map_err(|e| format!("invalid --shm-size '{v}': {e}"))?,
                );
            }
            "--platform" => {
                a.platform = Some(next_value(args, &mut i, "--platform")?);
            }
            "--entrypoint" => {
                a.entrypoint = Some(next_value(args, &mut i, "--entrypoint")?);
            }
            "--workdir" | "-w" => {
                a.workdir = Some(next_value(args, &mut i, s)?);
            }
            "--pull" => {
                let v = next_value(args, &mut i, "--pull")?;
                a.pull = PullPolicy::parse(&v)?;
            }
            "--log-max-size" => {
                let v = next_value(args, &mut i, "--log-max-size")?;
                a.log.max_size =
                    logs::parse_size(&v).map_err(|e| format!("invalid --log-max-size: {e}"))?;
                a.log_options_set = true;
            }
            "--log-max-file" => {
                let v = next_value(args, &mut i, "--log-max-file")?;
                a.log.max_files = logs::parse_max_files(&v)
                    .map_err(|e| format!("invalid --log-max-file: {e}"))?;
                a.log_options_set = true;
            }
            "--env" | "-e" => {
                let value = next_value(args, &mut i, s)?;
                workload::validate_env_spec(&value).map_err(|e| e.to_string())?;
                a.env.push(value);
            }
            "--env-file" => {
                let value = next_value(args, &mut i, s)?;
                if value.is_empty() {
                    return Err("--env-file path cannot be empty".to_string());
                }
                a.env_files.push(value);
            }
            "--volume" | "-v" => {
                let v = next_value(args, &mut i, s)?;
                a.volumes
                    .push(mounts::parse_bind(&v).map_err(|e| e.to_string())?);
            }
            "--mount" => {
                let v = next_value(args, &mut i, "--mount")?;
                append_run_mount(&mut a, &v)?;
            }
            "--device" => {
                let v = next_value(args, &mut i, "--device")?;
                a.devices
                    .push(mounts::parse_device(&v).map_err(|e| e.to_string())?);
            }
            "--publish" | "-p" => {
                let v = next_value(args, &mut i, s)?;
                a.ports.extend(parse_publish(&v)?);
            }
            "--expose" => {
                let value = next_value(args, &mut i, "--expose")?;
                a.exposed_ports.extend(
                    network::parse_expose_list(&value).map_err(|e| format!("--expose: {e}"))?,
                );
            }
            "--publish-all" | "-P" => {
                a.publish_all = true;
                i += 1;
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
                append_dns_servers(&mut a.dns, &v)?;
            }
            "--dns-search" => {
                let v = next_value(args, &mut i, "--dns-search")?;
                append_dns_search(&mut a.dns_search, &v)?;
            }
            "--dns-option" | "--dns-opt" => {
                let v = next_value(args, &mut i, "--dns-option")?;
                append_dns_options(&mut a.dns_options, &v)?;
            }
            "--add-host" => {
                let v = next_value(args, &mut i, "--add-host")?;
                a.add_hosts.push(network::HostAlias::parse(&v)?);
            }
            "--sysctl" => {
                let value = next_value(args, &mut i, "--sysctl")?;
                let (key, value) = sysctl::parse(&value)?;
                a.sysctls.insert(key, value);
            }
            "--label" => {
                let (k, v) = labels::parse_cli(&next_value(args, &mut i, "--label")?)?;
                a.labels.insert(k, v);
            }
            "--label-file" => {
                let path = next_value(args, &mut i, "--label-file")?;
                if path.is_empty() {
                    return Err("--label-file path cannot be empty".to_string());
                }
                for (key, value) in labels::load_file(std::path::Path::new(&path))? {
                    a.labels.insert(key, value);
                }
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
            "--cidfile" => {
                let v = next_value(args, &mut i, "--cidfile")?;
                if v.is_empty() {
                    return Err("--cidfile path cannot be empty".to_string());
                }
                a.cidfile = Some(v);
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
            other if other.starts_with("--pull=") => {
                a.pull = PullPolicy::parse(&other["--pull=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--health-cmd=") => {
                let value = &other["--health-cmd=".len()..];
                validate_health_command(value)?;
                a.health.cmd = Some(value.to_string());
                i += 1;
            }
            other if other.starts_with("--health-interval=") => {
                let value = &other["--health-interval=".len()..];
                a.health.interval_ns = Some(parse_health_duration("--health-interval", value)?);
                i += 1;
            }
            other if other.starts_with("--health-timeout=") => {
                let value = &other["--health-timeout=".len()..];
                a.health.timeout_ns = Some(parse_health_duration("--health-timeout", value)?);
                i += 1;
            }
            other if other.starts_with("--health-start-period=") => {
                let value = &other["--health-start-period=".len()..];
                a.health.start_period_ns =
                    Some(parse_health_duration("--health-start-period", value)?);
                i += 1;
            }
            other if other.starts_with("--health-start-interval=") => {
                let value = &other["--health-start-interval=".len()..];
                a.health.start_interval_ns =
                    Some(parse_health_duration("--health-start-interval", value)?);
                i += 1;
            }
            other if other.starts_with("--health-retries=") => {
                let value = &other["--health-retries=".len()..];
                a.health.retries = Some(parse_health_retries(value)?);
                i += 1;
            }
            other if other.starts_with("--seccomp=") => {
                a.seccomp = parse_seccomp_mode("--seccomp", &other["--seccomp=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--security-opt=") => {
                apply_security_opt(&other["--security-opt=".len()..], &mut a.seccomp)?;
                i += 1;
            }
            other if other.starts_with("--stop-signal=") => {
                a.stop_signal = Some(signal::parse(&other["--stop-signal=".len()..])?);
                i += 1;
            }
            other if other.starts_with("--stop-timeout=") => {
                a.stop_timeout = Some(parse_seconds(
                    &other["--stop-timeout=".len()..],
                    "--stop-timeout",
                )?);
                i += 1;
            }
            other if other.starts_with("--env-file=") => {
                let value = &other["--env-file=".len()..];
                if value.is_empty() {
                    return Err("--env-file path cannot be empty".to_string());
                }
                a.env_files.push(value.to_string());
                i += 1;
            }
            other if other.starts_with("--label=") => {
                let (key, value) = labels::parse_cli(&other["--label=".len()..])?;
                a.labels.insert(key, value);
                i += 1;
            }
            other if other.starts_with("--label-file=") => {
                let path = &other["--label-file=".len()..];
                if path.is_empty() {
                    return Err("--label-file path cannot be empty".to_string());
                }
                for (key, value) in labels::load_file(std::path::Path::new(path))? {
                    a.labels.insert(key, value);
                }
                i += 1;
            }
            other if other.starts_with("--cidfile=") => {
                let path = &other["--cidfile=".len()..];
                if path.is_empty() {
                    return Err("--cidfile path cannot be empty".to_string());
                }
                a.cidfile = Some(path.to_string());
                i += 1;
            }
            other if other.starts_with("--expose=") => {
                let value = &other["--expose=".len()..];
                a.exposed_ports.extend(
                    network::parse_expose_list(value).map_err(|e| format!("--expose: {e}"))?,
                );
                i += 1;
            }
            other if other.starts_with("--mount=") => {
                append_run_mount(&mut a, &other["--mount=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--sysctl=") => {
                let (key, value) = sysctl::parse(&other["--sysctl=".len()..])?;
                a.sysctls.insert(key, value);
                i += 1;
            }
            other if other.starts_with("--shm-size=") => {
                let value = &other["--shm-size=".len()..];
                a.shm_size = Some(
                    units::parse_size(value)
                        .map_err(|e| format!("invalid --shm-size '{value}': {e}"))?,
                );
                i += 1;
            }
            other if other.starts_with("--pids=") => {
                let value = &other["--pids=".len()..];
                a.pids = Some(parse_pids_limit("--pids", value)?);
                i += 1;
            }
            other if other.starts_with("--pids-limit=") => {
                let value = &other["--pids-limit=".len()..];
                a.pids = Some(parse_pids_limit("--pids-limit", value)?);
                i += 1;
            }
            other if other.starts_with("--net=") => {
                let value = &other["--net=".len()..];
                a.net_specified = true;
                a.net = parse_net_mode("--net", value)?;
                i += 1;
            }
            other if other.starts_with("--network=") => {
                let value = &other["--network=".len()..];
                a.net_specified = true;
                a.net = parse_net_mode("--network", value)?;
                i += 1;
            }
            other if other.starts_with("--cpu-shares=") => {
                let value = &other["--cpu-shares=".len()..];
                a.cpu_shares = Some(cgroup::parse_cpu_shares(value).map_err(|e| e.to_string())?);
                i += 1;
            }
            other if other.starts_with("--device=") => {
                a.devices.push(
                    mounts::parse_device(&other["--device=".len()..]).map_err(|e| e.to_string())?,
                );
                i += 1;
            }
            other if other.starts_with("--restart=") => {
                a.restart = Some(other["--restart=".len()..].parse()?);
                i += 1;
            }
            other if other.starts_with("--ulimit=") => {
                let value = &other["--ulimit=".len()..];
                a.ulimits
                    .insert_spec(value)
                    .map_err(|error| format!("--ulimit: {error}"))?;
                i += 1;
            }
            other if other.starts_with("--group-add=") => {
                append_group_additions(&mut a.group_add, &other["--group-add=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--pid=") => {
                a.namespaces.pid = state::NamespaceMode::parse("--pid", &other["--pid=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--ipc=") => {
                a.namespaces.ipc = state::IpcMode::parse(&other["--ipc=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--dns=") => {
                let value = &other["--dns=".len()..];
                append_dns_servers(&mut a.dns, value)?;
                i += 1;
            }
            other if other.starts_with("--dns-search=") => {
                let value = &other["--dns-search=".len()..];
                append_dns_search(&mut a.dns_search, value)?;
                i += 1;
            }
            other if other.starts_with("--dns-option=") => {
                let value = &other["--dns-option=".len()..];
                append_dns_options(&mut a.dns_options, value)?;
                i += 1;
            }
            other if other.starts_with("--dns-opt=") => {
                let value = &other["--dns-opt=".len()..];
                append_dns_options(&mut a.dns_options, value)?;
                i += 1;
            }
            other if other.starts_with("--uts=") => {
                a.namespaces.uts = state::NamespaceMode::parse("--uts", &other["--uts=".len()..])?;
                i += 1;
            }
            other if other.starts_with("--cap-add=") => {
                a.cap_add.extend(security::parse_capability_list(
                    &other["--cap-add=".len()..],
                )?);
                i += 1;
            }
            other if other.starts_with("--cap-drop=") => {
                a.cap_drop.extend(security::parse_capability_list(
                    &other["--cap-drop=".len()..],
                )?);
                i += 1;
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
    if a.namespaces.uts == state::NamespaceMode::Host && a.hostname.is_some() {
        return Err("--hostname cannot be used with --uts host".to_string());
    }
    mounts::validate_device_targets(&a.devices)?;
    Ok(a)
}

fn append_run_mount(a: &mut RunArgs, value: &str) -> Result<(), String> {
    match mounts::parse_mount(value)? {
        mounts::MountRequest::Bind(mount) => a.volumes.push(mount),
        mounts::MountRequest::Tmpfs(mount) => a.tmpfs.push(mount),
    }
    Ok(())
}

fn append_group_additions(target: &mut Vec<String>, raw: &str) -> Result<(), String> {
    for group in
        security::parse_group_add_values(raw).map_err(|error| format!("--group-add: {error}"))?
    {
        if !target.contains(&group) {
            target.push(group);
        }
    }
    Ok(())
}

fn append_dns_servers(target: &mut Vec<String>, raw: &str) -> Result<(), String> {
    for value in raw.split(',') {
        target.push(resolv::parse_nameserver(value).map_err(|e| format!("--dns: {e}"))?);
    }
    Ok(())
}

fn append_dns_search(target: &mut Vec<String>, raw: &str) -> Result<(), String> {
    for value in raw.split(',') {
        target.push(resolv::parse_search_domain(value).map_err(|e| format!("--dns-search: {e}"))?);
    }
    Ok(())
}

fn append_dns_options(target: &mut Vec<String>, raw: &str) -> Result<(), String> {
    for value in raw.split(',') {
        target.push(resolv::parse_option(value).map_err(|e| format!("--dns-option: {e}"))?);
    }
    Ok(())
}

/// Parse `-p`/`--publish` values. Supported forms:
///   HOST[-HOST_END][:CONTAINER[-CONTAINER_END]][/tcp|/udp]
///   ADDRESS:HOST[-HOST_END][:CONTAINER[-CONTAINER_END]][/tcp|/udp]
/// IPv6 addresses are bracketed (`[::1]:8080-8081:80-81`). Host and container
/// ranges must contain the same number of ports and are paired in order.
fn parse_publish(v: &str) -> Result<Vec<network::PublishedPort>, String> {
    use std::net::IpAddr;

    fn parse_port(s: &str, raw: &str) -> Result<u16, String> {
        s.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("-p: invalid port in '{raw}' (expected 1-65535)"))
    }

    fn parse_range(s: &str, raw: &str) -> Result<(u16, u16), String> {
        let (start, end) = match s.split_once('-') {
            Some((start, end)) => (parse_port(start, raw)?, parse_port(end, raw)?),
            None => {
                let port = parse_port(s, raw)?;
                (port, port)
            }
        };
        if start > end {
            return Err(format!(
                "-p: invalid port range in '{raw}': start must not exceed end"
            ));
        }
        Ok((start, end))
    }

    let (value, protocol) = match v.split_once('/') {
        Some((value, protocol)) if protocol.eq_ignore_ascii_case("tcp") => {
            (value, network::PortProtocol::Tcp)
        }
        Some((value, protocol)) if protocol.eq_ignore_ascii_case("udp") => {
            (value, network::PortProtocol::Udp)
        }
        Some((_, protocol)) => {
            return Err(format!(
                "-p: invalid protocol '{protocol}' in '{v}' (expected tcp or udp)"
            ))
        }
        None => (v, network::PortProtocol::Tcp),
    };
    if value.is_empty() {
        return Err(format!("-p: invalid port publish '{value}'"));
    }

    let (host_ip, rest) = if let Some(rest) = value.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| format!("-p: missing ']' in IPv6 publish '{value}'"))?;
        let ip: IpAddr = rest[..close]
            .parse()
            .map_err(|_| format!("-p: invalid host address in '{value}'"))?;
        let rest = rest[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| format!("-p: invalid port publish '{value}'"))?;
        (ip, rest)
    } else {
        match value.matches(':').count() {
            0 => (std::net::Ipv4Addr::UNSPECIFIED.into(), value),
            1 => {
                let (first, second) = value.split_once(':').expect("one colon was counted");
                match first.parse::<IpAddr>() {
                    Ok(ip) => (ip, second),
                    Err(_) => (std::net::Ipv4Addr::UNSPECIFIED.into(), value),
                }
            }
            2 => {
                let ip: IpAddr = value
                    .split(':')
                    .next()
                    .expect("two colons were counted")
                    .parse()
                    .map_err(|_| format!("-p: invalid host address in '{value}'"))?;
                (
                    ip,
                    &value[value.find(':').expect("two colons were counted") + 1..],
                )
            }
            _ => return Err(
                "-p: bracket IPv6 addresses ('[::1]:HOST:CONTAINER'); use ADDRESS:HOST:CONTAINER"
                    .to_string(),
            ),
        }
    };

    let (host_range, container_range) = match rest.split_once(':') {
        Some((host, container)) => (parse_range(host, v)?, parse_range(container, v)?),
        None => {
            let range = parse_range(rest, v)?;
            (range, range)
        }
    };
    let host_count = u32::from(host_range.1) - u32::from(host_range.0) + 1;
    let container_count = u32::from(container_range.1) - u32::from(container_range.0) + 1;
    if host_count != container_count {
        return Err(format!(
            "-p: host and container port ranges must have the same length in '{v}'"
        ));
    }
    Ok((0..host_count)
        .map(|offset| network::PublishedPort {
            host_ip,
            host: host_range.0 + offset as u16,
            container: container_range.0 + offset as u16,
            protocol,
        })
        .collect())
}

fn next_value(args: &[String], i: &mut usize, opt: &str) -> Result<String, String> {
    let v = args
        .get(*i + 1)
        .ok_or_else(|| format!("option {opt} requires a value"))?;
    *i += 2;
    Ok(v.clone())
}

fn parse_seconds(value: &str, option: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{option}: invalid seconds value '{value}'"))
}

fn parse_health_duration(option: &str, value: &str) -> Result<u64, String> {
    health::parse_duration_ns(value)
        .map_err(|error| format!("{option}: invalid duration '{value}': {error}"))
}

fn parse_health_retries(value: &str) -> Result<u32, String> {
    let retries = value
        .parse::<u32>()
        .map_err(|_| format!("--health-retries: invalid positive integer '{value}'"))?;
    if retries == 0 {
        return Err("--health-retries must be greater than zero".to_string());
    }
    Ok(retries)
}

fn validate_health_command(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("--health-cmd cannot be empty (use --no-healthcheck to disable)".to_string());
    }
    if value.contains('\0') {
        return Err("--health-cmd cannot contain a NUL byte".to_string());
    }
    Ok(())
}

fn parse_pids_limit(option: &str, value: &str) -> Result<i64, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {option} value '{value}'"))
}

fn parse_net_mode(option: &str, value: &str) -> Result<NetMode, String> {
    match value {
        "bridge" => Ok(NetMode::Bridge),
        "host" => Ok(NetMode::Host),
        "none" => Ok(NetMode::None),
        other => Err(format!(
            "invalid {option} value '{other}' (bridge|host|none)"
        )),
    }
}

/// Rootful workloads get a conservative process cap unless the operator
/// explicitly chooses another limit. Rootless runs cannot rely on a writable
/// cgroup hierarchy, so an implicit cap would turn a security default into a
/// hard startup dependency.
const DEFAULT_PIDS_LIMIT: i64 = 256;

fn default_pids_limit(euid: u32) -> Option<i64> {
    (euid == 0).then_some(DEFAULT_PIDS_LIMIT)
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

/// Materialize named-volume bind sources under the active data root.
///
/// Parsing deliberately does not create storage: `generate-service` and
/// validation-only callers reuse the same parser, while `run` owns creation.
fn resolve_named_volumes(store: &Store, volumes: &mut [mounts::BindMount]) -> Result<(), String> {
    for volume in volumes {
        let Some(name) = &volume.named else {
            continue;
        };
        mounts::validate_volume_name(name)?;
        let dir = store.volume_dir(name);
        fsutil::mkdir_p(&dir).map_err(|e| format!("-v: create volume '{name}': {e}"))?;
        volume.source = dir;
    }
    Ok(())
}

/// Anonymous volumes created from image `VOLUME` declarations. The guard
/// removes them if setup fails before a retained container record takes
/// ownership; detached runs explicitly hand the names to that record.
struct AnonymousVolumeGuard {
    store: Store,
    id: String,
    names: Option<Vec<String>>,
}

impl AnonymousVolumeGuard {
    fn new(store: Store, id: String, names: Vec<String>) -> Self {
        Self {
            store,
            id,
            names: Some(names),
        }
    }

    fn into_names(mut self) -> Vec<String> {
        self.names.take().unwrap_or_default()
    }
}

impl Drop for AnonymousVolumeGuard {
    fn drop(&mut self) {
        if let Some(names) = self.names.take() {
            remove_anonymous_volumes(&self.store, &self.id, &names);
        }
    }
}

fn anonymous_volume_name(id: &str, index: usize) -> String {
    format!("zerun-anon-{id}-{index}")
}

fn owned_anonymous_volume_name(id: &str, name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(&format!("zerun-anon-{id}-")) else {
        return false;
    };
    !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
        && mounts::validate_volume_name(name).is_ok()
}

/// Remove only volumes that follow the ownership naming scheme for `id`.
/// State records are owner-controlled, but validating this boundary prevents a
/// corrupted `anonymous_volumes` list from deleting an unrelated named volume.
pub(crate) fn remove_anonymous_volumes(store: &Store, id: &str, names: &[String]) {
    if !(1..=64).contains(&id.len()) || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return;
    }
    for name in names {
        if !owned_anonymous_volume_name(id, name) {
            eprintln!(
                "zerun: warn: refusing to remove volume '{name}' not owned by container {id}"
            );
            continue;
        }
        fsutil::remove_dir_all_quiet(&store.volume_dir(name));
    }
}

fn mount_target_covers(candidate: &Path, target: &Path) -> bool {
    target == candidate || target.starts_with(candidate)
}

/// Materialize image-declared volumes as fresh per-container volumes. A user
/// bind or tmpfs at the same path or an ancestor suppresses the image volume,
/// matching Docker's "a user mount hides the image declaration" behavior.
/// Existing image-directory content seeds a new anonymous volume.
fn materialize_image_volumes(
    store: &Store,
    id: &str,
    rootfs: &Path,
    targets: &[String],
    user_mounts: &[mounts::BindMount],
    user_tmpfs: &[mounts::TmpfsMount],
) -> Result<(Vec<mounts::BindMount>, Vec<String>), String> {
    let mut created = Vec::new();
    let result = (|| {
        let mut mounts = Vec::new();
        for raw_target in targets {
            mounts::validate_container_target("image VOLUME", raw_target)?;
            if raw_target.contains(':') {
                return Err(format!(
                    "image VOLUME path '{raw_target}' cannot contain ':' because restart metadata uses -v syntax"
                ));
            }
            let target = PathBuf::from(raw_target);
            if user_mounts
                .iter()
                .any(|mount| mount_target_covers(&mount.target, &target))
                || user_tmpfs
                    .iter()
                    .any(|mount| mount_target_covers(&mount.target, &target))
            {
                continue;
            }

            let name = anonymous_volume_name(id, created.len());
            let dir = store.volume_dir(&name);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("create anonymous volume '{name}': {e}"))?;
            created.push(name.clone());

            let source = mounts::safe_target(rootfs, &target).map_err(|e| e.to_string())?;
            match std::fs::symlink_metadata(&source) {
                Ok(meta) if meta.file_type().is_dir() => {
                    fsutil::copy_dir_all(&source, &dir).map_err(|e| {
                        format!(
                            "seed anonymous volume '{name}' from image path {}: {e}",
                            target.display()
                        )
                    })?;
                }
                Ok(_) => {
                    return Err(format!(
                        "image VOLUME {} exists but is not a directory",
                        target.display()
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect image VOLUME target {}: {error}",
                        target.display()
                    ))
                }
            }

            mounts.push(mounts::BindMount {
                source: dir,
                target,
                readonly: false,
                named: Some(name.clone()),
                raw: format!("{name}:{raw_target}"),
            });
        }
        Ok((mounts, created.clone()))
    })();
    if result.is_err() {
        remove_anonymous_volumes(store, id, &created);
    }
    result
}

/// Recover the resolved process environment from a detached state record.
fn state_env(entries: &[String]) -> Result<Vec<(String, String)>, String> {
    entries
        .iter()
        .map(|entry| {
            let (key, value) = entry
                .split_once('=')
                .ok_or_else(|| format!("invalid environment entry in state: '{entry}'"))?;
            workload::validate_env_pair(key, value)
                .map_err(|e| format!("invalid environment entry in state: '{entry}': {e}"))?;
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Reconcile a dead detached reaper and require the terminal state to be
/// persisted before a lifecycle command continues. A best-effort reconcile is
/// unsafe: callers could otherwise act on an in-memory Exited record while the
/// filesystem still advertises Running.
fn reconcile_stale_state(store: &Store, st: &mut ContainerState) -> Result<(), String> {
    lifecycle::reconcile_stale_and_save(store, st)
        .map(|_| ())
        .map_err(|e| format!("failed to persist reconciled state for {}: {e}", st.id))
}

fn state_environment(st: &ContainerState) -> Result<Option<Vec<(String, String)>>, String> {
    // Legacy --rootfs runs inherited the host environment and persisted no
    // explicit entries. Do not turn an empty record into an empty envp.
    if st.env.is_empty() && st.image.starts_with("rootfs:") {
        Ok(None)
    } else {
        state_env(&st.env).map(Some)
    }
}

/// Materialized image rootfs directories still referenced by retained
/// containers. They must survive image tag removal and `prune --images` so a
/// stopped container can be started or committed without re-pulling its image.
fn protected_image_rootfs(imgstore: &image::store::ImageStore, store: &Store) -> BTreeSet<PathBuf> {
    protected_image_rootfs_excluding(imgstore, store, &BTreeSet::new())
}

fn protected_image_rootfs_excluding(
    imgstore: &image::store::ImageStore,
    store: &Store,
    excluded_ids: &BTreeSet<String>,
) -> BTreeSet<PathBuf> {
    let rootfs_root =
        std::fs::canonicalize(imgstore.rootfs_dir()).unwrap_or_else(|_| imgstore.rootfs_dir());
    state::list(store)
        .into_iter()
        .filter(|st| !excluded_ids.contains(&st.id))
        .filter_map(|st| st.lower)
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .filter(|path| path.starts_with(&rootfs_root))
        .collect()
}

fn cmd_run(args: &[String]) -> i32 {
    cmd_run_inner(args, None, true)
}

fn cmd_run_inner(args: &[String], resume: Option<ContainerState>, report_id: bool) -> i32 {
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
    let euid = syscalls::effective_uid();
    if !a.net_specified {
        a.net = default_net(euid);
    }
    if a.pids.is_none() {
        a.pids = default_pids_limit(euid);
    }
    if let Err(error) = sysctl::validate_for_namespaces(&a.sysctls, a.namespaces, a.net) {
        eprintln!("zerun run: {error}");
        return 2;
    }
    if let Err(error) = mounts::validate_device_permissions(euid != 0, &a.devices) {
        eprintln!("zerun run: {error}");
        return 2;
    }
    if let Err(error) = mounts::validate_device_targets(&a.devices) {
        eprintln!("zerun run: {error}");
        return 2;
    }
    if a.no_overlay && a.tmpfs_upper {
        eprintln!("zerun run: --tmpfs-upper requires the writable overlay; remove --no-overlay");
        return 2;
    }
    if (a.publish_all || !a.ports.is_empty()) && a.net != NetMode::Bridge {
        eprintln!("zerun run: -p/--publish and -P/--publish-all require --net bridge");
        return 2;
    }
    if a.interactive && a.detach {
        eprintln!(
            "zerun: warning: -i has no effect with -d (detached stdin is not connected; \
             -t still allocates a terminal for the workload)"
        );
    }
    if (!a.dns.is_empty() || !a.dns_search.is_empty() || !a.dns_options.is_empty())
        && a.net != NetMode::Bridge
    {
        eprintln!("zerun: warning: DNS options only apply to --net bridge; ignoring");
    }
    if a.rootfs.is_none() && a.image.is_none() {
        eprintln!("zerun run: an IMAGE (or --rootfs DIR for legacy mode) is required");
        print_run_usage();
        return 2;
    }
    if a.rootfs.is_some() && a.entrypoint.is_some() {
        eprintln!("zerun run: --entrypoint requires image mode (drop --rootfs)");
        return 2;
    }
    if a.rootfs.is_some() && a.pull != PullPolicy::Missing {
        eprintln!("zerun run: --pull requires image mode (drop --rootfs)");
        return 2;
    }
    if a.rootfs.is_some() && !a.env.is_empty() {
        eprintln!("zerun run: -e/--env requires image mode (drop --rootfs)");
        return 2;
    }
    if a.rootfs.is_some() && !a.env_files.is_empty() {
        eprintln!("zerun run: --env-file requires image mode (drop --rootfs)");
        return 2;
    }
    if a.workdir.as_deref() == Some("") {
        eprintln!("zerun run: --workdir cannot be empty");
        return 2;
    }
    if a.log_options_set && !a.detach {
        eprintln!(
            "zerun: warning: log rotation options only apply to detached containers; ignoring"
        );
    }
    // A resumed container's persisted policy is authoritative: `update --restart`
    // may have changed it after the canonical launch arguments were captured.
    let restart_policy = resume
        .as_ref()
        .map(|st| st.restart_policy)
        .or(a.restart)
        .unwrap_or_default();
    if a.restart.is_some() && !a.detach {
        eprintln!("zerun run: --restart requires -d/--detach");
        return 2;
    }
    if (a.health.has_settings() || a.health.disabled) && !a.detach {
        eprintln!("zerun run: healthcheck options require -d/--detach");
        return 2;
    }
    if a.restart.is_some() && a.rm {
        eprintln!("zerun run: --restart cannot be combined with --rm");
        return 2;
    }
    let host_aliases = if !a.add_hosts.is_empty() && a.net == NetMode::Host {
        eprintln!("zerun run: --add-host cannot be used with --net host");
        return 2;
    } else {
        match network::resolve_host_aliases(
            &a.add_hosts,
            (a.net == NetMode::Bridge).then_some(network::GATEWAY_IP),
        ) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("zerun run: {e}");
                return 2;
            }
        }
    };
    let capabilities = match security::CapabilitySet::resolve(&a.cap_add, &a.cap_drop) {
        Ok(capabilities) => capabilities,
        Err(e) => {
            eprintln!("zerun run: {e}");
            return 2;
        }
    };

    // Environment files are host inputs to a new container. Resolve them before
    // allocating storage, and never re-read them while resuming from persisted
    // state: restart must preserve the environment the container was created
    // with even if the source file was edited or removed.
    let env_file_overrides = if resume.is_none() && !a.env_files.is_empty() {
        let paths = match workload::resolve_env_file_paths(&a.env_files) {
            Ok(paths) => paths,
            Err(error) => {
                eprintln!("zerun run: {error}");
                return 2;
            }
        };
        let entries = match workload::load_env_files(&paths) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("zerun run: {error}");
                return 2;
            }
        };
        a.env_files = paths
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        entries
    } else {
        Vec::new()
    };

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
    if let Err(e) = resolve_named_volumes(&store, &mut a.volumes) {
        eprintln!("zerun run: {e}");
        return 2;
    }

    // Protect image lookup/pull until a rootfs-scoped lease is established.
    // Detached state then protects the lower rootfs after it is persisted.
    let image_store_lease = if resume.is_none() && a.image.is_some() {
        let imgstore = match image::store::ImageStore::open(&store) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("zerun: {error}");
                return 1;
            }
        };
        match imgstore.lock_operations() {
            Ok(lease) => Some(lease),
            Err(error) => {
                eprintln!("zerun: {error}");
                return 1;
            }
        }
    } else {
        None
    };
    let mut image_rootfs_lease = None;

    // One id per run: used for the HOSTNAME default, the per-run overlay, the
    // nft table/veth names and the lifecycle state directory. New runs reserve
    // their directory atomically before any filesystem or kernel resources are
    // created; resuming keeps the original identity and writable layer.
    let id_reservation = if resume.is_some() {
        None
    } else {
        match ContainerIdReservation::reserve(&store) {
            Ok(reservation) => Some(reservation),
            Err(e) => {
                eprintln!("zerun run: {e}");
                return 1;
            }
        }
    };
    let id = resume
        .as_ref()
        .map(|st| st.id.clone())
        .or_else(|| {
            id_reservation
                .as_ref()
                .map(|reservation| reservation.id.clone())
        })
        .expect("new runs reserve an id and resumed runs have one");

    // A resumed container keeps its original id and cidfile. Recreating the
    // client-side receipt would either overwrite an operator file or make
    // `start`/`restart` fail just because the original run succeeded.
    let mut cidfile_guard = if resume.is_none() {
        match a.cidfile.as_deref() {
            Some(path) => match cidfile::CidFile::create(Path::new(path), &id) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    eprintln!("zerun run: {error}");
                    return 2;
                }
            },
            None => None,
        }
    } else {
        None
    };

    // A host UTS namespace cannot be renamed without host privileges (and
    // `--hostname` is rejected with it). Use the live host name for the
    // container's HOSTNAME default and /etc/hosts identity instead of the id.
    let effective_hostname = match a.namespaces.uts {
        state::NamespaceMode::Host => match syscalls::host_name() {
            Some(name) => Some(name),
            None => {
                eprintln!("zerun run: cannot read the host hostname for --uts host");
                return 1;
            }
        },
        state::NamespaceMode::Private => a.hostname.clone(),
    };

    // Resolve the container root filesystem and, for image mode, the process
    // environment / working directory / default command from the OCI config.
    let mut image_volume_targets = resume
        .as_ref()
        .map(|st| st.image_volumes.clone())
        .unwrap_or_default();
    let mut anonymous_volumes = resume
        .as_ref()
        .map(|st| st.anonymous_volumes.clone())
        .unwrap_or_default();
    let (
        rootfs,
        env,
        cwd,
        user,
        stop_signal,
        stop_timeout,
        argv,
        labels,
        capabilities,
        seccomp,
        healthcheck,
    ) = if let Some(st) = &resume {
        if st.tmpfs_upper {
            eprintln!(
                "zerun start: container {} used --tmpfs-upper; its writable layer was ephemeral",
                display_name(st)
            );
            return 1;
        }
        let lower = match resumable_lower_rootfs(&store, st) {
            Ok(lower) => lower,
            Err(e) => {
                eprintln!("zerun start: {e}");
                return 1;
            }
        };
        let env = match state_environment(st) {
            Ok(env) => env,
            Err(e) => {
                eprintln!("zerun start: {e}");
                return 1;
            }
        };
        let capabilities = match st.capabilities.as_deref() {
            Some(names) => match security::CapabilitySet::from_names(names) {
                Ok(caps) => caps,
                Err(e) => {
                    eprintln!("zerun start: {e}");
                    return 1;
                }
            },
            None => capabilities,
        };
        let seccomp = st.seccomp.unwrap_or(a.seccomp);
        let stop_signal = match signal::validate(st.stop_signal) {
            Ok(signal) => signal,
            Err(e) => {
                eprintln!("zerun start: invalid persisted stop signal: {e}");
                return 1;
            }
        };
        let stop_timeout = st.stop_timeout;
        (
            lower,
            env,
            st.cwd.clone(),
            st.user.clone(),
            stop_signal,
            stop_timeout,
            st.cmd.clone(),
            st.labels.clone(),
            capabilities,
            seccomp,
            st.healthcheck.clone(),
        )
    } else if let Some(rootfs_str) = &a.rootfs {
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
        let healthcheck = match health::resolve(None, &a.health) {
            Ok(check) => check,
            Err(error) => {
                eprintln!("zerun run: {error}");
                return 2;
            }
        };
        (
            rootfs,
            None,
            a.workdir.clone(),
            None,
            a.stop_signal.unwrap_or(signal::DEFAULT_STOP_SIGNAL),
            a.stop_timeout.unwrap_or(state::DEFAULT_STOP_TIMEOUT_SECS),
            argv,
            a.labels.clone(),
            capabilities,
            a.seccomp,
            healthcheck,
        )
    } else {
        let image = a.image.as_deref().expect("image required");
        let reference = match Reference::parse(image) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("zerun run: invalid image reference '{image}': {e}");
                return 2;
            }
        };
        match resolve_run_image(
            &store,
            &reference,
            a.platform.as_deref(),
            a.pull,
            image_store_lease
                .as_ref()
                .expect("image runs hold an image-store lease"),
        ) {
            Ok((rootfs, cfg)) => {
                let imgstore = match image::store::ImageStore::open(&store) {
                    Ok(store) => store,
                    Err(error) => {
                        eprintln!("zerun: {error}");
                        return 1;
                    }
                };
                image_rootfs_lease = match imgstore.lock_rootfs_path(
                    image_store_lease
                        .as_ref()
                        .expect("image runs hold an image-store lease"),
                    &rootfs,
                ) {
                    Ok(lease) => Some(lease),
                    Err(error) => {
                        eprintln!("zerun: {error}");
                        return 1;
                    }
                };
                match image_exposed_ports(&cfg) {
                    Ok(ports) => a.exposed_ports.extend(ports),
                    Err(error) => {
                        eprintln!("zerun run: {error}");
                        return 1;
                    }
                }
                image_volume_targets = cfg.config.volumes.keys().cloned().collect();
                let env = match build_image_env(
                    &cfg.config.env,
                    &env_file_overrides,
                    &a.env,
                    effective_hostname.as_deref(),
                    &id,
                    a.tty,
                ) {
                    Ok(env) => env,
                    Err(e) => {
                        eprintln!("zerun run: {e}");
                        return 1;
                    }
                };
                let argv = resolve_image_argv(&cfg, a.entrypoint.as_deref(), &a.argv);
                let mut labels = cfg.config.labels.clone();
                labels.extend(a.labels.clone());
                let cwd = a.workdir.clone().or_else(|| {
                    (!cfg.config.working_dir.is_empty()).then(|| cfg.config.working_dir.clone())
                });
                let rootless = syscalls::effective_uid() != 0;
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
                let stop_signal = match resolve_stop_signal(a.stop_signal, &cfg.config.stop_signal)
                {
                    Ok(signal) => signal,
                    Err(e) => {
                        eprintln!("zerun run: {e}");
                        return 1;
                    }
                };
                let image_health = match cfg.config.healthcheck.as_ref() {
                    Some(raw) => match health::from_image(raw) {
                        Ok(check) => check,
                        Err(error) => {
                            eprintln!("zerun run: image config Healthcheck: {error}");
                            return 1;
                        }
                    },
                    None => None,
                };
                let healthcheck = match health::resolve(image_health, &a.health) {
                    Ok(check) => check,
                    Err(error) => {
                        eprintln!("zerun run: {error}");
                        return 2;
                    }
                };
                if healthcheck.is_some() && !a.detach {
                    eprintln!("zerun: warning: image HEALTHCHECK requires -d/--detach; ignoring");
                }
                (
                    rootfs,
                    Some(env),
                    cwd,
                    user,
                    stop_signal,
                    a.stop_timeout.unwrap_or(state::DEFAULT_STOP_TIMEOUT_SECS),
                    argv,
                    labels,
                    capabilities,
                    a.seccomp,
                    healthcheck,
                )
            }
            Err(e) => {
                eprintln!("zerun: {e}");
                return 1;
            }
        }
    };

    if a.publish_all {
        if let Err(error) = network::publish_exposed_ports(&mut a.ports, &a.exposed_ports) {
            eprintln!("zerun run: {error}");
            return 1;
        }
    }

    let mut anonymous_volume_guard = None;
    if resume.is_none() && !image_volume_targets.is_empty() {
        let (image_mounts, names) = match materialize_image_volumes(
            &store,
            &id,
            &rootfs,
            &image_volume_targets,
            &a.volumes,
            &a.tmpfs,
        ) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("zerun run: {error}");
                return 1;
            }
        };
        a.volumes.splice(0..0, image_mounts);
        anonymous_volumes = names.clone();
        if !names.is_empty() {
            anonymous_volume_guard =
                Some(AnonymousVolumeGuard::new(store.clone(), id.clone(), names));
        }
    }

    let ulimits = if let Some(st) = &resume {
        match st.ulimits.as_deref() {
            Some(specs) => match rlimit::UlimitSet::from_specs(specs) {
                Ok(limits) => limits,
                Err(error) => {
                    eprintln!("zerun start: invalid persisted --ulimit: {error}");
                    return 1;
                }
            },
            None => a.ulimits.clone(),
        }
    } else {
        a.ulimits.clone()
    };
    let group_add = match resume.as_ref().and_then(|st| st.group_add.as_ref()) {
        Some(values) => values.clone(),
        None => a.group_add.clone(),
    };
    let sysctls = resume
        .as_ref()
        .map(|st| st.sysctls.clone())
        .unwrap_or_else(|| a.sysctls.clone());

    drop(image_store_lease);
    let container_fs = if let Some(st) = &resume {
        if st.overlay.is_some() {
            match store.reopen_container_fs(&id, &rootfs, st.tmpfs_upper) {
                Ok(fs) => Some(fs),
                Err(e) => {
                    eprintln!("zerun start: {e}");
                    return 1;
                }
            }
        } else {
            None
        }
    } else if a.no_overlay {
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
    inject_resolv_conf(
        a.net,
        &a.dns,
        &a.dns_search,
        &a.dns_options,
        container_fs.as_ref(),
    );
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

    let launch_args = if !a.detach {
        Vec::new()
    } else if let Some(st) = &resume {
        let mut args = st.launch_args.clone().unwrap_or_default();
        set_launch_name(&mut args, st.name.as_deref());
        args
    } else {
        detached_launch_args(&a, &rootfs)
    };

    let image_desc = resume
        .as_ref()
        .map(|st| st.image.clone())
        .unwrap_or_else(|| match &a.image {
            Some(i) => i.clone(),
            None => format!("rootfs:{}", fsutil::canonical_or_self(&rootfs).display()),
        });

    // Where the container actually pivoted to (overlay merged dir or the raw
    // rootfs), recorded in lifecycle state so `ze exec` can chroot there.
    let state_rootfs = match &container_fs {
        Some(fs) => fs.root().display().to_string(),
        None => fsutil::canonical_or_self(&rootfs).display().to_string(),
    };

    let spec = RunSpec {
        rootfs: pivot_root,
        argv,
        hostname: effective_hostname,
        namespaces: a.namespaces,
        net: a.net,
        use_init: a.use_init,
        limits: ResourceLimits {
            memory: a.memory,
            memory_reservation: a.memory_reservation,
            memory_swap: a.memory_swap,
            cpus: a.cpus,
            cpu_shares: a.cpu_shares,
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
        seccomp,
        capabilities,
        ulimits,
        group_add,
        sysctls,
        tty: a.tty,
        // A detached reaper has no caller stdin to pump. Keep the PTY itself
        // (so the workload sees a terminal) but never poll the collector's
        // /dev/null stdin as an interactive session.
        interactive: a.interactive && !a.detach,
        overlay,
        id,
        stop_signal,
        env,
        cwd,
        user,
        ports: a.ports,
        volumes: a.volumes,
        devices: a.devices,
        hosts: host_aliases,
        readonly: a.readonly,
        tmpfs: a.tmpfs,
        shm_size: a.shm_size,
        // Allocated from the file IPAM inside run_container (bridge mode).
        bridge_ip: None,
        run_root: store.run_root().to_path_buf(),
        lifecycle_cgroup: a.detach,
    };

    let lower = container_fs
        .as_ref()
        .map(|fs| fs.lower.display().to_string())
        .unwrap_or_else(|| fsutil::canonical_or_self(&rootfs).display().to_string());

    if a.detach {
        let anonymous_volumes = match anonymous_volume_guard.take() {
            Some(guard) => guard.into_names(),
            None => anonymous_volumes,
        };
        let code = run_detached(
            &store,
            spec,
            container_fs,
            &image_desc,
            &state_rootfs,
            DetachedInfo {
                launch_args,
                stop_signal,
                stop_timeout,
                healthcheck,
                restart_policy,
                name: if resume.is_some() {
                    resume.as_ref().and_then(|st| st.name.clone())
                } else {
                    a.name
                },
                rm: a.rm,
                labels,
                log: a.log,
                lower,
                anonymous_volumes,
                image_volumes: image_volume_targets,
                exposed_ports: a.exposed_ports.iter().map(ToString::to_string).collect(),
                resume,
                report_id,
                image_rootfs_lease,
            },
            id_reservation,
        );
        if code == 0 {
            if let Some(guard) = cidfile_guard.take() {
                guard.keep();
            }
        }
        return code;
    }

    // Foreground: this CLI is the parent and waits for the container.
    let result = namespace::run_container_with_report(spec, |_| Ok(()));
    if let Some(fs) = container_fs {
        store.cleanup_container_fs(&fs);
    }
    match result {
        Ok(exit) => {
            if exit.started {
                if let Some(guard) = cidfile_guard.take() {
                    guard.keep();
                }
            }
            exit.code
        }
        Err(e) => {
            eprintln!("zerun: {e}");
            1
        }
    }
}

fn cmd_pause(args: &[String]) -> i32 {
    cmd_set_paused(args, true)
}

fn cmd_unpause(args: &[String]) -> i32 {
    cmd_set_paused(args, false)
}

/// Pause or resume detached containers through the cgroup v2 freezer.
fn cmd_set_paused(args: &[String], paused: bool) -> i32 {
    let command = if paused { "pause" } else { "unpause" };
    let mut targets: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun {command} CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun {command}: unknown option {other}");
                return 2;
            }
            _ => targets.push(arg.clone()),
        }
    }
    if targets.is_empty() {
        eprintln!("zerun {command}: at least one CONTAINER is required");
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
        match set_container_paused(&store, &target, paused) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun {command}: {e}");
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

/// Apply the cgroup freezer state and persist it without replacing the
/// container identity or writable layer.
fn set_container_paused(store: &Store, target: &str, paused: bool) -> Result<String, String> {
    let initial = state::resolve(store, target)?;
    let _lock = state::ContainerOperationLock::try_acquire(store, &initial.id)?;
    let mut st = state::ContainerState::load(store, &initial.id).ok_or_else(|| {
        format!(
            "container {} disappeared before {}",
            display_name(&initial),
            if paused { "pause" } else { "unpause" }
        )
    })?;
    reconcile_stale_state(store, &mut st)?;
    let name = display_name(&st);
    if st.status != state::Status::Running || !st.pid_alive() {
        return Err(format!(
            "container {name} is not running (status {})",
            st.status_label()
        ));
    }
    let cgroup_path = st.cgroup.as_deref().ok_or_else(|| {
        format!(
            "container {name} has no lifecycle cgroup; pause/unpause requires a delegated \
             cgroup v2 hierarchy"
        )
    })?;
    let cgroup = cgroup::CgroupV2::open_for_container(&st.id, Path::new(cgroup_path))
        .map_err(|e| e.to_string())?;
    cgroup.freeze(paused).map_err(|e| e.to_string())?;
    st.paused = paused;
    if let Err(error) = st.save(store) {
        // Keep the persisted state and the kernel freezer consistent when the
        // state write itself fails. Report a failed rollback because the
        // caller must not assume the requested state was restored.
        if let Err(rollback) = cgroup.freeze(!paused) {
            return Err(format!(
                "{error}; failed to roll back cgroup freezer state: {rollback}"
            ));
        }
        return Err(error.to_string());
    }
    Ok(name)
}

fn cmd_start(args: &[String]) -> i32 {
    let mut targets: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("usage: zerun start CONTAINER...");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("zerun start: unknown option {other}");
                return 2;
            }
            _ => targets.push(arg.clone()),
        }
    }
    if targets.is_empty() {
        eprintln!("zerun start: at least one CONTAINER is required");
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
    let mut failed = false;
    for target in targets {
        match start_one(&store, &target) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun start: {e}");
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

/// Resume a stopped detached container without replacing its identity,
/// writable layer, or console history.
fn start_one(store: &Store, target: &str) -> Result<String, String> {
    let initial = state::resolve(store, target)?;
    let _lock = state::ContainerOperationLock::acquire(store, &initial.id, Duration::from_secs(5))?;
    let mut st = state::ContainerState::load(store, &initial.id).ok_or_else(|| {
        format!(
            "container {} disappeared before start",
            display_name(&initial)
        )
    })?;
    let name = display_name(&st);
    match st.status {
        state::Status::Running if st.pid_alive() => {
            return Err(format!("container {name} is already running"));
        }
        state::Status::Running => {
            if st.reaper_alive() {
                return Err(format!(
                    "container {name} is restarting; stop it before starting manually"
                ));
            }
            reconcile_stale_state(store, &mut st)?;
        }
        state::Status::Created => {
            if st.reaper_alive() {
                return Err(format!("container {name} is still starting"));
            }
        }
        state::Status::Exited if st.restart_pending => {
            if st.reaper_alive() {
                return Err(format!(
                    "container {name} is restarting; stop it before starting manually"
                ));
            }
            reconcile_stale_state(store, &mut st)?;
        }
        state::Status::Exited => {}
    }
    // A paused marker is only meaningful while the PID/cgroup are alive. Clear
    // it before launching the resumed workload so stale/corrupt records cannot
    // make a fresh process look paused.
    st.paused = false;
    let launch_args = st.launch_args.clone().ok_or_else(|| {
        format!("container {name} predates restart metadata and cannot be started")
    })?;
    if launch_args.first().map(String::as_str) != Some("-d") {
        return Err(format!(
            "container {name} has invalid launch metadata and cannot be started"
        ));
    }
    state::clear_restart_suppression(store, &st.id).map_err(|error| error.to_string())?;
    lifecycle::reclaim_resources(store, &st);
    let code = cmd_run_inner(&launch_args, Some(st), false);
    if code != 0 {
        return Err(format!("failed to start container {name}"));
    }
    Ok(name)
}

/// Remove resources prepared for a new detached run when the reaper cannot
/// even be forked. Once the state record is written, the id reservation has
/// been committed, so dropping it alone is no longer enough to avoid a stale
/// `Created` container.
fn cleanup_failed_detached_start(
    store: &Store,
    id: &str,
    container_fs: Option<&store::ContainerFs>,
    anonymous_volumes: &[String],
    state_dir: &Path,
) {
    if let Some(fs) = container_fs {
        store.cleanup_container_fs(fs);
    }
    remove_anonymous_volumes(store, id, anonymous_volumes);
    fsutil::remove_dir_all_quiet(state_dir);
}

/// `zerun run -d` / `zerun start`: fork a per-container reaper, optionally
/// print the container id once the workload is up, and exit. Everything
/// container-shaped (spawn, wait, host-resource teardown, overlay cleanup,
/// state updates) happens in the reaper child (src/lifecycle.rs); it writes
/// `0` / `1:<error>` over the started pipe so the CLI never reports success
/// for a container that failed to start.
struct DetachedInfo {
    launch_args: Vec<String>,
    /// Signal `stop`/`restart` deliver before escalating to SIGKILL. This is
    /// lifecycle metadata, not namespace/child configuration.
    stop_signal: i32,
    /// Grace period between `stop_signal` and the SIGKILL fallback.
    stop_timeout: u64,
    /// Persisted healthcheck selected from the image or run flags.
    healthcheck: Option<health::Healthcheck>,
    /// Automatic restart behavior used by the detached reaper.
    restart_policy: restart::RestartPolicy,
    name: Option<String>,
    rm: bool,
    labels: BTreeMap<String, String>,
    log: logs::LogOptions,
    lower: String,
    /// Image-declared volumes owned by a new detached container. Empty for
    /// resumes because the existing state record remains authoritative.
    anonymous_volumes: Vec<String>,
    /// Original image `VOLUME` targets retained for commit metadata.
    image_volumes: Vec<String>,
    /// Normalized image/CLI exposed-port declarations retained for inspection
    /// and `ps`; publishing itself uses the concrete `RunSpec::ports` list.
    exposed_ports: Vec<String>,
    resume: Option<ContainerState>,
    report_id: bool,
    image_rootfs_lease: Option<image::store::ImageRootfsLease>,
}

fn run_detached(
    store: &Store,
    spec: RunSpec,
    container_fs: Option<store::ContainerFs>,
    image_desc: &str,
    state_rootfs: &str,
    mut info: DetachedInfo,
    mut id_reservation: Option<ContainerIdReservation>,
) -> i32 {
    use std::os::unix::io::AsRawFd;

    let id = spec.id.clone();
    let resuming = info.resume.is_some();
    let sdir = state::ContainerState::dir(store, &id);
    let name_lock = if !resuming && info.name.is_some() {
        match state::ContainerNameLock::try_acquire(store) {
            Ok(lock) => Some(lock),
            Err(error) => {
                eprintln!("zerun run: {error}");
                if !resuming {
                    cleanup_failed_detached_start(
                        store,
                        &id,
                        container_fs.as_ref(),
                        &info.anonymous_volumes,
                        &sdir,
                    );
                }
                return 1;
            }
        }
    } else {
        None
    };
    if !resuming {
        if let Some(n) = &info.name {
            if state::list(store)
                .iter()
                .any(|c| c.name.as_deref() == Some(n))
            {
                eprintln!("zerun run: name '{n}' is already in use by another container");
                if !resuming {
                    cleanup_failed_detached_start(
                        store,
                        &id,
                        container_fs.as_ref(),
                        &info.anonymous_volumes,
                        &sdir,
                    );
                }
                return 1;
            }
        }
    }

    if let Err(e) = fsutil::mkdir_p_mode(&sdir, 0o700) {
        eprintln!("zerun: {e}");
        if !resuming {
            cleanup_failed_detached_start(
                store,
                &id,
                container_fs.as_ref(),
                &info.anonymous_volumes,
                &sdir,
            );
        }
        return 1;
    }
    let log_path = info
        .resume
        .as_ref()
        .map(|st| st.log_path_for(store))
        .unwrap_or_else(|| sdir.join("console.log"));
    let log_fd = match if resuming {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
    } else {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&log_path)
    } {
        Ok(f) => f,
        Err(e) => {
            eprintln!("zerun: open {}: {e}", log_path.display());
            if !resuming {
                cleanup_failed_detached_start(
                    store,
                    &id,
                    container_fs.as_ref(),
                    &info.anonymous_volumes,
                    &sdir,
                );
            }
            return 1;
        }
    };
    if let Err(e) = log_fd.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        eprintln!("zerun: secure {}: {e}", log_path.display());
        if !resuming {
            cleanup_failed_detached_start(
                store,
                &id,
                container_fs.as_ref(),
                &info.anonymous_volumes,
                &sdir,
            );
        }
        return 1;
    }
    let env: Vec<String> = spec
        .env
        .as_ref()
        .map(|pairs| pairs.iter().map(|(k, v)| format!("{k}={v}")).collect())
        .unwrap_or_default();
    let mut st = info.resume.take().unwrap_or_else(|| state::ContainerState {
        version: 1,
        id: id.clone(),
        name: info.name.clone(),
        image: image_desc.to_string(),
        pid: None,
        pid_start_time: None,
        reaper_pid: None,
        reaper_start_time: None,
        status: state::Status::Created,
        paused: false,
        exit_code: None,
        created: state::now_rfc3339(),
        started: None,
        finished: None,
        rootless: syscalls::effective_uid() != 0,
        net: net_label(spec.net),
        namespaces: spec.namespaces,
        ports: Vec::new(),
        port_protocols: None,
        port_ips: None,
        exposed_ports: Vec::new(),
        ip: None,
        cmd: Vec::new(),
        env: Vec::new(),
        cwd: None,
        user: None,
        group_add: None,
        sysctls: BTreeMap::new(),
        stop_signal: signal::DEFAULT_STOP_SIGNAL,
        stop_timeout: state::DEFAULT_STOP_TIMEOUT_SECS,
        restart_policy: restart::RestartPolicy::No,
        restart_count: 0,
        restart_pending: false,
        healthcheck: None,
        health: None,
        capabilities: None,
        seccomp: None,
        ulimits: None,
        anonymous_volumes: Vec::new(),
        image_volumes: Vec::new(),
        labels: BTreeMap::new(),
        log: String::new(),
        log_max_size: None,
        log_max_file: None,
        lower: None,
        rootfs: String::new(),
        overlay: None,
        tmpfs_upper: false,
        launch_args: Some(info.launch_args.clone()),
        table: None,
        veth: None,
        cgroup: None,
        metrics: None,
    });
    st.status = state::Status::Created;
    st.pid = None;
    st.pid_start_time = None;
    st.reaper_pid = None;
    st.reaper_start_time = None;
    st.restart_pending = false;
    st.paused = false;
    st.exit_code = None;
    st.started = None;
    st.finished = None;
    st.ip = None;
    st.rootless = syscalls::effective_uid() != 0;
    st.net = net_label(spec.net);
    st.namespaces = spec.namespaces;
    st.ports = spec.ports.iter().map(|p| (p.host, p.container)).collect();
    st.port_protocols = if spec.ports.is_empty() {
        None
    } else {
        Some(
            spec.ports
                .iter()
                .map(|p| p.protocol.label().to_string())
                .collect(),
        )
    };
    st.port_ips = if spec.ports.is_empty() {
        None
    } else {
        Some(spec.ports.iter().map(|p| p.host_ip.to_string()).collect())
    };
    if !resuming {
        st.exposed_ports = info.exposed_ports.clone();
    }
    st.name = info.name;
    st.cmd = spec.argv.clone();
    st.env = env;
    st.cwd = spec.cwd.clone();
    st.user = spec.user.clone();
    st.stop_signal = info.stop_signal;
    st.stop_timeout = info.stop_timeout;
    st.healthcheck = info.healthcheck;
    st.health = None;
    st.restart_policy = info.restart_policy;
    st.restart_count = 0;
    st.capabilities = Some(spec.capabilities.names());
    st.seccomp = Some(spec.seccomp);
    st.ulimits = (!spec.ulimits.is_empty()).then(|| spec.ulimits.canonical());
    if !resuming {
        st.anonymous_volumes = info.anonymous_volumes.clone();
        st.image_volumes = info.image_volumes.clone();
    }
    st.group_add = (!spec.group_add.is_empty()).then(|| spec.group_add.clone());
    st.sysctls = spec.sysctls.clone();
    st.labels = info.labels;
    st.log = log_path.display().to_string();
    st.log_max_size = Some(info.log.max_size);
    st.log_max_file = Some(info.log.max_files);
    st.lower = Some(info.lower);
    st.rootfs = state_rootfs.to_string();
    st.overlay = container_fs
        .as_ref()
        .map(|fs| fs.dir().display().to_string());
    st.tmpfs_upper = container_fs.as_ref().is_some_and(|fs| fs.tmpfs_upper);
    st.table = None;
    st.veth = None;
    st.cgroup = None;
    st.metrics = None;
    st.launch_args = Some(info.launch_args.clone());
    if let Err(e) = st.save(store) {
        eprintln!("zerun: {e}");
        if !resuming {
            cleanup_failed_detached_start(
                store,
                &id,
                container_fs.as_ref(),
                &info.anonymous_volumes,
                &sdir,
            );
        }
        return 1;
    }
    // The state record now owns the directory. Disarm the reservation before
    // forking so neither the CLI nor the reaper removes it on scope exit.
    if let Some(reservation) = id_reservation.as_mut() {
        reservation.commit();
    }
    // The persisted lower-rootfs reference now protects this image from GC.
    // Drop before fork so the reaper cannot retain a rootfs lease for life.
    drop(info.image_rootfs_lease.take());
    // The name is now persisted and visible to the next serialized creator or
    // rename. Release before fork so the reaper cannot retain the global lock.
    drop(name_lock);

    let (started_r, started_w) = match syscalls::pipe2_cloexec() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zerun: {e}");
            if !resuming {
                cleanup_failed_detached_start(
                    store,
                    &id,
                    container_fs.as_ref(),
                    &info.anonymous_volumes,
                    &sdir,
                );
            }
            return 1;
        }
    };

    // Double purpose of the fork: the reaper becomes the container's parent and
    // survives this CLI; setsid() detaches it from the terminal so closing the
    // terminal cannot kill the container.
    match syscalls::fork_process() {
        Err(error) => {
            eprintln!("zerun: fork: {error}");
            syscalls::close(started_r);
            syscalls::close(started_w);
            if !resuming {
                cleanup_failed_detached_start(
                    store,
                    &id,
                    container_fs.as_ref(),
                    &info.anonymous_volumes,
                    &sdir,
                );
            }
            1
        }
        Ok(0) => {
            // --- reaper child ---
            syscalls::close(started_r);
            if let Err(error) = syscalls::new_session() {
                eprintln!("zerun: setsid: {error}");
                crate::syscalls::exit_process(1);
            }
            let code = lifecycle::run_detached(
                store.clone(),
                spec,
                container_fs,
                info.rm,
                started_w,
                lifecycle::LogTarget {
                    path: &log_path,
                    previous_fd: log_fd.as_raw_fd(),
                    options: info.log,
                },
            );
            crate::syscalls::exit_process(code)
        }
        Ok(_) => {
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
                if info.report_id {
                    println!("{id}");
                }
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
    if a.tty {
        args.push("--tty".to_string());
    }
    if let Some(name) = &a.name {
        args.extend(["--name".to_string(), name.clone()]);
    }
    if let Some(path) = &a.cidfile {
        args.extend(["--cidfile".to_string(), path.clone()]);
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
    if let Some(v) = a.cpu_shares {
        args.extend(["--cpu-shares".to_string(), v.to_string()]);
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
    for value in a.ulimits.canonical() {
        args.extend(["--ulimit".to_string(), value]);
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
    for (flag, mode) in [("--pid", a.namespaces.pid), ("--uts", a.namespaces.uts)] {
        if mode == state::NamespaceMode::Host {
            args.extend([flag.to_string(), mode.label().to_string()]);
        }
    }
    if a.namespaces.ipc != state::IpcMode::Private {
        args.extend(["--ipc".to_string(), a.namespaces.ipc.label().to_string()]);
    }
    if let Some(v) = &a.user {
        args.extend(["--user".to_string(), v.clone()]);
    }
    for value in &a.group_add {
        args.extend(["--group-add".to_string(), value.clone()]);
    }
    if let Some(v) = a.stop_signal {
        args.extend(["--stop-signal".to_string(), signal::name(v)]);
    }
    if let Some(v) = a.stop_timeout {
        args.extend(["--stop-timeout".to_string(), v.to_string()]);
    }
    if let Some(v) = &a.health.cmd {
        args.extend(["--health-cmd".to_string(), v.clone()]);
    }
    if let Some(v) = a.health.interval_ns {
        args.extend(["--health-interval".to_string(), format!("{v}ns")]);
    }
    if let Some(v) = a.health.timeout_ns {
        args.extend(["--health-timeout".to_string(), format!("{v}ns")]);
    }
    if let Some(v) = a.health.start_period_ns {
        args.extend(["--health-start-period".to_string(), format!("{v}ns")]);
    }
    if let Some(v) = a.health.start_interval_ns {
        args.extend(["--health-start-interval".to_string(), format!("{v}ns")]);
    }
    if let Some(v) = a.health.retries {
        args.extend(["--health-retries".to_string(), v.to_string()]);
    }
    if a.health.disabled {
        args.push("--no-healthcheck".to_string());
    }
    if let Some(policy) = a.restart.filter(|policy| policy.is_enabled()) {
        args.extend(["--restart".to_string(), policy.to_string()]);
    }
    args.extend(["--net".to_string(), net_label(a.net)]);
    if a.use_init {
        args.push("--init".to_string());
    }
    if matches!(a.seccomp, SeccompMode::Unconfined) {
        args.extend(["--seccomp".to_string(), "unconfined".to_string()]);
    }
    for cap in &a.cap_add {
        args.extend(["--cap-add".to_string(), cap.clone()]);
    }
    for cap in &a.cap_drop {
        args.extend(["--cap-drop".to_string(), cap.clone()]);
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
    if let Some(size) = a.shm_size {
        args.extend(["--shm-size".to_string(), size.to_string()]);
    }
    if let Some(v) = &a.platform {
        args.extend(["--platform".to_string(), v.clone()]);
    }
    if let Some(v) = &a.entrypoint {
        args.extend(["--entrypoint".to_string(), v.clone()]);
    }
    if let Some(v) = &a.workdir {
        args.extend(["--workdir".to_string(), v.clone()]);
    }
    if a.pull != PullPolicy::Missing {
        args.extend(["--pull".to_string(), a.pull.label().to_string()]);
    }
    if a.log_options_set {
        args.extend(["--log-max-size".to_string(), a.log.max_size.to_string()]);
        args.extend(["--log-max-file".to_string(), a.log.max_files.to_string()]);
    }
    for path in &a.env_files {
        args.extend(["--env-file".to_string(), path.clone()]);
    }
    for v in &a.env {
        args.extend(["--env".to_string(), v.clone()]);
    }
    for p in &a.ports {
        args.extend(["--publish".to_string(), p.to_string()]);
    }
    for v in &a.volumes {
        args.extend(["--volume".to_string(), v.raw.clone()]);
    }
    for device in &a.devices {
        args.extend(["--device".to_string(), device.raw.clone()]);
    }
    for v in &a.dns {
        args.extend(["--dns".to_string(), v.clone()]);
    }
    for v in &a.dns_search {
        args.extend(["--dns-search".to_string(), v.clone()]);
    }
    for v in &a.dns_options {
        args.extend(["--dns-option".to_string(), v.clone()]);
    }
    for v in &a.add_hosts {
        args.extend(["--add-host".to_string(), v.render()]);
    }
    for (key, value) in &a.sysctls {
        args.extend(["--sysctl".to_string(), format!("{key}={value}")]);
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

/// Keep canonical launch metadata in sync with a container rename.
fn set_launch_name(args: &mut Vec<String>, name: Option<&str>) {
    let option_end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let name_pos = args[..option_end].iter().position(|arg| arg == "--name");
    match (name_pos, name) {
        (Some(pos), Some(name)) if pos + 1 < args.len() => args[pos + 1] = name.to_string(),
        (Some(pos), _) => {
            let end = (pos + 2).min(args.len());
            args.drain(pos..end);
            if let Some(name) = name {
                args.insert(pos, "--name".to_string());
                args.insert(pos + 1, name.to_string());
            }
        }
        (None, Some(name)) => {
            let at = usize::from(args.first().map(String::as_str) == Some("-d"));
            args.splice(at..at, ["--name".to_string(), name.to_string()]);
        }
        (None, None) => {}
    }
}

fn launch_has_flag(args: &[String], flag: &str) -> bool {
    let option_end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    args[..option_end].iter().any(|arg| arg == flag)
}

fn cmd_restart(args: &[String]) -> i32 {
    let mut timeout_secs: Option<u64> = None;
    let mut stop_signal: Option<i32> = None;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-t" | "--time" => match next_value(args, &mut i, a) {
                Ok(v) => match parse_seconds(&v, "--time") {
                    Ok(n) => timeout_secs = Some(n),
                    Err(e) => {
                        eprintln!("zerun restart: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun restart: {e}");
                    return 2;
                }
            },
            "-s" | "--signal" => match next_value(args, &mut i, a) {
                Ok(v) => match signal::parse(&v) {
                    Ok(signal) => stop_signal = Some(signal),
                    Err(e) => {
                        eprintln!("zerun restart: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun restart: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun restart [--time SECONDS] [--signal SIGNAL] CONTAINER...");
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
        let st = match state::resolve(&store, &target) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("zerun restart: {e}");
                failed = true;
                continue;
            }
        };
        match st.launch_args.as_ref() {
            Some(args) if args.first().map(String::as_str) == Some("-d") => {}
            _ => {
                eprintln!(
                    "zerun restart: container {} predates restart metadata and cannot be restarted",
                    display_name(&st)
                );
                failed = true;
                continue;
            }
        }
        if st
            .launch_args
            .as_deref()
            .is_some_and(|args| launch_has_flag(args, "--rm"))
        {
            eprintln!(
                "zerun restart: container {} uses --rm and is removed when stopped; recreate it with run",
                display_name(&st)
            );
            failed = true;
            continue;
        }
        if let Err(e) = stop_one(&store, &target, timeout_secs, stop_signal) {
            eprintln!("zerun restart: {e}");
            failed = true;
            continue;
        }
        match start_one(&store, &target) {
            Ok(name) => println!("{name}"),
            Err(e) => {
                eprintln!("zerun restart: {e}");
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
    let initial = match state::resolve(&store, container) {
        Ok(st) => st,
        Err(e) => {
            eprintln!("zerun commit: {e}");
            return 1;
        }
    };
    let _container_lock = match state::ContainerOperationLock::try_acquire(&store, &initial.id) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("zerun commit: {e}");
            return 1;
        }
    };
    let st = match state::ContainerState::load(&store, &initial.id) {
        Some(st) => st,
        None => {
            eprintln!(
                "zerun commit: container {} disappeared",
                display_name(&initial)
            );
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
    let exposed_ports = match normalize_exposed_port_metadata(&st.exposed_ports) {
        Ok(ports) => ports,
        Err(error) => {
            eprintln!("zerun commit: {error}");
            return 1;
        }
    };
    let stop_signal = match signal::validate(st.stop_signal) {
        Ok(signal) => signal::name(signal),
        Err(error) => {
            eprintln!("zerun commit: invalid persisted stop signal: {error}");
            return 1;
        }
    };

    // Reconstruct from the host-side lower rootfs and overlay upper. A live
    // container's merged view lives in its own mount namespace (and includes
    // volumes, tmpfs, and pseudo-filesystems), so archiving /proc/<pid>/root
    // is both host-dependent and would leak mounted volume data into the image.
    // The persisted upper contains exactly the container's rootfs changes.
    let mut rebuilt: Option<std::path::PathBuf> = None;
    let rootfs = match st.overlay.as_ref() {
        Some(_) => {
            let upper = store.container_overlay_dir(&st.id).join("upper");
            let staging = imgstore.blob_tmp("commit-source");
            match lower_rootfs(&store, &st) {
                Ok(lower) => {
                    let root = match image::commit::rebuild_rootfs(&lower, &upper, &staging) {
                        Ok(p) => p,
                        Err(e) => {
                            fsutil::remove_dir_all_quiet(&staging);
                            eprintln!("zerun commit: rebuild container rootfs: {e}");
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
        None => match lower_rootfs(&store, &st) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("zerun commit: {e}");
                return 1;
            }
        },
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
        volumes: st.image_volumes.clone(),
        exposed_ports,
        stop_signal: Some(stop_signal),
        healthcheck: st.healthcheck.clone(),
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
/// Docker semantics: explicit `--dns`, `--dns-search`, and `--dns-option`
/// values replace their corresponding host lists, while unspecified lists are
/// inherited. The file is written into the per-run overlay `upper` on the host
/// side, so it appears in the container's `/etc` once the overlay is mounted —
/// no bind mounts across the pivot are needed.
fn inject_resolv_conf(
    net: NetMode,
    explicit_nameservers: &[String],
    explicit_search: &[String],
    explicit_options: &[String],
    container_fs: Option<&store::ContainerFs>,
) {
    if net != NetMode::Bridge {
        return;
    }
    let Some(fs) = container_fs else {
        eprintln!("zerun: warning: --no-overlay has no writable layer; DNS is not injected");
        return;
    };
    let config = match resolv::ResolvConf::effective(
        explicit_nameservers,
        explicit_search,
        explicit_options,
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("zerun: warning: DNS injection: {error}");
            return;
        }
    };
    let content = config.render();
    let etc = fs.upper.join("etc");
    if let Err(e) = fsutil::mkdir_p(&etc) {
        eprintln!("zerun: warning: DNS injection: {e}");
        return;
    }
    if let Err(e) = fsutil::atomic_write(&etc.join("resolv.conf"), content.as_bytes()) {
        eprintln!("zerun: warning: DNS injection: {e}");
    }
}

/// Resolve an image for `run`: find it locally or pull it. Returns the
/// read-only rootfs path plus the parsed image config.
fn resolve_run_image(
    store: &Store,
    reference: &Reference,
    platform: Option<&str>,
    pull: PullPolicy,
    lease: &image::store::ImageStoreLease,
) -> Result<(PathBuf, image::config::ImageConfig), error::ZError> {
    let imgstore = image::store::ImageStore::open(store)?;
    let requested = platform
        .map(image::manifest::Platform::parse)
        .transpose()?
        .unwrap_or_else(image::manifest::host_platform);
    let mut refreshing = pull == PullPolicy::Always;
    if pull != PullPolicy::Always {
        if let Some((rootfs, config)) = image::local_image(&imgstore, reference)? {
            if local_image_matches_platform(&config, &requested) {
                return Ok((rootfs, config));
            }
            if pull == PullPolicy::Never {
                return Err(crate::zerr!(
                    "local image {} is {}/{} but requested {}/{} and --pull=never was set",
                    reference.canonical(),
                    config.os,
                    config.architecture,
                    requested.os,
                    requested.architecture
                ));
            }
            refreshing = true;
            eprintln!(
                "zerun: local image {} is {}/{}, refreshing for requested {}/{}...",
                reference.canonical(),
                config.os,
                config.architecture,
                requested.os,
                requested.architecture
            );
        }
    }
    if pull == PullPolicy::Never {
        return Err(crate::zerr!(
            "image {} is not present locally and --pull=never was set",
            reference.canonical()
        ));
    }
    if pull == PullPolicy::Always {
        eprintln!("zerun: refreshing image {}...", reference.canonical());
    } else if !refreshing {
        eprintln!(
            "zerun: image {} not found locally, pulling...",
            reference.canonical()
        );
    }
    let mut client = image::registry::RegistryClient::new();
    let opts = PullOptions {
        platform: platform.map(str::to_string),
    };
    let pulled = image::pull_image_with_lease(&imgstore, &mut client, reference, &opts, lease)?;
    eprintln!(
        "zerun: pulled {} ({}), rootfs ready",
        reference.canonical(),
        fsutil::human_size(pulled.size_bytes)
    );
    Ok((pulled.rootfs, pulled.config))
}

/// Whether a local image config can satisfy the requested platform. Empty
/// config fields are tolerated for foreign/older images.
fn local_image_matches_platform(
    config: &image::config::ImageConfig,
    requested: &image::manifest::Platform,
) -> bool {
    (config.os.is_empty() || config.os == requested.os)
        && (config.architecture.is_empty() || config.architecture == requested.architecture)
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
    env_file: &[(String, String)],
    overrides: &[String],
    hostname: Option<&str>,
    id: &str,
    tty: bool,
) -> Result<Vec<(String, String)>, String> {
    let mut env: Vec<(String, String)> = Vec::new();
    for entry in cfg_env {
        let Some((k, v)) = entry.split_once('=') else {
            return Err(format!(
                "image contains malformed environment entry '{entry}'"
            ));
        };
        workload::validate_env_pair(k, v)
            .map_err(|e| format!("invalid image environment entry '{entry}': {e}"))?;
        upsert_env(&mut env, k.to_string(), v.to_string());
    }
    if workload::env_value(&env, "PATH").is_none() {
        env.push(("PATH".to_string(), workload::DEFAULT_PATH.to_string()));
    }
    if workload::env_value(&env, "HOME").is_none() {
        env.push(("HOME".to_string(), "/root".to_string()));
    }
    for (key, value) in env_file {
        upsert_env(&mut env, key.clone(), value.clone());
    }
    for o in overrides {
        workload::validate_env_spec(o).map_err(|e| format!("invalid --env '{o}': {e}"))?;
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
    Ok(env)
}

fn upsert_env(env: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some(slot) = env.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        env.push((key, value));
    }
}

/// Resolve Docker's `STOPSIGNAL` precedence: an explicit run flag wins over
/// the image config, which wins over the runtime default. An invalid image
/// value fails before container resources are created.
fn resolve_stop_signal(explicit: Option<i32>, image: &str) -> Result<i32, String> {
    if let Some(signal) = explicit {
        return signal::validate(signal);
    }
    if image.is_empty() {
        return Ok(signal::DEFAULT_STOP_SIGNAL);
    }
    signal::parse(image).map_err(|e| format!("image config StopSignal: {e}"))
}

/// Parse image `config.ExposedPorts` keys into the same normalized set used
/// by `--expose`. Docker records these as `PORT/PROTOCOL` keys, but accepting
/// the bare-port form keeps hand-built OCI configs compatible.
fn image_exposed_ports(
    cfg: &image::config::ImageConfig,
) -> Result<BTreeSet<network::ExposedPort>, String> {
    let mut ports = BTreeSet::new();
    for key in cfg.config.exposed_ports.keys() {
        let parsed = network::parse_expose(key).map_err(|error| {
            format!("image config ExposedPorts contains invalid key '{key}': {error}")
        })?;
        ports.extend(parsed);
    }
    Ok(ports)
}

/// Validate and normalize exposed-port metadata loaded from a container state
/// record before carrying it into a committed image config.
fn normalize_exposed_port_metadata(values: &[String]) -> Result<Vec<String>, String> {
    let mut ports = BTreeSet::new();
    for value in values {
        let parsed = network::parse_expose(value).map_err(|error| {
            format!("container state has invalid exposed port '{value}': {error}")
        })?;
        ports.extend(parsed);
    }
    Ok(ports.iter().map(ToString::to_string).collect())
}

/// Combine image Entrypoint/Cmd with CLI arguments (docker semantics):
/// CLI args replace Cmd but never Entrypoint; no CLI args run Entrypoint+Cmd.
/// An explicit `--entrypoint` replaces the image entrypoint; an empty value
/// resets it.
fn resolve_image_argv(
    cfg: &image::config::ImageConfig,
    entrypoint: Option<&str>,
    cli: &[String],
) -> Vec<String> {
    let entry = match entrypoint {
        Some("") => Vec::new(),
        Some(value) => vec![value.to_string()],
        None => cfg.config.entrypoint.clone(),
    };
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

#[derive(Debug, Default, PartialEq, Eq)]
struct ImagesOptions {
    digests: bool,
    quiet: bool,
    json: bool,
}

fn parse_images_options(args: &[String]) -> Result<ImagesOptions, String> {
    let mut opts = ImagesOptions::default();
    for arg in args {
        match arg.as_str() {
            "--digests" => opts.digests = true,
            "-q" | "--quiet" => opts.quiet = true,
            "--json" => opts.json = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(opts)
}

fn image_digest(record: &image::store::ImageRecord) -> &str {
    record.index.as_deref().unwrap_or(&record.manifest)
}

fn image_id(record: &image::store::ImageRecord) -> String {
    image::store::digest_hex(&record.manifest)
        .map(|h| h[..12.min(h.len())].to_string())
        .unwrap_or_else(|_| "?".to_string())
}

fn cmd_images(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: zerun images [--digests] [-q|--quiet] [--json]");
        return 0;
    }
    let opts = match parse_images_options(args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("zerun images: {e}");
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
    let mut records = match imgstore.records() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    records.sort_by(|a, b| a.name.cmp(&b.name).then(a.tag.cmp(&b.tag)));
    if opts.json {
        match serde_json::to_string_pretty(&records) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("zerun images: serialize JSON: {e}");
                return 1;
            }
        }
        return 0;
    }
    if opts.quiet {
        for r in &records {
            println!("{}", image_id(r));
        }
        return 0;
    }
    if opts.digests {
        println!(
            "{:<40} {:<16} {:<14} {:<71} SIZE",
            "REPOSITORY", "TAG", "IMAGE ID", "DIGEST"
        );
    } else {
        println!("{:<40} {:<16} {:<14} SIZE", "REPOSITORY", "TAG", "IMAGE ID");
    }
    for r in &records {
        let tag = r.tag.as_deref().unwrap_or("<none>");
        let id = image_id(r);
        if opts.digests {
            println!(
                "{:<40} {:<16} {:<14} {:<71} {}",
                r.name,
                tag,
                id,
                image_digest(r),
                fsutil::human_size(r.size_bytes)
            );
        } else {
            println!(
                "{:<40} {:<16} {:<14} {}",
                r.name,
                tag,
                id,
                fsutil::human_size(r.size_bytes)
            );
        }
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
        if let Err(e) =
            imgstore.gc_with_protected_from(|| protected_image_rootfs(&imgstore, &store))
        {
            eprintln!("zerun rmi: garbage collection: {e}");
            failed = true;
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
    let euid = syscalls::effective_uid();
    if !a.net_specified {
        a.net = default_net(euid);
    }
    if a.pids.is_none() {
        a.pids = default_pids_limit(euid);
    }
    match service::generate(&a, &mut std::io::stdout().lock()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("zerun generate-service: {e}");
            1
        }
    }
}

fn print_doctor_usage() {
    println!("usage: zerun doctor");
    println!();
    println!("Reports host capabilities used by Zerun. The command exits 1 when the");
    println!("capabilities required for the current user's run mode are unavailable.");
}

fn cmd_doctor(args: &[String]) -> i32 {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_doctor_usage();
        return 0;
    }
    if !args.is_empty() {
        eprintln!("zerun doctor: no options or arguments are accepted");
        print_doctor_usage();
        return 2;
    }

    println!("== Zerun environment doctor ==");
    if let Some(rel) = syscalls::kernel_release() {
        println!("kernel release : {rel}  (baseline recommendation >= 5.10 LTS)");
    }

    let mut required_failure = false;
    let cgroup_available = match cgroup::detect_cgroup2_root() {
        Ok(root) => {
            let ctrl = std::fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
            println!(
                "cgroup v2      : OK at {}  controllers: {}",
                root.display(),
                ctrl.trim()
            );
            true
        }
        Err(e) => {
            println!("cgroup v2      : MISSING ({e})");
            false
        }
    };

    let uid = syscalls::effective_uid();
    if uid == 0 {
        if cgroup_available {
            match device_cgroup::probe() {
                Ok(()) => println!(
                    "device policy  : OK (mandatory cgroup v2 eBPF allowlist for rootful runs)"
                ),
                Err(e) => {
                    println!("device policy  : UNAVAILABLE ({e}); rootful runs will be refused");
                    required_failure = true;
                }
            }
        } else {
            println!("device policy  : UNAVAILABLE (cgroup v2 is required); rootful runs will be refused");
            required_failure = true;
        }
    } else {
        println!("device policy  : not required for rootless runs");
    }

    let user_namespace_limit = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if uid == 0 {
        match user_namespace_limit {
            Some(limit) => println!("user namespaces: max = {limit}"),
            None => println!("user namespaces: max unavailable"),
        }
    } else {
        match namespace::probe_rootless_user_namespace() {
            Ok(()) => match user_namespace_limit {
                Some(limit) => {
                    println!("user namespaces: OK (unprivileged mapping works; max = {limit})")
                }
                None => println!("user namespaces: OK (unprivileged mapping works)"),
            },
            Err(error) => {
                println!("user namespaces: UNAVAILABLE ({error}); rootless runs will be refused");
                required_failure = true;
            }
        }
    }

    match std::fs::read_to_string("/proc/filesystems") {
        Ok(fs) => println!(
            "overlayfs      : {}",
            if fs.lines().any(|line| line.contains("overlay")) {
                "available (used from M2)"
            } else {
                "NOT available"
            }
        ),
        Err(_) => println!("overlayfs      : unknown"),
    }
    println!("cap_last_cap   : {}", syscalls::cap_last_cap());

    match Store::detect() {
        Ok(store) => {
            println!("data root      : {}", store.data_root().display());
            println!("runtime root   : {}", store.run_root().display());
            match network::check_ipam_state(store.run_root()) {
                Ok(false) => println!("bridge IPAM    : not initialized"),
                Ok(true) => println!("bridge IPAM    : OK"),
                Err(error) => println!("bridge IPAM    : INVALID ({error})"),
            }
        }
        Err(error) => {
            println!("data root      : <error: {error}>");
            println!("runtime root   : <error>");
            println!("bridge IPAM    : unknown");
            required_failure = true;
        }
    }
    println!(
        "uid            : {} (rootful isolation needs uid=0; non-root goes rootless via NEWUSER)",
        uid
    );
    if required_failure {
        println!("readiness      : FAIL (required host capabilities are unavailable)");
        1
    } else {
        println!("readiness      : OK (this user can launch containers)");
        0
    }
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
        if let Err(e) = reconcile_stale_state(&store, &mut st) {
            eprintln!("zerun ps: {e}");
            return 1;
        }
        if !all
            && !filter.widens_status()
            && st.status != state::Status::Running
            && !st.restart_pending
        {
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
            &st.exposed_ports,
        ),
        st.name.clone().unwrap_or_default(),
    ]
}

fn ps_status(st: &ContainerState) -> String {
    if st.restart_pending {
        let code = st.exit_code.unwrap_or(-1);
        return match &st.finished {
            Some(t) => format!("Restarting ({code}) {} ago", elapsed_str(t)),
            None => format!("Restarting ({code})"),
        };
    }
    match st.status {
        state::Status::Running => {
            let status = match &st.started {
                Some(t) => format!("Up {}", elapsed_str(t)),
                None => "Up".to_string(),
            };
            if st.paused {
                format!("{status} (Paused)")
            } else {
                match st.health.as_ref().map(|health| health.status) {
                    Some(state::HealthStatus::Healthy) => format!("{status} (healthy)"),
                    Some(state::HealthStatus::Unhealthy) => format!("{status} (unhealthy)"),
                    Some(state::HealthStatus::Starting) => format!("{status} (health: starting)"),
                    None => status,
                }
            }
        }
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
    exposed: &[String],
) -> String {
    let mut labels: Vec<String> = ports
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
        .collect();
    let mut seen: BTreeSet<(u16, String)> = ports
        .iter()
        .enumerate()
        .map(|(i, (_, container))| {
            let protocol = protocols
                .and_then(|values| values.get(i).map(String::as_str))
                .unwrap_or("tcp")
                .to_ascii_lowercase();
            (*container, protocol)
        })
        .collect();
    for value in exposed {
        let Ok(ports) = network::parse_expose(value) else {
            continue;
        };
        for port in ports {
            let protocol = port.protocol.label().to_string();
            if seen.insert((port.port, protocol.clone())) {
                labels.push(format!("{}/{protocol}", port.port));
            }
        }
    }
    labels.join(", ")
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
    // `wait` reports the workload exit code as data. A non-zero workload exit
    // is not a failure of the wait operation itself; this matches Docker's
    // `docker wait` behavior and lets scripts distinguish lookup errors from
    // the container's own status using the printed value.
    let mut failed = false;
    for target in targets {
        match wait_one(&store, &target) {
            Ok(code) => println!("{code}"),
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
            if !st.restart_pending {
                return Ok(st.exit_code.unwrap_or(-1));
            }
            // An automatic retry is in progress while the reaper is alive.
            // If that reaper disappeared, reconcile the stored attempt and
            // preserve its exit code instead of waiting forever.
            reconcile_stale_state(store, &mut st)?;
            if st.status == state::Status::Exited && !st.restart_pending {
                return Ok(st.exit_code.unwrap_or(-1));
            }
        }
        if st.status == state::Status::Running && !st.pid_alive() {
            reconcile_stale_state(store, &mut st)?;
            if st.status == state::Status::Exited && !st.restart_pending {
                return Ok(st.exit_code.unwrap_or(-1));
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn cmd_stop(args: &[String]) -> i32 {
    let mut timeout_secs: Option<u64> = None;
    let mut stop_signal: Option<i32> = None;
    let mut targets: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-t" | "--time" => match next_value(args, &mut i, a) {
                Ok(v) => match parse_seconds(&v, "--time") {
                    Ok(n) => timeout_secs = Some(n),
                    Err(e) => {
                        eprintln!("zerun stop: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun stop: {e}");
                    return 2;
                }
            },
            "-s" | "--signal" => match next_value(args, &mut i, a) {
                Ok(v) => match signal::parse(&v) {
                    Ok(signal) => stop_signal = Some(signal),
                    Err(e) => {
                        eprintln!("zerun stop: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun stop: {e}");
                    return 2;
                }
            },
            "-h" | "--help" => {
                println!("usage: zerun stop [--time SECONDS] [--signal SIGNAL] CONTAINER...");
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
        match stop_one(&store, &t, timeout_secs, stop_signal) {
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
                Ok(v) => match signal::parse(&v) {
                    Ok(sig) => signal = sig,
                    Err(e) => {
                        eprintln!("zerun kill: {e}");
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

/// Send one signal to a detached container's PID 1. Unlike `stop`, this does
/// not impose a grace period; if the signal terminates the container, wait
/// briefly for the reaper to persist its final state.
fn kill_one(store: &Store, target: &str, signal: libc::c_int) -> Result<String, String> {
    let initial = state::resolve(store, target)?;
    let lock = state::ContainerOperationLock::acquire(store, &initial.id, Duration::from_secs(5))?;
    let mut st = state::ContainerState::load(store, &initial.id).ok_or_else(|| {
        format!(
            "container {} disappeared before kill",
            display_name(&initial)
        )
    })?;
    let name = display_name(&st);
    let policy_enabled = st.restart_policy.is_enabled();
    let suppress = policy_enabled && !state::restart_is_suppressed(store, &st.id);
    if suppress {
        state::suppress_restart(store, &st.id).map_err(|error| error.to_string())?;
    }
    match st.status {
        state::Status::Exited | state::Status::Created => {
            if st.restart_pending && !st.reaper_alive() {
                reconcile_stale_state(store, &mut st)?;
            }
            let pending = st.restart_pending;
            drop(lock);
            if pending {
                lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
            }
            return Ok(name);
        }
        state::Status::Running => {}
    }
    if !st.pid_alive() {
        if !st.reaper_alive() {
            reconcile_stale_state(store, &mut st)?;
        }
        drop(lock);
        lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
        return Ok(name);
    }
    if st.paused && signal_requires_thaw(signal) {
        if let Err(error) = thaw_paused_container(store, &mut st) {
            if suppress {
                let _ = state::clear_restart_suppression(store, &st.id);
            }
            return Err(error);
        }
    }
    if let Err(error) = signal_container(&st, signal) {
        if suppress {
            let _ = state::clear_restart_suppression(store, &st.id);
        }
        return Err(format!("signal container {name}: {error}"));
    }
    // Give a terminating signal a brief chance to take effect. A control
    // signal that leaves the workload alive must not permanently disable its
    // restart policy.
    let exited = wait_pid_gone(&st, Duration::from_millis(500));
    drop(lock);
    if exited {
        lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
    } else if suppress {
        state::clear_restart_suppression(store, &st.id).map_err(|error| error.to_string())?;
    }
    Ok(name)
}

/// Signals whose normal purpose is to terminate the workload must be
/// deliverable even while the cgroup freezer is active. STOP/CONT and
/// non-terminating notification signals leave the pause state untouched.
fn signal_requires_thaw(signal: libc::c_int) -> bool {
    matches!(
        signal,
        libc::SIGHUP
            | libc::SIGINT
            | libc::SIGQUIT
            | libc::SIGILL
            | libc::SIGTRAP
            | libc::SIGABRT
            | libc::SIGBUS
            | libc::SIGFPE
            | libc::SIGKILL
            | libc::SIGUSR1
            | libc::SIGSEGV
            | libc::SIGUSR2
            | libc::SIGPIPE
            | libc::SIGALRM
            | libc::SIGTERM
            | libc::SIGSTKFLT
            | libc::SIGXCPU
            | libc::SIGXFSZ
            | libc::SIGVTALRM
            | libc::SIGPROF
            | libc::SIGIO
            | libc::SIGPWR
            | libc::SIGSYS
    )
}

/// Thaw a paused container before a terminating lifecycle action and persist
/// the new state immediately so a crash cannot leave a frozen process marked
/// as unpaused.
fn thaw_paused_container(store: &Store, st: &mut state::ContainerState) -> Result<(), String> {
    if !st.paused {
        return Ok(());
    }
    let name = display_name(st);
    let cgroup_path = st
        .cgroup
        .as_deref()
        .ok_or_else(|| format!("container {name} is marked paused but has no lifecycle cgroup"))?;
    let cgroup = cgroup::CgroupV2::open_for_container(&st.id, Path::new(cgroup_path))
        .map_err(|e| e.to_string())?;
    cgroup.freeze(false).map_err(|e| e.to_string())?;
    st.paused = false;
    if let Err(error) = st.save(store) {
        // A failed state write must not leave the persisted record claiming the
        // container is paused while its cgroup is already thawed.
        if let Err(rollback) = cgroup.freeze(true) {
            return Err(format!(
                "{error}; failed to restore cgroup freezer state: {rollback}"
            ));
        }
        st.paused = true;
        return Err(error.to_string());
    }
    Ok(())
}

/// Docker semantics: send the container's configured signal (SIGTERM by
/// default), wait for its configured timeout (or the `--time` override), then
/// SIGKILL. The per-run reaper observes the death and persists the exit itself;
/// when it is gone (crash) the stale record is reconciled instead.
fn stop_one(
    store: &Store,
    target: &str,
    timeout_override: Option<u64>,
    override_signal: Option<i32>,
) -> Result<String, String> {
    let initial = state::resolve(store, target)?;
    let lock = state::ContainerOperationLock::acquire(store, &initial.id, Duration::from_secs(5))?;
    let mut st = state::ContainerState::load(store, &initial.id).ok_or_else(|| {
        format!(
            "container {} disappeared before stop",
            display_name(&initial)
        )
    })?;
    let name = display_name(&st);
    let policy_enabled = st.restart_policy.is_enabled();
    match st.status {
        state::Status::Exited | state::Status::Created => {
            if policy_enabled {
                state::suppress_restart(store, &st.id).map_err(|error| error.to_string())?;
            }
            if st.restart_pending && !st.reaper_alive() {
                reconcile_stale_state(store, &mut st)?;
            }
            let pending = st.restart_pending;
            drop(lock);
            if pending {
                lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
            }
            return Ok(name); // nothing to signal
        }
        state::Status::Running => {}
    }
    if !st.pid_alive() {
        if policy_enabled {
            state::suppress_restart(store, &st.id).map_err(|error| error.to_string())?;
        }
        if !st.reaper_alive() {
            reconcile_stale_state(store, &mut st)?;
        }
        drop(lock);
        lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
        return Ok(name);
    }
    let stop_signal =
        signal::validate(override_signal.unwrap_or(st.stop_signal)).map_err(|e| e.to_string())?;
    let timeout_secs = timeout_override.unwrap_or(st.stop_timeout);
    if policy_enabled {
        state::suppress_restart(store, &st.id).map_err(|error| error.to_string())?;
    }
    // A frozen task cannot service the stop signal; thaw first so the grace
    // period is meaningful instead of always ending in SIGKILL.
    if let Err(error) = thaw_paused_container(store, &mut st) {
        if policy_enabled {
            let _ = state::clear_restart_suppression(store, &st.id);
        }
        return Err(error);
    }
    if let Err(error) = signal_container(&st, stop_signal) {
        if policy_enabled {
            let _ = state::clear_restart_suppression(store, &st.id);
        }
        return Err(error);
    }
    if !wait_pid_gone(&st, Duration::from_secs(timeout_secs)) {
        if let Err(error) = signal_container(&st, libc::SIGKILL) {
            if policy_enabled {
                let _ = state::clear_restart_suppression(store, &st.id);
            }
            return Err(error);
        }
        wait_pid_gone(&st, Duration::from_secs(5));
    }
    // The reaper needs this lock to persist the terminal attempt. Release it
    // before waiting for that write; otherwise stop and its own reaper can
    // deadlock until the settlement timeout.
    drop(lock);
    lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
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
    let image_reclaimable =
        imgstore.reclaimable_bytes_with_protected(&protected_image_rootfs(&imgstore, &store));
    let volumes_root = store.data_root().join("volumes");
    let volume_count = std::fs::read_dir(&volumes_root)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    let volume_bytes = fsutil::dir_size(&volumes_root);

    let mut containers = 0;
    let mut container_bytes = 0;
    let mut reclaimable_bytes = 0;
    for mut st in state::list(&store) {
        if let Err(e) = reconcile_stale_state(&store, &mut st) {
            eprintln!("zerun system df: {e}");
            return 1;
        }
        let state_dir = state::ContainerState::dir(&store, &st.id);
        let overlay_bytes = if st.overlay.is_some() {
            fsutil::dir_size(&store.container_overlay_dir(&st.id))
        } else {
            0
        };
        let bytes = fsutil::dir_size(&state_dir) + overlay_bytes;
        containers += 1;
        container_bytes += bytes;
        if st.status != state::Status::Running && !st.restart_pending {
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
        fsutil::human_size(image_reclaimable),
    );
    println!(
        "{:<12} {:>7} {:>14} {:>14}",
        "Containers",
        containers,
        fsutil::human_size(container_bytes),
        fsutil::human_size(reclaimable_bytes)
    );
    println!(
        "{:<12} {:>7} {:>14} {:>14}",
        "Volumes",
        volume_count,
        fsutil::human_size(volume_bytes),
        "0 B"
    );
    0
}

/// `zerun prune` — remove retained exited containers, and optionally remove
/// unreachable image storage. Stale Running records are reconciled first, so
/// this is also the bulk crash-recovery path. Live containers are never touched.
fn cmd_prune(args: &[String]) -> i32 {
    let mut force = false;
    let mut images = false;
    for a in args {
        match a.as_str() {
            "-f" | "--force" => force = true,
            "--images" => images = true,
            "-h" | "--help" => {
                println!("usage: zerun prune [-f|--force] [--images]");
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
    let imgstore = match image::store::ImageStore::open(&store) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun prune: {e}");
            return 1;
        }
    };

    // Reconcile before selection so a dead reaper's Running record is treated
    // like the Exited record it logically represents.
    let states = state::list(&store);
    let mut targets = Vec::new();
    for mut st in states {
        if let Err(e) = reconcile_stale_state(&store, &mut st) {
            eprintln!("zerun prune: {e}");
            return 1;
        }
        if st.status == state::Status::Exited && !st.restart_pending {
            targets.push((st.id.clone(), display_name(&st)));
        }
    }
    let image_reclaimable = if images {
        imgstore.reclaimable_bytes_with_protected(&protected_image_rootfs(&imgstore, &store))
    } else {
        0
    };
    if targets.is_empty() && (!images || image_reclaimable == 0) {
        println!("No exited containers or unreachable image storage to prune");
        return 0;
    }

    let mut prompt = String::new();
    if !targets.is_empty() {
        prompt.push_str(&format!(
            "Remove {} exited container(s)? This deletes their writable layers.",
            targets.len()
        ));
    }
    if images && image_reclaimable > 0 {
        if !prompt.is_empty() {
            prompt.push(' ');
        }
        prompt.push_str(&format!(
            "Delete {image_reclaimable} bytes of unreachable image storage?"
        ));
    }
    prompt.push_str(" [y/N] ");
    match prompt::confirm(&prompt, force) {
        Ok(true) => {}
        Ok(false) => return 0,
        Err(e) => {
            eprintln!("zerun prune: {e}");
            return 2;
        }
    }

    let mut failed = false;
    if !targets.is_empty() {
        println!("Deleted Containers:");
        let mut removed = 0;
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
    }

    if images {
        match imgstore.gc_with_protected_from(|| protected_image_rootfs(&imgstore, &store)) {
            Ok(()) => println!(
                "Reclaimed image storage: {}",
                fsutil::human_size(image_reclaimable)
            ),
            Err(e) => {
                eprintln!("zerun prune: {e}");
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
    let initial = state::resolve(store, target)?;
    let lock = state::ContainerOperationLock::acquire(store, &initial.id, Duration::from_secs(5))?;
    let mut st = state::ContainerState::load(store, &initial.id).ok_or_else(|| {
        format!(
            "container {} disappeared before removal",
            display_name(&initial)
        )
    })?;
    let name = display_name(&st);
    reconcile_stale_state(store, &mut st)?;
    let active = st.status == state::Status::Running || st.restart_pending;
    if active {
        if !force {
            return Err(if st.restart_pending {
                format!("cannot remove a restarting container {name} - stop it first or use -f")
            } else {
                format!("cannot remove a running container {name} - stop it first or use -f")
            });
        }
        let policy_enabled = st.restart_policy.is_enabled();
        if policy_enabled {
            state::suppress_restart(store, &st.id).map_err(|error| error.to_string())?;
        }
        if let Err(error) = thaw_paused_container(store, &mut st) {
            if policy_enabled {
                let _ = state::clear_restart_suppression(store, &st.id);
            }
            return Err(error);
        }
        if st.pid.is_some() && st.pid_alive() {
            if let Err(error) = signal_container(&st, libc::SIGKILL) {
                if policy_enabled {
                    let _ = state::clear_restart_suppression(store, &st.id);
                }
                return Err(error);
            }
            wait_pid_gone(&st, Duration::from_secs(5));
        }
        // The reaper needs the operation lock to persist its terminal state.
        // Wait for that handoff, then reacquire before deleting its directory.
        drop(lock);
        lifecycle::settle_exit(store, &st.id).map_err(|e| e.to_string())?;
        let _lock = state::ContainerOperationLock::acquire(store, &st.id, Duration::from_secs(5))?;
        if let Some(fresh) = state::ContainerState::load(store, &st.id) {
            st = fresh;
        }
        return remove_container_files(store, &st, name);
    }
    remove_container_files(store, &st, name)
}

fn remove_container_files(
    store: &Store,
    st: &state::ContainerState,
    name: String,
) -> Result<String, String> {
    // Reclaim any host-side leftovers still recorded (best effort; the normal
    // reaper path already cleaned them up).
    lifecycle::reclaim_resources(store, st);
    if st.overlay.is_some() {
        fsutil::remove_dir_all_quiet(&store.container_overlay_dir(&st.id));
    }
    remove_anonymous_volumes(store, &st.id, &st.anonymous_volumes);
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
    let filter = match LogTimeFilter::parse(since.as_deref(), until.as_deref()) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("zerun logs: {e}");
            return 2;
        }
    };
    let path = st.log_path_for(&store);
    let max_files = st.log_max_file.unwrap_or(1).clamp(1, logs::MAX_FILES);
    // Stream the retained logs instead of materializing the whole rotation
    // budget. `--tail` retains only its requested raw lines before applying
    // the time filter; `--tail 0` can skip file contents entirely.
    let (cursor, read_any) = match stream_log_snapshot(&path, max_files, tail, &filter, |line| {
        write_log_output(line, timestamps)
    }) {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!(
                "zerun logs: cannot read log files for container {}: {e}",
                display_name(&st)
            );
            return 1;
        }
    };
    if !read_any {
        eprintln!(
            "zerun logs: no log files for container {}",
            display_name(&st)
        );
        return 1;
    }
    // A fixed --until is an end boundary: future times still follow until the
    // wall clock reaches them; a past time only shows the historical window.
    if follow {
        follow_log(
            &store,
            &st,
            &path,
            max_files,
            cursor,
            timestamps,
            Some(&filter),
        );
    }
    0
}

/// Print data appended to `console.log` until the container exits.
fn follow_log(
    store: &Store,
    st: &ContainerState,
    path: &Path,
    max_files: usize,
    mut seen: LogCursor,
    timestamps: bool,
    filter: Option<&LogTimeFilter>,
) {
    loop {
        if filter.is_some_and(LogTimeFilter::until_reached) {
            break;
        }
        if !container_observable(store, st) {
            drain_rotated_logs(path, max_files, &mut seen, timestamps, filter);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        drain_rotated_logs(path, max_files, &mut seen, timestamps, filter);
    }
}

type LogCursor = std::collections::HashMap<(u64, u64), u64>;

/// Stream the retained logs in chronological order while recording the exact
/// inode position consumed from each one.
///
/// Rotation may rename any path between opens; using the open file descriptor
/// plus its inode identity keeps the snapshot and follow cursor consistent
/// across that race. Only `--tail` keeps lines in memory, and only the number
/// requested by the operator.
fn stream_log_snapshot<F>(
    path: &Path,
    max_files: usize,
    tail: Option<usize>,
    filter: &LogTimeFilter,
    mut emit: F,
) -> std::io::Result<(LogCursor, bool)>
where
    F: FnMut(&[u8]),
{
    use std::collections::VecDeque;
    use std::io::{BufRead, BufReader, Read, Seek, Take};
    use std::os::unix::fs::MetadataExt;

    let mut cursor = LogCursor::new();
    let mut read_any = false;
    let mut tail_lines = tail.map(|_| VecDeque::<Vec<u8>>::new());
    for log_path in logs::log_paths(path, max_files) {
        let mut file = match std::fs::File::open(&log_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", log_path.display()),
                ));
            }
        };
        let meta = file.metadata()?;
        let id = (meta.dev(), meta.ino());
        let snapshot_len = meta.len();
        read_any = true;
        if tail == Some(0) {
            cursor.insert(id, snapshot_len);
            continue;
        }

        file.seek(std::io::SeekFrom::Start(0))?;
        let mut reader: Take<BufReader<std::fs::File>> = BufReader::new(file).take(snapshot_len);
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if let Some(lines) = &mut tail_lines {
                lines.push_back(std::mem::take(&mut line));
                if lines.len() > tail.unwrap_or(0) {
                    lines.pop_front();
                }
            } else if logs::log_line_matches(&line, filter) {
                emit(&line);
            }
        }
        cursor.insert(id, snapshot_len);
    }

    if let Some(lines) = tail_lines {
        for line in lines {
            if logs::log_line_matches(&line, filter) {
                emit(&line);
            }
        }
    }
    Ok((cursor, read_any))
}

fn drain_rotated_logs(
    path: &Path,
    max_files: usize,
    seen: &mut LogCursor,
    timestamps: bool,
    filter: Option<&LogTimeFilter>,
) {
    use std::io::{BufRead, BufReader, Read, Seek, Take};
    use std::os::unix::fs::MetadataExt;

    let filter = filter.copied();
    let paths = logs::log_paths(path, max_files);
    let mut present = std::collections::HashSet::with_capacity(paths.len());
    for log_path in &paths {
        let Ok(meta) = std::fs::metadata(log_path) else {
            continue;
        };
        let id = (meta.dev(), meta.ino());
        present.insert(id);
        let pos = seen.get(&id).copied().unwrap_or(0);
        let len = meta.len();
        if len <= pos {
            continue;
        }
        let Ok(mut file) = std::fs::File::open(log_path) else {
            continue;
        };
        if file.seek(std::io::SeekFrom::Start(pos)).is_err() {
            continue;
        }
        let mut reader: Take<BufReader<std::fs::File>> =
            BufReader::new(file).take(len.saturating_sub(pos));
        let mut line = Vec::new();
        let mut consumed = pos;
        let mut failed = false;
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(n) => {
                    consumed = consumed.saturating_add(n as u64);
                    if filter.is_none_or(|filter| logs::log_line_matches(&line, &filter)) {
                        write_log_output(&line, timestamps);
                    }
                }
                Err(error) => {
                    eprintln!("zerun logs: follow {}: {error}", log_path.display());
                    failed = true;
                    break;
                }
            }
        }
        if !failed {
            seen.insert(id, consumed);
        }
    }
    seen.retain(|id, _| present.contains(id));
}

fn container_observable(store: &Store, st: &ContainerState) -> bool {
    match state::ContainerState::load(store, &st.id) {
        Some(s) => {
            (s.status == state::Status::Running && s.pid_alive())
                // A live reaper can be between a workload exit and its
                // terminal-state write, or sleeping before the next attempt.
                || (s.reaper_alive() && (s.restart_pending || s.restart_policy.is_enabled()))
        }
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
            if let Err(e) = reconcile_stale_state(&store, &mut st) {
                eprintln!("zerun stats: {e}");
                return 1;
            }
            states.push(st);
        }
    } else {
        for target in &targets {
            match state::resolve(&store, target) {
                Ok(mut st) => {
                    if let Err(e) = reconcile_stale_state(&store, &mut st) {
                        eprintln!("zerun stats: {e}");
                        return 1;
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
                    .filter(|p| cgroup::CgroupV2::is_container_path(&st.id, p))
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
/// container in place (memory, CPU, cpuset, pids, I/O, oom-group), or update
/// its detached restart policy.
///
/// Resource changes require a live cgroup; a restart-only update may also
/// target an exited record. I/O updates merge with the kernel's current
/// `io.max`, so only the named devices and directions change. `restart` still
/// reverts resource limits to the launch-time values captured in
/// `launch_args`; the persisted restart policy is authoritative on resume.
fn cmd_update(args: &[String]) -> i32 {
    let mut limits = cgroup::ResourceLimits::default();
    let mut restart_policy: Option<restart::RestartPolicy> = None;
    let mut targets: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-h" | "--help" => {
                println!(
                    "usage: zerun update [--memory SIZE] [--memory-reservation SIZE] \
                     [--memory-swap SIZE] [--cpus VALUE] [--cpu-shares SHARES] \
                     [--cpuset-cpus LIST] \
                     [--cpuset-mems LIST] [--pids|--pids-limit N|-1] \
                     [--device-read-bps DEV:BYTES] [--device-write-bps DEV:BYTES] \
                     [--device-read-iops DEV:COUNT] [--device-write-iops DEV:COUNT] \
                     [--oom-group] [--restart POLICY] CONTAINER"
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
                Ok(v) => match cgroup::parse_cpus(&v) {
                    Ok(c) => {
                        limits.cpus = Some(c);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --cpus '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--cpu-shares" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_cpu_shares(&v) {
                    Ok(shares) => {
                        limits.cpu_shares = Some(shares);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --cpu-shares '{v}': {e}");
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
            "--pids" | "--pids-limit" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<i64>() {
                    Ok(p) if p == -1 || p > 0 => {
                        limits.pids = Some(p);
                        continue;
                    }
                    _ => {
                        eprintln!("zerun update: {a} expects a positive integer or -1, got '{v}'");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--device-read-bps" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_io_limit("device-read-bps", &v) {
                    Ok(limit) => {
                        limits.io.push(limit);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --device-read-bps '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--device-write-bps" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_io_limit("device-write-bps", &v) {
                    Ok(limit) => {
                        limits.io.push(limit);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --device-write-bps '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--device-read-iops" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_io_limit("device-read-iops", &v) {
                    Ok(limit) => {
                        limits.io.push(limit);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --device-read-iops '{v}': {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            "--device-write-iops" => match next_value(args, &mut i, a) {
                Ok(v) => match cgroup::parse_io_limit("device-write-iops", &v) {
                    Ok(limit) => {
                        limits.io.push(limit);
                        continue;
                    }
                    Err(e) => {
                        eprintln!("zerun update: invalid --device-write-iops '{v}': {e}");
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
            "--restart" => match next_value(args, &mut i, a) {
                Ok(v) => match v.parse::<restart::RestartPolicy>() {
                    Ok(policy) => restart_policy = Some(policy),
                    Err(e) => {
                        eprintln!("zerun update: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("zerun update: {e}");
                    return 2;
                }
            },
            other if other.starts_with("--restart=") => {
                let value = &other["--restart=".len()..];
                match value.parse::<restart::RestartPolicy>() {
                    Ok(policy) => restart_policy = Some(policy),
                    Err(e) => {
                        eprintln!("zerun update: {e}");
                        return 2;
                    }
                }
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
    let limits_requested = limits.memory.is_some()
        || limits.memory_reservation.is_some()
        || limits.memory_swap.is_some()
        || limits.cpus.is_some()
        || limits.cpu_shares.is_some()
        || limits.cpuset_cpus.is_some()
        || limits.cpuset_mems.is_some()
        || limits.pids.is_some()
        || !limits.io.is_empty()
        || limits.oom_group;
    if !limits_requested && restart_policy.is_none() {
        eprintln!("zerun update: provide at least one limit or --restart policy to change");
        return 2;
    }
    let store = match Store::detect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun: {e}");
            return 1;
        }
    };
    let initial = match state::resolve(&store, targets[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun update: {e}");
            return 1;
        }
    };
    let _lock = match state::ContainerOperationLock::try_acquire(&store, &initial.id) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("zerun update: {e}");
            return 1;
        }
    };
    let mut st = match state::ContainerState::load(&store, &initial.id) {
        Some(st) => st,
        None => {
            eprintln!(
                "zerun update: container {} disappeared",
                display_name(&initial)
            );
            return 1;
        }
    };
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun update: {e}");
        return 1;
    }
    let restart_only = restart_policy.is_some() && !limits_requested;
    let restart_on_exited = restart_only && st.status == state::Status::Exited;
    if !restart_on_exited && (st.status != state::Status::Running || !st.pid_alive()) {
        eprintln!(
            "zerun update: container {} is not running (only --restart may be changed on an exited container)",
            display_name(&st)
        );
        return 1;
    }
    if limits_requested {
        let Some(cgroup_path) = st.cgroup.clone() else {
            eprintln!(
                "zerun update: container {} has no cgroup (started without resource limits); \
                 restart it with the desired flags instead",
                display_name(&st)
            );
            return 1;
        };
        let cg = match cgroup::CgroupV2::open_for_container(&st.id, Path::new(&cgroup_path)) {
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
    }
    if let Some(policy) = restart_policy {
        st.restart_policy = policy;
        if let Err(e) = st.save(&store) {
            eprintln!("zerun update: persist restart policy: {e}");
            return 1;
        }
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
        if let Err(e) = reconcile_stale_state(&store, &mut st) {
            eprintln!("zerun inspect: {e}");
            return 1;
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
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun port: {e}");
        return 1;
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
/// Lifecycle commands serialize through the per-container operation lock.
/// The detached reaper still writes its own state without taking that lock,
/// so a rename racing the reaper's start/exit update can be overwritten.
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
    let initial = match state::resolve(&store, old) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zerun rename: {e}");
            return 1;
        }
    };
    let _lock = match state::ContainerOperationLock::try_acquire(&store, &initial.id) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("zerun rename: {e}");
            return 1;
        }
    };
    let _name_lock = match state::ContainerNameLock::try_acquire(&store) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("zerun rename: {e}");
            return 1;
        }
    };
    let mut st = match state::ContainerState::load(&store, &initial.id) {
        Some(st) => st,
        None => {
            eprintln!(
                "zerun rename: container {} disappeared before rename",
                display_name(&initial)
            );
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
    if let Some(args) = st.launch_args.as_mut() {
        set_launch_name(args, Some(new));
    }
    if let Err(e) = st.save(&store) {
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
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun top: {e}");
        return 1;
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
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun cp: {e}");
        return 1;
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
        fsutil::copy_file(src, dst)
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
    let initial = match state::resolve(&store, target) {
        Ok(st) => st,
        Err(e) => {
            eprintln!("zerun diff: {e}");
            return 1;
        }
    };
    let _container_lock = match state::ContainerOperationLock::try_acquire(&store, &initial.id) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("zerun diff: {e}");
            return 1;
        }
    };
    let st = match state::ContainerState::load(&store, &initial.id) {
        Some(st) => st,
        None => {
            eprintln!(
                "zerun diff: container {} disappeared",
                display_name(&initial)
            );
            return 1;
        }
    };
    if st.tmpfs_upper {
        eprintln!("zerun diff: a --tmpfs-upper container has no persisted writable layer");
        return 1;
    }
    if st.overlay.is_none() {
        eprintln!(
            "zerun diff: container {} has no writable overlay",
            display_name(&st)
        );
        return 1;
    }
    let upper = store.container_overlay_dir(&st.id).join("upper");
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
/// Resolve the persisted lower rootfs for a resumable container.
///
/// The lower path is captured at creation time so retained containers continue
/// to work after their image tag is removed. For image-backed records, accept
/// only a materialized directory below the current image store root; a
/// tampered state path must never become an arbitrary host path passed to
/// overlayfs or pivot_root. Legacy `rootfs:` records intentionally retain
/// their operator-supplied external rootfs semantics.
fn resumable_lower_rootfs(store: &Store, st: &state::ContainerState) -> Result<PathBuf, String> {
    let Some(raw) = st.lower.as_deref() else {
        return Err(format!(
            "container {} predates resumable state and cannot be started",
            display_name(st)
        ));
    };
    let lower = PathBuf::from(raw);
    if !lower.is_absolute() {
        return Err(format!(
            "container {} has a non-absolute lower rootfs path",
            display_name(st)
        ));
    }
    if let Some(raw_image_root) = st.image.strip_prefix("rootfs:") {
        let recorded_root = PathBuf::from(raw_image_root);
        let canonical_recorded = std::fs::canonicalize(&recorded_root).map_err(|e| {
            format!(
                "container {} recorded rootfs is unavailable at {}: {e}",
                display_name(st),
                recorded_root.display()
            )
        })?;
        let canonical_lower = std::fs::canonicalize(&lower).map_err(|e| {
            format!(
                "container {} lower rootfs is missing at {}: {e}",
                display_name(st),
                lower.display()
            )
        })?;
        if canonical_recorded != canonical_lower {
            return Err(format!(
                "container {} lower rootfs does not match its recorded rootfs",
                display_name(st)
            ));
        }
        return Ok(canonical_lower);
    }

    let imgstore = image::store::ImageStore::open(store).map_err(|e| e.to_string())?;
    let rootfs_root = std::fs::canonicalize(imgstore.rootfs_dir()).map_err(|e| {
        format!(
            "container {} image rootfs store is unavailable: {e}",
            display_name(st)
        )
    })?;
    let canonical_lower = std::fs::canonicalize(&lower).map_err(|e| {
        format!(
            "container {} lower rootfs is missing at {}: {e}",
            display_name(st),
            lower.display()
        )
    })?;
    if !canonical_lower.starts_with(&rootfs_root) {
        return Err(format!(
            "container {} lower rootfs {} is outside the image store",
            display_name(st),
            lower.display()
        ));
    }
    if !canonical_lower.is_dir() {
        return Err(format!(
            "container {} lower rootfs is not a directory: {}",
            display_name(st),
            lower.display()
        ));
    }
    Ok(canonical_lower)
}

/// Locate the base rootfs for a container. Prefer the persisted materialized
/// lower so `diff` and `commit` continue to work after image-tag garbage
/// collection; older records without `lower` fall back to the local index.
fn lower_rootfs(store: &Store, st: &state::ContainerState) -> Result<PathBuf, String> {
    if st.lower.is_some() {
        return resumable_lower_rootfs(store, st);
    }
    if let Some(path) = st.image.strip_prefix("rootfs:") {
        let rootfs = PathBuf::from(path);
        let canonical = std::fs::canonicalize(&rootfs).map_err(|e| {
            format!(
                "recorded rootfs is unavailable at {}: {e}",
                rootfs.display()
            )
        })?;
        if !canonical.is_dir() {
            return Err(format!(
                "recorded rootfs is not a directory: {}",
                rootfs.display()
            ));
        }
        return Ok(canonical);
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
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun export: {e}");
        return 1;
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
        export_to_file(&path, &root, &mounts)
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

/// Write an export beside the requested destination and install it atomically.
///
/// The destination itself may already exist or be a symlink; rename replaces
/// that directory entry rather than following it. The temporary file is
/// created exclusively in the same directory so a concurrent writer cannot
/// redirect the archive or expose a partial tarball.
fn export_to_file(
    output: &Path,
    root: &Path,
    mounts: &std::collections::HashSet<PathBuf>,
) -> crate::error::ZResult<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("export.tar");
    let sequence = EXPORT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.tmp-{}-{sequence}", std::process::id()));
    fsutil::remove_dir_all_quiet(&temporary);
    let guard = fsutil::TempFileGuard::new(temporary.clone());
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| crate::zerr!("create {}: {e}", temporary.display()))?;
    archive_tree(&mut file, root, mounts)?;
    file.flush()
        .map_err(|e| crate::zerr!("flush {}: {e}", temporary.display()))?;
    file.sync_all()
        .map_err(|e| crate::zerr!("sync {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, output)
        .map_err(|e| crate::zerr!("install export {}: {e}", output.display()))?;
    let _ = guard.persist();
    fsutil::sync_directory(parent)?;
    Ok(())
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
    let time_filter = match logs::LogTimeFilter::parse(since, until) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("zerun events: {e}");
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
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let replay = time_filter.is_active();
    let mut previous = if replay {
        Vec::new()
    } else {
        state::list(&store)
    };
    loop {
        // A bounded replay should emit existing records immediately, while an
        // unbounded invocation keeps the first snapshot silent like Docker's
        // live event stream.
        let current = state::list(&store);
        for event in events::diff_events(&previous, &current) {
            let event = events::select_events_with_time_filter(vec![event], &filters, &time_filter);
            let Some(event) = event.first() else {
                continue;
            };
            let _ = writeln!(out, "{}", events::format_event(event));
        }
        let _ = out.flush();
        if time_filter.until_reached() {
            break;
        }
        previous = current;
        std::thread::sleep(Duration::from_millis(200));
    }
    0
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
    if let Err(e) = reconcile_stale_state(&store, &mut st) {
        eprintln!("zerun attach: {e}");
        return 1;
    }
    if st.status != state::Status::Running || !st.pid_alive() {
        eprintln!(
            "zerun attach: container {} is not running",
            display_name(&st)
        );
        return 1;
    }
    let sock_path = st.log_path_for(&store).with_file_name("attach.sock");
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
    let mut final_code = None;
    loop {
        match lifecycle::read_attach_frame(&mut stream) {
            Ok(lifecycle::AttachFrame::Data(chunk)) => {
                if out.write_all(&chunk).is_err() {
                    eprintln!("zerun attach: write workload output failed");
                    return 1;
                }
                let _ = out.flush();
            }
            Ok(lifecycle::AttachFrame::Exit(code)) => {
                final_code = Some(code);
                break;
            }
            Ok(lifecycle::AttachFrame::Eof) => break,
            Err(error) => {
                eprintln!("zerun attach: read attach stream: {error}");
                return 1;
            }
        }
    }
    if let Some(code) = final_code {
        return code;
    }
    // A reaper crash may close the socket before sending its final control
    // frame. In that case, use the state record if it was persisted.
    match state::ContainerState::load(&store, &st.id) {
        Some(final_state) => final_state.exit_code.unwrap_or(0),
        None => 0,
    }
}

#[derive(Debug, Default)]
struct ExecArgs {
    env_files: Vec<String>,
    env: Vec<String>,
    user: Option<String>,
    workdir: Option<String>,
    interactive: bool,
    tty: bool,
    target: String,
    cmd: Vec<String>,
}

#[derive(Debug)]
enum ParsedExec {
    Help,
    Run(ExecArgs),
}

fn parse_exec_args(args: &[String]) -> Result<ParsedExec, String> {
    let mut parsed = ExecArgs::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-e" | "--env" => {
                let value = next_value(args, &mut i, arg)?;
                workload::validate_env_spec(&value)
                    .map_err(|error| format!("invalid --env '{value}': {error}"))?;
                parsed.env.push(value);
            }
            "--env-file" => {
                let value = next_value(args, &mut i, arg)?;
                if value.is_empty() {
                    return Err("--env-file path cannot be empty".to_string());
                }
                parsed.env_files.push(value);
            }
            "-u" | "--user" => {
                let value = next_value(args, &mut i, arg)?;
                if value.trim().is_empty() {
                    return Err("--user cannot be empty".to_string());
                }
                parsed.user = Some(value);
            }
            "-w" | "--workdir" => {
                parsed.workdir = Some(next_value(args, &mut i, arg)?);
            }
            "-i" | "--interactive" => {
                parsed.interactive = true;
                i += 1;
            }
            "-t" | "--tty" => {
                parsed.tty = true;
                i += 1;
            }
            "-it" | "-ti" => {
                parsed.interactive = true;
                parsed.tty = true;
                i += 1;
            }
            "-h" | "--help" => return Ok(ParsedExec::Help),
            other if other.starts_with("--env-file=") => {
                let value = &other["--env-file=".len()..];
                if value.is_empty() {
                    return Err("--env-file path cannot be empty".to_string());
                }
                parsed.env_files.push(value.to_string());
                i += 1;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"));
            }
            _ => {
                parsed.target = args[i].clone();
                parsed.cmd = args[i + 1..].to_vec();
                if parsed.cmd.is_empty() {
                    return Err("a command is required after CONTAINER".to_string());
                }
                return Ok(ParsedExec::Run(parsed));
            }
        }
    }
    Err("CONTAINER and COMMAND are required".to_string())
}

/// Materialize `exec --env-file` entries before explicit `-e` values.
fn exec_env(env_files: &[String], explicit: &[String]) -> Result<Vec<String>, String> {
    let paths = workload::resolve_env_file_paths(env_files)?;
    let entries = workload::load_env_files(&paths)?;
    let mut env = Vec::with_capacity(entries.len() + explicit.len());
    env.extend(
        entries
            .into_iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    env.extend(explicit.iter().cloned());
    Ok(env)
}

fn cmd_exec(args: &[String]) -> i32 {
    let parsed = match parse_exec_args(args) {
        Ok(ParsedExec::Help) => {
            println!(
                "usage: zerun exec [-e NAME=VAL] [--env-file FILE] [-u USER[:GROUP]] [-w DIR] [-it] CONTAINER CMD [ARG...]"
            );
            return 0;
        }
        Ok(ParsedExec::Run(parsed)) => parsed,
        Err(error) => {
            eprintln!("zerun exec: {error}");
            return 2;
        }
    };
    let env_extra = match exec_env(&parsed.env_files, &parsed.env) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("zerun exec: {error}");
            return 2;
        }
    };
    let store = match Store::detect() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("zerun: {error}");
            return 1;
        }
    };
    let st = match state::resolve(&store, &parsed.target) {
        Ok(st) => st,
        Err(error) => {
            eprintln!("zerun exec: {error}");
            return 1;
        }
    };
    match execc::run(execc::ExecRequest {
        state: &st,
        env_extra: &env_extra,
        user_override: parsed.user.as_deref(),
        workdir: parsed.workdir.as_deref(),
        tty: parsed.tty,
        interactive: parsed.interactive,
        argv: &parsed.cmd,
    }) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("zerun exec: {error}");
            1
        }
    }
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

/// Deliver a lifecycle signal without allowing a stale PID to target an
/// unrelated process. New records carry a starttime and use pidfds; legacy
/// records retain the historical PID fallback because they have no identity
/// token with which to validate the process opened by pidfd_open.
fn signal_container(state: &state::ContainerState, signal: libc::c_int) -> Result<(), String> {
    let pid = state
        .pid
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "container has no valid PID".to_string())?;
    if let Some(expected) = state.pid_start_time {
        let pidfd = syscalls::pidfd_open(pid).map_err(|e| e.to_string())?;
        if crate::procinfo::process_start_time(pid) != Some(expected) {
            return Err("container PID is no longer the recorded process".to_string());
        }
        syscalls::pidfd_send_signal(pidfd.as_raw_fd(), signal).map_err(|e| e.to_string())
    } else {
        syscalls::kill(pid, signal).map_err(|e| e.to_string())
    }
}

fn wait_pid_gone(state: &state::ContainerState, timeout: Duration) -> bool {
    // Compare elapsed time rather than adding a user-controlled Duration to an
    // Instant: `Instant + Duration` can overflow for very large --time values.
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !state.pid_alive() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !state.pid_alive()
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

static ID_FALLBACK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generate a compact, filesystem-safe container ID. Six bytes from the host
/// kernel's entropy pool preserve the existing 12-character display format;
/// the fallback is only for unusual hosts without `/dev/urandom`.
fn short_id() -> String {
    use std::io::Read;

    let mut bytes = [0u8; 6];
    if let Ok(mut random) = std::fs::File::open("/dev/urandom") {
        if random.read_exact(&mut bytes).is_ok() {
            return bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        }
    }

    // Keep the fallback deterministic enough to avoid same-process collisions
    // while retaining the old time-based behavior on severely restricted hosts.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let seq = ID_FALLBACK_SEQ.fetch_add(1, Ordering::Relaxed);
    let mixed =
        nanos ^ (u64::from(std::process::id()) << 32) ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    format!("{:012x}", mixed & 0xffff_ffff_ffff)
}

/// Reservation for a newly allocated container id.
///
/// The runtime directory itself is the reservation token: `mkdir` is atomic,
/// so concurrent CLI processes cannot select the same id between a check and
/// the later state/overlay creation. The reservation is removed automatically
/// when setup fails before the detached state record takes ownership.
struct ContainerIdReservation {
    id: String,
    path: PathBuf,
    committed: bool,
}

impl ContainerIdReservation {
    fn reserve(store: &Store) -> Result<Self, String> {
        let containers = store.run_root().join("containers");
        loop {
            let id = short_id();
            let path = containers.join(&id);
            let result = std::fs::DirBuilder::new().mode(0o700).create(&path);
            match result {
                Ok(()) => {
                    return Ok(Self {
                        id,
                        path,
                        committed: false,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "reserve container id in {}: {error}",
                        containers.display()
                    ));
                }
            }
        }
    }

    /// Hand ownership of the reserved directory to the state record.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ContainerIdReservation {
    fn drop(&mut self) {
        if !self.committed {
            fsutil::remove_dir_all_quiet(&self.path);
        }
    }
}

fn print_run_usage() {
    println!(
        "usage:\n  \
         zerun run [OPTIONS] IMAGE [CMD [ARGS...]]\n  \
         zerun run -d [--name NAME] [OPTIONS] IMAGE [CMD [ARGS...]]   (detached)\n  \
         zerun run --rootfs DIR [OPTIONS] [--] CMD [ARGS...]   (legacy)"
    );
}

fn version_string() -> String {
    format!("zerun {}", env!("CARGO_PKG_VERSION"))
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
  zerun start CONTAINER...              resume stopped containers in place\n  \
  zerun pause CONTAINER...              freeze all processes in detached containers\n  \
  zerun unpause CONTAINER...            resume frozen detached containers\n  \
  zerun stop [--time S] [--signal SIG] CONTAINER...\n  \
                                        send the stop signal, then SIGKILL after timeout\n  \
  zerun kill [--signal SIG] CONTAINER... signal detached containers (default KILL)\n  \
  zerun restart [--time S] [--signal SIG] CONTAINER...\n  \
                                        restart detached containers\n  \
  zerun rm [-f] CONTAINER...            remove stopped containers (-f: kill first)\n  \
  zerun logs [--tail N] [--since TIME] [--until TIME] [-f] [-t] CONTAINER\n  \
  zerun stats [-a] [CONTAINER...]        one-shot resource metrics\n  \
  zerun update [opts] CONTAINER          change live limits or restart policy\n  \
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
  zerun exec [-e K=V] [--env-file FILE] [-u USER[:GROUP]] [-w DIR] [-it] CONTAINER CMD [ARG...]\n  \
                                        run a command in a running container\n  \
  zerun pull [--platform ...] IMAGE...   pull OCI images (Docker Hub, mirrors)\n  \
  zerun login [REGISTRY] [-u USER] [--password-stdin]\n  \
                                        log in to a private registry\n  \
  zerun logout [REGISTRY]               remove stored registry credentials\n  \
  zerun images [--digests] [-q] [--json]\n  \
                                        list local images\n  \
  zerun rmi IMAGE...                     remove local images\n  \
  zerun prune [-f] [--images]            remove exited containers/image garbage\n  \
  zerun system df                        summarize image/container disk usage\n  \
  zerun tag SOURCE TARGET[:TAG]          add a local tag to an image\n  \
  zerun push IMAGE[:TAG]                 push a local image to a registry\n  \
  zerun save -o FILE.tar IMAGE...        export images as an OCI archive\n  \
  zerun load -i FILE.tar                import images from an OCI archive\n  \
  zerun commit [-m MSG] CONTAINER IMAGE[:TAG]  save a container as an image\n  \
  zerun generate-service [opts] IMAGE    write a systemd unit to stdout\n  \
  zerun doctor                           environment diagnostics\n  \
  zerun version                          print the runtime version\n\
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
  --cpu-shares 512    relative CPU weight (Docker-compatible shares)\n  \
  --cpuset-cpus 0-3   pin CPUs (cgroups v2 cpuset.cpus)\n  \
  --cpuset-mems 0     pin memory nodes (cgroups v2 cpuset.mems)\n  \
  --pids, --pids-limit N  cgroup v2 pids.max (rootful default: 256; -1 = unlimited)\n  \
  --oom-group         kill the whole cgroup on OOM (memory.oom.group)\n  \
  --device-read-bps DEV:BYTES    cgroup v2 io.max read rate (repeatable)\n  \
  --device-write-bps DEV:BYTES   cgroup v2 io.max write rate (repeatable)\n  \
  --device-read-iops DEV:COUNT   cgroup v2 io.max read IOPS (repeatable)\n  \
  --device-write-iops DEV:COUNT  cgroup v2 io.max write IOPS (repeatable)\n  \
  --ulimit TYPE=SOFT[:HARD]      per-process rlimit (repeatable; -1 = unlimited)\n  \
  -h, --hostname H    container hostname (new UTS namespace)\n  \
  --cidfile FILE      write the container id to FILE without overwriting it\n  \
  --pid private|host  private PID namespace (default) or share host PID (sensitive)\n  \
  --ipc private|none|host\n  \
                      private IPC+shm (default), private IPC without /dev/shm, or\n  \
                      share host IPC (sensitive)\n  \
  --uts private|host  private UTS namespace (default) or share host name (sensitive)\n  \
  -u, --user USER[:GROUP]  run as container user (numeric or /etc/passwd name)\n  \
  --group-add NAME|GID     add a supplementary group (repeatable/comma-separated)\n  \
  --stop-signal SIGNAL     stop/restart signal (image StopSignal; default SIGTERM)\n  \
  --stop-timeout S         seconds before stop/restart sends SIGKILL (default 10)\n  \
  --health-cmd CMD         detached liveness probe (shell form; image HEALTHCHECK inherited)\n  \
  --health-interval D      delay between probes (Docker duration syntax; default 30s)\n  \
  --health-timeout D       per-probe timeout before SIGKILL (default 30s)\n  \
  --health-retries N       consecutive failures before unhealthy (default 3)\n  \
  --health-start-period D  initialization window excluded from retry counting\n  \
  --health-start-interval D  probe delay during the start period (default 5s)\n  \
  --no-healthcheck         disable an image-declared HEALTHCHECK\n  \
  --restart POLICY        detached restart policy (no|on-failure[:max]|always|unless-stopped)\n  \
  --net, --network none|host|bridge\n  \
                      none = fresh netns + loopback; host = share host net;\n  \
                      bridge = zerun0 bridge + NAT (needs CAP_NET_ADMIN;\n  \
                      rootful default; rootless default is none)\n  \
  -i, --interactive      keep stdin attached (foreground runs)\n  \
  -t, --tty              allocate a PTY for foreground or detached output\n  \
  -p, --publish [ADDR:]HOST[-END][:CONTAINER[-END]][/proto]\n  \
                                      publish TCP/UDP port ranges (requires --net bridge)\n  \
  --expose PORT[-PORT][/proto]       expose container ports without publishing them\n  \
  -P, --publish-all                 publish every image/--expose port to a random host port\n  \
  -v, --volume HOST|NAME:CONTAINER[:ro]\n  \
                                        bind-mount a host path or managed named volume\n  \
  --mount type=bind|volume|tmpfs,src=SOURCE,dst=TARGET[,readonly]\n  \
                                        Docker-style mount syntax; tmpfs accepts\n  \
                                        tmpfs-size= and tmpfs-mode= options\n  \
  --device HOST[:CONTAINER[:rwm]]      expose a host device node\n  \
  --dns IP            container DNS server (repeatable/comma-separated; bridge mode;\n  \
                      defaults to the host's)\n  \
  --dns-search DOMAIN resolver search domain (repeatable/comma-separated;\n  \
                      defaults to the host's)\n  \
  --dns-option OPTION resolver option such as ndots:2 (repeatable/comma-separated;\n  \
                      defaults to the host's)\n  \
  --add-host HOST:IP  add an /etc/hosts entry (repeatable; IP or host-gateway)\n  \
  --sysctl KEY=VALUE  apply a namespaced kernel setting (repeatable; net.*,\n  \
                      kernel.shm*, kernel.msg*, kernel.sem*, fs.mqueue.*,\n  \
                      kernel.domainname)\n  \
  --init              run the built-in mini-init (reap orphans + forward signals)\n  \
  --seccomp default|unconfined\n  \
  --security-opt seccomp=default|unconfined|no-new-privileges\n  \
                      Docker-compatible security option (repeatable)\n  \
  --cap-add CAP|ALL    add capability to the default set (repeatable/comma-separated)\n  \
  --cap-drop CAP|ALL   remove capability from the default set (repeatable; before adds)\n  \
  --platform os/arch[/variant]  pull/run a specific platform\n  \
  --entrypoint CMD    override the image ENTRYPOINT (empty resets it)\n  \
  -w, --workdir DIR   override the image WorkingDir\n  \
  --pull POLICY       missing|always|never (default: missing)\n  \
  -e, --env NAME[=VALUE]  set a container environment variable (image mode)\n  \
  --env-file FILE     load NAME=VALUE lines from a file (repeatable; image mode;\n  \
                      later files win, then -e overrides)\n  \
  --label KEY[=VALUE]  add container metadata (repeatable; overrides image labels)\n  \
  --label-file FILE    load KEY=VALUE labels from a file (repeatable; later wins)\n  \
  --log-max-size SIZE  detached console.log rotation size (default: 10m; 0 disables)\n  \
  --log-max-file N     retained detached log files including active (default: 3; max: 1024)\n  \
  --shm-size SIZE     private /dev/shm size (default: 64m)\n  \
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
    fn doctor_rejects_arguments_with_a_usage_error() {
        assert_eq!(cmd_doctor(&["--unknown".to_string()]), 2);
        assert_eq!(cmd_doctor(&["--help".to_string()]), 0);
    }

    #[test]
    fn version_string_uses_the_package_version() {
        assert_eq!(
            version_string(),
            format!("zerun {}", env!("CARGO_PKG_VERSION"))
        );
        assert!(!version_string().trim().is_empty());
    }

    #[test]
    fn parses_images_options_and_rejects_unknown_flags() {
        let args: Vec<_> = ["--digests", "-q", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            parse_images_options(&args).unwrap(),
            ImagesOptions {
                digests: true,
                quiet: true,
                json: true,
            }
        );
        assert!(parse_images_options(&["--all".to_string()])
            .unwrap_err()
            .contains("unknown option --all"));
    }

    #[test]
    fn image_digest_prefers_the_multi_arch_index() {
        let mut record = image::store::ImageRecord {
            name: "docker.io/library/alpine".to_string(),
            tag: Some("latest".to_string()),
            manifest: format!("sha256:{}", "1".repeat(64)),
            index: None,
            config: format!("sha256:{}", "2".repeat(64)),
            size_bytes: 0,
            created_at: 0,
        };
        assert_eq!(image_digest(&record), record.manifest);
        record.index = Some(format!("sha256:{}", "3".repeat(64)));
        assert_eq!(image_digest(&record), record.index.as_deref().unwrap());
        assert_eq!(image_id(&record), "111111111111");
    }

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
    fn export_to_file_replaces_symlink_without_following_it() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-export-atomic-{}-{}",
            std::process::id(),
            EXPORT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root")).unwrap();
        std::fs::write(dir.join("root/marker"), b"exported").unwrap();
        let outside = dir.join("outside");
        std::fs::write(&outside, b"must survive").unwrap();
        let output = dir.join("result.tar");
        std::os::unix::fs::symlink(&outside, &output).unwrap();

        export_to_file(
            &output,
            &dir.join("root"),
            &std::collections::HashSet::new(),
        )
        .unwrap();

        assert!(!std::fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&outside).unwrap(), b"must survive");
        let mut archive = tar::Archive::new(std::fs::File::open(&output).unwrap());
        assert!(archive
            .entries()
            .unwrap()
            .any(|entry| entry.unwrap().path().unwrap() == Path::new("marker")));
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
        a.env_files.push("/tmp/app.env".to_string());
        a.env.push("MODE=prod".to_string());
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
                "--env-file",
                "/tmp/app.env",
                "--env",
                "MODE=prod",
                "--publish",
                "8080:80",
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
    fn launch_metadata_tracks_container_rename() {
        let mut args = vec![
            "-d".to_string(),
            "--name".to_string(),
            "old".to_string(),
            "alpine".to_string(),
        ];
        set_launch_name(&mut args, Some("new"));
        assert_eq!(args[1], "--name");
        assert_eq!(args[2], "new");

        set_launch_name(&mut args, None);
        assert!(!args.iter().any(|arg| arg == "--name"));
        assert_eq!(args[0], "-d");
        assert_eq!(args[1], "alpine");

        set_launch_name(&mut args, Some("named"));
        assert_eq!(args[0], "-d");
        assert_eq!(args[1], "--name");
        assert_eq!(args[2], "named");

        let workload_flag = vec![
            "-d".to_string(),
            "alpine".to_string(),
            "--".to_string(),
            "echo".to_string(),
            "--name".to_string(),
            "literal".to_string(),
            "--rm".to_string(),
        ];
        assert!(!launch_has_flag(&workload_flag, "--name"));
        assert!(!launch_has_flag(&workload_flag, "--rm"));
        assert!(!launch_has_flag(&workload_flag, "--init"));

        let lifecycle_flag = vec![
            "-d".to_string(),
            "--rm".to_string(),
            "alpine".to_string(),
            "--".to_string(),
            "--rm".to_string(),
        ];
        assert!(launch_has_flag(&lifecycle_flag, "--rm"));
    }

    #[test]
    fn state_environment_round_trips_entries() {
        assert_eq!(
            state_env(&["A=1".to_string(), "EMPTY=".to_string()]).unwrap(),
            vec![
                ("A".to_string(), "1".to_string()),
                ("EMPTY".to_string(), String::new())
            ]
        );
        assert!(state_env(&["MALFORMED".to_string()]).is_err());
    }

    #[test]
    fn parses_exec_environment_files_and_workload_arguments() {
        let args: Vec<_> = [
            "--env-file",
            "first.env",
            "-e",
            "MODE=explicit",
            "--env-file=second.env",
            "-u",
            "1000:1000",
            "-w",
            "/srv/app",
            "-it",
            "box",
            "env",
            "--env-file",
            "literal-command-argument",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect();
        let ParsedExec::Run(parsed) = parse_exec_args(&args).unwrap() else {
            panic!("expected exec invocation");
        };
        assert_eq!(parsed.env_files, ["first.env", "second.env"]);
        assert_eq!(parsed.env, ["MODE=explicit"]);
        assert_eq!(parsed.user.as_deref(), Some("1000:1000"));
        assert_eq!(parsed.workdir.as_deref(), Some("/srv/app"));
        assert!(parsed.interactive);
        assert!(parsed.tty);
        assert_eq!(parsed.target, "box");
        assert_eq!(
            parsed.cmd,
            ["env", "--env-file", "literal-command-argument"]
        );

        assert!(matches!(
            parse_exec_args(&["--unknown".to_string(), "box".to_string()]).unwrap_err(),
            error if error.contains("unknown option")
        ));
        assert!(parse_exec_args(&["box".to_string()]).is_err());
        assert!(parse_exec_args(&[]).is_err());
        assert!(parse_exec_args(&["--env-file=".to_string(), "box".to_string()]).is_err());
        assert!(parse_exec_args(&["-u".to_string(), "  ".to_string(), "box".to_string()]).is_err());

        let flags: Vec<_> = ["--interactive", "--tty", "box", "id"]
            .iter()
            .map(|value| value.to_string())
            .collect();
        let ParsedExec::Run(flags) = parse_exec_args(&flags).unwrap() else {
            panic!("expected exec invocation");
        };
        assert!(flags.interactive);
        assert!(flags.tty);
    }

    #[test]
    fn exec_environment_files_precede_explicit_overrides() {
        let root = std::env::temp_dir().join(format!(
            "zerun-exec-env-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("first.env");
        let second = root.join("second.env");
        std::fs::write(&first, "A=first\nB=first\n").unwrap();
        std::fs::write(&second, "B=second\nC=second\n").unwrap();

        let env = exec_env(
            &[first.display().to_string(), second.display().to_string()],
            &["B=explicit".to_string()],
        )
        .unwrap();
        assert_eq!(
            env,
            ["A=first", "B=first", "B=second", "C=second", "B=explicit"]
        );
        assert!(exec_env(&[String::new()], &[]).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_entrypoint_workdir_and_pull_policy() {
        let args: Vec<_> = [
            "--entrypoint",
            "",
            "-w",
            "/srv/app",
            "--pull=always",
            "alpine",
            "echo",
            "hi",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid image overrides");
        assert_eq!(a.entrypoint.as_deref(), Some(""));
        assert_eq!(a.workdir.as_deref(), Some("/srv/app"));
        assert_eq!(a.pull, PullPolicy::Always);

        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch.windows(2).any(|pair| pair == ["--entrypoint", ""]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--workdir", "/srv/app"]));
        assert!(launch.windows(2).any(|pair| pair == ["--pull", "always"]));

        let args: Vec<_> = ["--pull", "never", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(parse_run_args(&args).unwrap().pull, PullPolicy::Never);
        assert!(PullPolicy::parse("sometimes").is_err());
    }

    #[test]
    fn parses_and_captures_log_rotation() {
        let args: Vec<_> = [
            "-d",
            "--log-max-size",
            "16m",
            "--log-max-file",
            "4",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid log rotation");
        assert_eq!(a.log.max_size, 16 * 1024 * 1024);
        assert_eq!(a.log.max_files, 4);
        assert!(a.log_options_set);
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--log-max-size", "16777216"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--log-max-file", "4"]));

        let args: Vec<_> = ["--log-max-file", "0", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&args).is_err());

        let args: Vec<_> = ["--log-max-file", "1025", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&args).is_err());
    }

    #[test]
    fn accepts_supported_security_options_and_keeps_security_defaults() {
        let args: Vec<_> = [
            "--security-opt",
            "no-new-privileges",
            "--security-opt=seccomp=unconfined",
            "alpine",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("security options");
        assert_eq!(a.seccomp, SeccompMode::Unconfined);
        assert!(detached_launch_args(&a, Path::new("/tmp/rootfs"))
            .windows(2)
            .any(|pair| pair == ["--seccomp", "unconfined"]));

        let restore_default = [
            "--security-opt=seccomp=unconfined",
            "--seccomp=default",
            "alpine",
        ]
        .map(String::from);
        assert_eq!(
            parse_run_args(&restore_default).unwrap().seccomp,
            SeccompMode::Default
        );

        for value in [
            "seccomp=/tmp/profile.json",
            "seccomp=disabled",
            "no-new-privileges=false",
            "label=disable",
        ] {
            let args = ["--security-opt", value, "alpine"].map(String::from);
            assert!(parse_run_args(&args).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn parses_and_captures_capability_controls() {
        let args: Vec<_> = [
            "--cap-drop",
            "ALL",
            "--cap-add",
            "cap_net_raw,SYS_ADMIN",
            "--cap-add=NET_BIND_SERVICE",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid capability controls");
        assert_eq!(
            a.cap_add.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SYS_ADMIN"]
        );
        assert_eq!(
            a.cap_drop.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["ALL"]
        );

        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        for cap in ["CAP_NET_RAW", "CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"] {
            assert!(launch.windows(2).any(|pair| pair == ["--cap-add", cap]));
        }
        assert!(launch.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));

        let args: Vec<_> = ["--cap-add", "CAP_NOT_REAL", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&args)
            .err()
            .expect("invalid capability")
            .contains("unknown capability"));
        assert!(parse_run_args(&["--cap-add=".to_string(), "alpine".to_string()]).is_err());
    }

    #[test]
    fn parses_and_captures_namespaced_sysctls() {
        let args: Vec<_> = [
            "--net",
            "none",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--sysctl=kernel.domainname=example.test",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid sysctls");
        assert_eq!(
            a.sysctls.get("net.ipv4.ip_forward").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            a.sysctls.get("kernel.domainname").map(String::as_str),
            Some("example.test")
        );
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--sysctl", "kernel.domainname=example.test"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--sysctl", "net.ipv4.ip_forward=1"]));

        let malformed: Vec<_> = ["--sysctl", "vm.swappiness=1", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&malformed).is_err());
    }

    #[test]
    fn log_snapshot_streams_archives_in_order_and_tracks_positions() {
        let dir = std::env::temp_dir().join(format!("zerun-log-snapshot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let active = dir.join("console.log");
        std::fs::write(&active, b"newest\n").unwrap();
        std::fs::write(dir.join("console.log.1"), b"middle\n").unwrap();
        std::fs::write(dir.join("console.log.2"), b"oldest\n").unwrap();
        let filter = LogTimeFilter::parse(None, None).unwrap();

        let mut bytes = Vec::new();
        let (cursor, read_any) = stream_log_snapshot(&active, 3, None, &filter, |line| {
            bytes.extend_from_slice(line)
        })
        .unwrap();
        assert!(read_any);
        assert_eq!(bytes, b"oldest\nmiddle\nnewest\n");
        assert_eq!(cursor.len(), 3);
        assert!(cursor.values().all(|position| *position > 0));

        let mut bytes = Vec::new();
        let (_, read_any) = stream_log_snapshot(&active, 3, Some(2), &filter, |line| {
            bytes.extend_from_slice(line)
        })
        .unwrap();
        assert!(read_any);
        assert_eq!(bytes, b"middle\nnewest\n");

        let mut bytes = Vec::new();
        let (cursor, read_any) = stream_log_snapshot(&active, 3, Some(0), &filter, |line| {
            bytes.extend_from_slice(line)
        })
        .unwrap();
        assert!(read_any);
        assert!(bytes.is_empty());
        assert_eq!(cursor.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn image_volumes_seed_content_and_honor_operator_mounts() {
        let root = std::env::temp_dir().join(format!("zerun-image-volumes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let image_root = root.join("image");
        std::fs::create_dir_all(image_root.join("data")).unwrap();
        std::fs::write(image_root.join("data/seed.txt"), b"from image\n").unwrap();
        std::fs::create_dir_all(image_root.join("user-covered")).unwrap();
        std::fs::create_dir_all(image_root.join("tmp-covered")).unwrap();

        let user_mount = mounts::BindMount {
            source: root.clone(),
            target: PathBuf::from("/user-covered"),
            readonly: false,
            named: None,
            raw: format!("{}:/user-covered", root.display()),
        };
        let user_tmpfs = mounts::parse_tmpfs("/tmp-covered").unwrap();
        let targets = vec![
            "/data".to_string(),
            "/user-covered".to_string(),
            "/tmp-covered".to_string(),
        ];
        let (image_mounts, names) = materialize_image_volumes(
            &store,
            "abc123",
            &image_root,
            &targets,
            std::slice::from_ref(&user_mount),
            std::slice::from_ref(&user_tmpfs),
        )
        .unwrap();

        assert_eq!(image_mounts.len(), 1);
        assert_eq!(image_mounts[0].target, Path::new("/data"));
        assert_eq!(names, vec!["zerun-anon-abc123-0".to_string()]);
        assert_eq!(
            std::fs::read_to_string(image_mounts[0].source.join("seed.txt")).unwrap(),
            "from image\n"
        );
        assert_eq!(image_mounts[0].raw, "zerun-anon-abc123-0:/data");
        assert!(!store.volume_dir("zerun-anon-abc123-1").exists());

        remove_anonymous_volumes(&store, "abc123", &names);
        assert!(!image_mounts[0].source.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn image_volumes_keep_parents_of_nested_operator_mounts() {
        let root =
            std::env::temp_dir().join(format!("zerun-image-volume-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let image_root = root.join("image");
        std::fs::create_dir_all(&image_root).unwrap();
        let user_mount = mounts::BindMount {
            source: root.clone(),
            target: PathBuf::from("/data/cache"),
            readonly: false,
            named: None,
            raw: format!("{}:/data/cache", root.display()),
        };
        let (image_mounts, names) = materialize_image_volumes(
            &store,
            "def456",
            &image_root,
            &["/data".to_string()],
            std::slice::from_ref(&user_mount),
            &[],
        )
        .unwrap();
        assert_eq!(image_mounts.len(), 1);
        assert_eq!(image_mounts[0].target, Path::new("/data"));
        assert_eq!(names.len(), 1);

        remove_anonymous_volumes(&store, "def456", &names);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn image_volumes_reject_unsafe_paths_and_foreign_cleanup() {
        let root =
            std::env::temp_dir().join(format!("zerun-image-volume-safe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let image_root = root.join("image");
        std::fs::create_dir_all(&image_root).unwrap();

        for target in ["relative", "/", "/../escape", "/data:tag"] {
            assert!(
                materialize_image_volumes(
                    &store,
                    "abc123",
                    &image_root,
                    &[target.to_string()],
                    &[],
                    &[],
                )
                .is_err(),
                "{target} should be rejected"
            );
        }
        let foreign = store.volume_dir("app-data");
        std::fs::create_dir_all(&foreign).unwrap();
        remove_anonymous_volumes(
            &store,
            "abc123",
            &["app-data".to_string(), "zerun-anon-def456-0".to_string()],
        );
        assert!(foreign.is_dir());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn image_volume_materialization_rolls_back_on_later_failure() {
        let root = std::env::temp_dir().join(format!(
            "zerun-image-volume-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();
        let image_root = root.join("image");
        std::fs::create_dir_all(image_root.join("data")).unwrap();

        assert!(materialize_image_volumes(
            &store,
            "abc123",
            &image_root,
            &["/data".to_string(), "/data:tag".to_string()],
            &[],
            &[],
        )
        .is_err());
        assert!(!store.volume_dir("zerun-anon-abc123-0").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn image_argv_honors_entrypoint_override_and_reset() {
        let cfg = image::config::ImageConfig::parse(
            br#"{
                "config": {
                    "Entrypoint": ["/image-entry"],
                    "Cmd": ["default-cmd"]
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            resolve_image_argv(&cfg, None, &["cli".to_string()]),
            vec!["/image-entry", "cli"]
        );
        assert_eq!(
            resolve_image_argv(&cfg, Some("/override"), &["cli".to_string()]),
            vec!["/override", "cli"]
        );
        assert_eq!(resolve_image_argv(&cfg, Some(""), &[]), vec!["default-cmd"]);
        assert_eq!(
            resolve_image_argv(&cfg, Some("/override"), &[]),
            vec!["/override", "default-cmd"]
        );
    }

    #[test]
    fn local_image_platform_must_match_requested() {
        let mut cfg = image::config::ImageConfig {
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            ..Default::default()
        };
        let host = image::manifest::Platform {
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
            variant: None,
        };
        let arm = image::manifest::Platform {
            os: "linux".to_string(),
            architecture: "arm64".to_string(),
            variant: None,
        };
        assert!(local_image_matches_platform(&cfg, &host));
        assert!(!local_image_matches_platform(&cfg, &arm));

        cfg.architecture.clear();
        cfg.os.clear();
        assert!(local_image_matches_platform(&cfg, &arm));
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
    fn parses_and_captures_process_ulimits() {
        let args: Vec<_> = [
            "--ulimit",
            "nofile=64",
            "--ulimit=nofile=32:96",
            "--ulimit",
            "as=1:2",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid ulimit arguments");
        assert_eq!(a.ulimits.canonical(), vec!["as=1:2", "nofile=32:96"]);

        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert_eq!(
            launch_args
                .windows(2)
                .filter(|pair| pair[0] == "--ulimit")
                .map(|pair| pair[1].as_str())
                .collect::<Vec<_>>(),
            vec!["as=1:2", "nofile=32:96"]
        );

        for value in ["unknown=1", "nofile=2:1", "nofile=bad"] {
            let args: Vec<_> = ["--ulimit", value, "alpine", "true"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert!(parse_run_args(&args).is_err(), "{value} should be rejected");
        }
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
            "--shm-size",
            "96M",
            "--shm-size=32m",
            "alpine",
            "sh",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("flags");
        assert!(a.readonly);
        assert_eq!(a.tmpfs.len(), 2);
        assert_eq!(a.tmpfs[0].data, "size=16777216");
        assert!(a.tmpfs[1].readonly);
        assert_eq!(a.shm_size, Some(32 * 1024 * 1024));
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch.contains(&"--read-only".to_string()));
        assert!(launch.contains(&"/scratch:size=16m".to_string()));
        assert!(launch.contains(&"/run/shm:ro".to_string()));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--shm-size", "33554432"]));

        for value in ["", "NaN", "-1", "1..5M"] {
            let args = vec![format!("--shm-size={value}"), "alpine".to_string()];
            assert!(
                parse_run_args(&args).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn parses_and_captures_docker_style_mounts() {
        let args: Vec<_> = [
            "--mount",
            "type=volume,source=app-data,target=/var/lib/app,readonly",
            "--mount=type=tmpfs,target=/scratch,tmpfs-size=16m,tmpfs-mode=0700,readonly",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid --mount requests");
        assert_eq!(a.volumes.len(), 1);
        assert!(a.volumes[0].source.as_os_str().is_empty());
        assert_eq!(a.volumes[0].named.as_deref(), Some("app-data"));
        assert_eq!(a.volumes[0].target, Path::new("/var/lib/app"));
        assert!(a.volumes[0].readonly);
        assert_eq!(a.tmpfs.len(), 1);
        assert_eq!(a.tmpfs[0].target, Path::new("/scratch"));
        assert_eq!(a.tmpfs[0].data, "size=16777216,mode=700");
        assert!(a.tmpfs[0].readonly);

        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--volume", "app-data:/var/lib/app:ro"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--tmpfs", "/scratch:ro,size=16777216,mode=700"]));

        for value in [
            "",
            "type=bind,source=relative,target=/mnt",
            "type=volume,source=/tmp,target=/mnt",
            "type=tmpfs,target=/scratch,tmpfs-size=invalid",
            "type=tmpfs,target=/scratch,unknown=true",
        ] {
            let args = vec![format!("--mount={value}"), "alpine".to_string()];
            assert!(
                parse_run_args(&args).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn parses_and_captures_device_passthrough() {
        let args: Vec<_> = [
            "--device",
            "/dev/null:/dev/zerun-null:rw",
            "--device=/dev/zero:r",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid --device requests");
        assert_eq!(a.devices.len(), 2);
        assert_eq!(a.devices[0].target, Path::new("/dev/zerun-null"));
        assert!(a.devices[0].permissions.read);
        assert!(a.devices[0].permissions.write);
        assert!(!a.devices[0].permissions.mknod);
        assert_eq!(a.devices[1].target, Path::new("/dev/zero"));
        assert!(a.devices[1].permissions.read);
        assert!(!a.devices[1].permissions.write);

        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--device", "/dev/null:/dev/zerun-null:rw"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--device", "/dev/zero:r"]));

        for value in [
            "relative",
            "/tmp",
            "/dev/null:/dev/zerun-null:rx",
            "/dev/null:/../zerun-null:rw",
        ] {
            let args = vec![format!("--device={value}"), "alpine".to_string()];
            assert!(
                parse_run_args(&args).is_err(),
                "{value:?} should be rejected"
            );
        }
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
    fn parses_and_captures_group_additions() {
        let args: Vec<_> = [
            "--group-add",
            "staff",
            "--group-add=0044,1001",
            "--group-add",
            "44",
            "alpine",
            "id",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("--group-add");
        assert_eq!(a.group_add, vec!["staff", "44", "1001"]);
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert_eq!(
            launch_args
                .windows(2)
                .filter(|pair| pair[0] == "--group-add")
                .map(|pair| pair[1].as_str())
                .collect::<Vec<_>>(),
            vec!["staff", "44", "1001"]
        );

        for value in ["", "staff,", "staff:100", "-1", "4294967296"] {
            let args: Vec<_> = ["--group-add", value, "alpine", "true"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert!(parse_run_args(&args).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn parses_and_captures_host_namespace_modes() {
        let args: Vec<_> = [
            "--pid=host",
            "--ipc",
            "host",
            "--uts=private",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("namespace modes");
        assert_eq!(a.namespaces.pid, state::NamespaceMode::Host);
        assert_eq!(a.namespaces.ipc, state::IpcMode::Host);
        assert_eq!(a.namespaces.uts, state::NamespaceMode::Private);
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch.windows(2).any(|pair| pair == ["--pid", "host"]));
        assert!(launch.windows(2).any(|pair| pair == ["--ipc", "host"]));
        assert!(!launch.iter().any(|arg| arg == "--uts"));

        let ipc_none = ["--ipc=none", "alpine", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let ipc_none = parse_run_args(&ipc_none).expect("--ipc none");
        assert_eq!(ipc_none.namespaces.ipc, state::IpcMode::None);
        let launch = detached_launch_args(&ipc_none, Path::new("/tmp/rootfs"));
        assert!(launch.windows(2).any(|pair| pair == ["--ipc", "none"]));

        for option in [
            "--pid=container:web",
            "--pid=none",
            "--ipc=container:web",
            "--uts=",
        ] {
            let args = vec![option.to_string(), "alpine".to_string()];
            assert!(parse_run_args(&args).is_err(), "{option} should fail");
        }
        let incompatible = ["--uts=host", "--hostname", "box", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        assert!(parse_run_args(&incompatible).is_err());
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
    fn parses_expose_and_publish_all() {
        let args: Vec<_> = [
            "--expose",
            "80,53/udp",
            "--expose=8000-8001",
            "-dP",
            "alpine",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("expose flags");
        assert!(a.detach);
        assert!(a.publish_all);
        assert_eq!(
            a.exposed_ports,
            network::parse_expose_list("80,53/udp,8000-8001")
                .unwrap()
                .into_iter()
                .collect()
        );
        assert!(parse_run_args(&["--expose".into(), "0".into(), "alpine".into()]).is_err());
        assert!(parse_run_args(&["--expose=".into(), "alpine".into()]).is_err());
    }

    #[test]
    fn parses_image_exposed_ports_and_rejects_bad_keys() {
        let cfg = image::config::ImageConfig::parse(
            br#"{"config":{"ExposedPorts":{"80/tcp":{},"53/udp":{},"8000-8001/tcp":{}}}}"#,
        )
        .unwrap();
        assert_eq!(
            image_exposed_ports(&cfg).unwrap(),
            network::parse_expose_list("80,53/udp,8000-8001")
                .unwrap()
                .into_iter()
                .collect()
        );

        let bad =
            image::config::ImageConfig::parse(br#"{"config":{"ExposedPorts":{"http/tcp":{}}}}"#)
                .unwrap();
        let error = image_exposed_ports(&bad).unwrap_err();
        assert!(error.contains("ExposedPorts"));
        assert!(error.contains("http/tcp"));
    }

    #[test]
    fn normalizes_persisted_exposed_port_metadata() {
        assert_eq!(
            normalize_exposed_port_metadata(&[
                "8001/tcp".to_string(),
                "53/udp".to_string(),
                "8000-8001/tcp".to_string(),
                "53/udp".to_string(),
            ])
            .unwrap(),
            vec!["53/udp", "8000/tcp", "8001/tcp"]
        );
        assert!(normalize_exposed_port_metadata(&["invalid".to_string()]).is_err());
    }

    #[test]
    fn parses_bound_publish_addresses() {
        let tcp = parse_publish("127.0.0.1:8080:80").unwrap()[0];
        assert_eq!(tcp.host_ip, std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(tcp.host, 8080);
        assert_eq!(tcp.container, 80);

        let short_tcp = parse_publish("127.0.0.1:8080").unwrap()[0];
        assert_eq!(short_tcp.host, 8080);
        assert_eq!(short_tcp.container, 8080);

        let udp = parse_publish("[::1]:5353:53/udp").unwrap()[0];
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
    fn expands_published_port_ranges() {
        let same_range = parse_publish("8000-8002/udp").unwrap();
        assert_eq!(
            same_range
                .iter()
                .map(|port| (port.host, port.container, port.protocol))
                .collect::<Vec<_>>(),
            vec![
                (8000, 8000, network::PortProtocol::Udp),
                (8001, 8001, network::PortProtocol::Udp),
                (8002, 8002, network::PortProtocol::Udp),
            ]
        );

        let translated = parse_publish("127.0.0.1:9000-9001:80-81/tcp").unwrap();
        assert_eq!(translated.len(), 2);
        assert_eq!((translated[0].host, translated[0].container), (9000, 80));
        assert_eq!((translated[1].host, translated[1].container), (9001, 81));
        assert_eq!(
            translated[0].host_ip,
            std::net::IpAddr::from([127, 0, 0, 1])
        );

        for invalid in [
            "9000-9001:80",
            "9000:80-81",
            "9000-9001:80-82",
            "9001-9000:80-79",
            "80/sctp",
        ] {
            assert!(parse_publish(invalid).is_err(), "accepted {invalid:?}");
        }
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
                Some(&["udp".to_string(), "tcp".to_string()]),
                &[]
            ),
            "127.0.0.1:53->53/udp, [::1]:8080->80/tcp"
        );
        assert_eq!(
            ports_label(&ports, None, None, &[]),
            "0.0.0.0:53->53/tcp, 0.0.0.0:8080->80/tcp"
        );
        let exposed = [
            "53/udp".to_string(),
            "80/tcp".to_string(),
            "443/tcp".to_string(),
            "443/tcp".to_string(),
        ];
        assert_eq!(
            ports_label(
                &ports,
                ips.as_deref(),
                Some(&["udp".to_string(), "tcp".to_string()]),
                &exposed
            ),
            "127.0.0.1:53->53/udp, [::1]:8080->80/tcp, 443/tcp"
        );
        assert_eq!(ports_label(&[], None, None, &exposed[2..]), "443/tcp");
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
            "--label",
            "bare",
            "alpine",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid labels");
        assert_eq!(a.labels.get("tier").map(String::as_str), Some("dev"));
        assert_eq!(a.labels.get("only").map(String::as_str), Some(""));
        assert_eq!(a.labels.get("bare").map(String::as_str), Some(""));
        assert!(labels::parse_cli("=value").is_err());
        assert!(labels::parse_cli("white space=value").is_err());
    }

    #[test]
    fn parses_and_persists_cidfile() {
        let args: Vec<_> = ["--cidfile", "/tmp/web.cid", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("valid cidfile");
        assert_eq!(a.cidfile.as_deref(), Some("/tmp/web.cid"));
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--cidfile", "/tmp/web.cid"]));

        let inline: Vec<_> = ["--cidfile=/tmp/other.cid", "alpine"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            parse_run_args(&inline).unwrap().cidfile.as_deref(),
            Some("/tmp/other.cid")
        );
        assert!(parse_run_args(&["--cidfile=".to_string()]).is_err());
        assert!(parse_run_args(&["--cidfile".to_string()]).is_err());
    }

    #[test]
    fn parses_label_files_in_option_order() {
        let root = std::env::temp_dir().join(format!(
            "zerun-label-args-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("labels");
        std::fs::write(&path, "tier=file\nfrom-file=yes\nbare\n").unwrap();

        let args = vec![
            "--label".to_string(),
            "tier=before".to_string(),
            format!("--label-file={}", path.display()),
            "--label=tier=after".to_string(),
            "alpine".to_string(),
        ];
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(parsed.labels.get("tier").map(String::as_str), Some("after"));
        assert_eq!(
            parsed.labels.get("from-file").map(String::as_str),
            Some("yes")
        );
        assert!(!parsed.labels.contains_key("bare"));

        assert!(parse_run_args(&["--label-file=".to_string(), "alpine".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_and_persists_custom_host_aliases() {
        let args: Vec<_> = [
            "--net",
            "bridge",
            "--add-host",
            "db.internal:192.0.2.10",
            "--add-host",
            "host.zerun.internal:host-gateway",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid host aliases");
        assert_eq!(a.add_hosts.len(), 2);
        let entries =
            network::resolve_host_aliases(&a.add_hosts, Some(network::GATEWAY_IP)).unwrap();
        assert_eq!(entries[1].ip, std::net::IpAddr::V4(network::GATEWAY_IP));
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|w| w == ["--add-host", "db.internal:192.0.2.10"]));
        assert!(launch
            .windows(2)
            .any(|w| w == ["--add-host", "host.zerun.internal:host-gateway"]));

        assert!(parse_run_args(&["--add-host".to_string(), "host:not-an-ip".to_string()]).is_err());
    }

    #[test]
    fn parses_and_persists_dns_resolver_options() {
        let args: Vec<_> = [
            "--net",
            "bridge",
            "--dns=2001:0db8::53,198.51.100.53",
            "--dns-search",
            "svc.local",
            "--dns-search=corp.example,legacy.local",
            "--dns-option",
            "ndots:2",
            "--dns-opt=rotate,edns0",
            "alpine",
            "true",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid DNS options");
        assert_eq!(a.dns, ["2001:db8::53", "198.51.100.53"]);
        assert_eq!(a.dns_search, ["svc.local", "corp.example", "legacy.local"]);
        assert_eq!(a.dns_options, ["ndots:2", "rotate", "edns0"]);

        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--dns", "2001:db8::53"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--dns-search", "corp.example"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--dns-search", "legacy.local"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--dns-option", "rotate"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--dns-option", "edns0"]));

        for args in [
            ["--dns=not-an-ip", "alpine"],
            ["--dns=1.1.1.1,", "alpine"],
            ["--dns-search= svc.local", "alpine"],
            ["--dns-search=bad domain", "alpine"],
            ["--dns-option=rotate ", "alpine"],
            ["--dns-option=ndots:2 rotate", "alpine"],
        ] {
            let args = args
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            assert!(
                parse_run_args(&args).is_err(),
                "{args:?} should be rejected"
            );
        }
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
    fn parses_and_launches_cpu_limits() {
        let args: Vec<_> = [
            "--cpus",
            "0.5",
            "--cpu-shares",
            "2048",
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
        assert_eq!(a.cpu_shares, Some(2048));
        assert_eq!(a.cpuset_cpus.as_deref(), Some("0-3,8"));
        assert_eq!(a.cpuset_mems.as_deref(), Some("0"));
        let launch_args = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch_args.contains(&"--cpus".to_string()));
        assert!(launch_args.contains(&"0.5".to_string()));
        assert!(launch_args
            .windows(2)
            .any(|pair| pair == ["--cpu-shares", "2048"]));
        assert!(launch_args.contains(&"--cpuset-cpus".to_string()));
        assert!(launch_args.contains(&"0-3,8".to_string()));
        assert!(launch_args.contains(&"--cpuset-mems".to_string()));
        assert!(launch_args.contains(&"0".to_string()));
        assert!(cgroup::parse_cpuset("4-2").is_err());
        assert!(cgroup::parse_cpu_shares("1").is_err());
        assert!(cgroup::parse_cpu_shares("262145").is_err());
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

        let args: Vec<_> = ["-dt", "alpine", "echo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("detached tty flags");
        assert!(a.detach);
        assert!(a.tty);
        assert!(!a.interactive);
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch.iter().any(|arg| arg == "--tty"));

        let args: Vec<_> = ["-dit", "alpine", "echo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_run_args(&args).expect("combined detached flags");
        assert!(a.detach);
        assert!(a.interactive);
        assert!(a.tty);
    }

    #[test]
    fn parses_repeated_env_files() {
        let args: Vec<_> = ["--env-file", "first.env", "--env-file=second.env", "alpine"]
            .iter()
            .map(|value| value.to_string())
            .collect();
        let a = parse_run_args(&args).unwrap();
        assert_eq!(a.env_files, ["first.env", "second.env"]);
        assert!(parse_run_args(&["--env-file=".to_string(), "alpine".to_string()]).is_err());
        assert!(parse_run_args(&["--env-file".to_string(), String::new()]).is_err());
    }

    #[test]
    fn malformed_image_environment_is_rejected() {
        assert!(build_image_env(&["=bad".to_string()], &[], &[], None, "id", false).is_err());
        assert!(build_image_env(&["NO_EQUALS".to_string()], &[], &[], None, "id", false).is_err());
        assert!(
            build_image_env(&["OK=bad\0value".to_string()], &[], &[], None, "id", false).is_err()
        );
    }

    #[test]
    fn image_tty_gets_default_term() {
        let env = build_image_env(&[], &[], &[], None, "abc123", true).unwrap();
        assert_eq!(workload::env_value(&env, "TERM"), Some("xterm"));
    }

    #[test]
    fn env_files_precede_explicit_image_overrides() {
        let image = ["IMAGE_ONLY=image".to_string(), "ORDER=image".to_string()];
        let files = [
            ("FILE_ONLY".to_string(), "file".to_string()),
            ("ORDER".to_string(), "file".to_string()),
        ];
        let overrides = [
            "ORDER=explicit".to_string(),
            "EXPLICIT_ONLY=explicit".to_string(),
        ];
        let env = build_image_env(&image, &files, &overrides, None, "id", false).unwrap();
        assert_eq!(workload::env_value(&env, "IMAGE_ONLY"), Some("image"));
        assert_eq!(workload::env_value(&env, "FILE_ONLY"), Some("file"));
        assert_eq!(workload::env_value(&env, "ORDER"), Some("explicit"));
        assert_eq!(workload::env_value(&env, "EXPLICIT_ONLY"), Some("explicit"));
    }

    #[test]
    fn container_ids_are_random_sized_and_store_unique() {
        let root = std::env::temp_dir().join(format!(
            "zerun-id-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::at(root.join("data"), root.join("run"));
        store.ensure_dirs().unwrap();

        let first = ContainerIdReservation::reserve(&store).unwrap();
        assert_eq!(first.id.len(), 12);
        assert!(first.id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(first.path.is_dir());
        let first_id = first.id.clone();
        drop(first);
        assert!(!ContainerState::dir(&store, &first_id).exists());

        let second = ContainerIdReservation::reserve(&store).unwrap();
        assert_ne!(first_id, second.id);
        let second_dir = second.path.clone();
        let mut second = second;
        second.commit();
        drop(second);
        assert!(second_dir.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_id_reservations_are_unique() {
        use std::sync::Arc;
        use std::thread;

        let root = std::env::temp_dir().join(format!(
            "zerun-id-concurrent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = Arc::new(Store::at(root.join("data"), root.join("run")));
        store.ensure_dirs().unwrap();

        let mut workers = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            workers.push(thread::spawn(move || {
                let mut reservation = ContainerIdReservation::reserve(&store).unwrap();
                let id = reservation.id.clone();
                reservation.commit();
                id
            }));
        }
        let ids: Vec<String> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let unique: BTreeSet<_> = ids.iter().cloned().collect();
        assert_eq!(unique.len(), ids.len());
        assert!(ids
            .iter()
            .all(|id| ContainerState::dir(&store, id).is_dir()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rootful_defaults_to_bridge_and_rootless_to_none() {
        assert_eq!(default_net(0), NetMode::Bridge);
        assert_eq!(default_net(1000), NetMode::None);
        assert_eq!(default_pids_limit(0), Some(DEFAULT_PIDS_LIMIT));
        assert_eq!(default_pids_limit(1000), None);
    }

    #[test]
    fn accepts_docker_network_and_pids_aliases() {
        let args: Vec<String> = ["--network=host", "--pids-limit", "128", "alpine", "true"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(parsed.net, NetMode::Host);
        assert!(parsed.net_specified);
        assert_eq!(parsed.pids, Some(128));

        let args: Vec<String> = ["--net=none", "--pids=64", "alpine", "true"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(parsed.net, NetMode::None);
        assert_eq!(parsed.pids, Some(64));
        let launch = detached_launch_args(&parsed, Path::new("/tmp/rootfs"));
        assert!(launch.windows(2).any(|pair| pair == ["--net", "none"]));
        assert!(launch.windows(2).any(|pair| pair == ["--pids", "64"]));

        let args: Vec<String> = ["--network", "bridge", "--pids-limit=-1", "alpine", "true"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(parsed.net, NetMode::Bridge);
        assert_eq!(parsed.pids, Some(-1));

        assert!(
            parse_run_args(&["--network=container:web".to_string(), "alpine".to_string()])
                .err()
                .expect("container network mode must be rejected")
                .contains("bridge|host|none")
        );
        assert!(parse_run_args(&["--pids-limit=all".to_string(), "alpine".to_string()]).is_err());
    }

    #[test]
    fn parses_and_captures_healthcheck_options() {
        let args: Vec<_> = [
            "-d",
            "--health-cmd",
            "test -f /ready",
            "--health-interval=500ms",
            "--health-timeout",
            "2s",
            "--health-start-period",
            "1m",
            "--health-start-interval=100ms",
            "--health-retries",
            "4",
            "alpine",
            "sleep",
            "30",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect();
        let a = parse_run_args(&args).expect("valid health options");
        assert_eq!(a.health.cmd.as_deref(), Some("test -f /ready"));
        assert_eq!(a.health.interval_ns, Some(500_000_000));
        assert_eq!(a.health.timeout_ns, Some(2_000_000_000));
        assert_eq!(a.health.start_period_ns, Some(60_000_000_000));
        assert_eq!(a.health.start_interval_ns, Some(100_000_000));
        assert_eq!(a.health.retries, Some(4));
        let launch = detached_launch_args(&a, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--health-cmd", "test -f /ready"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--health-interval", "500000000ns"]));

        let disabled: Vec<_> = ["--no-healthcheck", "alpine"]
            .iter()
            .map(|value| value.to_string())
            .collect();
        assert!(parse_run_args(&disabled).unwrap().health.disabled);
        for invalid in [
            vec!["--health-retries=0", "alpine"],
            vec!["--health-interval=1d", "alpine"],
            vec!["--health-cmd=", "alpine"],
        ] {
            let args: Vec<_> = invalid.into_iter().map(String::from).collect();
            assert!(parse_run_args(&args).is_err());
        }
    }

    #[test]
    fn stop_signal_override_is_captured_in_launch_metadata() {
        let args: Vec<String> = [
            "--stop-signal",
            "SIGUSR1",
            "--stop-timeout",
            "7",
            "alpine",
            "echo",
            "ok",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(parsed.stop_signal, Some(libc::SIGUSR1));
        assert_eq!(parsed.stop_timeout, Some(7));
        let launch = detached_launch_args(&parsed, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--stop-signal", "SIGUSR1"]));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--stop-timeout", "7"]));
    }

    #[test]
    fn stop_timeout_rejects_negative_and_overflowing_values() {
        for value in ["-1", "18446744073709551616", "1.5", "ten"] {
            let args = vec!["--stop-timeout".to_string(), value.to_string()];
            assert!(parse_run_args(&args).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn restart_policy_is_parsed_and_captured_in_launch_metadata() {
        let args: Vec<String> = ["-d", "--restart=on-failure:2", "alpine", "echo", "ok"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let parsed = parse_run_args(&args).unwrap();
        assert_eq!(
            parsed.restart,
            Some(restart::RestartPolicy::OnFailure {
                max_retries: Some(2)
            })
        );
        let launch = detached_launch_args(&parsed, Path::new("/tmp/rootfs"));
        assert!(launch
            .windows(2)
            .any(|pair| pair == ["--restart", "on-failure:2"]));
    }

    #[test]
    fn run_rejects_malformed_restart_policies() {
        for value in [
            "",
            "on",
            "on-failure:",
            "on-failure:-1",
            "on-failure:nope",
            "always:2",
        ] {
            let args = vec![
                "-d".to_string(),
                "--restart".to_string(),
                value.to_string(),
                "alpine".to_string(),
            ];
            assert!(parse_run_args(&args).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn stop_signal_precedence_prefers_run_then_image_then_default() {
        assert_eq!(
            resolve_stop_signal(Some(libc::SIGUSR1), "SIGQUIT"),
            Ok(libc::SIGUSR1)
        );
        assert_eq!(resolve_stop_signal(None, "SIGQUIT"), Ok(libc::SIGQUIT));
        assert_eq!(
            resolve_stop_signal(None, ""),
            Ok(signal::DEFAULT_STOP_SIGNAL)
        );
        assert!(resolve_stop_signal(None, "not-a-signal").is_err());
    }

    #[test]
    fn terminating_signals_thaw_paused_containers() {
        assert!(signal_requires_thaw(libc::SIGTERM));
        assert!(signal_requires_thaw(libc::SIGKILL));
        assert!(!signal_requires_thaw(libc::SIGSTOP));
        assert!(!signal_requires_thaw(libc::SIGCONT));
        assert!(!signal_requires_thaw(libc::SIGWINCH));
    }
}
