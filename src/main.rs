//! zerun — daemonless, single-binary Linux container runtime.
//!
//! Current milestone (M1 baseline): run a workload in an isolated namespace
//! environment from a local rootfs directory:
//!
//!   sudo ./zerun run --rootfs ./alpine-rootfs --memory 64M --pids 256 -- /bin/sh
//!   ./zerun doctor
mod cgroup;
mod error;
mod mini_init;
mod mounts;
mod namespace;
mod seccomp;
mod security;
mod syscalls;
mod trace;

use cgroup::ResourceLimits;
use namespace::{NetMode, RunSpec};
use seccomp::SeccompMode;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[2..]),
        Some("doctor") => cmd_doctor(),
        Some("__init") => {
            // Internal re-exec entry: __init -- <cmd...>
            let pos = args.iter().position(|a| a == "--");
            let business: Vec<String> = pos.map(|p| args[p + 1..].to_vec()).unwrap_or_default();
            match mini_init::run(&business) {
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
    memory: Option<String>,
    cpus: Option<f64>,
    pids: Option<i64>,
    hostname: Option<String>,
    net: NetMode,
    use_init: bool,
    seccomp: SeccompMode,
    argv: Vec<String>,
}

fn cmd_run(args: &[String]) -> i32 {
    let mut a = RunArgs::default();
    let mut i = 0;
    while i < args.len() {
        let s = &args[i];
        match s.as_str() {
            "--rootfs" => {
                a.rootfs = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--memory" => {
                a.memory = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--cpus" => {
                a.cpus = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "--pids" => {
                a.pids = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "--hostname" => {
                a.hostname = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
            "--net" => {
                a.net = match args.get(i + 1).map(|s| s.as_str()) {
                    Some("host") => NetMode::Host,
                    _ => NetMode::None,
                };
                i += 2;
            }
            "--init" => {
                a.use_init = true;
                i += 1;
            }
            "--seccomp" => {
                a.seccomp = match args.get(i + 1).map(|s| s.as_str()) {
                    Some("unconfined") => SeccompMode::Unconfined,
                    _ => SeccompMode::Default,
                };
                i += 2;
            }
            "--" => {
                a.argv = args[i + 1..].to_vec();
                i = args.len();
            }
            other if other.starts_with("--") => {
                eprintln!("zerun: unknown option {other}");
                return 2;
            }
            _ => {
                // First non-option argument starts the command.
                a.argv = args[i..].to_vec();
                i = args.len();
            }
        }
    }

    let rootfs = match a.rootfs {
        Some(r) => std::path::PathBuf::from(r),
        None => {
            eprintln!(
                "zerun run: --rootfs is required (only unpacked rootfs dirs are supported for now)"
            );
            return 2;
        }
    };
    if !rootfs.join("bin").exists() && !rootfs.join("usr/bin").exists() {
        eprintln!("zerun: {rootfs:?} does not look like a valid rootfs (missing bin/ or usr/bin/)");
    }
    if a.argv.is_empty() {
        a.argv = vec!["/bin/sh".to_string()];
    }

    let spec = RunSpec {
        rootfs,
        argv: a.argv,
        hostname: a.hostname,
        net: a.net,
        use_init: a.use_init,
        limits: ResourceLimits {
            memory: a.memory,
            cpus: a.cpus,
            pids: a.pids,
        },
        seccomp: a.seccomp,
        id: short_id(),
    };

    match namespace::run_container(spec) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zerun: {e}");
            1
        }
    }
}

fn cmd_doctor() -> i32 {
    println!("== Zerun environment doctor ==");
    // Kernel version.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let rel = syscalls::cstr_to_string(u.release.as_ptr());
            println!("kernel release : {rel}  (baseline recommendation >= 5.10 LTS)");
        }
    }
    // cgroup v2.
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
    // User namespaces.
    match std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        Ok(v) => println!("user namespaces: max = {}", v.trim()),
        Err(_) => println!("user namespaces: unknown"),
    }
    // OverlayFS.
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
    println!(
        "uid            : {} (rootful isolation needs uid=0; non-root goes rootless via NEWUSER)",
        unsafe { libc::geteuid() }
    );
    0
}

fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos & 0xffff_ffff_ffff)
}

fn print_help() {
    println!(
        "zerun — daemonless single-binary container runtime\n\
\n\
USAGE:\n  \
  zerun run --rootfs DIR [options] -- CMD [ARGS...]\n  \
  zerun doctor\n\
\n\
RUN OPTIONS:\n  \
  --rootfs DIR    unpacked container root filesystem directory (required for now)\n  \
  --memory 64M    cgroup v2 memory.max (K/M/G suffixes)\n  \
  --cpus 0.5      cgroup v2 cpu.max (cores)\n  \
  --pids 256      cgroup v2 pids.max\n  \
  --hostname H    container hostname (new UTS namespace)\n  \
  --net none|host none = fresh netns with loopback only (default); host = share host net\n  \
  --init          run the built-in mini-init (reap orphans + forward signals)\n\
\n\
ENV:\n  \
  ZERUN_TRACE=1   print per-stage nanosecond timings to stderr (bench harness)"
    );
}
