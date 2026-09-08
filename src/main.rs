//! zerun — daemonless, single-binary Linux container runtime.
//!
//! Command surface (Docker-compatible top 20%):
//!   zerun run [opts] IMAGE [CMD...]     run a container from an OCI image
//!   zerun run --rootfs DIR [opts] -- CMD  legacy: run from an unpacked rootfs
//!   zerun pull / images / rmi           OCI image lifecycle (M3)
//!   zerun doctor                        environment diagnostics
mod cgroup;
mod error;
mod fsutil;
mod image;
mod mini_init;
mod mounts;
mod namespace;
mod seccomp;
mod security;
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
use std::path::PathBuf;
use std::process::exit;
use store::Store;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("run") => cmd_run(&args[2..]),
        Some("pull") => cmd_pull(&args[2..]),
        Some("images") => cmd_images(&args[2..]),
        Some("rmi") => cmd_rmi(&args[2..]),
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
    use_init: bool,
    seccomp: SeccompMode,
    no_overlay: bool,
    platform: Option<String>,
    env: Vec<String>,
    argv: Vec<String>,
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
                a.net = match v.as_str() {
                    "host" => NetMode::Host,
                    "none" => NetMode::None,
                    other => return Err(format!("invalid --net value '{other}' (host|none)")),
                };
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

fn next_value(args: &[String], i: &mut usize, opt: &str) -> Result<String, String> {
    let v = args
        .get(*i + 1)
        .ok_or_else(|| format!("option {opt} requires a value"))?;
    *i += 2;
    Ok(v.clone())
}

fn cmd_run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help") {
        print_run_usage();
        return 0;
    }
    let a = match parse_run_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("zerun run: {e}");
            return 2;
        }
    };
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
        let mut argv = a.argv;
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
                    build_image_env(&cfg.config.env, &a.env, a.hostname.as_deref(), &short_id());
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

    let id = short_id();
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
        overlay,
        id,
        env,
        cwd,
    };

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
         zerun run --rootfs DIR [OPTIONS] [--] CMD [ARGS...]   (legacy)"
    );
}

fn print_help() {
    println!(
        "zerun — daemonless single-binary container runtime\n\
\n\
USAGE:\n  \
  zerun run [opts] IMAGE [CMD...]        run a container from an OCI image\n  \
  zerun pull [--platform ...] IMAGE...   pull OCI images (Docker Hub, mirrors)\n  \
  zerun images                           list local images\n  \
  zerun rmi IMAGE...                     remove local images\n  \
  zerun doctor                           environment diagnostics\n\
\n\
RUN OPTIONS:\n  \
  --rootfs DIR    run from an unpacked rootfs dir instead of an image (legacy)\n  \
  -m, --memory 64M    cgroup v2 memory.max (K/M/G suffixes)\n  \
  --cpus 0.5          cgroup v2 cpu.max (cores)\n  \
  --pids 256          cgroup v2 pids.max\n  \
  -h, --hostname H    container hostname (new UTS namespace)\n  \
  --net none|host     none = fresh netns with loopback only (default); host = share host net\n  \
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
