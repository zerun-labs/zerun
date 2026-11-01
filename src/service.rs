//! systemd integration for foreground containers (`zerun generate-service`).
//!
//! Zerun is daemonless.  Rather than asking systemd to supervise an internal
//! daemon, it supervises the normal foreground `zerun run` process. The
//! container is then an ordinary child of the unit; SIGTERM reaches Zerun's
//! signal-forwarding path and is translated to the image/operator stop signal.
//! A failed container is restarted by systemd.
//!
//! The generated unit is intentionally declarative: it is built from the same
//! run arguments the operator would type, not from mutable runtime state under
//! `/run` (which does not survive a reboot).
use crate::namespace::NetMode;
use crate::seccomp::SeccompMode;
use crate::{PullPolicy, RunArgs};
use std::io::Write;
use std::path::Path;

/// Render a systemd unit for the supplied `run` arguments to `out`.
pub fn generate(a: &RunArgs, out: &mut dyn Write) -> Result<(), String> {
    let binary = std::env::current_exe()
        .map_err(|e| format!("resolve current executable: {e}"))?
        .canonicalize()
        .map_err(|e| format!("canonicalize current executable: {e}"))?;
    let rootful = crate::syscalls::effective_uid() == 0;
    let unit = render(&binary, a, rootful)?;
    out.write_all(unit.as_bytes())
        .map_err(|e| format!("write service: {e}"))?;
    Ok(())
}

/// Generate unit text.  `binary` is injected separately for testability.
pub fn render(binary: &Path, a: &RunArgs, rootful: bool) -> Result<String, String> {
    validate(a, rootful)?;

    let container_name = a
        .name
        .clone()
        .unwrap_or_else(|| source_label(a.rootfs.as_deref(), a.image.as_deref()));
    let mut run_args = vec![
        "run".to_string(),
        "--name".to_string(),
        container_name.clone(),
    ];

    if let Some(rootfs) = &a.rootfs {
        // A service starts with / as its working directory.  Resolve the rootfs
        // while generating the unit to catch relative paths and a rootfs that
        // has already disappeared.
        let abs = std::fs::canonicalize(rootfs).map_err(|e| format!("rootfs {rootfs}: {e}"))?;
        run_args.push("--rootfs".into());
        run_args.push(abs.display().to_string());
    }

    if let Some(v) = &a.memory {
        run_args.push("--memory".into());
        run_args.push(v.clone());
    }
    if let Some(v) = &a.memory_reservation {
        run_args.push("--memory-reservation".into());
        run_args.push(v.clone());
    }
    if let Some(v) = a.memory_swap {
        run_args.push("--memory-swap".into());
        run_args.push(if v < 0 { "-1".into() } else { v.to_string() });
    }
    if let Some(v) = a.cpus {
        run_args.push("--cpus".into());
        run_args.push(v.to_string());
    }
    if let Some(v) = a.cpu_shares {
        run_args.push("--cpu-shares".into());
        run_args.push(v.to_string());
    }
    if let Some(v) = &a.cpuset_cpus {
        run_args.push("--cpuset-cpus".into());
        run_args.push(v.clone());
    }
    if let Some(v) = &a.cpuset_mems {
        run_args.push("--cpuset-mems".into());
        run_args.push(v.clone());
    }
    if let Some(v) = a.pids {
        run_args.push("--pids".into());
        run_args.push(v.to_string());
    }
    if a.oom_group {
        run_args.push("--oom-group".into());
    }
    for value in a.ulimits.canonical() {
        run_args.push("--ulimit".into());
        run_args.push(value);
    }
    for v in &a.device_read_bps {
        if let Some(limit) = v.read_bps {
            run_args.push("--device-read-bps".into());
            run_args.push(format!("{}:{}", v.device, limit));
        }
    }
    for v in &a.device_write_bps {
        if let Some(limit) = v.write_bps {
            run_args.push("--device-write-bps".into());
            run_args.push(format!("{}:{}", v.device, limit));
        }
    }
    for v in &a.device_read_iops {
        if let Some(limit) = v.read_iops {
            run_args.push("--device-read-iops".into());
            run_args.push(format!("{}:{}", v.device, limit));
        }
    }
    for v in &a.device_write_iops {
        if let Some(limit) = v.write_iops {
            run_args.push("--device-write-iops".into());
            run_args.push(format!("{}:{}", v.device, limit));
        }
    }
    if let Some(v) = &a.hostname {
        run_args.push("--hostname".into());
        run_args.push(v.clone());
    }
    for (flag, mode) in [("--pid", a.namespaces.pid), ("--uts", a.namespaces.uts)] {
        if mode == crate::state::NamespaceMode::Host {
            run_args.push(flag.into());
            run_args.push(mode.label().into());
        }
    }
    if a.namespaces.ipc != crate::state::IpcMode::Private {
        run_args.push("--ipc".into());
        run_args.push(a.namespaces.ipc.label().into());
    }
    if let Some(v) = &a.user {
        run_args.push("--user".into());
        run_args.push(v.clone());
    }
    for value in &a.group_add {
        run_args.push("--group-add".into());
        run_args.push(value.clone());
    }
    if let Some(v) = a.stop_signal {
        run_args.push("--stop-signal".into());
        run_args.push(crate::signal::name(v));
    }
    if let Some(v) = a.stop_timeout {
        run_args.push("--stop-timeout".into());
        run_args.push(v.to_string());
    }
    if a.net != NetMode::None {
        run_args.push("--net".into());
        run_args.push(match a.net {
            NetMode::Host => "host".into(),
            NetMode::Bridge => "bridge".into(),
            NetMode::None => unreachable!("handled above"),
        });
    }
    if a.use_init {
        run_args.push("--init".into());
    }
    if matches!(a.seccomp, SeccompMode::Unconfined) {
        run_args.push("--seccomp".into());
        run_args.push("unconfined".into());
    }
    for cap in &a.cap_add {
        run_args.push("--cap-add".into());
        run_args.push(cap.clone());
    }
    for cap in &a.cap_drop {
        run_args.push("--cap-drop".into());
        run_args.push(cap.clone());
    }
    if a.no_overlay {
        run_args.push("--no-overlay".into());
    }
    if a.tmpfs_upper {
        run_args.push("--tmpfs-upper".into());
    }
    if a.readonly {
        run_args.push("--read-only".into());
    }
    for t in &a.tmpfs {
        run_args.push("--tmpfs".into());
        run_args.push(t.raw.clone());
    }
    if let Some(size) = a.shm_size {
        run_args.push("--shm-size".into());
        run_args.push(size.to_string());
    }
    for v in &a.volumes {
        run_args.push("--volume".into());
        run_args.push(v.raw.clone());
    }
    for device in &a.devices {
        run_args.push("--device".into());
        run_args.push(device.raw.clone());
    }
    if let Some(v) = &a.platform {
        run_args.push("--platform".into());
        run_args.push(v.clone());
    }
    if let Some(v) = &a.entrypoint {
        run_args.push("--entrypoint".into());
        run_args.push(v.clone());
    }
    if let Some(v) = &a.workdir {
        run_args.push("--workdir".into());
        run_args.push(v.clone());
    }
    if a.pull != PullPolicy::Missing {
        run_args.push("--pull".into());
        run_args.push(a.pull.label().into());
    }
    let env_files = crate::workload::resolve_env_file_paths(&a.env_files)?;
    crate::workload::load_env_files(&env_files)?;
    for path in env_files {
        run_args.push("--env-file".into());
        run_args.push(path.display().to_string());
    }
    for v in &a.env {
        run_args.push("--env".into());
        run_args.push(v.clone());
    }
    for p in &a.ports {
        run_args.push("--publish".into());
        run_args.push(format!("{}:{}", p.host, p.container));
    }
    for v in &a.dns {
        run_args.push("--dns".into());
        run_args.push(v.clone());
    }
    for v in &a.dns_search {
        run_args.push("--dns-search".into());
        run_args.push(v.clone());
    }
    for v in &a.dns_options {
        run_args.push("--dns-option".into());
        run_args.push(v.clone());
    }
    for v in &a.add_hosts {
        run_args.push("--add-host".into());
        run_args.push(v.render());
    }
    for (k, v) in &a.labels {
        run_args.push("--label".into());
        run_args.push(format!("{k}={v}"));
    }
    if let Some(image) = &a.image {
        run_args.push(image.clone());
    }
    if !a.argv.is_empty() {
        if a.rootfs.is_none() {
            if let Some(last) = run_args.last() {
                if last != "--" {
                    run_args.push("--".into());
                }
            }
        } else {
            // Legacy mode consumes everything after --rootfs as the command, so
            // run options must remain on the left of the separator.
            run_args.push("--".into());
        }
        run_args.extend(a.argv.iter().cloned());
    }

    let mut exec_start = Vec::new();
    for value in std::iter::once(binary.display().to_string()).chain(run_args) {
        exec_start.push(quote_systemd(&value)?);
    }
    let exec_start = exec_start.join(" ");

    let mut s = String::new();
    s.push_str("# Generated by zerun generate-service; edit run arguments with care.\n");
    s.push_str("[Unit]\n");
    s.push_str(&format!(
        "Description=Zerun container {}\n",
        quote_systemd(&container_name)?
    ));
    if rootful {
        s.push_str("After=network-online.target\n");
        s.push_str("Wants=network-online.target\n");
    } else {
        // A user manager cannot reliably order against system network targets.
        // Keep the unit self-contained; systemd restarts the unit if Zerun
        // exits because networking was unavailable.
        s.push_str("# Install as a user unit (systemctl --user) to preserve rootless semantics.\n");
    }
    s.push('\n');
    s.push_str("[Service]\n");
    s.push_str("Type=simple\n");
    s.push_str(&format!("ExecStart={exec_start}\n"));
    for key in ["ZERUN_DATA_ROOT", "ZERUN_RUNTIME_ROOT"] {
        if let Some(v) = std::env::var_os(key) {
            let value = v
                .into_string()
                .map_err(|_| format!("{key} contains invalid UTF-8"))?;
            let value = quote_environment(&value)?;
            s.push_str(&format!("Environment=\"{key}={value}\"\n"));
        }
    }
    s.push_str("Restart=on-failure\n");
    s.push_str("RestartSec=2s\n");
    s.push_str("KillMode=mixed\n");
    // The foreground parent maps SIGTERM to the image/operator stop signal, so
    // systemd does not need to know that signal at unit-generation time.
    s.push_str("KillSignal=SIGTERM\n");
    s.push_str(&format!(
        "TimeoutStopSec={}\n",
        systemd_timeout(
            a.stop_timeout
                .unwrap_or(crate::state::DEFAULT_STOP_TIMEOUT_SECS)
        )
    ));
    s.push_str("NoNewPrivileges=true\n");
    // A workload terminated by its stop signal produces 128+signal after the
    // foreground parent forwards it. Explicit run policy is known here; image
    // policy is resolved at runtime and otherwise falls back to SIGTERM.
    let stop_exit_status = 128 + a.stop_signal.unwrap_or(crate::signal::DEFAULT_STOP_SIGNAL);
    s.push_str(&format!("SuccessExitStatus={stop_exit_status}\n"));
    s.push_str("StandardOutput=journal\n");
    s.push_str("StandardError=journal\n");
    s.push_str("\n[Install]\n");
    if rootful {
        s.push_str("WantedBy=multi-user.target\n");
    } else {
        s.push_str("WantedBy=default.target\n");
    }
    Ok(s)
}

// systemd parses time spans into u64 microseconds. Keep one second below the
// arithmetic boundary so its decimal parser cannot round into overflow.
const SYSTEMD_MAX_TIMEOUT_SECS: u64 = u64::MAX / 1_000_000 - 1;

pub fn print_usage() {
    println!(
        "usage:\n  \
         zerun generate-service [RUN OPTIONS] IMAGE [CMD [ARGS...]]\n  \
         zerun generate-service [RUN OPTIONS] --rootfs DIR [--] CMD [ARGS...]\n\n\
         Writes a systemd unit to stdout. Most zerun run options are supported;\n\
         -d/--detach, --rm, and --restart are rejected because systemd owns the lifecycle."
    );
}

fn validate(a: &RunArgs, rootful: bool) -> Result<(), String> {
    if let Some(timeout) = a.stop_timeout {
        if timeout > SYSTEMD_MAX_TIMEOUT_SECS {
            return Err(format!(
                "--stop-timeout {timeout} exceeds systemd's maximum of {SYSTEMD_MAX_TIMEOUT_SECS} seconds"
            ));
        }
    }
    if a.detach {
        return Err(
            "-d/--detach cannot be used with generate-service; systemd runs the foreground process"
                .into(),
        );
    }
    if a.rm {
        return Err("--rm cannot be used with generate-service; systemd owns the lifecycle".into());
    }
    if a.restart.is_some() {
        return Err(
            "--restart cannot be used with generate-service; systemd owns restart policy".into(),
        );
    }
    if a.tty || a.interactive {
        return Err(
            "-t/--tty and -i/--interactive cannot be used with generate-service; \
             service units have no attached terminal"
                .into(),
        );
    }
    if a.rootfs.is_some() && a.image.is_some() {
        return Err("--rootfs and IMAGE are mutually exclusive".into());
    }
    if a.no_overlay && a.tmpfs_upper {
        return Err("--tmpfs-upper requires the writable overlay; remove --no-overlay".into());
    }
    crate::mounts::validate_device_permissions(!rootful, &a.devices)?;
    crate::mounts::validate_device_targets(&a.devices)?;
    let effective_net = if a.net_specified {
        a.net
    } else if rootful {
        NetMode::Bridge
    } else {
        NetMode::None
    };
    if !a.ports.is_empty() && effective_net != NetMode::Bridge {
        return Err("-p/--publish requires --net bridge".into());
    }
    if (!a.dns.is_empty() || !a.dns_search.is_empty() || !a.dns_options.is_empty())
        && effective_net != NetMode::Bridge
    {
        return Err("DNS options require --net bridge".into());
    }
    if !a.add_hosts.is_empty() && effective_net == NetMode::Host {
        return Err("--add-host cannot be used with --net host".into());
    }
    crate::network::resolve_host_aliases(
        &a.add_hosts,
        (effective_net == NetMode::Bridge).then_some(crate::network::GATEWAY_IP),
    )?;
    if a.rootfs.is_some() && (!a.env.is_empty() || !a.env_files.is_empty()) {
        return Err("-e/--env and --env-file require image mode (drop --rootfs)".into());
    }
    if a.rootfs.is_some() && a.entrypoint.is_some() {
        return Err("--entrypoint requires image mode (drop --rootfs)".into());
    }
    if a.rootfs.is_some() && a.pull != PullPolicy::Missing {
        return Err("--pull requires image mode (drop --rootfs)".into());
    }
    if a.workdir.as_deref() == Some("") {
        return Err("--workdir cannot be empty".into());
    }
    if a.log_options_set {
        return Err(
            "log rotation options are not supported with generate-service; systemd journald owns service logs"
                .into(),
        );
    }
    if a.rootfs.is_none() && a.image.is_none() {
        return Err("an IMAGE (or --rootfs DIR for legacy mode) is required".into());
    }
    if let Some(name) = &a.name {
        let valid = !name.is_empty()
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if !valid {
            return Err(format!(
                "invalid --name '{name}' for a service unit (use ASCII alphanumerics, '.', '_' or '-')"
            ));
        }
    }
    Ok(())
}

/// systemd treats a zero timeout as "disabled"; Zerun's zero means an
/// immediate SIGKILL, so use the smallest practical positive duration instead.
fn systemd_timeout(seconds: u64) -> String {
    if seconds == 0 {
        "1ms".to_string()
    } else {
        format!("{seconds}s")
    }
}

fn source_label(rootfs: Option<&str>, image: Option<&str>) -> String {
    match (rootfs, image) {
        (_, Some(image)) => sanitize(image),
        (Some(rootfs), _) => Path::new(rootfs)
            .file_name()
            .map(|s| sanitize(&s.to_string_lossy()))
            .unwrap_or_else(|| "container".into()),
        _ => "container".into(),
    }
}

/// Map a user-provided label to a safe systemd unit filename component.
fn sanitize(value: &str) -> String {
    let out: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let out = out.trim_matches('-').to_string();
    if out.is_empty() || out == "." || out == ".." {
        "container".to_string()
    } else {
        out
    }
}

/// Quote one argument using systemd's ExecStart command-line grammar.
///
/// `$$` and `%%` preserve literal values through systemd's environment and
/// specifier expansion.  Newlines and NULs are rejected because they cannot be
/// represented reliably in a one-line unit setting.
fn quote_systemd(value: &str) -> Result<String, String> {
    if value.contains(['\n', '\r', '\0']) {
        return Err("control characters are not supported in service arguments".into());
    }
    if value.is_empty() {
        return Ok("\"\"".to_string());
    }
    if !value.contains([' ', '\t', '"', '\\', '$', '%']) {
        return Ok(value.to_string());
    }

    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("$$"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Quote the value of an `Environment=` setting.
///
/// The setting itself is wrapped in double quotes; characters that would end
/// that quote or trigger expansion are escaped inside it.
fn quote_environment(value: &str) -> Result<String, String> {
    if value.contains(['\n', '\r', '\0']) {
        return Err("control characters are not supported in service environment values".into());
    }
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("$$"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> RunArgs {
        let owned: Vec<String> = values.iter().map(|s| s.to_string()).collect();
        crate::parse_run_args(&owned).expect("valid run args")
    }

    #[test]
    fn renders_image_service() {
        let a = args(&[
            "--init", "--net", "bridge", "-p", "8080:80", "--name", "web", "alpine", "echo",
            "hello",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.starts_with("# Generated by zerun generate-service;"));
        assert!(unit.contains("Description=Zerun container web\n"));
        assert!(unit.contains("ExecStart=/usr/local/bin/zerun run --name web"));
        assert!(unit.contains("--init"));
        assert!(unit.contains("--net bridge"));
        assert!(unit.contains("--publish 8080:80"));
        assert!(unit.contains("alpine -- echo hello\n"));
        assert!(unit.contains("--publish 8080:80"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn renders_cpuset_limits() {
        let a = args(&[
            "--cpuset-cpus",
            "0-1",
            "--cpuset-mems",
            "0",
            "alpine",
            "true",
        ]);
        let unit = render(&PathBuf::from("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--cpuset-cpus 0-1"));
        assert!(unit.contains("--cpuset-mems 0"));
    }

    #[test]
    fn renders_canonical_mount_requests() {
        let a = args(&[
            "--mount",
            "type=volume,source=app-data,target=/var/lib/app,readonly",
            "--mount",
            "type=tmpfs,target=/scratch,tmpfs-size=16m",
            "--device",
            "/dev/null:/dev/zerun-null:rw",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--volume app-data:/var/lib/app:ro"));
        assert!(unit.contains("--tmpfs /scratch:size=16777216"));
        assert!(unit.contains("--device /dev/null:/dev/zerun-null:rw"));
    }

    #[test]
    fn rejects_restricted_device_permissions_for_rootless_services() {
        let a = args(&["--device", "/dev/null:r", "alpine", "true"]);
        let error = render(Path::new("/usr/local/bin/zerun"), &a, false).unwrap_err();
        assert!(error.contains("permission subsets require rootful"));
    }

    #[test]
    fn renders_cpu_shares() {
        let a = args(&["--cpu-shares", "512", "alpine", "true"]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--cpu-shares 512"));
    }

    #[test]
    fn renders_private_shm_size() {
        let a = args(&["--shm-size", "96m", "alpine", "true"]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--shm-size 100663296"));
    }

    #[test]
    fn renders_group_additions() {
        let a = args(&[
            "--user",
            "1000:1000",
            "--group-add",
            "staff",
            "--group-add=0044,1001",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--user 1000:1000"));
        assert!(unit.contains("--group-add staff"));
        assert!(unit.contains("--group-add 44"));
        assert!(unit.contains("--group-add 1001"));
    }

    #[test]
    fn renders_host_namespace_modes() {
        let a = args(&[
            "--pid=host",
            "--ipc",
            "host",
            "--uts=host",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--pid host"));
        assert!(unit.contains("--ipc host"));
        assert!(unit.contains("--uts host"));
    }

    #[test]
    fn renders_ipc_without_shared_memory() {
        let a = args(&["--ipc=none", "alpine", "true"]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--ipc none"));
    }

    #[test]
    fn renders_dns_search_domains_and_options() {
        let a = args(&[
            "--dns=1.1.1.1",
            "--dns-search=svc.local",
            "--dns-option=ndots:2",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--dns 1.1.1.1"));
        assert!(unit.contains("--dns-search svc.local"));
        assert!(unit.contains("--dns-option ndots:2"));

        let error = render(Path::new("/usr/local/bin/zerun"), &a, false).unwrap_err();
        assert!(error.contains("require --net bridge"));
    }

    #[test]
    fn renders_process_ulimits() {
        let a = args(&[
            "--ulimit",
            "nofile=64:96",
            "--ulimit=as=unlimited",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--ulimit as=-1:-1"));
        assert!(unit.contains("--ulimit nofile=64:96"));
    }

    #[test]
    fn renders_capability_controls() {
        let a = args(&[
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_RAW,SYS_ADMIN",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/usr/local/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("--cap-drop ALL"));
        assert!(unit.contains("--cap-add CAP_NET_RAW"));
        assert!(unit.contains("--cap-add CAP_SYS_ADMIN"));
    }

    #[test]
    fn renders_labels_in_run_options() {
        let mut a = RunArgs {
            image: Some("alpine".to_string()),
            labels: BTreeMap::from([("tier".to_string(), "prod".to_string())]),
            ..Default::default()
        };
        a.argv = vec!["/bin/sh".to_string()];
        let mut out = Vec::new();
        generate(&a, &mut out).unwrap();
        let unit = String::from_utf8(out).unwrap();
        assert!(unit.contains("--label tier=prod"));
    }

    #[test]
    fn renders_and_validates_custom_host_aliases() {
        let a = args(&[
            "--net",
            "bridge",
            "--add-host",
            "db.internal:192.0.2.10",
            "--add-host",
            "host.zerun.internal:host-gateway",
            "alpine",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --add-host db.internal:192.0.2.10 "));
        assert!(unit.contains(" --add-host host.zerun.internal:host-gateway "));

        let host_net = args(&[
            "--net",
            "host",
            "--add-host",
            "db.internal:192.0.2.10",
            "alpine",
        ]);
        assert!(render(Path::new("/bin/zerun"), &host_net, true).is_err());

        let no_gateway = args(&[
            "--net",
            "none",
            "--add-host",
            "host.zerun.internal:host-gateway",
            "alpine",
        ]);
        assert!(render(Path::new("/bin/zerun"), &no_gateway, true).is_err());
    }

    #[test]
    fn renders_image_command_overrides() {
        let a = args(&[
            "--entrypoint",
            "/bin/sh",
            "--workdir",
            "/srv/app",
            "--pull",
            "never",
            "alpine",
            "-c",
            "echo hi",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --entrypoint /bin/sh "));
        assert!(unit.contains(" --workdir /srv/app "));
        assert!(unit.contains(" --pull never "));
    }

    #[test]
    fn renders_and_validates_canonical_env_files() {
        let dir = std::env::temp_dir().join(format!(
            "zerun-service-env-file-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join("app.env");
        std::fs::write(&env_file, "MODE=production\n").unwrap();
        let a = args(&[
            "--env-file",
            env_file.to_str().unwrap(),
            "--env",
            "MODE=test",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(&format!(
            " --env-file {} --env MODE=test ",
            env_file.display()
        )));

        std::fs::remove_file(&env_file).unwrap();
        assert!(render(Path::new("/bin/zerun"), &a, true).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_detached_log_rotation_for_services() {
        let a = args(&["--log-max-size", "1m", "--name", "web", "alpine"]);
        let err = render(Path::new("/bin/zerun"), &a, true).unwrap_err();
        assert!(err.contains("journald"));
    }

    #[test]
    fn renders_and_validates_tmpfs_upper() {
        let a = args(&["--tmpfs-upper", "--name", "web", "alpine", "echo", "hi"]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --tmpfs-upper alpine -- echo hi\n"));

        let invalid = args(&["--no-overlay", "--tmpfs-upper", "alpine"]);
        assert!(render(Path::new("/bin/zerun"), &invalid, true).is_err());
    }

    #[test]
    fn renders_and_applies_stop_policy() {
        let a = args(&[
            "--stop-signal",
            "USR1",
            "--stop-timeout",
            "7",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --stop-signal SIGUSR1 --stop-timeout 7 "));
        assert!(unit.contains("KillSignal=SIGTERM\n"));
        assert!(unit.contains("TimeoutStopSec=7s\n"));
        assert!(unit.contains("SuccessExitStatus=138\n"));

        let defaults = args(&["alpine", "true"]);
        let unit = render(Path::new("/bin/zerun"), &defaults, true).unwrap();
        assert!(unit.contains("TimeoutStopSec=10s\n"));
        assert!(!unit.contains("--stop-signal"));
        assert!(!unit.contains("--stop-timeout"));
    }

    #[test]
    fn zero_stop_timeout_is_not_rendered_as_systemd_disable() {
        assert_eq!(systemd_timeout(0), "1ms");
        assert_eq!(systemd_timeout(1), "1s");
    }

    #[test]
    fn rejects_timeouts_beyond_systemd_representation() {
        let value = (SYSTEMD_MAX_TIMEOUT_SECS + 1).to_string();
        let a = args(&["--stop-timeout", &value, "alpine", "true"]);
        let err = render(Path::new("/bin/zerun"), &a, true).unwrap_err();
        assert!(err.contains("systemd's maximum"));
    }

    #[test]
    fn renders_memory_reservation_and_oom_group() {
        let a = args(&[
            "--memory",
            "64M",
            "--memory-reservation",
            "48M",
            "--memory-swap",
            "268435456",
            "--oom-group",
            "--name",
            "web",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --memory 64M "));
        assert!(unit.contains(" --memory-reservation 48M "));
        assert!(unit.contains(" --memory-swap 268435456 "));
        assert!(unit.contains(" --oom-group "));
    }

    #[test]
    fn renders_device_io_limits() {
        let a = args(&[
            "--device-read-bps",
            "8:48:1m",
            "--device-write-iops",
            "8:48:100",
            "--name",
            "web",
            "alpine",
            "true",
        ]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" --device-read-bps 8:48:1048576 "));
        assert!(unit.contains(" --device-write-iops 8:48:100 "));
    }

    #[test]
    fn systemd_settings_are_escaped() {
        assert_eq!(quote_systemd("hello world").unwrap(), "\"hello world\"");
        assert_eq!(quote_systemd("$HOME").unwrap(), "\"$$HOME\"");
        assert_eq!(quote_environment("a b\"c").unwrap(), "a b\\\"c");
        assert!(quote_environment("bad\nvalue").is_err());
    }

    #[test]
    fn quotes_arguments_and_rejects_detach() {
        let a = args(&["--name", "web", "alpine", "echo", "hello world"]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(" echo \"hello world\"\n"));

        let detached = args(&["-d", "alpine"]);
        assert!(render(Path::new("/bin/zerun"), &detached, true).is_err());

        let restart = args(&["--restart", "always", "alpine"]);
        let err = render(Path::new("/bin/zerun"), &restart, true).unwrap_err();
        assert!(err.contains("systemd owns restart policy"));
    }

    #[test]
    fn renders_resolved_legacy_rootfs() {
        let dir = std::env::temp_dir().join(format!("zerun-service-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.display().to_string();
        let a = args(&["--rootfs", &dir_str, "--init", "--", "/bin/true"]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains(&format!("--rootfs {} --init -- /bin/true", dir.display())));
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn image_command_is_separated_from_run_options() {
        let a = args(&["--name", "web", "alpine", "echo", "hi"]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("ExecStart=/bin/zerun run --name web alpine -- echo hi\n"));
    }

    #[test]
    fn derives_stable_unit_name() {
        let a = args(&["--name", "api_v1.2", "docker.io/library/alpine:latest"]);
        let unit = render(Path::new("/bin/zerun"), &a, true).unwrap();
        assert!(unit.contains("Description=Zerun container api_v1.2\n"));
    }
}
