//! systemd integration for foreground containers (`zerun generate-service`).
//!
//! Zerun is daemonless.  Rather than asking systemd to supervise an internal
//! daemon, it supervises the normal foreground `zerun run` process.  The
//! container is then an ordinary child of the unit, SIGTERM reaches Zerun's
//! existing signal-forwarding path, and a failed container is restarted by
//! systemd.
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
    let rootful = unsafe { libc::geteuid() } == 0;
    let unit = render(&binary, a, rootful)?;
    out.write_all(unit.as_bytes())
        .map_err(|e| format!("write service: {e}"))?;
    Ok(())
}

/// Generate unit text.  `binary` is injected separately for testability.
pub fn render(binary: &Path, a: &RunArgs, rootful: bool) -> Result<String, String> {
    validate(a)?;

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
    if let Some(v) = &a.user {
        run_args.push("--user".into());
        run_args.push(v.clone());
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
    s.push_str("KillSignal=SIGTERM\n");
    s.push_str("TimeoutStopSec=15s\n");
    s.push_str("NoNewPrivileges=true\n");
    // Zerun's parent returns 128+SIGTERM after forwarding systemd's stop
    // signal to the container.  Treat that normal stop path as clean.
    s.push_str("SuccessExitStatus=143\n");
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

pub fn print_usage() {
    println!(
        "usage:\n  \
         zerun generate-service [RUN OPTIONS] IMAGE [CMD [ARGS...]]\n  \
         zerun generate-service [RUN OPTIONS] --rootfs DIR [--] CMD [ARGS...]\n\n\
         Writes a systemd unit to stdout. Most zerun run options are supported;\n\
         -d/--detach and --rm are rejected because systemd owns the lifecycle."
    );
}

fn validate(a: &RunArgs) -> Result<(), String> {
    if a.detach {
        return Err(
            "-d/--detach cannot be used with generate-service; systemd runs the foreground process"
                .into(),
        );
    }
    if a.rm {
        return Err("--rm cannot be used with generate-service; systemd owns the lifecycle".into());
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
    if !a.ports.is_empty() && a.net != NetMode::Bridge {
        return Err("-p/--publish requires --net bridge".into());
    }
    if !a.dns.is_empty() && a.net != NetMode::Bridge {
        return Err("--dns requires --net bridge".into());
    }
    if a.rootfs.is_some() && !a.env.is_empty() {
        return Err("-e/--env requires image mode (drop --rootfs)".into());
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
