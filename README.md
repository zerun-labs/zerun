# Zerun — a daemonless, single-binary Linux container runtime

[![CI](https://github.com/zerun-labs/zerun/actions/workflows/ci.yml/badge.svg)](https://github.com/zerun-labs/zerun/actions/workflows/ci.yml)

**Zerun** (binary `zerun`, install-time alias `ze`) is a lightweight container runtime for
low-end cloud VMs (512 MB–2 GB), edge gateways, and embedded Linux. It converges the pieces
that usually live in 5–6 separate components — OCI image pulling, OverlayFS storage, kernel
networking via netlink/nftables, and minimal security isolation — into **one static Rust
binary with no daemon**.

> Design document: `ZerunDesignDoc.md` at the repo root (v2.1 draft, kept out of git on
> purpose). It is an early-stage spec: the broad direction is followed, implementation
> details may deviate where engineering judgment says otherwise. See `AGENTS.md` for the
> authoritative maintenance guide.

## Status

Milestone-based development (roadmap in `AGENTS.md` §5):

- **M1 — isolation executor (done)**: namespace isolation (PID/MNT/UTS/IPC/NET/USER),
  corrected `pivot_root(".", ".")` sequence, container pseudo-filesystems, minimal `/dev`,
  masked/readonly paths, capability dropping, cgroups v2 (memory/cpu/pids/io), per-process
  rlimits, namespaced `--sysctl` settings, optional
  built-in mini-init, and a reproducible benchmark harness.
- **M2 — storage & security (done)**: deny-by-default seccomp allowlist; per-run OverlayFS
  with disk upper and automatic cleanup; OCI whiteout materialization; safe host bind-mount
  volumes with `-v HOST:CONTAINER[:ro|rw]`, auto-created named volumes with
  `-v NAME:CONTAINER[:ro|rw]`, Docker-style `--mount type=bind|volume|tmpfs,...` requests,
  configurable private `/dev/shm` sizing with `--shm-size`, optional ephemeral
  `--tmpfs-upper` writable layers.
- **M3 — OCI image engine (done)**: `zerun login / logout / pull / push / tag / save / load / images / rmi`; Docker v2
  pull with Bearer token auth, private-registry credentials, multi-arch platform selection (`--platform`), compressed-blob and
  diff_id double verification, zstd layer decode + magic sniffing, transient request retries,
  mirror inheritance
  (env, zerun `config.toml`, `/etc/docker/daemon.json`), and per-layer pull progress. Pulls
  preserve the complete multi-architecture index, so a later `push` can upload every platform;
  `zerun run IMAGE` auto-pulls and applies image env/entrypoint/cmd/working-dir.
- **M4 — kernel networking (done)**: `--net bridge` (rootful) creates the `zerun0` bridge
  (10.88.0.1/24) and a per-container veth pair with container-side `eth0` and a default
  route (verified: host ↔ container reachable). Per-container egress NAT via nf_tables
  (pure netlink, shared `zerun-nat` subnet rule), `-p [ADDR:]HOST[-END][:CONTAINER[-END]][/tcp|/udp]` publishing through a built-in userland
  proxy (Docker's docker-proxy in-binary), image `EXPOSE` plus `--expose` and
  `-P`/`--publish-all` random host-port mapping, `--dns` / host resolv.conf inheritance,
  `--dns-search` / `--dns-option` resolver controls, and repeatable
  `--add-host NAME:IP` aliases (including `host-gateway`).
- **M5 — detached lifecycle (done)**: `run -d` forks a tiny per-container reaper that
  redirects stdio to `console.log` and persists state to disk;
  `ps [-a] [-q] [--format table|json] [--filter KEY=VALUE]`, `start`, `pause`, `unpause`, `stop`, `restart`,
  `rm`, `prune [-f] [--images]`, `logs [--since/--until/-f]`, `stats`, `exec`, `attach`, and `commit` address containers by id/name with crash reconcile
  of stale records; `run -d --restart` applies Docker-style restart policies inside the
  per-container reaper; Docker-compatible `--health-*` checks are monitored by a tiny
  per-attempt process and exposed through `ps --filter health=...`/`inspect`; file-based
  IPAM; `--rm` for auto-removal (see AGENTS.md).
- **M6 — operations and distribution (done)**: `generate-service` emits declarative foreground
  systemd units; `install.sh` verifies checksums, detects architectures, supports rootless
  installation, and creates the `ze` alias; Arch and Homebrew source packaging is included.
- **M7 — introspection and storage controls (done)**: `inspect`, `port`, `rename`, `top`, `diff`,
  `cp`, `export`, `import`, `events`, `update`, `system df`, live/rootfs `commit`, OCI
  image-declared volumes, persisted labels and user identity, OCI save/load/tag/push flows,
  and hardened state/resource cleanup.

## Continuous integration

Every push and pull request runs formatting, ShellCheck/shell syntax checks, dependency
advisory auditing, Clippy, the serialized unit/integration suite on Ubuntu 22.04 and
24.04, and the release-profile test suite. Dedicated rootful jobs exercise namespace
isolation, OverlayFS, read-only roots with tmpfs mounts, named-volume persistence,
cgroups v2, detached lifecycle controls (`pause`/`unpause`/`update`/`rename`/`attach`/`prune`),
concurrent name uniqueness across creation and rename,
`inspect`/`stats`/`top`, `system df`, `cp`, `diff`, `export`/`import`, live and retained-overlay
`commit`,
bounded `events` replay, bridge/veth networking, TCP/UDP published-port proxies, translated
published-port ranges, `--expose`/`-P` traffic, and service rendering that retains port
bindings. A separate
rootless smoke job creates a dedicated unprivileged runner account and verifies
user-namespace execution; static GNU and musl builds plus ARM64, ARMv7, and RISC-V64
cross-builds are checked as well. Tagged releases are gated on both debug and release-profile
source tests before artifacts are published.

The rootful integration fixture is reproducible locally (root or passwordless sudo is required):

```bash
rootfs=$(mktemp -d)
data=$(mktemp -d)
runtime=$(mktemp -d)
ci/prepare-rootful-fixtures.sh "$rootfs"
ci/rootful-runtime.sh target/debug/zerun "$rootfs" "$data" "$runtime"
```

## Highlights

- **Daemonless**: every command is a short-lived CLI process. Foreground runs leave zero
  resident runtime behind; detached runs only spawn a tiny per-container reaper.
- **Single static binary**: `musl`-linked, ~a few hundred KiB for the current skeleton;
  release profile optimized for size (`opt-level=z`, LTO, strip, panic=abort).
- **No external command dependencies**: namespaces, mounts, cgroups, and netlink are driven
  directly (rtnetlink) — no shelling out to `ip`, `nft`, or a daemon.
- **Secure defaults**: `PR_SET_NO_NEW_PRIVS`, a Docker-compatible capability set with
  `CAP_NET_RAW`/`CAP_SYS_ADMIN` removed, masked `/proc`/`/sys` paths, a deny-by-default
  seccomp allowlist, and a deny-by-default cgroup v2 device allowlist on rootful runs
  (capabilities can be tuned with `--cap-add`/`--cap-drop`; seccomp can be opted out with
  `--seccomp unconfined` or `--security-opt seccomp=unconfined`, while `--device`
  extends the device allowlist).
- **Docker-compatible top 20% CLI**: `run / ps / wait / start / pause / unpause / stop / restart / rm / prune / logs / exec / inspect /
  port / rename / top / diff / cp / export / import / events / update / attach / kill / pull / push / tag / save / load /
  login / logout / images / rmi / commit / generate-service / system df / doctor`.

## Install

On Linux, install a tagged release with the checksum-verified helper script:

```bash
curl -fsSL https://raw.githubusercontent.com/zerun-labs/zerun/main/install.sh | sh
# Or pin a release and prefix:
ZERUN_INSTALL_VERSION=v0.2.0 ./install.sh --prefix ~/.local
```

The script detects x86_64, ARM64, ARMv7, and RISC-V64, downloads the static
musl build, verifies SHA-256, and creates `zerun` plus the shorter `ze`
command. It uses `/usr/local` when it has root access and falls back to
`~/.local` for rootless hosts.

On Arch Linux, a source package is provided in `packaging/aur/PKGBUILD`. It
builds the tagged release with Cargo and installs both commands.

A Homebrew source formula is provided in `packaging/homebrew/zerun.rb` for
Homebrew on Linux.

## Build

Building from source requires Rust 1.89 or newer.

```bash
cargo build --release
./target/release/zerun version
./target/release/zerun doctor
```

`doctor` also creates a short-lived empty cgroup and attaches the same device
BPF policy used by rootful workloads, so it reports whether the mandatory
device boundary is actually available on the host. For rootless operation it
forks a short-lived child, creates a user namespace, and performs the same
single-uid/gid mapping used by `run`, rather than relying only on the sysctl
limit. It exits `1` when a capability required by the current run mode is
unavailable and `2` for invalid command-line arguments.

Static musl build (for minimal edge root filesystems):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Cross targets (edge devices): `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`,
`riscv64gc-unknown-linux-musl`.

## Quick start

### Image mode (M3, recommended)

```bash
cargo build --release

# Rootful (recommended on real targets): run with sudo.
sudo target/release/zerun run alpine echo hello

# Rootless: run as the current user; the runtime auto-enters a user namespace.
target/release/zerun pull alpine
target/release/zerun run --init alpine /bin/sh -c 'echo hi; exit 7'; echo $?

# Image lifecycle
target/release/zerun images
target/release/zerun images --digests       # include manifest/index digests
target/release/zerun images -q              # image IDs only
target/release/zerun images --json          # machine-readable records
target/release/zerun rmi alpine
```

For multi-architecture images, `--digests` reports the preserved OCI index
digest rather than the selected platform manifest digest. `--json` exposes
the complete local image records, including both digests and the image config.

Commit a detached container's current filesystem into a local OCI image
(`commit` works while running, but a running filesystem may be inconsistent):

```bash
target/release/zerun run -d --name builder alpine sleep 5
# ... make changes with zerun exec builder ...
target/release/zerun commit -m "add tooling" --author "You <you@example.com>" builder myapp:v1
target/release/zerun run myapp:v1 /bin/busybox echo committed
target/release/zerun rm builder
```

`run IMAGE` pulls the image automatically when it is not present locally; `-e NAME=V`
sets environment variables, `--env-file FILE` loads them from disk, `--init` adds
the built-in mini-init, and
`--platform os/arch[/variant]` selects a specific architecture (default: host).
Environment files contain one `NAME=VALUE` per line; blank lines and lines whose
first non-whitespace character is `#` are ignored, and values are literal (no shell
expansion). Later files override earlier files, then `-e` overrides both. Files are
limited to 1 MiB each and are only accepted in image mode.

Run options (current subset):

```
-d, --detach         run in the background (print id once started; see M5 section)
--name NAME          name the container (ps/stop/rm/logs/exec accept it)
--cidfile FILE       write the new container id to FILE (must not already exist)
--rm                 remove state + writable layer automatically on exit
-m, --memory 64M     cgroup v2 memory.max (K/M/G suffixes)
--memory-reservation 64M
                     cgroup v2 memory.high soft limit
--memory-swap 128M   total memory+swap ceiling; -1/unlimited
--cpus 0.5           cgroup v2 cpu.max (cores)
--cpu-shares 512     relative CPU weight via cgroup v2 cpu.weight
                     (Docker-compatible 2-262144 shares; 0 restores the default)
--cpuset-cpus 0-3    pin CPUs (cgroups v2 cpuset.cpus)
--cpuset-mems 0      pin memory nodes (cgroups v2 cpuset.mems)
--pids 256           cgroup v2 pids.max; rootful default is 256, -1 disables the
                     cap (Docker-compatible --pids-limit alias)
--oom-group          kill the whole cgroup on OOM
--device-read-bps DEV:RATE    cgroup v2 io.max (e.g. /dev/sda:10mb)
--device-write-bps DEV:RATE   cgroup v2 io.max (e.g. 8:0:10mb)
--device-read-iops DEV:COUNT  cgroup v2 io.max
--device-write-iops DEV:COUNT cgroup v2 io.max
--ulimit TYPE=SOFT[:HARD]     per-process rlimit (repeatable; -1/unlimited)
-h, --hostname H     container hostname (new UTS namespace)
--pid private|host   private PID namespace (default) or share the host PID namespace
--ipc private|none|host
                     private IPC and /dev/shm (default), a private IPC namespace
                     without /dev/shm mounted, or the host IPC namespace
--uts private|host   private UTS namespace (default) or share the host hostname
                     (host PID/IPC/UTS sharing is security-sensitive; --hostname is
                     incompatible with --uts host)
-u, --user USER[:GROUP]
                     run as a container user (numeric or from the image's /etc/passwd;
                     image config USER applies automatically when --user is absent)
--group-add NAME|GID add a supplementary group (repeatable/comma-separated; names
                     resolve in the container's /etc/group)
--stop-signal SIGNAL stop/restart signal name or number 1-64 (image STOPSIGNAL;
                     default SIGTERM; SIGTERM sent to a foreground supervisor is
                     translated to this signal)
--stop-timeout S     seconds to wait for the stop signal before SIGKILL (default 10;
                     generate-service maps this to TimeoutStopSec)
--health-cmd CMD     detached liveness command (shell form; image HEALTHCHECK also applies)
--health-interval D  time between checks (default 30s; Docker duration syntax)
--health-timeout D   per-check timeout before killing its process group (default 30s)
--health-retries N   consecutive failures before marking unhealthy (default 3)
--health-start-period D
                     initialization window whose failures do not consume retries
--health-start-interval D
                     check interval during the start period (default 5s)
--no-healthcheck     disable an image-declared HEALTHCHECK
--restart POLICY     detached restart policy: no, on-failure[:MAX], always, or
                     unless-stopped (requires -d; incompatible with --rm)
--net, --network bridge|none|host
                     bridge = rootful bridge networking on zerun0 (veth + eth0 in container;
                     rootful default); none = fresh netns with loopback only (rootless default);
                     host = share host net
-i, --interactive   keep stdin attached (foreground runs; without it stdin is /dev/null)
-t, --tty           allocate a PTY for foreground or detached output (e.g. -dt)
-p, --publish [ADDR:]HOST[-END][:CONTAINER[-END]][/proto]
                     publish TCP (default) or UDP ports; equal-length host and
                     container ranges are paired in order. ADDR supports IPv4 and
                     bracketed IPv6 bind addresses (for example 127.0.0.1 or [::1])
--expose PORT[-PORT][/tcp|/udp]
                     expose container ports without publishing them (repeatable;
                     comma-separated values and port ranges are accepted)
-P, --publish-all    publish each image EXPOSE and --expose port to a random host
                     port (requires --net bridge)
--add-host HOST:IP  add an /etc/hosts entry (repeatable; IP or host-gateway)
--dns IP            container DNS server (repeatable/comma-separated; bridge mode;
                    defaults to the host's)
--dns-search DOMAIN resolver search domain (repeatable/comma-separated;
                    defaults to the host's)
--dns-option OPTION resolver option such as ndots:2 (repeatable/comma-separated;
                    defaults to the host's)
--sysctl KEY=VALUE  apply a namespaced kernel setting (repeatable; net.*,
                    kernel.shm*, kernel.msg*, kernel.sem*, fs.mqueue.*,
                    kernel.domainname)
--init               run built-in mini-init (reap orphans, forward signals)
--seccomp default|unconfined   seccomp policy (default: deny-by-default allowlist)
--security-opt seccomp=default|unconfined
                     Docker-compatible seccomp switch (repeatable)
--security-opt no-new-privileges
                     accepted because Zerun always enables no_new_privs
--cap-add CAP|ALL              add capabilities to the default set (repeatable/comma-separated)
--cap-drop CAP|ALL             remove capabilities from the default set (applied before adds)
--platform os/arch[/variant]   pull/run a specific platform
--entrypoint CMD               override the image ENTRYPOINT (empty string resets it)
-w, --workdir DIR              override the image WorkingDir
--pull missing|always|never    image refresh policy (default: missing)
-e, --env NAME[=VALUE]         set a container environment variable (image mode)
--env-file FILE                load NAME=VALUE lines (repeatable; image mode)
--log-max-size SIZE            rotate detached console.log at SIZE (default 10m; 0 disables)
--log-max-file N               retain N detached log files including active (default 3; max 1024)
--label KEY[=VALUE]           add container metadata (repeatable; overrides image labels)
--label-file FILE             load KEY=VALUE labels from a file (repeatable)
-v, --volume HOST|NAME:CONTAINER[:ro]
                     bind-mount an existing host path, or auto-create/use a managed
                     named volume under the data root
--mount type=bind|volume|tmpfs,src=SOURCE,dst=TARGET[,readonly]
                     Docker-style mount syntax; `type=tmpfs` accepts tmpfs-size= and
                     tmpfs-mode= instead of src= (repeatable)
--device HOST[:CONTAINER[:rwm]]
                     expose a character or block device (repeatable; default target is
                     HOST and default permissions are rwm). Rootful runs always use a
                     deny-by-default cgroup v2 device allowlist; --device extends it. Rootless
                     runs support full rwm only
--no-overlay        pivot directly into the rootfs (no writable upper layer)
--tmpfs-upper       keep the overlay writable layer in tmpfs (not committable)
--read-only         remount the container root read-only before exec
--tmpfs PATH[:opts] mount an in-container tmpfs (size=bytes or K/M/G/T units,
                    optional B suffix; mode=/ro, repeatable; pairs naturally with
                    --read-only for /tmp-like scratch space)
--shm-size SIZE    private /dev/shm size (default: 64m; ignored with
                    --ipc host or --ipc none)
```

Cgroup flags bound aggregate container resource use. `--ulimit` additionally
sets POSIX per-process limits; supported types match Docker (`core`, `cpu`,
`data`, `fsize`, `locks`, `memlock`, `msgqueue`, `nice`, `nofile`, `nproc`,
`rss`, `rtprio`, `rttime`, `sigpending`, `stack`, and `as`). A missing hard
limit defaults to the soft value, `-1`/`unlimited` removes the ceiling, and a
repeated type uses its last value. Detached restart and `exec` restore the
persisted limits; raising a hard limit above the host ceiling still requires
the corresponding host privilege and otherwise fails explicitly.

`zerun update` can change memory, CPU quota and shares, cpuset, PID, OOM-group,
per-device I/O limits, and the restart policy of a running detached container. I/O updates
merge into the current `io.max` view, so changing one device or direction leaves the other
kernel limits intact; the updated restart policy is used by the reaper on the next exit and
is retained by manual `start`/`restart`. `--restart` may also be changed on an exited
container. Changing the policy to `no` while the reaper is between attempts cancels the
pending retry. Resource limits return to their launch-time values after `restart`.

`--group-add` replaces the inherited supplementary group list, whether the workload
runs as root or another user. Names are resolved against the container's `/etc/group`
after `pivot_root`; numeric gids need no group file. Rootless containers deny `setgroups`
and map only gid 0, so group additions fail explicitly. Detached restart/exec and generated
service units retain the same launch policy.

`--sysctl` accepts only settings scoped to a private container namespace.
Network and IPC families are rejected with `--net host` or `--ipc host`, and
`kernel.domainname` is rejected with `--uts host`, so a container option cannot
silently mutate the host. Values are applied after bridge/loopback setup (which
allows per-interface keys such as `net.ipv4.conf.eth0.*`) and before `/proc/sys`
is remounted read-only for the workload. Detached restart and generated service
units preserve the same settings.

`ZERUN_REGISTRY_MIRRORS` (comma-separated), a zerun config file
(`/etc/zerun/config.toml` with `[registry] mirrors = [...]`, overridable via
`ZERUN_CONFIG` or `~/.config/zerun/config.toml`), and the `/etc/docker/daemon.json`
`registry-mirrors` list are honored for `docker.io` pulls (in that priority order).

### Private registries

Log in once before pulling from a private registry:

```bash
zerun login ghcr.io
zerun login registry.example:5000 -u alice --password-stdin
zerun logout ghcr.io
```

Credentials live in `~/.config/zerun/credentials.json` (or `$XDG_CONFIG_HOME/zerun/...`).
Set `ZERUN_CREDENTIALS` to use another file. The file is written atomically with `0600`
permissions and its parent with `0700`; passwords are validated against `/v2/` before they
are stored. For a migration from Docker, Zerun also reads embedded Basic `auths` from
`$DOCKER_CONFIG/config.json` or `~/.docker/config.json`; explicit `zerun login` entries win.
External Docker credential helpers (`credsStore` / `credHelpers`) are not executed. For
`docker.io`, credentials are used only for the official registry endpoint and are never sent
to configured mirrors.

Push a local image with the normal OCI distribution protocol. Registry challenges
are answered with a `pull,push` Bearer scope, referenced blobs are skipped when the
registry already has them, and layer files stream from the local store:

```bash
zerun commit -m snapshot web web:snapshot
zerun push web:snapshot
# Or retag an existing image (including a pulled upstream image) and push it:
zerun tag web:snapshot registry.example:5000/team/app:v1
zerun push registry.example:5000/team/app:v1
```

Local registries on `localhost[:PORT]` accept plain HTTP as an insecure dev endpoint;
remote registries always use HTTPS.

### Named volumes

A volume name creates one persistent directory under the data root; absolute paths
continue to bind existing host files or directories. Names are preserved by
`restart` and `generate-service` rather than being rewritten to store paths:

```bash
sudo zerun run --rm -v app-data:/var/lib/app alpine /bin/sh -c \
  'echo persisted >/var/lib/app/state && cat /var/lib/app/state'
# The equivalent Docker-style spelling:
sudo zerun run --rm --mount type=volume,src=app-data,dst=/var/lib/app \
  alpine /bin/sh -c 'cat /var/lib/app/state'
sudo zerun system df   # Volumes shows the managed storage
```

Images may declare directories with OCI `Config.Volumes` (Dockerfile `VOLUME`).
A new container gets a fresh managed anonymous volume for each declaration and
seeds it from the image directory. A user `-v`/`--mount` at the same path or an
ancestor suppresses that anonymous volume. The data survives `stop`/`start` and
detached restarts, is removed with `rm` (or `--rm`), and mounted volume data is
excluded from `commit`; the declaration itself is preserved in the new image.

### Offline image transfer (save / load)

Export any local image (or several, sharing blobs by digest) as a standard OCI image
layout tarball, then import it on another host that already has the `zerun` binary:

```bash
zerun save -o images.tar alpine:3.20 myapp:v1
# ... copy images.tar to the target ...
zerun load -i images.tar
```

`save` writes `oci-layout`, `index.json`, and content-addressed `blobs/sha256/*`; `load`
verifies every blob digest while importing, materializes the rootfs, and recreates the tag
index — so imported images are immediately runnable with `zerun run IMAGE`. There is no
registry or daemon involved anywhere in the path.


### Detached lifecycle (M5)

```bash
# Run in the background (prints the container id once the workload has started)
sudo target/release/zerun run -d --name web -p 18080:80 --net bridge --init \
  --restart=on-failure:3 \
  alpine /bin/sh -c 'while true; do echo hi | nc -l -p 80; done'

sudo target/release/zerun ps                          # running containers
sudo target/release/zerun ps -a --filter name=web     # inspect one container's records
sudo target/release/zerun ps --filter status=exited   # exited detached containers
sudo target/release/zerun ps --filter status=restarting
sudo target/release/zerun ps --filter exitCode=0      # successful detached exits
sudo target/release/zerun ps --filter label=tier=prod # containers with a label key/value
sudo target/release/zerun ps -q                       # container IDs only
sudo target/release/zerun ps --format json -a         # machine-readable full state
sudo target/release/zerun wait web                    # block until exit; prints the exit code
# `wait` exits successfully when it retrieved the code, even if that code is non-zero.
sudo target/release/zerun logs --tail 20 web          # container console.log
sudo target/release/zerun logs --since 10m web        # last ten minutes
sudo target/release/zerun logs --until 2026-01-01T12:00:00Z web
sudo target/release/zerun logs -t web                 # include capture timestamps
sudo target/release/zerun attach web                  # stream live container output
sudo target/release/zerun stats web                   # one-shot resource metrics
sudo target/release/zerun exec web /bin/sh            # join the container
sudo target/release/zerun exec --env-file app.env web env  # environment overrides
sudo target/release/zerun exec -u 1000:1000 web id    # one-off user override
sudo target/release/zerun exec -it web /bin/sh         # interactive terminal
sudo target/release/zerun diff web                    # changed/added/deleted paths
sudo target/release/zerun stop --time 3 web           # configured signal, then SIGKILL
sudo target/release/zerun stop --signal USR1 web      # one-off signal override
sudo target/release/zerun kill --signal TERM web      # send any Linux signal
sudo target/release/zerun start web                   # resume with the same id/writable layer
sudo target/release/zerun pause web                   # freeze the complete process tree
sudo target/release/zerun unpause web                 # thaw it and continue execution
sudo target/release/zerun restart --time 3 web        # stop, then resume from saved options
sudo target/release/zerun commit -m snapshot web web:snapshot
sudo target/release/zerun rm web                      # remove the stopped container
sudo target/release/zerun prune -f                    # remove all exited containers
sudo target/release/zerun prune -f --images           # also remove unreachable image blobs/rootfs
sudo target/release/zerun system df                   # image and container disk usage
```

Detached containers keep no daemon: the per-container reaper is a tiny process that
disappears when the container exits. If the host crashes (or the reaper is killed), the
next `ps`/`rm` reconciles the stale record and reclaims host-side resources.

`-dt` allocates a PTY for a detached workload, so terminal-aware services retain
line-buffered output and `TERM` defaults. Detached PTYs start at a conventional 24x80
geometry; output-only foreground PTYs mirror and follow the caller terminal's resize
events when stdin is a terminal. `logs` and `attach` receive the PTY stream; detached
stdin is not connected, so `-i` remains a foreground-only option. The TTY choice is part
of the saved launch arguments and survives `start`/`restart`.

Docker-compatible healthchecks are available for detached containers. A command from
`--health-cmd` overrides the image `Healthcheck.Test`; timing flags override matching
image values and `--no-healthcheck` disables the image declaration. The probe joins the
container's namespaces and cgroup, uses its user/environment/capabilities/seccomp policy,
captures bounded combined output, and is killed as a process group on timeout. `ps` shows
`(health: starting)`, `(healthy)`, or `(unhealthy)`, `ps --filter health=...` selects those
states (including `none`), and `inspect` exposes the last five probe records. Health state
resets to `starting` for every automatic restart attempt, and `commit` preserves the effective
check in the new image config. Timings use Go/Docker duration syntax such as `500ms`, `30s`,
or `1m30s`. Monitoring is intentionally scoped to detached containers, where durable state
exists for other commands to inspect.

Container labels can be supplied directly or from line-oriented files. A bare `--label key`
sets an empty value; `--label-file` ignores blank lines, comments, and lines without `=`, and
later files or explicit `--label` options override earlier keys. Label files are limited to
1 MiB and must be UTF-8, with values preserved literally after the first `=`.

`--cidfile FILE` writes the new container id without a trailing newline and refuses to
overwrite an existing path, matching Docker's script-facing behavior. The file is created
with Docker's `0644` default (subject to the process umask) and remains after the container
starts or exits; failed validation or startup removes only the file created by that attempt.
`start` and `restart` reuse the original id without touching the cidfile. Service units reject
`--cidfile` because a systemd restart would otherwise encounter the receipt from the previous
run.

`--restart=on-failure[:MAX]` retries non-zero exits (an omitted or zero maximum is
unlimited), `always` retries every exit, and `unless-stopped` retries every exit until a
manual stop. Retries use a bounded 100 ms-to-1 s backoff, and `ps` reports the transient
state as `Restarting`. `wait` and `logs -f` follow the policy across attempts, so they
return only after a terminal exit or a manual stop. `stop`, `kill` when it terminates the
workload, and `rm -f` suppress pending automatic restarts; a later manual `start`
reactivates the persisted policy. Because Zerun has no daemon or boot-time state loader,
`always` and `unless-stopped` have the same effect for the lifetime of the per-container
reaper; neither recreates a container after a host reboot. `--restart` requires `-d`,
cannot be combined with `--rm`, and is rejected by `generate-service` because systemd owns
service restart semantics.
`-p` can bind a specific host address (`127.0.0.1:18080:80` or `[::1]:18080:80`);
`zerun port` and `ps` display the selected bind address. Image `EXPOSE` and `--expose`
declarations are persisted in the container state, shown by `inspect`, and listed as
unpublished `PORT/PROTOCOL` entries in `ps`; restarting a container retains them. Repeatable
`--add-host NAME:IP` entries are written to the container `/etc/hosts`; the special
`host-gateway` value resolves to the bridge gateway (`10.88.0.1`) in bridge mode.
`logs` hides capture-time timestamps by default; `-t/--timestamps` shows them.
`--since`/`--until` accept RFC3339 times, UNIX seconds, or Go-style durations such as
`10m` (relative to now) and select inclusive capture-time bounds. `--tail N` narrows the
raw lines before applying the time window. Log files are streamed in chronological
order, so only the requested `--tail` lines are retained in memory. Untimestamped legacy
logs are displayed normally but cannot be selected by time. `--until` ends follow mode at
that boundary; `--since` remains fixed while following. An unterminated line is split into 64 KiB
timestamped records in `console.log`, so a workload cannot make the reaper buffer an
unbounded line; `attach` still receives the original bytes unchanged.
`prune` removes every retained exited container and its writable layer. It reconciles stale
Running records first, never touches live containers, and requires `--force` when stdin is
not a terminal. `--images` additionally runs the image-store garbage collector for unreachable
blobs/rootfs left by interrupted pulls or removed records; tagged images are retained.
`stats` is a one-shot snapshot of cgroup v2 memory, CPU, PID, and block-I/O data.
It reads live control files while a container runs and persists a final snapshot
when it exits. Metrics are `n/a` when the cgroup was unavailable or the command
cannot read it.
`start` resumes an exited container without replacing its id, console history, or writable
overlay. `restart` first applies the normal stop sequence and then resumes it from the
canonical launch options saved in `state.json`. Containers created before resumable state
was added are not startable; recreate them with `run`. A container created with `--rm`
cannot be restarted after it stops because its state is intentionally removed.
`pause` freezes every process in a detached container through the cgroup v2 freezer;
`unpause` thaws it without replacing its identity or writable state. `ps` displays
`Up ... (Paused)`, and `ps --filter status=paused` selects those containers. Rootless
hosts need a delegated cgroup v2 hierarchy; otherwise pause/unpause reports that no
lifecycle cgroup is available.
Stopped containers retain both their writable layer and read-only lower rootfs; image
garbage collection keeps that lower reachable even after the image tag is removed, until
the container itself is removed.
`attach` streams a running detached container's live output over an owner-only Unix socket.
Detached state and console logs are stored owner-only because state contains the resolved
command line and environment. When the workload exits, a final control frame closes the stream
and the attach command returns the container's exit code without mixing runtime metadata into
output. Up to 32 clients may attach to one container; disconnected clients are pruned as new
connections arrive so the reaper's descriptor and memory use stay bounded.
`exec -i` forwards stdin, `exec -t` allocates a PTY, and `exec -it` combines them;
without `-i`, the command receives `/dev/null` as stdin.
`commit` produces a single-layer OCI image from the container's host-side overlay
(changes in progress may race while it is running). Mounted volumes, tmpfs mounts,
and pseudo-filesystems are excluded; image-declared `Volumes`, exposed ports, and the
effective stop signal are retained in the committed config. Exited detached containers
retain their writable layer until `rm`;
`--rm` still removes it on exit.

`ps` supports repeated Docker-style filters, combined with AND:
`status=created|running|exited`, `name=NAME`, `id=PREFIX`, `image=IMAGE`, `net=MODE`, and
`exitCode=CODE`. An explicit non-running status or an exit-code filter also surfaces those
records without `-a`; other filters narrow the normal running-only view unless `-a` is set.
`ps -q` prints IDs for scripts; `--format json` serializes the matching full container state
records (use `-a` to include exited and created records).
`events` follows lifecycle changes without a daemon. Repeated `--filter action=die`,
`--filter container=web`, `--filter image=alpine`, and `--filter exitCode=0` selectors are
ANDed; `--since`/`--until` accept RFC3339 UTC times and first replay matching history.

### systemd integration (M6)

Generate a declarative systemd unit from the same arguments you would pass to `run`.
The unit runs a foreground container, so systemd supervises Zerun and failed workloads
can be restarted. systemd's stop signal is SIGTERM; Zerun translates it to the resolved
image/operator `--stop-signal`, while `--stop-timeout` (or the 10-second default) becomes
`TimeoutStopSec` before systemd force-kills the cgroup:

```bash
sudo ./target/release/zerun generate-service \
  --name web --net bridge -p 18080:80 --init \
  alpine /bin/sh -c 'while true; do sleep 1; done' \
  > /etc/systemd/system/zerun-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now zerun-web.service
sudo journalctl -u zerun-web.service -f
```

Use `--init` with services whose signal handling matters. For a rootless container,
generate the unit as that user, install it under `~/.config/systemd/user/`, and use
`systemctl --user enable --now`. `generate-service` rejects `-d`/`--rm` because systemd
owns lifecycle and restart semantics. A zero stop timeout becomes systemd's smallest
practical positive timeout (`1ms`), because systemd otherwise treats zero as "wait forever".

### Legacy rootfs mode (M1/M2)

Run a command inside a plain unpacked rootfs directory (no image engine):

```bash
mkdir -p /tmp/zerun-test/rootfs
curl -sSL https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz \
  | tar -xz -C /tmp/zerun-test/rootfs

sudo target/release/zerun run --rootfs /tmp/zerun-test/rootfs --hostname box --init -- /bin/sh
target/release/zerun run --rootfs /tmp/zerun-test/rootfs --init -- /bin/echo hello
```

`ZERUN_TRACE=1` prints per-stage nanosecond timings to stderr (parsed by `bench/analyze.py`).

## Benchmark

```bash
./bench/bench.sh 100 /tmp/zerun-test/rootfs
```

See `bench/README.md` for methodology (same-rootfs, same-core comparison against crun/runc;
T0 budget ≤ 8 ms wall-clock for the isolation hot path).

## Architecture

See `AGENTS.md` §2/§4. Short version:

- One crate, one binary; **all raw syscalls are concentrated in `src/syscalls.rs`**.
- The runtime forks a single-threaded namespace supervisor, which enters the requested
  namespaces and forks the workload. The parent writes `cgroup.procs`, forwards signals, and
  waits; the worker mounts, pivots, hardens, and execs (zero runtime residue inside).
- Child-side failures are reported to the parent over a CLOEXEC error pipe; EOF means the
  workload successfully exec'd.

## License

Apache-2.0 — see [LICENSE](LICENSE).
