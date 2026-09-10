# Zerun — a daemonless, single-binary Linux container runtime

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
  masked/readonly paths, capability dropping, cgroups v2 (memory/cpu/pids/io), optional
  built-in mini-init, and a reproducible benchmark harness.
- **M2 — storage & security (done)**: deny-by-default seccomp allowlist; per-run OverlayFS
  with disk upper and automatic cleanup; OCI whiteout materialization; safe host bind-mount
  volumes with `-v HOST:CONTAINER[:ro|rw]`, auto-created named volumes with
  `-v NAME:CONTAINER[:ro|rw]`, optional ephemeral `--tmpfs-upper` writable layers.
- **M3 — OCI image engine (done)**: `zerun login / logout / pull / push / tag / save / load / images / rmi`; Docker v2
  pull with Bearer token auth, private-registry credentials, multi-arch platform selection (`--platform`), compressed-blob and
  diff_id double verification, zstd layer decode + magic sniffing, transient request retries,
  mirror inheritance
  (env, zerun `config.toml`, `/etc/docker/daemon.json`), and per-layer pull progress;
  `zerun run IMAGE` auto-pulls and applies image env/entrypoint/cmd/working-dir.
- **M4 — kernel networking (done)**: `--net bridge` (rootful) creates the `zerun0` bridge
  (10.88.0.1/24) and a per-container veth pair with container-side `eth0` and a default
  route (verified: host ↔ container reachable). Per-container egress NAT via nf_tables
  (pure netlink, shared `zerun-nat` subnet rule), `-p [ADDR:]HOST[:CONTAINER][/tcp|/udp]` publishing through a built-in userland
  proxy (Docker's docker-proxy in-binary), and `--dns` / host resolv.conf inheritance.
- **M5 — detached lifecycle (done)**: `run -d` forks a tiny per-container reaper that
  redirects stdio to `console.log` and persists state to disk;
  `ps [-a] [-q] [--format table|json] [--filter KEY=VALUE]`, `stop`, `restart`,
  `rm`, `prune [-f]`, `logs [--since/--until/-f]`, `stats`, `exec`, `attach`, and `commit` address containers by id/name with crash reconcile
  of stale records; file-based IPAM; `--rm` for auto-removal (see AGENTS.md).

## Highlights

- **Daemonless**: every command is a short-lived CLI process. Foreground runs leave zero
  resident runtime behind; detached runs only spawn a tiny per-container reaper.
- **Single static binary**: `musl`-linked, ~a few hundred KiB for the current skeleton;
  release profile optimized for size (`opt-level=z`, LTO, strip, panic=abort).
- **No external command dependencies**: namespaces, mounts, cgroups, and netlink are driven
  directly (rtnetlink) — no shelling out to `ip`, `nft`, or a daemon.
- **Secure defaults**: `PR_SET_NO_NEW_PRIVS`, capability bounding-set cleared, masked
  `/proc`/`/sys` paths, and a deny-by-default seccomp allowlist (opt out with
  `--seccomp unconfined`).
- **Docker-compatible top 20% CLI**: `run / ps / wait / stop / restart / rm / prune / logs / exec / inspect /
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

```bash
cargo build --release
./target/release/zerun doctor
```

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
target/release/zerun rmi alpine
```

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
sets environment variables, `--init` adds the built-in mini-init, and
`--platform os/arch[/variant]` selects a specific architecture (default: host).

Run options (current subset):

```
-d, --detach         run in the background (print id once started; see M5 section)
--name NAME          name the container (ps/stop/rm/logs/exec accept it)
--rm                 remove state + writable layer automatically on exit
-m, --memory 64M     cgroup v2 memory.max (K/M/G suffixes)
--memory-reservation 64M
                     cgroup v2 memory.high soft limit
--memory-swap 128M   total memory+swap ceiling; -1/unlimited
--cpus 0.5           cgroup v2 cpu.max (cores)
--cpuset-cpus 0-3    pin CPUs (cgroups v2 cpuset.cpus)
--cpuset-mems 0      pin memory nodes (cgroups v2 cpuset.mems)
--pids 256           cgroup v2 pids.max
--oom-group          kill the whole cgroup on OOM
--device-read-bps DEV:RATE    cgroup v2 io.max (e.g. /dev/sda:10mb)
--device-write-bps DEV:RATE   cgroup v2 io.max (e.g. 8:0:10mb)
--device-read-iops DEV:COUNT  cgroup v2 io.max
--device-write-iops DEV:COUNT cgroup v2 io.max
-h, --hostname H     container hostname (new UTS namespace)
-u, --user USER[:GROUP]
                     run as a container user (numeric or from the image's /etc/passwd;
                     image config USER applies automatically when --user is absent)
--net bridge|none|host
                     bridge = rootful bridge networking on zerun0 (veth + eth0 in container;
                     rootful default); none = fresh netns with loopback only (rootless default);
                     host = share host net
-i, --interactive   keep stdin attached (foreground runs; without it stdin is /dev/null)
-t, --tty           allocate a PTY (foreground runs; often combined as -it)
-p, --publish [ADDR:]HOST[:CONTAINER][/proto]
                     publish a TCP (default) or UDP port; ADDR supports IPv4 and
                     bracketed IPv6 bind addresses (for example 127.0.0.1 or [::1])
--init               run built-in mini-init (reap orphans, forward signals)
--seccomp default|unconfined   seccomp policy (default: deny-by-default allowlist)
--platform os/arch[/variant]   pull/run a specific platform
-e, --env NAME[=VALUE]         set a container environment variable (image mode)
--label KEY=VALUE             add container metadata (repeatable; overrides image labels)
-v, --volume HOST|NAME:CONTAINER[:ro]
                     bind-mount an existing host path, or auto-create/use a managed
                     named volume under the data root
--no-overlay        pivot directly into the rootfs (no writable upper layer)
--tmpfs-upper       keep the overlay writable layer in tmpfs (not committable)
--read-only         remount the container root read-only before exec
--tmpfs PATH[:opts] mount an in-container tmpfs (size=/mode=/ro, repeatable; pairs
                    naturally with --read-only for /tmp-like scratch space)
```

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
are stored. For `docker.io`, credentials are used only for the official registry endpoint
and are never sent to configured mirrors.

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
sudo zerun system df   # Volumes shows the managed storage
```

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
  alpine /bin/sh -c 'while true; do echo hi | nc -l -p 80; done'

sudo target/release/zerun ps                          # running containers
sudo target/release/zerun ps -a --filter name=web     # inspect one container's records
sudo target/release/zerun ps --filter status=exited   # exited detached containers
sudo target/release/zerun ps --filter exitCode=0      # successful detached exits
sudo target/release/zerun ps --filter label=tier=prod # containers with a label key/value
sudo target/release/zerun ps -q                       # container IDs only
sudo target/release/zerun ps --format json -a         # machine-readable full state
sudo target/release/zerun wait web                    # block until exit; prints the exit code
sudo target/release/zerun logs --tail 20 web          # container console.log
sudo target/release/zerun logs --since 10m web        # last ten minutes
sudo target/release/zerun logs --until 2026-01-01T12:00:00Z web
sudo target/release/zerun logs -t web                 # include capture timestamps
sudo target/release/zerun attach web                  # stream live container output
sudo target/release/zerun stats web                   # one-shot resource metrics
sudo target/release/zerun exec web /bin/sh            # join the container
sudo target/release/zerun diff web                    # changed/added/deleted paths
sudo target/release/zerun stop --time 3 web           # SIGTERM, then SIGKILL
sudo target/release/zerun kill --signal TERM web      # send any Linux signal
sudo target/release/zerun restart --time 3 web        # stop, then recreate from saved options
sudo target/release/zerun commit -m snapshot web web:snapshot
sudo target/release/zerun rm web                      # remove the stopped container
sudo target/release/zerun prune -f                    # remove all exited containers
sudo target/release/zerun system df                   # image and container disk usage
```

Detached containers keep no daemon: the per-container reaper is a tiny process that

Detached containers keep no daemon: the per-container reaper is a tiny process that
disappears when the container exits. If the host crashes (or the reaper is killed), the
next `ps`/`rm` reconciles the stale record and reclaims host-side resources.
`-p` can bind a specific host address (`127.0.0.1:18080:80` or `[::1]:18080:80`);
`zerun port` and `ps` display the selected bind address.
`logs` hides capture-time timestamps by default; `-t/--timestamps` shows them.
`--since`/`--until` accept RFC3339 times, UNIX seconds, or Go-style durations such as
`10m` (relative to now) and select inclusive capture-time bounds. `--tail N` narrows the
raw lines before applying the time window. Untimestamped legacy logs are displayed
normally but cannot be selected by time. `--until` ends follow mode at that boundary;
`--since` remains fixed while following.
`prune` removes every retained exited container and its writable layer. It reconciles stale
Running records first, never touches live containers, and requires `--force` when stdin is
not a terminal.
`stats` is a one-shot snapshot of cgroup v2 memory, CPU, PID, and block-I/O data.
It reads live control files while a container runs and persists a final snapshot
when it exits. Metrics are `n/a` when the cgroup was unavailable or the command
cannot read it.
`restart` recreates a detached container from the canonical launch options saved in
`state.json`; containers created before this metadata was added are not restartable.
`attach` streams a running detached container's live output over an owner-only Unix socket.
When the workload exits, a final control frame closes the stream and the attach command
returns the container's exit code without mixing runtime metadata into output.
Use `exec` for interactive input.
`commit` produces a single-layer OCI image from the container rootfs. Exited detached
containers retain their writable layer until `rm`; `--rm` still removes it on exit.

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
The unit runs a foreground container, so systemd supervises Zerun, SIGTERM follows the
normal signal-forwarding path, and failed workloads can be restarted:

```bash
sudo ./target/release/zerun generate-service \
  --name web --net bridge -p 18080:80 --init \
  alpine /bin/sh -c 'while true; do sleep 1; done' \
  > /etc/systemd/system/zerun-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now zerun-web.service
sudo journalctl -u zerun-web.service -f
```

Use `--init` with services whose SIGTERM handling matters. For a rootless container,
generate the unit as that user, install it under `~/.config/systemd/user/`, and use
`systemctl --user enable --now`. `generate-service` rejects `-d`/`--rm` because systemd
owns lifecycle and restart semantics.

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
- Parent process clones the container, writes `cgroup.procs`, forwards signals, and waits;
  the child mounts, pivots, hardens, and execs the workload (zero runtime residue inside).
- Child-side failures are reported to the parent over a CLOEXEC error pipe; EOF means the
  workload successfully exec'd.

## License

Apache-2.0 — see [LICENSE](LICENSE).
