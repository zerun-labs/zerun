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
  volumes with `-v HOST:CONTAINER[:ro|rw]`; optional ephemeral `--tmpfs-upper` writable layers.
- **M3 — OCI image engine (done)**: `zerun login / logout / pull / push / tag / images / rmi`; Docker v2
  pull with Bearer token auth, private-registry credentials, multi-arch platform selection (`--platform`), compressed-blob and
  diff_id double verification, zstd layer decode + magic sniffing, transient request retries,
  mirror inheritance
  (env, zerun `config.toml`, `/etc/docker/daemon.json`), and per-layer pull progress;
  `zerun run IMAGE` auto-pulls and applies image env/entrypoint/cmd/working-dir.
- **M4 — kernel networking (done)**: `--net bridge` (rootful) creates the `zerun0` bridge
  (10.88.0.1/24) and a per-container veth pair with container-side `eth0` and a default
  route (verified: host ↔ container reachable). Per-container egress NAT via nf_tables
  (pure netlink), `-p HOST:CONTAINER[/tcp|/udp]` publishing through a built-in userland
  proxy (Docker's docker-proxy in-binary), and `--dns` / host resolv.conf inheritance.
- **M5 — detached lifecycle (done)**: `run -d` forks a tiny per-container reaper that
  redirects stdio to `console.log` and persists state to disk; `ps [-a]`, `stop`, `restart`,
  `rm`, `logs [-f]`, `exec`, and `commit` address containers by id/name with crash reconcile
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
- **Docker-compatible top 20% CLI**: `run / ps / wait / stop / restart / rm / logs / exec / pull /
  push / tag / login / logout / images / rmi / commit / generate-service / doctor`.

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
--cpus 0.5           cgroup v2 cpu.max (cores)
--pids 256           cgroup v2 pids.max
--oom-group          kill the whole cgroup on OOM
--device-read-bps DEV:RATE    cgroup v2 io.max (e.g. /dev/sda:10mb)
--device-write-bps DEV:RATE   cgroup v2 io.max (e.g. 8:0:10mb)
--device-read-iops DEV:COUNT  cgroup v2 io.max
--device-write-iops DEV:COUNT cgroup v2 io.max
-h, --hostname H     container hostname (new UTS namespace)
--net bridge|none|host
                     bridge = rootful bridge networking on zerun0 (veth + eth0 in container;
                     rootful default); none = fresh netns with loopback only (rootless default);
                     host = share host net
-i, --interactive   keep stdin attached (foreground runs; without it stdin is /dev/null)
-t, --tty           allocate a PTY (foreground runs; often combined as -it)
-p, --publish HOST:CONTAINER[/udp]
                     publish a TCP (default) or UDP port on the host
--init               run built-in mini-init (reap orphans, forward signals)
--seccomp default|unconfined   seccomp policy (default: deny-by-default allowlist)
--platform os/arch[/variant]   pull/run a specific platform
-e, --env NAME[=VALUE]         set a container environment variable (image mode)
-v, --volume HOST:CONTAINER[:ro]
                     bind-mount an existing host file/directory into the container
--no-overlay        pivot directly into the rootfs (no writable upper layer)
--tmpfs-upper       keep the overlay writable layer in tmpfs (not committable)
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

### Detached lifecycle (M5)

```bash
# Run in the background (prints the container id once the workload has started)
sudo target/release/zerun run -d --name web -p 18080:80 --net bridge --init \
  alpine /bin/sh -c 'while true; do echo hi | nc -l -p 80; done'

sudo target/release/zerun ps                          # running containers
sudo target/release/zerun wait web                    # block until exit; prints the exit code
sudo target/release/zerun logs --tail 20 web          # container console.log
sudo target/release/zerun logs -t web                 # include capture timestamps
sudo target/release/zerun exec web /bin/sh            # join the container
sudo target/release/zerun stop --time 3 web           # SIGTERM, then SIGKILL
sudo target/release/zerun restart --time 3 web        # stop, then recreate from saved options
sudo target/release/zerun commit -m snapshot web web:snapshot
sudo target/release/zerun rm web                      # remove the stopped container
```

Detached containers keep no daemon: the per-container reaper is a tiny process that

Detached containers keep no daemon: the per-container reaper is a tiny process that
disappears when the container exits. If the host crashes (or the reaper is killed), the
next `ps`/`rm` reconciles the stale record and reclaims host-side resources.
`logs` hides capture-time timestamps by default; `-t/--timestamps` shows them.
`restart` recreates a detached container from the canonical launch options saved in
`state.json`; containers created before this metadata was added are not restartable.
`commit` produces a single-layer OCI image from the container rootfs. Exited detached
containers retain their writable layer until `rm`; `--rm` still removes it on exit.

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
