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
  masked/readonly paths, capability dropping, cgroups v2 (memory/cpu/pids), optional
  built-in mini-init, and a reproducible benchmark harness.
- **M2 — storage & security (in progress)**: default seccomp allowlist (done), OverlayFS
  read-write mounts, OCI layer whiteout materialization.
- **M3+** — OCI pull, kernel networking, detached lifecycle, distribution (see AGENTS.md).

## Highlights

- **Daemonless**: every command is a short-lived CLI process. Foreground runs leave zero
  resident runtime behind; detached runs only spawn a tiny per-container reaper.
- **Single static binary**: `musl`-linked, ~a few hundred KiB for the current skeleton;
  release profile optimized for size (`opt-level=z`, LTO, strip, panic=abort).
- **No external command dependencies**: namespaces, mounts, cgroups, and (later) netlink /
  nftables are driven directly through syscalls. No shelling out to `ip`, `nft`, or a daemon.
- **Secure defaults**: `PR_SET_NO_NEW_PRIVS`, capability bounding-set cleared, masked
  `/proc`/`/sys` paths, and a deny-by-default seccomp allowlist (opt out with
  `--seccomp unconfined`).
- **Docker-compatible top 20% CLI**: `run / ps / stop / rm / logs / exec / pull / images /
  rmi / generate-service / doctor`.

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

## Quick start (M1 stage)

Prepare a rootfs (example: Alpine minirootfs) and run a command inside it:

```bash
mkdir -p /tmp/zerun-test/rootfs
curl -sSL https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz \
  | tar -xz -C /tmp/zerun-test/rootfs

# Rootful (recommended on real targets): run with sudo.
sudo target/release/zerun run --rootfs /tmp/zerun-test/rootfs --hostname box --init -- /bin/sh

# Rootless: run as the current user; the runtime auto-enters a user namespace.
target/release/zerun run --rootfs /tmp/zerun-test/rootfs --init -- /bin/echo hello
```

Run options (M1 subset):

```
--rootfs DIR     unpacked container root filesystem directory (required for now)
--memory 64M     cgroup v2 memory.max (K/M/G suffixes)
--cpus 0.5       cgroup v2 cpu.max (cores)
--pids 256       cgroup v2 pids.max
--hostname H     container hostname (new UTS namespace)
--net none|host  none = new netns with loopback only (default); host = share host net
--init           run built-in mini-init (reap orphans, forward signals)
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
