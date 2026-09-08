# AGENTS.md — Zerun maintenance guide

This file is for AI agents and developers who take over this repository. Read it before
making changes. When architecture or conventions change, update this file in the same effort.

## 1. What this project is

- **Zerun** (binary `zerun`, install-time alias `ze`): a single-machine, **daemonless**
  lightweight container runtime, written in Rust as one static binary.
  Positioning: "the SQLite of containers" — converging OCI image pulling, OverlayFS storage,
  kernel networking (netlink/nftables), and minimal security isolation into one binary for
  512 MB–2 GB VPSes, edge gateways, and embedded Linux.
- Target kernel >= 5.10 (cgroups v2); older kernels get feature detection + explicit
  degradation or a clear error.
- The reference (but not gospel) document is `ZerunDesignDoc.md` at the repo root
  (v2.1 draft). **It must never be committed to git** (see `.gitignore`). It is an early
  draft and may be wrong in places; follow its broad direction, but concrete implementation
  details and this file take precedence.
- Comparable projects to learn from (do NOT copy; only borrow ideas), located on this
  machine under /home/user/projects:
  - `nerdctl`: Docker-compatible CLI for containerd (Go) — CLI syntax/UX reference.
  - `ocre-runtime`: WebAssembly-driven OCI-like runtime for embedded/MCU (C) — footprint
    philosophy reference.
  - `zerun-m1-skeleton`: the M1 minimal isolation executor (written by another AI), the
    baseline this codebase was ported from; read-only reference.

## 2. Repository layout and current architecture

```
zerun/                      # crate root == repository root
├── Cargo.toml              # package zerun; release: opt-level=z + lto + strip + panic=abort
├── src/
│   ├── main.rs             # CLI entry: run / doctor / __init (internal)
│   ├── error.rs            # ZError / zerr! / ZResult
│   ├── trace.rs            # ZERUN_TRACE=1 stage timing (bench/analyze.py parses its format!)
│   ├── syscalls.rs         # ★ ALL unsafe syscalls live here (mount/clone/pivot_root/caps/pipe)
│   ├── namespace.rs        # parent/child orchestration: clone, error pipe, signals, wait
│   ├── mounts.rs           # pivot_root sequence, pseudo-fs, masked/readonly paths, minimal /dev
│   ├── cgroup.rs           # cgroups v2 driver (memory/cpu/pids) + subtree_control setup
│   ├── security.rs         # no_new_privs -> capability drop -> seccomp orchestration
│   ├── seccomp.rs          # default deny-by-default BPF allowlist (x86_64 table; extend per arch)
│   ├── mini_init.rs        # container PID1 mini-init (signal forwarding + orphan reaping)
│   ├── store.rs            # state layout: data/run roots (rootful vs rootless), per-run overlay fs
│   ├── fsutil.rs           # recursive copy, force-remove (mode-000 overlay workdirs), atomic write
│   ├── workload.rs         # container env application + PATH argv[0] resolution
│   └── image/              # M3 OCI image engine
│       ├── name.rs         # image reference parsing (registry/name[:tag][@digest])
│       ├── config.rs       # parsed OCI image config (env/entrypoint/cmd/workingdir)
│       ├── manifest.rs     # schema2 manifest / multi-arch index + platform selection
│       ├── unpack.rs       # layer tar application: whiteouts + path-traversal guards
│       ├── store.rs        # content-addressed blobs, materialized rootfs, tag index, GC
│       ├── registry.rs     # Docker v2 pull client: Bearer token, mirrors, retries
│       └── pull.rs         # pull orchestration + run-time local image lookup
├── bench/                  # comparison harness (zerun/crun/runc); see bench/README.md
├── AGENTS.md / README.md / LICENSE
```

> Image store layout (under the data root): `blobs/sha256/<hex>` raw registry
> blobs; `rootfs/<config-digest-hex>` materialized read-only rootfs (shared by
> every tag whose config digest matches); `images.json` tag index. Layers are
> materialized per image-config digest rather than mounted as separate overlay
> lowers: whiteouts are plain deletions during unpack, which works rootful and
> rootless alike (no mknod needed).

## 3. Frequent commands

```bash
cargo build --release                 # artifact: target/release/zerun
cargo test                            # unit/integration tests (some need root/sudo)
cargo clippy --all-targets -- -D warnings   # keep zero warnings (rustup component add clippy)
cargo fmt --check / cargo fmt

# Dev smoke test (rootful requires sudo; this sandbox has passwordless sudo)
sudo target/release/zerun doctor
sudo target/release/zerun run --rootfs /tmp/zerun-test/rootfs --hostname box --init -- /bin/sh -c 'exit 42'; echo $?

# Image-mode smoke test (M3): pull + run an OCI image
target/release/zerun pull alpine
target/release/zerun images
target/release/zerun run alpine echo hi            # rootless
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun run --init alpine /bin/sh -c 'exit 7'; echo $?

# Prepare a minimal rootfs (Alpine minirootfs)
mkdir -p /tmp/zerun-test/rootfs
curl -sSL https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz \
  | tar -xz -C /tmp/zerun-test/rootfs

# musl static cross build (brought into CI from M6 onward)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 4. Architecture invariants (must not be violated)

1. **Unsafe concentration**: bare syscalls only in `src/syscalls.rs` (and future kernel-interface
   files such as netlink/nfnetlink modules; when adding one, update this section). Everything else
   calls the safe wrappers.
2. **Parent/child process model**: the container is cloned from the CLI parent. The parent writes
   cgroup.procs, assembles networking, and either waits (foreground) or hands off (detached).
   The child mounts/pivots/execs inside the new namespaces. There is no "single process enters
   a new PID namespace".
3. **Error-pipe protocol**: if the child fails before exec, it must write the error to the
   error pipe (write end has O_CLOEXEC); the parent blocks on read, and **EOF == child exec'd
   successfully**. Any new child-side stage must keep this synchronization protocol.
4. **State lives on the filesystem**: no central daemon. Container runtime state goes under
   `/run/zerun` (rootful) or `$XDG_RUNTIME_DIR/zerun` (rootless); data under `/var/lib/zerun`
   or `$XDG_DATA_HOME/zerun`. Never keep cross-process state in memory.
5. **Secure by default**: no_new_privs -> drop all caps -> seccomp (default profile from M2 on).
   New syscall dependencies must be reflected in the seccomp table. The "warn-and-degrade"
   strategy for rootless mount restrictions is allowed only under the explicitly commented
   environment limitations.
6. **Docker-compatible top 20% CLI**: run/ps/stop/rm/logs/exec/pull/images/rmi/generate-service/
   doctor. No nested two-level subcommands, no resident HTTP API. Image format is 100% OCI.
7. **Image-mode environment is explicit**: `run IMAGE` clears the inherited
   environment and applies the image `config.Env` + `-e` overrides + PATH/HOME/HOSTNAME
   defaults (built in `main.rs::build_image_env`). Legacy `--rootfs` mode keeps the
   inherited environment. When the explicit env is set, bare argv[0] is resolved
   against the container PATH before exec (`workload.rs`).

## 5. Milestones and status (keep current)

| Milestone | Scope | Status |
|---|---|---|
| M1 | Isolation executor: namespaces, pivot_root, pseudo-fs, mini-init, caps, bench | ✅ committed (ported from zerun-m1-skeleton) |
| M2 | Default seccomp allowlist; OverlayFS read-only lowers + disk upper; layer whiteout materialization | ✅ committed: seccomp; per-run OverlayFS (disk upper, auto-cleanup); whiteout materialization (done as part of the M3 rootfs builder) |
| M3 | OCI pull: multi-arch manifest list, Bearer token, diff_id double verification, mirror inheritance | ✅ core committed: `pull/images/rmi`; `run IMAGE` auto-pull + config env/cmd/entrypoint/cwd; multi-arch platform selection; diff_id double verification; mirror inheritance (env + /etc/docker/daemon.json). ⏳ still open: zstd layers, private-registry auth, `/etc/zerun/config.toml` |
| M4 | Netlink veth/bridge + nftables 4-chain NAT, host loopback, DNS/hosts | ⏳ |
| M5 | Detached reaper, logs, ps/stop/logs/exec, crash reconcile | ⏳ |
| M6 | cargo-dist, install.sh, generate-service, AUR/Brew | ⏳ |

## 6. Pitfalls learned from real runs (read before coding)

- Inside a fresh user namespace and before writing uid_map, geteuid() reports 65534: capture the
  host euid/egid **before clone**.
- Must write `setgroups=deny` before gid_map.
- pivot_root sequence: MS_REC|MS_PRIVATE -> bind-mount rootfs onto itself (must be a mount point)
  -> chdir -> pivot_root(".", ".") -> umount2(".", MNT_DETACH) -> chdir("/").
- The `--init` path does not execve, so the error-pipe write end must be **closed manually**;
  otherwise the parent blocks forever on the sync read.
- A business program running directly as PID1 silently ignores unhandled fatal signals
  (verified with /bin/sleep + SIGTERM); use `--init` when signal semantics matter.
- Each clone leaks an 8 MB virtual stack mapping (reclaimed on process exit; acceptable because
  CLI processes are short-lived).
- In rootless nested hosts (this sandbox): mounting proc/sys inside a non-initial user namespace
  can be rejected by LSM, so the code must warn-and-continue. Real rootful targets have no such
  restriction. cgroups v2 without delegation is skipped automatically.
- `ZERUN_TRACE` stderr line format is parsed by bench/analyze.py — changing it requires updating
  the script.
- cgroups v2 needs controllers enabled in the parent subtree_control: the intermediate
  /sys/fs/cgroup/zerun cgroup enables cpu/memory/pids on demand (see cgroup.rs).
- Capabilities are fully dropped, so a rootful container can only write paths whose ownership
  it already matches (e.g. root-owned image files); files unpacked by an unprivileged user stay
  read-only for the container root. Unpack images with the same identity that runs containers.
- OverlayFS creates its internal work/work dir with mode 000: recursive cleanup must not descend
  into it (see fsutil::remove_rec: rmdir first, readdir only when non-empty).
- This dev machine is WSL2: `/mnt/c` is a 9P cross-filesystem and must never hold code/rootfs
  (overlay/pivot need native ext4; this repo is on /dev/sdd ext4). Kernel 6.18 with
  NF_TABLES/VETH/OVERLAY_FS/USER_NS enabled.
- The child clone stack is an anonymous mmap with a PROT_NONE guard page
  (src/syscalls.rs). Do NOT "simplify" it back to `Box::new([0u8; 8MB])`: the array
  literal is built on the caller stack in debug builds and overflows the 8 MB main
  thread stack. Each clone still leaks one 8 MB virtual mapping until process exit
  (short-lived CLI, acceptable).
- Serde needs explicit `#[serde(rename = "mediaType")]` (and friends) — the registry
  JSON uses camelCase. A missing rename silently yields an empty field (this once made
  gzip layers look uncompressed and failed with confusing tar cksum errors).
- The OCI `diff_id` is the sha256 of the *entire* uncompressed layer stream. Do not
  compute it by hashing bytes consumed by a lazy tar parser (it skips trailing
  padding); `pull.rs` decompresses to a spool file first and hashes the full stream.
- Docker Hub's first TLS connection is occasionally flaky; the registry client retries
  transport errors and 429/5xx with short backoff (src/image/registry.rs).
- Pull and run with the same identity: the materialized rootfs is owned by whoever
  unpacked it, and a rootful container can only write paths it owns.
- **Language**: the whole repository is developed and maintained in **English** — code comments,
  docs, CLI/help/error messages, commit messages.
- Commit messages use Conventional Commits (feat/fix/refactor/chore/test/docs), with reasonable
  granularity.

## 7. Environment facts (this dev sandbox, 2026-09)

- Ubuntu 24.04 WSL2, kernel 6.18.33.2, 16 vCPU / 7.6 GB RAM, systemd enabled, cgroups v2.
- Current user uid=1001 with **passwordless sudo** (use it for rootful tests); without root the
  binary automatically goes rootless via NEWUSER.
- Rust 1.98.1; installed target: x86_64-unknown-linux-gnu (add musl/cross targets on demand via
  `rustup target add`).
- Network reachable: GitHub, Docker Hub registry, dl-cdn.alpinelinux.org.
- Reference repos: /home/user/projects/nerdctl, /home/user/projects/ocre-runtime,
  /home/user/projects/zerun-m1-skeleton (read-only).
