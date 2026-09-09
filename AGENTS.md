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
│   ├── main.rs             # CLI entry: run / ps / stop / rm / logs / exec / pull / ... / doctor
│   ├── error.rs            # ZError / zerr! / ZResult
│   ├── trace.rs            # ZERUN_TRACE=1 stage timing (bench/analyze.py parses its format!)
│   ├── syscalls.rs         # ★ ALL unsafe syscalls live here (mount/clone/pivot_root/caps/pipe)
│   ├── namespace.rs        # parent/child orchestration: clone, error/net-ready pipes, signals, wait
│   ├── netlink.rs          # kernel interface: rtnetlink wrapper (links/addresses/routes)
│   ├── nfnetlink.rs        # kernel interface: nf_tables via netlink (egress NAT, no nft binary)
│   ├── network.rs          # bridge-mode orchestration: zerun0 bridge, veth pair, IPAM, -p proxy
│   ├── mounts.rs           # pivot_root sequence, pseudo-fs, masked/readonly paths, minimal /dev
│   ├── cgroup.rs           # cgroups v2 driver (memory/cpu/pids) + subtree_control setup
│   ├── security.rs         # no_new_privs -> capability drop -> seccomp orchestration
│   ├── seccomp.rs          # default deny-by-default BPF allowlist (x86_64 table; extend per arch)
│   ├── mini_init.rs        # container PID1 mini-init (signal forwarding + orphan reaping)
│   ├── state.rs            # M5 per-container state.json schema (<run>/containers/<id>/)
│   ├── lifecycle.rs        # M5 detached reaper: run_detached + crash reconcile / settle_exit
│   ├── execc.rs            # M5 `exec`: join a running container's namespaces in-process
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

# M4 bridge networking (rootful only): container gets eth0 on bridge zerun0
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun run --net bridge alpine /bin/ls /sys/class/net   # eth0 lo
sudo ip -br addr show zerun0   # 10.88.0.1/24 while a bridge container runs

# M5 detached lifecycle: run -d + ps/stop/rm/logs/exec (same binary, no daemon)
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun run -d --name web -p 18080:80 --net bridge --init \
  alpine /bin/sh -c 'while true; do echo hi | nc -l -p 80; done'   # prints the container id
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun ps            # table of running containers
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun logs --tail 20 web
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun exec web /bin/sh -c 'echo in-container; hostname'
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun stop --time 3 web
sudo env ZERUN_DATA_ROOT=/tmp/zerun-root ./target/release/zerun rm web

# Prepare a minimal rootfs (Alpine minirootfs)
mkdir -p /tmp/zerun-test/rootfs
curl -sSL https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz \
  | tar -xz -C /tmp/zerun-test/rootfs

# musl static cross build (brought into CI from M6 onward)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 4. Architecture invariants (must not be violated)

1. **Unsafe concentration**: bare syscalls only in `src/syscalls.rs`; kernel-interface files are
   `src/netlink.rs` (rtnetlink) and the future nfnetlink/nftables module. Everything else calls
   the safe wrappers. When adding a kernel-interface file, update this section.
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
| M3 | OCI pull: multi-arch manifest list, Bearer token, diff_id double verification, mirror inheritance | ✅ committed: `pull/images/rmi`; `run IMAGE` auto-pull + config env/cmd/entrypoint/cwd; multi-arch platform selection; diff_id double verification; mirror inheritance (env + zerun config.toml + `/etc/docker/daemon.json`); zstd layer decode + compression magic sniffing; per-layer pull progress. ⏳ still open: private-registry auth |
| M4 | Netlink veth/bridge + egress NAT, `-p` publishing, DNS | ✅ committed: `--net bridge` (rootful) — `zerun0` bridge 10.88.0.1/24, per-container veth pair, net-ready sync, container `eth0` addr + default route, egress masquerade per container (nf_tables via pure netlink), `-p HOST:CONTAINER` via a built-in userland proxy (Docker's docker-proxy, in-binary), `--dns` + host resolv.conf inheritance. ⏳ left open: `/etc/hosts` entries, default `--net bridge` |
| M5 | Detached reaper, logs, ps/stop/logs/exec, crash reconcile | ✅ committed: `run -d/--name/--rm` (per-container reaper that redirects stdio to console.log and persists state under `<run>/containers/<id>/`); `ps [-a]` (crash reconcile of stale Running records), `stop [-t]` (TERM->KILL with reaper settle), `rm [-f]` (state + overlay removal), `logs [--tail N] [-f]`, `exec [-e] [-w]` (in-process setns join of user/mnt/uts/ipc/net/cgroup/pid + hardened exec); file-based IPAM with flock (deterministic slot first, crash-reclaimed); `--init`-safe started-pipe protocol. ⏳ left open: `/etc/hosts` entries, TTY (-t/-i), `logs` timestamps, restart/commit |
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
- rtnetlink sockets must be created inside a tokio runtime context (netlink-sys registers
  with the reactor): `Netlink::new()` builds the runtime first, then calls
  `rtnetlink::new_connection()` inside `Runtime::block_on` and spawns the connection task.
- A locally generated packet whose source is 127.0.0.1 **cannot be routed to the bridge**:
  after an OUTPUT-chain DNAT the post-DNAT route lookup fails (EINVAL / martian source) and
  the SYN dies before POSTROUTING. This is why Docker excludes 127.0.0.0/8 from OUTPUT DNAT
  and ships docker-proxy. Zerun publishes `-p` ports with a built-in userland TCP proxy
  (src/network.rs `bind_port_proxies`, bound before the clone so a busy port fails fast) and
  keeps only egress masquerade in the kernel. Do not "simplify" this back to kernel DNAT.
- `-p` proxy listeners and their pump threads are deliberately untracked: they live exactly as
  long as the owning process (foreground CLI or detached reaper), which never outlives the
  container run, so process exit cleans them up.
- Container <-> host bridge traffic is verified working in this sandbox (ping both ways, TCP to
  a host listener, `curl localhost:HOST` through the proxy). Bridge **internet egress** is
  blocked by this sandbox's outer NAT even though the SYN leaves the host correctly
  masqueraded (source 198.18.0.1); it works on real hosts exactly like Docker's bridge.
- A crashed/killed `run` (SIGKILL of the CLI, power loss) leaves its nft table + veth host end
  behind: teardown runs in the parent after `waitpid`, so it only survives a parent that never
  got to wait. In M5 a killed **reaper** leaves state "Running" for a live container: `ps` shows
  it Up, and `stop`/`rm -f` kill the PID and then `lifecycle::settle_exit` waits briefly for the
  reaper's own final write before falling back to `reconcile_stale` (mark Exited, reclaim nft
  table/veth/cgroup/IPAM and remove the per-run overlay). A Running record whose PID is already
  dead is reconciled directly by `ps -a`.
- When a container netns dies, the kernel removes the whole veth pair automatically; host-side
  teardown must tolerate "No such device" (look the link up by name first).
- Bridge-mode networking needs CAP_NET_ADMIN in the host netns (rootful only for now): rootless
  runs are rejected with a clear error until a user-mode NAT lands.
- Container IPv4 addresses are deterministic from the container id and tracked in a file IPAM
  (src/network.rs, M5): `<run>/net/ipam.json` under an flock on `<run>/net/ipam.lock`. The
  deterministic slot is tried first; occupied slots are skipped; `release_ip` runs on every exit
  path and stale records are reclaimed by crash reconcile.
- The net-ready pipe protocol (parent writes `0` = ready / `1` + error text; the child relays
  host-side failures over the error pipe) must be preserved by any future child-side stage.
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
- `run -d`'s started pipe carries a **single newline-terminated status line** (`0` / `1: err`).
  The CLI must stop reading at the first newline, not wait for EOF: with `--init` the container
  child never execs, so the CLOEXEC write end stays open in the container and EOF only arrives
  when the container exits (this hung the CLI once). Same rule as the error pipe: keep the
  protocol byte-exact.
- `exec` (src/execc.rs) joins namespaces **in-process**: open all `/proc/<pid>/ns/*` fds first
  and keep the `File`s alive (raw fds alone dangle), setns(user) only when `state.rootless`
  (setns into the *initial* user namespace fails with EINVAL), setns(pid) last because it only
  affects children, then fork the worker. The worker is born a child of the container's PID 1
  but reaped by the joiner through the host PID namespace.
- Detached state layout: `<run>/containers/<id>/state.json` + `console.log`; `state.json` is
  written by the CLI (Created), the reaper (Running/Exited), and reconcilers. The per-run
  overlay is removed by the reaper on exit (docker `--rm`-like semantics for every detached
  run); `rm` deletes the state dir (and any overlay dir still recorded). Foreground runs keep
  no state. `state::ContainerState::save()` derives its path from the `log` field — always set
  `log` before saving.
- `stop`/`rm -f` must never delete the state directory under a live reaper that is about to
  write its final record: kill the PID, wait for the reaper's Exited write (`settle_exit`), then
  remove. Killing only the container PID is enough to stop a container — when PID 1 of a PID
  namespace dies, the kernel SIGKILLs the rest of the namespace.
- `zerun exec` applies the default seccomp/caps hardening in the worker before exec'ing, like a
  fresh container process. State does not yet record per-container `--seccomp`/`--init` choices,
  so `exec` always uses the default profile.
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
