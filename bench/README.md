# Zerun Benchmark Harness

Same-machine comparison of **startup latency** and **per-startup memory peak** for
`zerun` / `crun` / `runc`, validating the layered latency budget from the design
doc. The scripts deliberately use only `bash + coreutils + python3 standard
library` — no numpy/pandas/plotting deps — so they also run on low-end edge hosts.

## 1. What is measured

| Metric | Meaning | How collected |
|---|---|---|
| `total_ns` | External wall clock: runtime process start -> workload `/bin/true` exit, including all namespace/mount/exec/wait work | `date +%s%N` around the run; identical for all runtimes, directly comparable |
| `internal_ns` | zerun pure runtime hot path: `parent:begin -> parent:end` | parsed from `ZERUN_TRACE=1` output; crun/runc have no equivalent, left empty |
| `memory.peak` | Transient single-startup peak of runtime + workload | dedicated cgroup v2 `memory.peak` (needs cgroup delegation) |
| minimum `memory.max` | Smallest memory ceiling where `/bin/true` still starts | stepped down 16 MiB -> 64 KiB |

### Layered budget (design doc)

- **T0** = clone -> execve (`--net none --no-overlay`, unpacked rootfs): budget **<= 8 ms**
- **T1** = T0 + OverlayFS mount (`--net none`): budget **<= 20 ms**
- **T2** = T1 + veth/bridge/NAT (`--net bridge`, rootful): budget **<= 40 ms**

External anchors (crun official data, 100x /bin/true): crun ~1.69 s (~17 ms
each), runc ~3.34 s (~33 ms each), crun can start a container inside a 512 KiB
cgroup. **Absolute values across machines are not comparable; only same-machine
relative percentages count.**

## 2. Prepare the rootfs

All runtimes must use the **same unpacked rootfs directory** (fairness):

```bash
# Alpine minirootfs (example; use the current version from the official site)
mkdir -p /tmp/rootfs
curl -sSL -o /tmp/alpine.tar.gz \
  https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf /tmp/alpine.tar.gz -C /tmp/rootfs
test -x /tmp/rootfs/bin/true && echo OK
```

## 3. Run

```bash
# Build the binary under test first
cargo build --release

# Default: warmup 20, sample 100 for each available budget mode
./bench.sh 100 /tmp/rootfs

# Bridge/NAT (T2) needs root; sudo also avoids a per-sample privilege prompt
sudo ./bench.sh 100 /tmp/rootfs

# Custom warmup count / custom binary
WARMUP=50 ZERUN_BIN=/path/to/zerun ./bench.sh 200 /tmp/rootfs
```

Script behavior:

1. `taskset`-pins to the last online core (no pinning without taskset);
2. warms up then samples `zerun-t0`, `zerun-t1`, and, when running as root,
   `zerun-t2`; it also samples each OCI runtime that **exists and runs in the
   current environment**, writing `results/latency-<ts>.csv` row by row;
3. crun/runc are skipped when missing; installed but unrunnable in a rootless /
   nested host (e.g. proc mounts rejected by LSM) are skipped with a note;
4. T2 is skipped when not running as root (bridge networking needs
   CAP_NET_ADMIN);
5. the memory section is skipped when cgroup v2 is not writable (rootless
   without delegation);
6. `analyze.py` summarizes into `results/report-<ts>.md` and updates
   `results/latest-report.md`.

## 4. Install comparison runtimes (optional but strongly recommended)

zerun-only numbers cannot prove a relative advantage. Comparison needs a rootful
environment or full rootless delegation:

```bash
# Debian/Ubuntu
apt-get install -y crun runc
# or put a static crun binary into PATH
command -v crun runc   # confirm visibility
```

crun/runc run `/bin/true` via an OCI bundle; `bench.sh` generates a minimal
`config.json` automatically (pid/mount/uts/ipc namespaces; a user namespace with
a single uid/gid mapping is added when rootless) and bind-mounts the same rootfs.

## 5. Output files

```
results/
├── latency-<ts>.csv      # raw samples: runtime,iter,total_ns,internal_ns,ok
├── mem-<ts>.csv          # memory peaks (only when cgroup writable)
├── report-<ts>.md        # statistics report
└── latest-report.md      # copy of the most recent report
```

Re-run the analysis without resampling:

```bash
python3 analyze.py results/latency-xxx.csv --mem results/mem-xxx.csv --out report.md
```

## 6. Fairness and known noise

- **Warmup is mandatory**: the first run loads the dynamic linker and fills the
  rootfs page cache; cold samples are significantly larger.
- **Pin the CPU**: avoids migrating between cores; if the machine has isolated
  cores (`isolcpus` / `nohz_full`), prefer those.
- **Rootless nested host**: this dev sandbox is one — non-initial user
  namespaces may have proc/sys mounts rejected by security policy; zerun warns
  and continues degraded. crun/runc usually cannot run there either, so run the
  comparison on a real target (rootful or fully delegated).
- **Workload is `/bin/true`**: measures runtime framework overhead only, not
  workload init; to measure a real workload, replace the payload in the rootfs
  and interpret accordingly.
- Sample count >= 100 is recommended; focus on **median and p95** — the mean is
  easily inflated by scheduler jitter.
