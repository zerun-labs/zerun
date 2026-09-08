# Zerun startup latency comparison report

- host: `Abyte-PC` / Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- kernel: `6.18.33.2-microsoft-standard-WSL2`
- CPU count: 16
- baseline runtime: **zerun** (relative percentages use its median as 100%)
- workload: `/bin/true`; values are external wall-clock total_ns (runtime start -> workload exit)
- `internal` column is the zerun-internal trace (parent:begin -> parent:end), excluding tail latency from parent scheduler wakeups

## 1. Latency statistics (ms)

| runtime | samples | min | median | p95 | mean | max | stdev | vs baseline (median) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `zerun` | 60 | 6.949 | 7.386 | 8.200 | 7.497 | 9.160 | 0.448 | 100.0% |

## 2. zerun internal hot path (trace, ms)

| runtime | min | median | p95 | mean |
|---|---:|---:|---:|---:|
| `zerun`(internal) | 3.085 | 3.558 | 4.119 | 3.616 |

## 3. Layered latency budget

- T0 = clone->execve (net=none, unpacked rootfs) budget **<= 8 ms**
- zerun median = **7.386 ms**, p95 = 8.200 ms -> PASS
- T1 (+OverlayFS <=20ms) and T2 (+veth/bridge/nft <=40ms) will be added once those milestones land

## 4. Reproduction

```bash
# same host and rootfs, warmup 20 then sample (default 100), taskset-pinned to the last core
./bench.sh 100 <rootfs-dir>
```

External anchors (crun official, 100x /bin/true): crun ~1.69 s (~17 ms each), runc ~3.34 s (~33 ms each).
Absolute values across kernels/CPUs/rootfs media are not comparable; use same-machine relative percentages.
