#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zerun benchmark analyzer (pure standard library, no third-party deps).

Reads the latency CSV produced by bench.sh (columns:
runtime,iter,total_ns,internal_ns,ok), computes min / median / p95 / mean per
runtime, derives relative percentages against a baseline (crun when present),
and compares against the T0 latency budget. Emits a Markdown report.

Usage:
  python3 analyze.py latency.csv [--mem mem.csv] [--out report.md]
"""
import argparse
import csv
import os
import platform
import statistics
import sys
from collections import defaultdict


def pct(sorted_vals, q):
    """Nearest-rank percentile, q in [0,100]; avoids a numpy dependency."""
    if not sorted_vals:
        return 0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (q / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def ns2ms(v):
    return v / 1_000_000.0


def load_latency(path):
    groups = defaultdict(list)   # runtime -> list[total_ns]
    internal = defaultdict(list) # runtime -> list[internal_ns]
    fails = defaultdict(int)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rt = row["runtime"]
            if row.get("ok") == "0":
                fails[rt] += 1
                continue
            try:
                groups[rt].append(int(row["total_ns"]))
            except (ValueError, KeyError):
                fails[rt] += 1
            iv = (row.get("internal_ns") or "").strip()
            if iv:
                try:
                    internal[rt].append(int(iv))
                except ValueError:
                    pass
    return groups, internal, fails


def summarize(vals):
    s = sorted(vals)
    return {
        "n": len(s),
        "min": s[0],
        "median": statistics.median(s),
        "mean": statistics.fmean(s),
        "p95": pct(s, 95),
        "max": s[-1],
        "stdev": statistics.pstdev(s) if len(s) > 1 else 0.0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("latency")
    ap.add_argument("--mem", help="optional memory CSV")
    ap.add_argument("--out", help="output markdown path; defaults to stdout")
    args = ap.parse_args()

    groups, internal, fails = load_latency(args.latency)
    if not groups:
        print("no valid samples", file=sys.stderr)
        sys.exit(1)

    stats = {rt: summarize(v) for rt, v in groups.items()}
    istats = {rt: summarize(v) for rt, v in internal.items() if v}

    # Baseline: prefer crun, otherwise the runtime with the smallest median.
    if "crun" in stats:
        baseline = "crun"
    else:
        baseline = min(stats, key=lambda r: stats[r]["median"])
    base_med = stats[baseline]["median"]

    order = ["zerun-t0", "zerun-t1", "zerun-t2", "zerun", "crun", "runc"]
    runtimes = [r for r in order if r in stats] + [r for r in stats if r not in order]

    lines = []
    lines.append("# Zerun startup latency comparison report")
    lines.append("")
    lines.append(f"- host: `{platform.node()}` / {platform.platform()}")
    lines.append(f"- kernel: `{platform.release()}`")
    try:
        lines.append(f"- CPU count: {os.cpu_count()}")
    except NotImplementedError:
        pass
    lines.append(f"- baseline runtime: **{baseline}** (relative percentages use its median as 100%)")
    lines.append("- workload: `/bin/true`; values are external wall-clock total_ns (runtime start -> workload exit)")
    lines.append("- `internal` column is the zerun-internal trace (parent:begin -> parent:end), excluding tail latency from parent scheduler wakeups")
    lines.append("")

    lines.append("## 1. Latency statistics (ms)")
    lines.append("")
    lines.append("| runtime | samples | min | median | p95 | mean | max | stdev | vs baseline (median) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for rt in runtimes:
        s = stats[rt]
        rel = s["median"] / base_med * 100.0
        lines.append(
            f"| `{rt}` | {s['n']} | {ns2ms(s['min']):.3f} | {ns2ms(s['median']):.3f} | "
            f"{ns2ms(s['p95']):.3f} | {ns2ms(s['mean']):.3f} | {ns2ms(s['max']):.3f} | "
            f"{ns2ms(s['stdev']):.3f} | {rel:.1f}% |"
        )
        if fails[rt]:
            lines.append(f"> note: `{rt}` had {fails[rt]} failed samples excluded")
    lines.append("")

    if istats:
        lines.append("## 2. zerun internal hot path (trace, ms)")
        lines.append("")
        lines.append("| runtime | min | median | p95 | mean |")
        lines.append("|---|---:|---:|---:|---:|")
        for rt, s in istats.items():
            lines.append(
                f"| `{rt}`(internal) | {ns2ms(s['min']):.3f} | {ns2ms(s['median']):.3f} | "
                f"{ns2ms(s['p95']):.3f} | {ns2ms(s['mean']):.3f} |"
            )
        lines.append("")

    # Compare the layered budgets from the design doc.
    lines.append("## 3. Layered latency budget")
    lines.append("")
    budgets = [
        ("zerun-t0", "clone->execve (net=none, unpacked rootfs)", 8.0),
        ("zerun-t1", "T0 + OverlayFS", 20.0),
        ("zerun-t2", "T1 + veth/bridge/nft", 40.0),
    ]
    saw_budget = False
    for runtime, description, budget_ms in budgets:
        z = stats.get(runtime)
        if not z:
            continue
        saw_budget = True
        med = ns2ms(z["median"])
        verdict = "PASS" if med <= budget_ms else "OVER BUDGET"
        lines.append(
            f"- {runtime} = {description} budget **<= {budget_ms:.0f} ms**; "
            f"median = **{med:.3f} ms**, p95 = {ns2ms(z['p95']):.3f} ms -> {verdict}"
        )
    if not saw_budget:
        lines.append("- no `zerun-t*` samples found")
    lines.append("")

    sec = 4
    if args.mem and os.path.exists(args.mem):
        lines.append(f"## {sec}. Memory (cgroup v2)")
        lines.append("")
        lines.append("| metric | value |")
        lines.append("|---|---:|")
        with open(args.mem, newline="") as f:
            for row in csv.reader(f):
                if len(row) == 2:
                    k, v = row
                    if v.isdigit():
                        v = f"{int(v)/1024:.1f} KiB ({v} B)"
                    lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("> cgroup `memory.peak` is the transient single-startup peak of runtime + workload;")
        lines.append("> resident memory will be measured as the detached reaper's /proc/<pid>/smaps_rollup Pss (M5).")
        lines.append("")
        sec += 1

    lines.append(f"## {sec}. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("# same host and rootfs, warmup 20 then sample (default 100), taskset-pinned to the last core")
    lines.append(f"./bench.sh 100 <rootfs-dir>")
    lines.append("```")
    lines.append("")
    lines.append("External anchors (crun official, 100x /bin/true): crun ~1.69 s (~17 ms each), runc ~3.34 s (~33 ms each).")
    lines.append("Absolute values across kernels/CPUs/rootfs media are not comparable; use same-machine relative percentages.")
    lines.append("")

    report = "\n".join(lines)
    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
    else:
        print(report)


if __name__ == "__main__":
    main()
