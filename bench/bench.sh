#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Zerun benchmark harness — same-machine comparison of zerun / crun / runc
#
# Measurements (aligned with the layered latency budget in the design doc):
#   total_ns    external wall clock: runtime process start -> workload /bin/true
#               exit (includes all isolation/mount/exec work)
#   internal_ns zerun-internal ZERUN_TRACE span: parent:begin -> parent:end
#               (the pure runtime hot path); crun/runc have no equivalent span
#
# Fairness controls:
#   - same rootfs, same kernel, same CPU (taskset pinning), same scheduler env
#   - warm up WARMUP iterations first (page cache / branch predictor / dynamic
#     linker caches) before sampling
#   - crun/runc are skipped automatically when missing; installed-but-unrunnable
#     runtimes (e.g. rootless nested hosts refusing proc mounts) are skipped too
#
# Usage:
#   ./bench.sh [sample count N=100] [rootfs directory]
#   ZERUN_BIN=/path/to/zerun ./bench.sh 200 /tmp/rootfs
#
# Output:
#   results/latency-<timestamp>.csv   raw samples
#   results/mem-<timestamp>.csv       cgroup memory.peak (needs cgroup delegation;
#                                     skipped automatically when rootless)
#   results/report-<timestamp>.md     analyze.py summary (updates latest-report.md)
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
N="${1:-100}"
ROOTFS="${2:-${ROOTFS_OVERRIDE:-/tmp/zerun-test/rootfs}}"
ZERUN_BIN="${ZERUN_BIN:-$REPO_DIR/target/release/zerun}"
PY="${PYTHON:-/opt/python3.12/bin/python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python3

WARMUP="${WARMUP:-20}"
OUT_DIR="$SCRIPT_DIR/results"
TS="$(date +%Y%m%d-%H%M%S)"
LAT_CSV="$OUT_DIR/latency-$TS.csv"
MEM_CSV="$OUT_DIR/mem-$TS.csv"
WORK="$(mktemp -d -t zerun-bench.XXXXXX)"
trap 'find "$WORK" -depth -delete' EXIT
mkdir -p "$OUT_DIR"

# ---- CPU pinning: pick the last online core to avoid CPU0 noise ----------------
PIN=()
if command -v taskset >/dev/null 2>&1; then
  LASTCPU=$(( $(nproc) - 1 ))
  PIN=(taskset -c "$LASTCPU")
  echo "[bench] pinning sampling to CPU $LASTCPU"
fi

log() { echo "[bench] $*"; }

# ---- preflight ----------------------------------------------------------------
if [[ ! -x "$ZERUN_BIN" ]]; then
  echo "[bench] error: zerun binary not found: $ZERUN_BIN (run cargo build --release first)" >&2
  exit 1
fi
if [[ ! -d "$ROOTFS/bin" ]]; then
  echo "[bench] error: rootfs unavailable: $ROOTFS (needs an unpacked dir with /bin/true, e.g. alpine minirootfs)" >&2
  echo "        fix: mkdir rootfs && curl -sSL <alpine-minirootfs-url> | tar -xz -C rootfs" >&2
  exit 1
fi
log "rootfs       = $ROOTFS"
log "sample count = $N (warmup $WARMUP)"
log "zerun binary = $ZERUN_BIN"

echo "runtime,iter,total_ns,internal_ns,ok" > "$LAT_CSV"

# Nanosecond timestamp.
now_ns() { date +%s%N; }

# ---- zerun sampling (external wall clock + internal trace) -------------------
# Extract the parent:begin -> parent:end delta from ZERUN_TRACE stderr.
extract_internal_ns() {
  local trace="$1"
  awk '
    /parent:begin/ { b=$2 }
    /parent:end/   { e=$2 }
    END { if (b!="" && e!="") printf "%d", e-b; else printf "" }
  ' <<<"$trace"
}

bench_zerun() {
  log "warming up zerun x$WARMUP ..."
  for ((i=0;i<WARMUP;i++)); do "$ZERUN_BIN" run --rootfs "$ROOTFS" --net none -- /bin/true >/dev/null 2>&1 || true; done
  log "sampling zerun x$N ..."
  for ((i=0;i<N;i++)); do
    local trace_file="$WORK/trace"
    local s e internal ok=1
    s=$(now_ns)
    trace=$(ZERUN_TRACE=1 "$ZERUN_BIN" run --rootfs "$ROOTFS" --net none -- /bin/true 2>"$trace_file") || ok=0
    e=$(now_ns)
    internal=$(extract_internal_ns "$(cat "$trace_file")")
    echo "zerun,$i,$((e-s)),${internal:-},$ok" >> "$LAT_CSV"
  done
}

# ---- generate a minimal OCI bundle for crun/runc comparison ------------------
make_oci_bundle() {
  local dir="$1" rootless="$2"
  mkdir -p "$dir/rootfs"
  # Reuse the same rootfs via a read-only bind (no copy; the mount is read-only).
  mountpoint -q "$dir/rootfs" 2>/dev/null || mount --bind "$ROOTFS" "$dir/rootfs" 2>/dev/null || {
    cp -a "$ROOTFS/." "$dir/rootfs/" 2>/dev/null || true
  }
  local userns_block=""
  if [[ "$rootless" == "1" ]]; then
    userns_block='"user"'
  fi
  cat > "$dir/config.json" <<JSON
{
  "ociVersion": "1.0.2",
  "process": {
    "args": ["/bin/true"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  },
  "root": { "path": "rootfs", "readonly": true },
  "linux": {
    "namespaces": [
      { "type": "pid" }, { "type": "mount" }, { "type": "uts" },
      { "type": "ipc" } $([ -n "$userns_block" ] && echo ",{ \"type\": \"user\" }")
    ]
  }
}
JSON
}

# Check whether an OCI runtime can actually run once here (rootless nested hosts
# may refuse).
probe_oci_runtime() {
  local rt="$1" bundle="$2"
  local cid="probe-$$"
  if "$rt" run --bundle "$bundle" "$cid" >/dev/null 2>&1; then
    "$rt" delete "$cid" >/dev/null 2>&1 || true
    return 0
  fi
  "$rt" delete "$cid" >/dev/null 2>&1 || true
  return 1
}

bench_oci_runtime() {
  local rt="$1"
  command -v "$rt" >/dev/null 2>&1 || { log "skipping $rt (not installed)"; return; }
  local rootless=0; [[ "$(id -u)" != "0" ]] && rootless=1
  local bundle="$WORK/$rt-bundle"; make_oci_bundle "$bundle" "$rootless"
  if ! probe_oci_runtime "$rt" "$bundle"; then
    log "skipping $rt (installed but cannot run here; common on rootless nested hosts that refuse proc mounts)"
    return
  fi
  log "warming up $rt x$WARMUP ..."
  for ((i=0;i<WARMUP;i++)); do "$rt" run --bundle "$bundle" "w-$i-$$" >/dev/null 2>&1 || true; done
  log "sampling $rt x$N ..."
  for ((i=0;i<N;i++)); do
    local s e ok=1 cid="r-$i-$$"
    s=$(now_ns)
    "${PIN[@]}" "$rt" run --bundle "$bundle" "$cid" >/dev/null 2>&1 || ok=0
    e=$(now_ns)
    "$rt" delete "$cid" >/dev/null 2>&1 || true
    echo "$rt,$i,$((e-s)),,$ok" >> "$LAT_CSV"
  done
}

# ---- memory peak (needs cgroup v2 delegation; skipped when rootless) ----------
bench_memory_peak() {
  local cg="/sys/fs/cgroup/zerun-bench-$$"
  if ! mkdir "$cg" 2>/dev/null; then
    log "cgroup v2 not writable (rootless without delegation); skipping memory.peak / minimum memory.max test"
    return
  fi
  log "cgroup memory peak test -> $cg"
  echo "runtime,memory_peak_bytes" > "$MEM_CSV"
  # zerun: place the runner in the cgroup, then read peak after the run
  # (includes the transient peak of runtime + workload).
  echo $$ > "$cg/cgroup.procs" 2>/dev/null || true
  "$ZERUN_BIN" run --rootfs "$ROOTFS" --net none -- /bin/true >/dev/null 2>&1 || true
  echo "zerun,$(cat "$cg/memory.peak" 2>/dev/null || echo NA)" >> "$MEM_CSV"

  # Step down memory.max to find the smallest value where /bin/true still runs.
  log "minimum memory.max stepping ..."
  local sizes=(16777216 8388608 4194304 2097152 1048576 524288 262144 131072 65536)
  local min_ok="NA"
  for sz in "${sizes[@]}"; do
    echo "$sz" > "$cg/memory.max" 2>/dev/null || continue
    if "$ZERUN_BIN" run --rootfs "$ROOTFS" --net none -- /bin/true >/dev/null 2>&1; then
      min_ok="$sz"
    else
      break # smaller will certainly fail; stop stepping
    fi
  done
  echo "min_runnable_memory_max_bytes,$min_ok" >> "$MEM_CSV"
  echo "max" > "$cg/memory.max" 2>/dev/null || true
  rmdir "$cg" 2>/dev/null || true
}

# ---- run ---------------------------------------------------------------------
"${PIN[@]}" true 2>/dev/null || PIN=()
bench_zerun
bench_oci_runtime crun
bench_oci_runtime runc
bench_memory_peak

# ---- summarize ---------------------------------------------------------------
log "raw samples: $LAT_CSV"
REPORT="$OUT_DIR/report-$TS.md"
"$PY" "$SCRIPT_DIR/analyze.py" "$LAT_CSV" ${MEM_CSV:+--mem "$MEM_CSV"} --out "$REPORT"
cp "$REPORT" "$OUT_DIR/latest-report.md"
log "report: $REPORT"
log "report (latest copy): $OUT_DIR/latest-report.md"
echo
cat "$REPORT"
