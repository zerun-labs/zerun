#!/usr/bin/env bash
# Exercise runtime paths that ordinary unit tests cannot cover because they
# need a real rootful Linux host: overlayfs, cgroups v2, bridge networking,
# lifecycle introspection, rootfs export/import, and the in-process published-port proxy.
set -Eeuo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 ZERUN_BIN ROOTFS DATA_ROOT RUNTIME_ROOT" >&2
  exit 2
fi

binary=$1
rootfs=$2
data_root=$3
runtime_root=$4

for path in "$binary" "$rootfs"; do
  [[ -e $path ]] || { echo "missing required path: $path" >&2; exit 1; }
done

if (( EUID == 0 )); then
  privileged=()
  zerun=(env
    ZERUN_DATA_ROOT="$data_root"
    ZERUN_RUNTIME_ROOT="$runtime_root"
    "$binary")
else
  command -v sudo >/dev/null || {
    echo "rootful runtime tests require sudo when not already running as root" >&2
    exit 1
  }
  privileged=(sudo)
  zerun=(sudo env
    ZERUN_DATA_ROOT="$data_root"
    ZERUN_RUNTIME_ROOT="$runtime_root"
    "$binary")
fi

# Always clean up detached records, including when a later integration check
# fails. The runner is ephemeral, but explicit cleanup makes repeated local
# runs deterministic and prevents leaked bridge listeners between checks.
cleanup_ids=()
cleanup_pids=()
cleanup_paths=()
cleanup_dirs=()
shared_net_target_state=
shared_net_target_state_backup=
shared_net_target_state_backup_ready=false
remove_cleanup_path() {
  if (( EUID == 0 )); then
    rm -f -- "$1"
  else
    sudo rm -f -- "$1"
  fi
}
remove_cleanup_dir() {
  if (( EUID == 0 )); then
    rm -rf -- "$1"
  else
    sudo rm -rf -- "$1"
  fi
}
# A background command started through sudo is represented by the sudo
# process, not necessarily the zerun process that owns the container. Locate
# the first zerun descendant so signal-forwarding tests exercise the runtime
# rather than killing the wrapper. Linux hosts always expose this tree in
# /proc, and the breadth-first search stops before container descendants.
find_zerun_process() {
  local root=$1
  local -a pending=("$root")
  local pid comm
  local -a children=()
  while ((${#pending[@]})); do
    pid=${pending[0]}
    pending=("${pending[@]:1}")
    [[ -r /proc/$pid/comm ]] || continue
    read -r comm </proc/$pid/comm
    if [[ $comm == zerun ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
    [[ -r /proc/$pid/task/$pid/children ]] || continue
    children=()
    read -r -a children </proc/$pid/task/$pid/children || true
    pending+=("${children[@]}")
  done
  return 1
}
signal_rootful_process() {
  local pid=$1
  local signal=$2
  if (( EUID == 0 )); then
    kill -s "$signal" "$pid"
  else
    sudo kill -s "$signal" "$pid"
  fi
}
cleanup() {
  if [[ -n $shared_net_target_state_backup ]] && $shared_net_target_state_backup_ready; then
    if ! "${privileged[@]}" cp -p -- "$shared_net_target_state_backup" "$shared_net_target_state"; then
      echo "failed to restore container state; backup retained at $shared_net_target_state_backup" >&2
    else
      remove_cleanup_path "$shared_net_target_state_backup" || true
    fi
  elif [[ -n $shared_net_target_state_backup ]]; then
    remove_cleanup_path "$shared_net_target_state_backup" || true
  fi
  for pid in "${cleanup_pids[@]}"; do
    runtime_pid=$(find_zerun_process "$pid" 2>/dev/null || true)
    if [[ -n $runtime_pid ]]; then
      signal_rootful_process "$runtime_pid" TERM >/dev/null 2>&1 || true
    else
      kill -TERM "$pid" >/dev/null 2>&1 || true
    fi
  done
  for id in "${cleanup_ids[@]}"; do
    "${zerun[@]}" rm -f "$id" >/dev/null 2>&1 || true
  done
  for path in "${cleanup_paths[@]}"; do
    remove_cleanup_path "$path" >/dev/null 2>&1 || true
  done
  for path in "${cleanup_dirs[@]}"; do
    remove_cleanup_dir "$path" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# Rootful runs now depend on cgroup v2 device BPF support. Doctor must exercise
# the same temporary-cgroup load/attach path that normal container startup uses.
doctor_output=$("${zerun[@]}" doctor)
grep -F 'device policy  : OK' <<<"$doctor_output" >/dev/null
grep -F 'readiness      : OK' <<<"$doctor_output" >/dev/null

# A damaged state record must be visible and fail closed. Silently skipping it
# would hide a retained container and could let image GC discard its lower
# rootfs. Empty reservation directories remain valid during concurrent runs.
corrupt_state_id=$(printf '%012x' "$BASHPID")
corrupt_state_dir="$runtime_root/containers/$corrupt_state_id"
cleanup_dirs+=("$corrupt_state_dir")
mkdir -p "$corrupt_state_dir"
printf '{not valid json\n' >"$corrupt_state_dir/state.json"
if corrupt_doctor_output=$("${zerun[@]}" doctor 2>&1); then
  echo "doctor accepted a corrupted container state record" >&2
  exit 1
fi
grep -F 'container state: INVALID' <<<"$corrupt_doctor_output" >/dev/null
if corrupt_ps_output=$("${zerun[@]}" ps -a 2>&1); then
  echo "ps silently accepted a corrupted container state record" >&2
  exit 1
fi
grep -F "parse container state" <<<"$corrupt_ps_output" >/dev/null
grep -F "$corrupt_state_id" <<<"$corrupt_ps_output" >/dev/null
if corrupt_prune_output=$("${zerun[@]}" prune -f --images 2>&1); then
  echo "prune proceeded with incomplete container protections" >&2
  exit 1
fi
grep -F "parse container state" <<<"$corrupt_prune_output" >/dev/null
remove_cleanup_dir "$corrupt_state_dir"
echo "rootful-state-inventory-fail-closed-ok"

# Pick a high, currently unused TCP port instead of assuming a shared runner
# has 18080 available. The check is intentionally only a race-avoidance hint:
# Zerun still binds the published port before cloning the container, so its
# own bind remains the authoritative conflict check.
find_free_tcp_port_range() {
  local count=$1
  local candidate=$((18080 + (BASHPID % 1000)))
  local attempt offset free
  [[ $count =~ ^[1-9][0-9]*$ ]] || {
    echo "invalid free-port range size: $count" >&2
    return 1
  }
  for attempt in $(seq 1 1000); do
    free=1
    for ((offset = 0; offset < count; offset++)); do
      if (echo >/dev/tcp/127.0.0.1/$((candidate + offset))) 2>/dev/null; then
        free=0
        break
      fi
    done
    if (( free )); then
      printf '%s\n' "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  echo "could not find a free TCP port for the published-port check" >&2
  return 1
}

find_free_tcp_port() {
  find_free_tcp_port_range 1
}

wait_for_http_body() {
  local port=$1 expected=$2 attempt
  for attempt in $(seq 1 50); do
    if curl --fail --silent --show-error "http://127.0.0.1:$port/" | \
        grep -Fxq "$expected"; then
      return 0
    fi
    sleep 0.2
  done
  echo "HTTP response '$expected' did not become ready on port $port" >&2
  return 1
}

# A foreground run proves the namespace/pivot/init path and preserves the
# workload exit code instead of treating a non-zero workload status as a
# runtime failure.
set +e
foreground_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --init -- \
  /bin/sh -c 'printf "foreground-ok\\n"; exit 17' 2>&1)
foreground_status=$?
set -e
printf '%s\n' "$foreground_output"
test "$foreground_status" -eq 17
grep -Fx foreground-ok <<<"$foreground_output" >/dev/null

# The Docker-compatible cidfile is an exclusive receipt: a successful startup
# leaves the container id behind, while a duplicate path is rejected without
# overwriting the original receipt.
cidfile=$(mktemp)
remove_cleanup_path "$cidfile"
cleanup_paths+=("$cidfile")
"${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay --cidfile "$cidfile" -- /bin/sh -c true
cid_value=$(cat "$cidfile")
[[ $cid_value =~ ^[0-9a-f]{12}$ ]] || {
  echo "cidfile contains an invalid container id: $cid_value" >&2
  exit 1
}
set +e
cidfile_conflict=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --cidfile "$cidfile" -- /bin/sh -c true 2>&1)
cidfile_conflict_status=$?
set -e
test "$cidfile_conflict_status" -eq 2
grep -F 'container ID file' <<<"$cidfile_conflict" >/dev/null
test "$(cat "$cidfile")" = "$cid_value"

# A failed workload launch must remove only the receipt created by that
# attempt, so scripts do not treat a dead container as a successful start.
failed_cidfile=$(mktemp)
remove_cleanup_path "$failed_cidfile"
cleanup_paths+=("$failed_cidfile")
set +e
"${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --cidfile "$failed_cidfile" -- /definitely-missing-zerun-command >/dev/null 2>&1
failed_cidfile_status=$?
set -e
test "$failed_cidfile_status" -eq 1
test ! -e "$failed_cidfile"

# Namespaced sysctls must be applied after the private network and loopback are
# ready, while /proc/sys remains writable during setup and read-only afterward.
sysctl_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.lo.forwarding=1 -- \
  /bin/sh -c 'cat /proc/sys/net/ipv4/ip_forward; cat /proc/sys/net/ipv4/conf/lo/forwarding; \
    if (printf 0 > /proc/sys/net/ipv4/ip_forward) 2>/dev/null; then echo writable; else echo readonly; fi')
test "$sysctl_output" = $'1\n1\nreadonly'
set +e
host_sysctl_output=$("${zerun[@]}" run --rootfs "$rootfs" --net host --no-overlay \
  --sysctl net.ipv4.ip_forward=1 -- /bin/true 2>&1)
host_sysctl_status=$?
set -e
test "$host_sysctl_status" -eq 2
grep -F 'requires a private network namespace' <<<"$host_sysctl_output" >/dev/null

# A failed direct exec must stay on the error pipe until execve succeeds or
# reports an error. Closing it before exec makes the parent mistake a dead
# workload for a successful start.
set +e
exec_failure_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay -- \
  /definitely-missing-zerun-command 2>&1)
exec_failure_status=$?
set -e
test "$exec_failure_status" -eq 1
grep -F "container setup failed: execve failed:" <<<"$exec_failure_output" >/dev/null

# Mini-init forks the workload instead of exec'ing it, but a workload exec
# failure must still reach the runtime parent rather than looking like a
# successful init start.
set +e
init_exec_failure_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay --init -- \
  /definitely-missing-zerun-command 2>&1)
init_exec_failure_status=$?
set -e
test "$init_exec_failure_status" -eq 1
grep -F "container setup failed: mini-init exec" <<<"$init_exec_failure_output" >/dev/null

# PID/IPC/UTS sharing must be opt-in, and host-shared /dev/shm must be the
# host's mount rather than a private tmpfs. The default private run is checked
# against the host namespace identities, not just the visible hostname.
host_pid_ns=$(readlink /proc/self/ns/pid)
host_ipc_ns=$(readlink /proc/self/ns/ipc)
host_uts_ns=$(readlink /proc/self/ns/uts)
host_hostname=$(hostname)
private_ns=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --pid private --ipc private --uts private -- /bin/sh -c \
  'printf "%s\n%s\n%s\n" "$(/bin/busybox readlink /proc/self/ns/pid)" "$(/bin/busybox readlink /proc/self/ns/ipc)" "$(/bin/busybox readlink /proc/self/ns/uts)"')
mapfile -t private_namespaces <<<"$private_ns"
test "${private_namespaces[0]}" != "$host_pid_ns"
test "${private_namespaces[1]}" != "$host_ipc_ns"
test "${private_namespaces[2]}" != "$host_uts_ns"

host_ns=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --pid host --ipc host --uts host -- /bin/sh -c \
  'printf "%s\n%s\n%s\n%s\n" "$(/bin/busybox readlink /proc/self/ns/pid)" "$(/bin/busybox readlink /proc/self/ns/ipc)" "$(/bin/busybox readlink /proc/self/ns/uts)" "$(/bin/busybox hostname)"')
mapfile -t host_namespaces <<<"$host_ns"
test "${host_namespaces[0]}" = "$host_pid_ns"
test "${host_namespaces[1]}" = "$host_ipc_ns"
test "${host_namespaces[2]}" = "$host_uts_ns"
test "${host_namespaces[3]}" = "$host_hostname"

host_shm_marker="/dev/shm/zerun-ci-namespace-${BASHPID}"
cleanup_paths+=("$host_shm_marker")
private_shm=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --ipc private -- /bin/sh -c \
  "if test -e '$host_shm_marker'; then exit 1; fi; printf private-shm-ok")
grep -Fx private-shm-ok <<<"$private_shm" >/dev/null
sized_shm=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --shm-size 96m -- /bin/sh -c \
  'size_kib=$(/bin/busybox df -k /dev/shm | /bin/busybox tail -n 1 | /bin/busybox awk "{print \$2}");
   test "$size_kib" -eq 98304 || { printf "unexpected /dev/shm KiB: %s\n" "$size_kib" >&2; exit 1; }
   printf sized-shm-ok')
grep -Fx sized-shm-ok <<<"$sized_shm" >/dev/null
"${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay --ipc host -- \
  /bin/sh -c "printf host-shm-ok > '$host_shm_marker'"
grep -Fx host-shm-ok "$host_shm_marker" >/dev/null

# --ipc none keeps the private IPC namespace but omits the shared-memory
# mount. Detached exec must still join that private namespace.
ipc_none_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --net none \
  --ipc none --init -- /bin/sh -c 'sleep 30')
cleanup_ids+=("$ipc_none_id")
ipc_none_inspect=$("${zerun[@]}" inspect "$ipc_none_id")
grep -q '"ipc": "none"' <<<"$ipc_none_inspect"
ipc_none_exec=$("${zerun[@]}" exec "$ipc_none_id" /bin/sh -c \
  'test "$(/bin/busybox readlink /proc/self/ns/ipc)" != "$1";
   if /bin/grep -q " /dev/shm " /proc/self/mounts; then exit 1; fi; printf ipc-none-ok' \
  sh "$host_ipc_ns")
grep -Fx ipc-none-ok <<<"$ipc_none_exec" >/dev/null
"${zerun[@]}" kill --signal TERM "$ipc_none_id" >/dev/null
"${zerun[@]}" wait "$ipc_none_id" >/dev/null
"${zerun[@]}" rm "$ipc_none_id" >/dev/null

# Shared IPC namespaces pin the target's namespace but keep each container's
# private /dev/shm mount, matching Docker's --ipc=container semantics. A
# running joiner stays in the old namespace when the target restarts; its next
# start reopens the concrete target id and joins the target's new namespace.
shared_ipc_target_name="ci-shared-ipc-$BASHPID"
shared_ipc_target=$("${zerun[@]}" run -d --name "$shared_ipc_target_name" \
  --rootfs "$rootfs" --net none --no-overlay --ipc private --init -- /bin/sleep 30)
shared_ipc_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --net none --no-overlay \
  --ipc "container:$shared_ipc_target_name" --init -- /bin/sleep 30)
cleanup_ids+=("$shared_ipc_id" "$shared_ipc_target")
shared_ipc_target_ns=$("${zerun[@]}" exec "$shared_ipc_target" \
  /bin/busybox readlink /proc/self/ns/ipc)
test "$("${zerun[@]}" exec "$shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$shared_ipc_target_ns"
shared_ipc_inspect=$("${zerun[@]}" inspect "$shared_ipc_id")
grep -F '"ipc": "container"' <<<"$shared_ipc_inspect" >/dev/null
grep -F "\"ipc_container\": \"$shared_ipc_target\"" \
  <<<"$shared_ipc_inspect" >/dev/null
grep -F "\"container:$shared_ipc_target\"" <<<"$shared_ipc_inspect" >/dev/null

shared_ipc_shm="/dev/shm/zerun-shared-ipc-$BASHPID"
"${zerun[@]}" exec "$shared_ipc_target" \
  /bin/sh -c "printf target > '$shared_ipc_shm'" >/dev/null
"${zerun[@]}" exec "$shared_ipc_id" /bin/sh -c \
  "if test -e '$shared_ipc_shm'; then exit 1; fi" >/dev/null

"${zerun[@]}" stop --time 2 "$shared_ipc_target" >/dev/null
shared_ipc_join_inspect=$("${zerun[@]}" inspect "$shared_ipc_id")
grep -F '"status": "running"' <<<"$shared_ipc_join_inspect" >/dev/null
test "$("${zerun[@]}" exec "$shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$shared_ipc_target_ns"
set +e
shared_ipc_stopped_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none \
  --no-overlay --ipc "container:$shared_ipc_target_name" -- /bin/true 2>&1)
shared_ipc_stopped_status=$?
set -e
test "$shared_ipc_stopped_status" -eq 1
grep -F 'IPC namespace target' <<<"$shared_ipc_stopped_output" >/dev/null
grep -F 'is not running' <<<"$shared_ipc_stopped_output" >/dev/null
"${zerun[@]}" start "$shared_ipc_target" >/dev/null
shared_ipc_target_ns_after_restart=$("${zerun[@]}" exec "$shared_ipc_target" \
  /bin/busybox readlink /proc/self/ns/ipc)
test "$shared_ipc_target_ns_after_restart" != "$shared_ipc_target_ns"
test "$("${zerun[@]}" exec "$shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$shared_ipc_target_ns"
"${zerun[@]}" stop --time 2 "$shared_ipc_id" >/dev/null
"${zerun[@]}" start "$shared_ipc_id" >/dev/null
test "$("${zerun[@]}" exec "$shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$shared_ipc_target_ns_after_restart"
"${zerun[@]}" stop --time 2 "$shared_ipc_id" >/dev/null
"${zerun[@]}" rm "$shared_ipc_id" >/dev/null
"${zerun[@]}" stop --time 2 "$shared_ipc_target" >/dev/null
"${zerun[@]}" rm "$shared_ipc_target" >/dev/null

# Automatic retry must discard the launch-time IPC namespace descriptor and
# reopen the persisted target id after the target itself restarts.
auto_shared_ipc_target_name="ci-auto-shared-ipc-$BASHPID"
auto_shared_ipc_target=$("${zerun[@]}" run -d --name "$auto_shared_ipc_target_name" \
  --rootfs "$rootfs" --net none --no-overlay --init -- /bin/sleep 30)
auto_shared_ipc_target_ns=$("${zerun[@]}" exec "$auto_shared_ipc_target" \
  /bin/busybox readlink /proc/self/ns/ipc)
auto_shared_ipc_id=$("${zerun[@]}" run -d --restart=on-failure:1 \
  --rootfs "$rootfs" --ipc "container:$auto_shared_ipc_target_name" \
  --init -- /bin/sh -c \
  'if [ ! -e /shared-ipc-auto-retry ]; then /bin/busybox touch /shared-ipc-auto-retry; while [ ! -e /shared-ipc-auto-release ]; do /bin/sleep 0.1; done; exit 7; fi; /bin/sleep 30')
cleanup_ids+=("$auto_shared_ipc_id" "$auto_shared_ipc_target")
test "$("${zerun[@]}" exec "$auto_shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$auto_shared_ipc_target_ns"
"${zerun[@]}" stop --time 2 "$auto_shared_ipc_target" >/dev/null
"${zerun[@]}" start "$auto_shared_ipc_target" >/dev/null
auto_shared_ipc_target_ns_after_restart=$("${zerun[@]}" exec "$auto_shared_ipc_target" \
  /bin/busybox readlink /proc/self/ns/ipc)
test "$auto_shared_ipc_target_ns_after_restart" != "$auto_shared_ipc_target_ns"
test "$("${zerun[@]}" exec "$auto_shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$auto_shared_ipc_target_ns"
"${zerun[@]}" exec "$auto_shared_ipc_id" \
  /bin/busybox touch /shared-ipc-auto-release >/dev/null
for attempt in $(seq 1 100); do
  auto_shared_ipc_inspect=$("${zerun[@]}" inspect "$auto_shared_ipc_id")
  if grep -F '"status": "running"' <<<"$auto_shared_ipc_inspect" >/dev/null &&
      grep -F '"restart_count": 1' <<<"$auto_shared_ipc_inspect" >/dev/null; then
    break
  fi
  if (( attempt == 100 )); then
    echo "shared-IPC automatic retry did not start" >&2
    printf '%s\n' "$auto_shared_ipc_inspect" >&2
    exit 1
  fi
  sleep 0.1
done
test "$("${zerun[@]}" exec "$auto_shared_ipc_id" \
  /bin/busybox readlink /proc/self/ns/ipc)" = "$auto_shared_ipc_target_ns_after_restart"
grep -F '"restart_pending": false' <<<"$auto_shared_ipc_inspect" >/dev/null
"${zerun[@]}" stop --time 2 "$auto_shared_ipc_id" >/dev/null
"${zerun[@]}" rm "$auto_shared_ipc_id" >/dev/null
"${zerun[@]}" stop --time 2 "$auto_shared_ipc_target" >/dev/null
"${zerun[@]}" rm "$auto_shared_ipc_target" >/dev/null
echo "rootful-shared-ipc-lifecycle-ok"

# A host PID namespace has no kernel-wide kill boundary when its top-level
# process exits. The runtime must act as a subreaper and reap every remaining
# descendant before returning, or a background workload would escape to the
# host init process.
host_orphan_log=$(mktemp)
cleanup_paths+=("$host_orphan_log")
"${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay --pid host -- \
  /bin/sh -c '/bin/busybox sleep 30 & printf "%s\n" "$!"' >"$host_orphan_log"
host_orphan_pid=$(cat "$host_orphan_log")
if [[ ! $host_orphan_pid =~ ^[0-9]+$ ]]; then
  echo "host-pid workload did not report its background PID" >&2
  exit 1
fi
for _ in $(seq 1 100); do
  [[ ! -e /proc/$host_orphan_pid ]] && break
  sleep 0.02
done
if [[ -e /proc/$host_orphan_pid ]]; then
  echo "--pid host left descendant $host_orphan_pid running" >&2
  if (( EUID == 0 )); then
    kill -KILL "$host_orphan_pid" >/dev/null 2>&1 || true
  else
    sudo kill -KILL "$host_orphan_pid" >/dev/null 2>&1 || true
  fi
  exit 1
fi

# A shared PID namespace must be pinned before the worker fork and re-entered
# by exec. The concrete target ID is persisted just like shared networking,
# but kernel semantics are stricter: when the target's PID 1 exits, every task
# in its namespace is killed, including a running joiner.
shared_pid_target_name="ci-shared-pid-$BASHPID"
shared_pid_target=$("${zerun[@]}" run -d --name "$shared_pid_target_name" \
  --rootfs "$rootfs" --net none --no-overlay --init -- /bin/sleep 30)
shared_pid_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --net none --no-overlay \
  --pid "container:$shared_pid_target_name" --init -- /bin/sleep 30)
cleanup_ids+=("$shared_pid_id" "$shared_pid_target")
shared_pid_target_ns=$("${zerun[@]}" exec "$shared_pid_target" \
  /bin/busybox readlink /proc/self/ns/pid)
test "$("${zerun[@]}" exec "$shared_pid_id" \
  /bin/busybox readlink /proc/self/ns/pid)" = "$shared_pid_target_ns"
shared_pid_inspect=$("${zerun[@]}" inspect "$shared_pid_id")
grep -F '"pid": "container"' <<<"$shared_pid_inspect" >/dev/null
grep -F "\"pid_container\": \"$shared_pid_target\"" \
  <<<"$shared_pid_inspect" >/dev/null
test "$(grep -Fc "container:$shared_pid_target" <<<"$shared_pid_inspect")" -ge 1

# A joiner keeps its shared namespace across its own stop/start while the
# target is alive. Once the target exits, the kernel kills the joiner, and a
# later start must reopen the target's new PID namespace.
"${zerun[@]}" stop --time 2 "$shared_pid_id" >/dev/null
"${zerun[@]}" start "$shared_pid_id" >/dev/null
test "$("${zerun[@]}" exec "$shared_pid_id" \
  /bin/busybox readlink /proc/self/ns/pid)" = "$shared_pid_target_ns"
"${zerun[@]}" stop --time 2 "$shared_pid_target" >/dev/null
for attempt in $(seq 1 100); do
  shared_pid_inspect=$("${zerun[@]}" inspect "$shared_pid_id")
  if grep -F '"status": "exited"' <<<"$shared_pid_inspect" >/dev/null; then
    break
  fi
  if (( attempt == 100 )); then
    echo "shared-PID joiner survived its target namespace" >&2
    printf '%s\n' "$shared_pid_inspect" >&2
    exit 1
  fi
  sleep 0.05
done
"${zerun[@]}" start "$shared_pid_target" >/dev/null
shared_pid_target_ns_after_restart=$("${zerun[@]}" exec "$shared_pid_target" \
  /bin/busybox readlink /proc/self/ns/pid)
"${zerun[@]}" start "$shared_pid_id" >/dev/null
test "$("${zerun[@]}" exec "$shared_pid_id" \
  /bin/busybox readlink /proc/self/ns/pid)" = "$shared_pid_target_ns_after_restart"
"${zerun[@]}" stop --time 2 "$shared_pid_id" >/dev/null
"${zerun[@]}" rm "$shared_pid_id" >/dev/null
"${zerun[@]}" stop --time 2 "$shared_pid_target" >/dev/null
"${zerun[@]}" rm "$shared_pid_target" >/dev/null

# Automatic restart must discard the launch-time PID namespace descriptor and
# reopen the persisted target ID. Restart the target while the reaper is in its
# failure backoff, then require the retry to enter the target's new namespace.
auto_shared_pid_target_name="ci-auto-shared-pid-$BASHPID"
auto_shared_pid_target=$("${zerun[@]}" run -d --name "$auto_shared_pid_target_name" \
  --rootfs "$rootfs" --net none --no-overlay --init -- /bin/sleep 30)
auto_shared_pid_target_ns=$("${zerun[@]}" exec "$auto_shared_pid_target" \
  /bin/busybox readlink /proc/self/ns/pid)
auto_shared_pid_id=$("${zerun[@]}" run -d --restart=on-failure:5 \
  --rootfs "$rootfs" --net none --no-overlay \
  --pid "container:$auto_shared_pid_target_name" --init -- /bin/sleep 30)
cleanup_ids+=("$auto_shared_pid_id" "$auto_shared_pid_target")
test "$("${zerun[@]}" exec "$auto_shared_pid_id" \
  /bin/busybox readlink /proc/self/ns/pid)" = "$auto_shared_pid_target_ns"
"${zerun[@]}" stop --time 2 "$auto_shared_pid_target" >/dev/null
"${zerun[@]}" start "$auto_shared_pid_target" >/dev/null
auto_shared_pid_target_ns_after_restart=$("${zerun[@]}" exec "$auto_shared_pid_target" \
  /bin/busybox readlink /proc/self/ns/pid)
for attempt in $(seq 1 100); do
  auto_shared_pid_inspect=$("${zerun[@]}" inspect "$auto_shared_pid_id")
  auto_shared_pid_restart_count=$(sed -n \
    's/^[[:space:]]*"restart_count": \([0-9][0-9]*\),$/\1/p' \
    <<<"$auto_shared_pid_inspect")
  if grep -F '"status": "running"' <<<"$auto_shared_pid_inspect" >/dev/null &&
      [[ ${auto_shared_pid_restart_count:-0} -gt 0 ]]; then
    break
  fi
  if (( attempt == 100 )); then
    echo "shared-PID automatic retry did not start" >&2
    printf '%s\n' "$auto_shared_pid_inspect" >&2
    exit 1
  fi
  sleep 0.1
done
test "$("${zerun[@]}" exec "$auto_shared_pid_id" \
  /bin/busybox readlink /proc/self/ns/pid)" = "$auto_shared_pid_target_ns_after_restart"
"${zerun[@]}" stop --time 2 "$auto_shared_pid_id" >/dev/null
"${zerun[@]}" rm "$auto_shared_pid_id" >/dev/null
"${zerun[@]}" stop --time 2 "$auto_shared_pid_target" >/dev/null
"${zerun[@]}" rm "$auto_shared_pid_target" >/dev/null
echo "rootful-shared-pid-lifecycle-ok"

# A supervisor such as systemd stops a foreground run with SIGTERM. The parent
# must translate that request into the resolved image/operator stop signal.
foreground_stop_log=$(mktemp)
cleanup_paths+=("$foreground_stop_log")
"${zerun[@]}" run --rootfs "$rootfs" --no-overlay --net none --init \
  --stop-signal USR1 -- /bin/sh -c \
  'trap "exit 42" USR1; printf "foreground-stop-ready\n"; while :; do sleep 1; done' \
  >"$foreground_stop_log" 2>&1 &
foreground_stop_pid=$!
cleanup_pids+=("$foreground_stop_pid")
for attempt in $(seq 1 50); do
  if grep -Fxq foreground-stop-ready "$foreground_stop_log"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "foreground stop workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
foreground_stop_runtime_pid=$(find_zerun_process "$foreground_stop_pid") || {
  echo "foreground stop could not locate the zerun runtime process" >&2
  exit 1
}
signal_rootful_process "$foreground_stop_runtime_pid" TERM
set +e
wait "$foreground_stop_pid"
foreground_stop_code=$?
set -e
cleanup_pids=()
test "$foreground_stop_code" -eq 42

# A rootful container must not inherit the caller's supplementary groups, even
# when no --user was requested and all capabilities are dropped. Clearing the
# groups must therefore happen before the capability drop.
if command -v setpriv >/dev/null 2>&1; then
  if (( EUID == 0 )); then
    grouped_zerun=(setpriv --groups 4242 -- "${zerun[@]}")
  else
    grouped_zerun=(sudo setpriv --groups 4242 -- env
      ZERUN_DATA_ROOT="$data_root"
      ZERUN_RUNTIME_ROOT="$runtime_root"
      "$binary")
  fi
  inherited_groups=$("${grouped_zerun[@]}" run --rootfs "$rootfs" --net none     --no-overlay --cap-drop ALL -- /bin/sh -c '/bin/busybox id -G')
  grep -Fx 0 <<<"$inherited_groups" >/dev/null
  explicit_groups=$("${grouped_zerun[@]}" run --rootfs "$rootfs" --net none     --no-overlay --group-add testgroup -- /bin/busybox id -G)
  grep -qw 4343 <<<"$explicit_groups"
  if grep -qw 4242 <<<"$explicit_groups"; then
    echo "explicit --group-add did not replace the inherited host groups: $explicit_groups" >&2
    exit 1
  fi
else
  echo "setpriv unavailable; skipping supplementary-group isolation check" >&2
fi

# Explicit supplementary groups are resolved in the container and replace the
# inherited host list.
group_add_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --user testuser --group-add testgroup --group-add 4344 -- /bin/busybox id -G)
grep -qw 4343 <<<"$group_add_output"
grep -qw 4344 <<<"$group_add_output"

# The default writable path must use overlayfs (or the documented rootless
# fallback) and allow writes without modifying the source rootfs.
overlay_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --init -- \
  /bin/sh -c 'printf "overlay-ok\\n" >/overlay-marker; cat /overlay-marker')
grep -Fx overlay-ok <<<"$overlay_output" >/dev/null
test ! -e "$rootfs/overlay-marker"

# A read-only root must reject writes while an explicitly requested tmpfs stays
# writable. This exercises the ordering of /etc/hosts setup, extra tmpfs
# mounts, and the final root remount.
readonly_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --read-only --tmpfs /run:size=16m --init -- /bin/sh -c \
  'if printf "unexpected\n" >/readonly-marker; then exit 41; fi; printf "tmpfs-ok\n" >/run/zerun-marker; cat /run/zerun-marker')
grep -Fx tmpfs-ok <<<"$readonly_output" >/dev/null
test ! -e "$rootfs/readonly-marker"

# Managed named volumes must persist independently of the container rootfs.
# The first run writes through the volume and the second run reads it back.
volume_write=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  -v ci-volume:/mnt/data:rw --init -- /bin/sh -c \
  'printf "volume-ok\n" >/mnt/data/marker; cat /mnt/data/marker')
grep -Fx volume-ok <<<"$volume_write" >/dev/null
volume_read=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  -v ci-volume:/mnt/data:ro --init -- /bin/sh -c 'cat /mnt/data/marker')
grep -Fx volume-ok <<<"$volume_read" >/dev/null

# Docker-style --mount requests use the same named-volume and tmpfs paths.
mounted_volume_write=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --mount type=volume,source=ci-mounted-volume,target=/mnt/mounted,readonly=false \
  --init -- /bin/sh -c \
  'printf "mounted-volume-ok\n" >/mnt/mounted/marker; cat /mnt/mounted/marker')
grep -Fx mounted-volume-ok <<<"$mounted_volume_write" >/dev/null
mounted_volume_read=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --mount type=volume,src=ci-mounted-volume,dst=/mnt/mounted,readonly \
  --init -- /bin/sh -c 'cat /mnt/mounted/marker')
grep -Fx mounted-volume-ok <<<"$mounted_volume_read" >/dev/null
mounted_tmpfs_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --mount type=tmpfs,target=/mnt/scratch,tmpfs-size=1m,tmpfs-mode=0700 \
  --init -- /bin/sh -c 'printf "mounted-tmpfs-ok\n" >/mnt/scratch/marker; cat /mnt/scratch/marker')
grep -Fx mounted-tmpfs-ok <<<"$mounted_tmpfs_output" >/dev/null

# Explicit devices are recreated from the host major/minor pair. A read-only
# permission subset must clear write bits instead of silently granting rwm.
device_args=(--device /dev/null:/dev/zerun-null:rw --device /dev/zero:/dev/zerun-read:r)
device_check='test -c /dev/zerun-null && test -c /dev/zerun-read &&
  test "$(/bin/busybox stat -c %a /dev/zerun-read)" = 444 &&
  printf "device-ok" >/dev/zerun-null && printf "device-ok\n"'
# /dev/kmsg is not in the built-in allowlist, so it also verifies that the
# parent-side cgroup device policy denies a write omitted from the request.
if [[ -c /dev/kmsg ]]; then
  device_args+=(--device /dev/kmsg:/dev/zerun-kmsg:r)
  device_check+=' &&
  test -c /dev/zerun-kmsg &&
  if printf x >/dev/zerun-kmsg 2>/dev/null; then exit 1; fi'
fi
device_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  "${device_args[@]}" --init -- /bin/sh -c "$device_check")
grep -Fx device-ok <<<"$device_output" >/dev/null

# The baseline policy applies even when no --device flag is present. Creating a
# non-allowlisted device node must be denied by the parent-side cgroup policy.
default_device_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --init -- /bin/sh -c \
  'if /bin/busybox mknod /dev/zerun-forbidden c 1 11 2>/dev/null; then exit 1; fi;
   printf "default-device-policy-ok\n"')
grep -Fx default-device-policy-ok <<<"$default_device_output" >/dev/null

# Common runtimes use advisory I/O hints and readahead; they are safe and part
# of Docker's default seccomp allowlist. Newer local fixtures provide this
# optional static probe, while hosted CI always builds it.
if [[ -x "$rootfs/bin/seccomp-io-probe" ]]; then
  seccomp_io_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
    --init -- /bin/seccomp-io-probe)
  grep -Fx seccomp-io-ok <<<"$seccomp_io_output" >/dev/null
else
  echo "skipping optional seccomp I/O compatibility check: $rootfs/bin/seccomp-io-probe is missing" >&2
fi

# Resource limits require an actual cgroup v2 hierarchy and exercise the
# parent-side cgroup creation/attach path.
cgroup_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --pids 32 --init -- /bin/sh -c 'printf "cgroup-ok\\n"')
grep -Fx cgroup-ok <<<"$cgroup_output" >/dev/null

# POSIX rlimits apply before hardening and are restored for detached exec.
ulimit_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --ulimit nofile=64:96 --init -- /bin/sh -c \
  'printf "soft=%s hard=%s\\n" "$(ulimit -Sn)" "$(ulimit -Hn)"')
grep -Fx 'soft=64 hard=96' <<<"$ulimit_output" >/dev/null

# Detached exec must join the same cgroup as the container. This also guards
# the persisted cgroup-path validation used by the exec joiner.
exec_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --pids 32 --cpu-shares 2048 --ulimit nofile=64:96 --group-add testgroup --init -- \
  /bin/sh -c 'sleep 30')
cleanup_ids+=("$exec_id")
exec_cgroup=$("${zerun[@]}" inspect "$exec_id" |
  sed -n 's/^  "cgroup": "\([^"]*\)".*/\1/p')
test -n "$exec_cgroup"
test "$(cat "$exec_cgroup/cpu.weight")" = 79
"${zerun[@]}" update --cpu-shares 4096 "$exec_id"
test "$(cat "$exec_cgroup/cpu.weight")" = 157
exec_output=$("${zerun[@]}" exec "$exec_id" /bin/sh -c 'printf "exec-ok\\n"')
grep -Fx exec-ok <<<"$exec_output" >/dev/null
exec_limits=$("${zerun[@]}" exec "$exec_id" /bin/sh -c \
  'printf "soft=%s hard=%s\n" "$(ulimit -Sn)" "$(ulimit -Hn)"')
grep -Fx 'soft=64 hard=96' <<<"$exec_limits" >/dev/null
exec_groups=$("${zerun[@]}" exec "$exec_id" /bin/busybox id -G)
grep -qw 4343 <<<"$exec_groups"
exec_uid=$("${zerun[@]}" exec --user testuser "$exec_id" /bin/busybox id -u)
exec_gid=$("${zerun[@]}" exec --user testuser "$exec_id" /bin/busybox id -g)
test "$exec_uid:$exec_gid" = 4242:4344
exec_uid=$("${zerun[@]}" exec -u testuser:testgroup "$exec_id" /bin/busybox id -u)
exec_gid=$("${zerun[@]}" exec -u testuser:testgroup "$exec_id" /bin/busybox id -g)
test "$exec_uid:$exec_gid" = 4242:4343
exec_stdin=$(printf 'exec-stdin-ok\n' | "${zerun[@]}" exec -i "$exec_id" /bin/sh -c \
  'IFS= read -r line; printf "read-%s\n" "$line"')
grep -Fxq read-exec-stdin-ok <<<"$exec_stdin"
exec_tty=$("${zerun[@]}" exec -t "$exec_id" /bin/sh -c \
  'test -t 0 && test -t 1 && test -t 2 && printf "exec-tty-ok\n"')
grep -Fq exec-tty-ok <<<"$exec_tty"
command -v script >/dev/null || {
  echo "interactive exec check requires util-linux script" >&2
  exit 1
}
printf -v exec_it_command '%q ' "${zerun[@]}" exec -it "$exec_id" /bin/sh -c \
  'test -t 0 && test -t 1 && test -t 2; printf "exec-it-ready\n"; IFS= read -r line; printf "read-%s\n" "$line"'
exec_it=$({ printf 'exec-it-stdin\n'; sleep 1; } | script -qefc "$exec_it_command" /dev/null)
grep -Fq exec-it-ready <<<"$exec_it"
grep -Fq read-exec-it-stdin <<<"$exec_it"
"${zerun[@]}" kill --signal TERM "$exec_id" >/dev/null
"${zerun[@]}" wait "$exec_id" >/dev/null
"${zerun[@]}" rm "$exec_id" >/dev/null

# Detached exec must not try to re-enter namespaces the container shares with
# the host. Re-entering them can fail for rootless callers or select the wrong
# namespace, so verify the persisted modes drive the exec join mask.
host_ns_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --pid host --ipc host --uts host --init -- /bin/sh -c 'sleep 30')
cleanup_ids+=("$host_ns_id")
host_ns_exec=$("${zerun[@]}" exec "$host_ns_id" /bin/sh -c \
  'printf "%s\n%s\n%s\n" "$(/bin/busybox readlink /proc/self/ns/pid)" "$(/bin/busybox readlink /proc/self/ns/ipc)" "$(/bin/busybox readlink /proc/self/ns/uts)"')
mapfile -t host_ns_exec_namespaces <<<"$host_ns_exec"
test "${host_ns_exec_namespaces[0]}" = "$host_pid_ns"
test "${host_ns_exec_namespaces[1]}" = "$host_ipc_ns"
test "${host_ns_exec_namespaces[2]}" = "$host_uts_ns"

# An exec worker is not a descendant of the container's top-level process. If
# it daemonizes in host PID mode, only cgroup-wide teardown can prevent it from
# surviving the container.
host_ns_exec_orphan=$("${zerun[@]}" exec "$host_ns_id" /bin/sh -c \
  '/bin/busybox start-stop-daemon -S -b -m -p /tmp/zerun-exec-orphan.pid -x /bin/sleep -- 30; cat /tmp/zerun-exec-orphan.pid')
if [[ ! $host_ns_exec_orphan =~ ^[0-9]+$ ]]; then
  echo "host-pid exec did not report its background PID" >&2
  exit 1
fi
"${zerun[@]}" kill --signal TERM "$host_ns_id" >/dev/null
"${zerun[@]}" wait "$host_ns_id" >/dev/null
"${zerun[@]}" rm "$host_ns_id" >/dev/null
for _ in $(seq 1 100); do
  [[ ! -e /proc/$host_ns_exec_orphan ]] && break
  sleep 0.02
done
if [[ -e /proc/$host_ns_exec_orphan ]]; then
  echo "--pid host left exec descendant $host_ns_exec_orphan running" >&2
  if (( EUID == 0 )); then
    kill -KILL "$host_ns_exec_orphan" >/dev/null 2>&1 || true
  else
    sudo kill -KILL "$host_ns_exec_orphan" >/dev/null 2>&1 || true
  fi
  exit 1
fi

# Restart must stop and resume the same detached record rather than creating a
# replacement container. Verify that the workload ran once before and once
# after the restart while retaining the same id, log history, PTY semantics,
# resource limits, and private /dev/shm size.
restart_id=$("${zerun[@]}" run -dt --rootfs "$rootfs" --no-overlay --net none \
  --ulimit nofile=64:96 --shm-size 96m --init -- /bin/sh -c \
  'if [ -t 0 ] && [ -t 1 ] && [ -t 2 ]; then tty=yes; else tty=no; fi; geometry=$(/bin/busybox stty -a 2>/dev/null | /bin/busybox grep -o "rows [0-9]*; columns [0-9]*"); shm_kib=$(/bin/busybox df -k /dev/shm | /bin/busybox tail -n 1 | /bin/busybox awk "{print \$2}"); printf "restart-ok nofile=%s:%s tty=%s geometry=%s shm=%s\\n" "$(ulimit -Sn)" "$(ulimit -Hn)" "$tty" "$geometry" "$shm_kib"; sleep 30')
cleanup_ids+=("$restart_id")
for attempt in $(seq 1 50); do
  restart_logs=$("${zerun[@]}" logs "$restart_id" 2>/dev/null || true)
  if (( $(grep -c 'restart-ok nofile=64:96 tty=yes geometry=rows 24; columns 80 shm=98304' <<<"$restart_logs" || true) >= 1 )); then
    break
  fi
  if (( attempt == 50 )); then
    echo "restart workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
"${zerun[@]}" restart --time 1 "$restart_id" >/dev/null
for attempt in $(seq 1 50); do
  restart_logs=$("${zerun[@]}" logs "$restart_id" 2>/dev/null || true)
  if (( $(grep -c 'restart-ok nofile=64:96 tty=yes geometry=rows 24; columns 80 shm=98304' <<<"$restart_logs" || true) >= 2 )); then
    break
  fi
  if (( attempt == 50 )); then
    echo "restart workload did not run twice" >&2
    exit 1
  fi
  sleep 0.1
done
"${zerun[@]}" kill --signal TERM "$restart_id" >/dev/null
"${zerun[@]}" wait "$restart_id" >/dev/null
"${zerun[@]}" rm "$restart_id" >/dev/null

# A manual start must keep a final unterminated record separate from the next
# attempt, including in time-filtered and tail views of the retained log.
partial_log_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --net none \
  -- /bin/sh -c 'printf partial-log')
cleanup_ids+=("$partial_log_id")
"${zerun[@]}" wait "$partial_log_id" >/dev/null
test "$("${zerun[@]}" logs "$partial_log_id")" = partial-log
"${zerun[@]}" start "$partial_log_id" >/dev/null
"${zerun[@]}" wait "$partial_log_id" >/dev/null
partial_logs=$("${zerun[@]}" logs --since 1970-01-01T00:00:00Z "$partial_log_id")
if [[ $partial_logs != $'partial-log\npartial-log' ]]; then
  echo "wait returned before separate partial log records were available" >&2
  exit 1
fi
test "$("${zerun[@]}" logs --tail 1 "$partial_log_id")" = partial-log
"${zerun[@]}" rm "$partial_log_id" >/dev/null

# Automatic restart policies are evaluated by the same reaper. Bind a published
# port so a retry also proves the previous proxy released its listener before
# the next attempt starts.
policy_port=$(find_free_tcp_port)
policy_id=$("${zerun[@]}" run -d --restart=on-failure:1 --rootfs "$rootfs"   --no-overlay --net bridge -p "$policy_port:8080" --init --   /bin/sh -c 'printf "restart-policy\n"; exit 7')
cleanup_ids+=("$policy_id")
policy_code=$("${zerun[@]}" wait "$policy_id")
test "$policy_code" -eq 7
policy_logs=$("${zerun[@]}" logs "$policy_id")
test "$(grep -c '^restart-policy$' <<<"$policy_logs" || true)" -eq 2
policy_inspect=$("${zerun[@]}" inspect "$policy_id")
grep -q '"restart_policy": "on-failure:1"' <<<"$policy_inspect"
grep -q '"restart_count": 1' <<<"$policy_inspect"
grep -q '"restart_pending": false' <<<"$policy_inspect"
"${zerun[@]}" rm "$policy_id" >/dev/null

# A manual stop suppresses a pending automatic restart. A later manual start
# clears that marker and re-enables the persisted policy.
always_id=$("${zerun[@]}" run -d --restart=always --rootfs "$rootfs"   --no-overlay --net none --init -- /bin/sh -c   'printf "always-attempt\n"; while :; do sleep 1; done')
cleanup_ids+=("$always_id")
for attempt in $(seq 1 50); do
  always_logs=$("${zerun[@]}" logs "$always_id" 2>/dev/null || true)
  if grep -Fxq always-attempt <<<"$always_logs"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "restart-policy workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
"${zerun[@]}" stop --time 1 "$always_id" >/dev/null
"${zerun[@]}" wait "$always_id" >/dev/null
always_before=$(grep -c '^always-attempt$' <<<"$("${zerun[@]}" logs "$always_id")" || true)
sleep 0.5
always_after=$(grep -c '^always-attempt$' <<<"$("${zerun[@]}" logs "$always_id")" || true)
test "$always_after" -eq "$always_before"
"${zerun[@]}" rm "$always_id" >/dev/null

# `update --restart` changes the policy used by the live reaper on the next
# exit. It remains authoritative for a later manual start even though the
# canonical launch arguments still describe the policy used at creation.
updated_policy_id=$(
  "${zerun[@]}" run -d --restart=no --rootfs "$rootfs" \
    --no-overlay --net none --init -- /bin/sh -c \
    'printf "updated-policy\n"; sleep 2; exit 7'
)
cleanup_ids+=("$updated_policy_id")
for attempt in $(seq 1 50); do
  updated_policy_logs=$("${zerun[@]}" logs "$updated_policy_id" 2>/dev/null || true)
  if grep -Fxq updated-policy <<<"$updated_policy_logs"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "update-restart workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
"${zerun[@]}" update --restart=on-failure:1 "$updated_policy_id" >/dev/null
updated_policy_code=$("${zerun[@]}" wait "$updated_policy_id")
test "$updated_policy_code" -eq 7
updated_policy_logs=$("${zerun[@]}" logs "$updated_policy_id")
test "$(grep -c '^updated-policy$' <<<"$updated_policy_logs" || true)" -eq 2
grep -q '"restart_policy": "on-failure:1"' \
  <<<"$("${zerun[@]}" inspect "$updated_policy_id")"
"${zerun[@]}" update --restart no "$updated_policy_id" >/dev/null
grep -q '"restart_policy": "no"' \
  <<<"$("${zerun[@]}" inspect "$updated_policy_id")"
"${zerun[@]}" start "$updated_policy_id" >/dev/null
updated_policy_code=$("${zerun[@]}" wait "$updated_policy_id")
test "$updated_policy_code" -eq 7
updated_policy_logs=$("${zerun[@]}" logs "$updated_policy_id")
test "$(grep -c '^updated-policy$' <<<"$updated_policy_logs" || true)" -eq 3
grep -q '"restart_policy": "no"' \
  <<<"$("${zerun[@]}" inspect "$updated_policy_id")"
"${zerun[@]}" rm "$updated_policy_id" >/dev/null

# A configured stop signal must reach the workload through mini-init. The
# shell child traps SIGUSR1 and exits with a distinctive code, proving Zerun
# did not silently substitute SIGTERM or leave the signal queued on PID 1.
custom_stop_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --init --stop-signal USR1 --stop-timeout 3 -- /bin/sh -c \
  'trap "exit 42" USR1; printf "custom-stop-ready\\n"; while :; do sleep 1; done')
cleanup_ids+=("$custom_stop_id")
for attempt in $(seq 1 50); do
  custom_stop_logs=$("${zerun[@]}" logs "$custom_stop_id" 2>/dev/null || true)
  if grep -Fxq custom-stop-ready <<<"$custom_stop_logs"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "custom-stop-signal workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
"${zerun[@]}" stop "$custom_stop_id" >/dev/null
custom_stop_code=$("${zerun[@]}" wait "$custom_stop_id")
test "$custom_stop_code" -eq 42
"${zerun[@]}" rm "$custom_stop_id" >/dev/null

# The persisted timeout is the fallback when a workload ignores the configured
# signal: Zerun must escalate to SIGKILL after roughly one second.
stop_timeout_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --init --stop-signal USR1 --stop-timeout 1 -- /bin/sh -c \
  'trap "" USR1; printf "stop-timeout-ready\\n"; while :; do sleep 1; done')
cleanup_ids+=("$stop_timeout_id")
for attempt in $(seq 1 50); do
  stop_timeout_logs=$("${zerun[@]}" logs "$stop_timeout_id" 2>/dev/null || true)
  if grep -Fxq stop-timeout-ready <<<"$stop_timeout_logs"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "stop-timeout workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done
stop_started=$(date +%s%N)
"${zerun[@]}" stop "$stop_timeout_id" >/dev/null
stop_elapsed_ms=$(( ($(date +%s%N) - stop_started) / 1000000 ))
stop_timeout_code=$("${zerun[@]}" wait "$stop_timeout_id")
test "$stop_timeout_code" -eq 137
test "$stop_elapsed_ms" -ge 500
"${zerun[@]}" rm "$stop_timeout_id" >/dev/null

# Detached healthchecks run through the same namespace/security path as
# `exec`, persist bounded probe history, and expose Docker-style status/filter
# transitions without a resident daemon.
health_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-health --health-cmd 'test ! -e /unhealthy' \
  --health-interval 100ms --health-timeout 1s --health-retries 2 -- \
  /bin/sh -c 'while :; do sleep 1; done')
cleanup_ids+=("$health_id")
cleanup_paths+=("$rootfs/unhealthy")
health_ready=false
for attempt in $(seq 1 100); do
  if "${zerun[@]}" ps --filter health=healthy -q | grep -Fxq "$health_id"; then
    health_ready=true
    break
  fi
  if (( attempt == 100 )); then
    echo "healthy probe did not become healthy" >&2
    "${zerun[@]}" inspect "$health_id" >&2 || true
    exit 1
  fi
  sleep 0.1
done
test "$health_ready" = true
"${zerun[@]}" exec "$health_id" /bin/busybox touch /unhealthy
health_unhealthy=false
for attempt in $(seq 1 100); do
  if "${zerun[@]}" ps --filter health=unhealthy -q | grep -Fxq "$health_id"; then
    health_unhealthy=true
    break
  fi
  if (( attempt == 100 )); then
    echo "failing probe did not become unhealthy" >&2
    "${zerun[@]}" inspect "$health_id" >&2 || true
    exit 1
  fi
  sleep 0.1
done
test "$health_unhealthy" = true
health_inspect=$("${zerun[@]}" inspect "$health_id")
grep -F '"status": "unhealthy"' <<<"$health_inspect" >/dev/null
grep -F '"failing_streak": 2' <<<"$health_inspect" >/dev/null
"${zerun[@]}" exec "$health_id" /bin/busybox rm /unhealthy
health_recovered=false
for attempt in $(seq 1 100); do
  if "${zerun[@]}" ps --filter health=healthy -q | grep -Fxq "$health_id"; then
    health_recovered=true
    break
  fi
  if (( attempt == 100 )); then
    echo "health probe did not recover" >&2
    "${zerun[@]}" inspect "$health_id" >&2 || true
    exit 1
  fi
  sleep 0.1
done
test "$health_recovered" = true
"${zerun[@]}" stop --time 1 "$health_id" >/dev/null
"${zerun[@]}" wait "$health_id" >/dev/null
"${zerun[@]}" rm "$health_id" >/dev/null

# A probe that exceeds its deadline is killed as a process group and reported
# with Docker's conventional timeout exit code rather than stalling monitoring.
health_timeout_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-health-timeout --health-cmd 'sleep 5' \
  --health-interval 100ms --health-timeout 100ms --health-retries 1 -- \
  /bin/sh -c 'while :; do sleep 1; done')
cleanup_ids+=("$health_timeout_id")
health_timed_out=false
for attempt in $(seq 1 100); do
  if "${zerun[@]}" ps --filter health=unhealthy -q | grep -Fxq "$health_timeout_id"; then
    health_timed_out=true
    break
  fi
  if (( attempt == 100 )); then
    echo "timed-out health probe did not become unhealthy" >&2
    "${zerun[@]}" inspect "$health_timeout_id" >&2 || true
    exit 1
  fi
  sleep 0.1
done
test "$health_timed_out" = true
health_timeout_inspect=$("${zerun[@]}" inspect "$health_timeout_id")
grep -F '"exit_code": 124' <<<"$health_timeout_inspect" >/dev/null
"${zerun[@]}" stop --time 1 "$health_timeout_id" >/dev/null
"${zerun[@]}" wait "$health_timeout_id" >/dev/null
"${zerun[@]}" rm "$health_timeout_id" >/dev/null

# M7 lifecycle and storage commands operate on a live writable container.
# Keep this workload alive while inspect/stats/top/cp/diff/export/commit run,
# then import the exported tar and execute it as a local image.
label_file="/tmp/zerun-labels-${BASHPID}"
cleanup_paths+=("$label_file")
printf 'ci.label-file=loaded\nci.override=file\n' >"$label_file"
m7_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --net none --pids 32 \
  --name ci-m7 --label ci.m7=ok --label-file "$label_file" \
  --label ci.override=cli --expose 8080/tcp --stop-signal SIGKILL --init -- /bin/sh -c \
  'printf "m7-running\\n"; printf "overlay-data\\n" >/run/m7-file;
   rm -rf /etc/opaque-test; mkdir /etc/opaque-test;
   printf "new-opaque-entry\\n" >/etc/opaque-test/new; sleep 30')
cleanup_ids+=("$m7_id")
for attempt in $(seq 1 50); do
  m7_logs=$("${zerun[@]}" logs "$m7_id" 2>/dev/null || true)
  if grep -Fxq m7-running <<<"$m7_logs"; then
    break
  fi
  if (( attempt == 50 )); then
    echo "M7 workload did not start" >&2
    exit 1
  fi
  sleep 0.1
done

inspect_output=$("${zerun[@]}" inspect "$m7_id")
grep -q '"status": "running"' <<<"$inspect_output"
grep -q '"ci.m7": "ok"' <<<"$inspect_output"
grep -q '"ci.label-file": "loaded"' <<<"$inspect_output"
grep -q '"ci.override": "cli"' <<<"$inspect_output"
grep -q '"8080/tcp"' <<<"$inspect_output"
grep -q '"stop_signal": 9' <<<"$inspect_output"
stats_output=$("${zerun[@]}" stats "$m7_id")
grep -q 'ci-m7' <<<"$stats_output"
top_output=$("${zerun[@]}" top "$m7_id")
grep -q 'CMD' <<<"$top_output"
"${zerun[@]}" pause "$m7_id" >/dev/null
paused_inspect=$("${zerun[@]}" inspect "$m7_id")
grep -q '"paused": true' <<<"$paused_inspect"
"${zerun[@]}" unpause "$m7_id" >/dev/null
unpaused_inspect=$("${zerun[@]}" inspect "$m7_id")
grep -q '"paused": false' <<<"$unpaused_inspect"
"${zerun[@]}" update --pids 16 "$m7_id" >/dev/null
# io.max is stateful. Updating one direction must not reset a previously
# configured direction for the same device, and the cgroupfs write must be one
# device record at a time (a multi-line write is rejected with EINVAL).
io_device=$(lsblk -ndo MAJ:MIN | head -n 1 | tr -d '[:space:]')
if [[ $io_device =~ ^[0-9]+:[0-9]+$ ]]; then
  cgroup_path=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["cgroup"])'     <<<"$inspect_output")
  "${zerun[@]}" update --device-read-bps "$io_device:1m" "$m7_id" >/dev/null
  "${zerun[@]}" update --device-write-bps "$io_device:2m" "$m7_id" >/dev/null
  if (( EUID == 0 )); then
    io_max=$(cat "$cgroup_path/io.max")
  else
    io_max=$(sudo cat "$cgroup_path/io.max")
  fi
  grep -Eq "^${io_device} rbps=1048576 wbps=2097152 riops=max wiops=max$" <<<"$io_max"
else
  echo "skipping cgroup I/O update check: no block device was discovered" >&2
fi
"${zerun[@]}" rename "$m7_id" ci-m7-renamed
renamed_inspect=$("${zerun[@]}" inspect ci-m7-renamed)
grep -q '"name": "ci-m7-renamed"' <<<"$renamed_inspect"
df_output=$("${zerun[@]}" system df)
grep -q '^Containers' <<<"$df_output"
# A bounded event replay must emit the current record and terminate at the
# requested wall-clock boundary instead of remaining an unbounded poll.
events_until=$(date -u -d '1 second' '+%Y-%m-%dT%H:%M:%SZ')
events_output=$("${zerun[@]}" events --filter "container=$m7_id" --until "$events_until")
grep -q 'container create' <<<"$events_output"
grep -q 'container start' <<<"$events_output"

cp_source="/tmp/zerun-cp-source-${BASHPID}"
cp_copy="/tmp/zerun-cp-copy-${BASHPID}"
export_tar="/tmp/zerun-export-${BASHPID}.tar"
cleanup_paths+=("$cp_source" "$cp_copy" "$export_tar")
printf 'host-to-container\n' >"$cp_source"
"${zerun[@]}" cp "$cp_source" "$m7_id:/run/host-file"
cp_in_container=$("${zerun[@]}" exec "$m7_id" /bin/sh -c 'cat /run/host-file')
grep -Fxq host-to-container <<<"$cp_in_container"
"${zerun[@]}" cp "$m7_id:/run/host-file" "$cp_copy"
grep -Fxq host-to-container "$cp_copy"

diff_output=$("${zerun[@]}" diff "$m7_id")
grep -q '/run/host-file' <<<"$diff_output"
grep -Fxq 'D /etc/opaque-test/old' <<<"$diff_output"
grep -Fxq 'A /etc/opaque-test/new' <<<"$diff_output"
"${zerun[@]}" export -o "$export_tar" "$m7_id"
if (( EUID == 0 )); then
  test -s "$export_tar"
else
  sudo test -s "$export_tar"
fi
# Commit while the container is live, then again after exit. Both paths rebuild
# from the host-side overlay upper so they remain portable to nested hosts and
# do not archive mounted volumes or pseudo-filesystems.
live_commit_digest=$("${zerun[@]}" commit -m ci-m7-live "$m7_id" ci-commit-live:test)
grep -Eq '^sha256:[0-9a-f]{64}$' <<<"$live_commit_digest"
live_commit_output=$("${zerun[@]}" run --net none ci-commit-live:test /bin/sh -c 'cat /run/m7-file')
grep -Fxq overlay-data <<<"$live_commit_output"
live_commit_meta_id=$("${zerun[@]}" run -d --net none --init ci-commit-live:test -- \
  /bin/sh -c 'sleep 30')
cleanup_ids+=("$live_commit_meta_id")
live_commit_meta=$("${zerun[@]}" inspect "$live_commit_meta_id")
grep -q '"8080/tcp"' <<<"$live_commit_meta"
grep -q '"stop_signal": 9' <<<"$live_commit_meta"
"${zerun[@]}" stop --time 1 "$live_commit_meta_id" >/dev/null
"${zerun[@]}" wait "$live_commit_meta_id" >/dev/null
"${zerun[@]}" rm "$live_commit_meta_id" >/dev/null
"${zerun[@]}" kill --signal TERM "$m7_id" >/dev/null
"${zerun[@]}" wait "$m7_id" >/dev/null
commit_digest=$("${zerun[@]}" commit -m ci-m7 "$m7_id" ci-commit:test)
grep -Eq '^sha256:[0-9a-f]{64}$' <<<"$commit_digest"
"${zerun[@]}" rm "$m7_id" >/dev/null
m7_id=''

import_digest=$("${zerun[@]}" import -m ci-m7 "$export_tar" ci-import:test)
grep -Eq '^sha256:[0-9a-f]{64}$' <<<"$import_digest"
import_output=$("${zerun[@]}" run --net none ci-import:test /bin/sh -c 'cat /run/m7-file')
grep -Fxq overlay-data <<<"$import_output"
echo "rootful-m7-ok"

# Attach must stream the reaper's live output and return the workload exit code.
attach_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --pids 16 --init -- /bin/sh -c 'sleep 1; printf "attach-ok\n"; sleep 2')
cleanup_ids+=("$attach_id")
attach_output=$("${zerun[@]}" attach "$attach_id")
grep -Fxq attach-ok <<<"$attach_output"
"${zerun[@]}" rm "$attach_id" >/dev/null

# The attach control frame must preserve non-zero exit codes even when --rm
# removes the state record before the attaching CLI performs its fallback read.
attach_rm_id=$("${zerun[@]}" run -d --rm --rootfs "$rootfs" --no-overlay --net none \
  --pids 16 --init -- /bin/sh -c 'sleep 1; printf "attach-rm-ok\n"; exit 23')
cleanup_ids+=("$attach_rm_id")
set +e
attach_rm_output=$("${zerun[@]}" attach "$attach_rm_id")
attach_rm_status=$?
set -e
test "$attach_rm_status" -eq 23
grep -Fxq attach-rm-ok <<<"$attach_rm_output"

# Prune should remove retained exited records without touching live containers.
prune_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-prune --init -- /bin/sh -c 'exit 0')
cleanup_ids+=("$prune_id")
"${zerun[@]}" wait "$prune_id" >/dev/null
prune_output=$("${zerun[@]}" prune -f)
grep -q 'ci-prune' <<<"$prune_output"
if "${zerun[@]}" inspect "$prune_id" >/dev/null 2>&1; then
  echo "prune left an exited container behind" >&2
  exit 1
fi

echo "rootful-lifecycle-controls-ok"

# Concurrent detached launches cannot both claim the same user-facing name.
name_race_a="/tmp/zerun-name-race-a-${BASHPID}"
name_race_b="/tmp/zerun-name-race-b-${BASHPID}"
name_race_err_a="/tmp/zerun-name-race-a-${BASHPID}.err"
name_race_err_b="/tmp/zerun-name-race-b-${BASHPID}.err"
cleanup_paths+=("$name_race_a" "$name_race_b" "$name_race_err_a" "$name_race_err_b")
set +e
"${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-name-race --init -- /bin/sh -c 'sleep 30' >"$name_race_a" 2>"$name_race_err_a" &
name_race_pid_a=$!
"${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-name-race --init -- /bin/sh -c 'sleep 30' >"$name_race_b" 2>"$name_race_err_b" &
name_race_pid_b=$!
wait "$name_race_pid_a"
name_race_status_a=$?
wait "$name_race_pid_b"
name_race_status_b=$?
set -e
if (( (name_race_status_a == 0) == (name_race_status_b == 0) )); then
  echo "concurrent named runs did not elect exactly one winner" >&2
  cat "$name_race_err_a" "$name_race_err_b" >&2
  exit 1
fi
if (( name_race_status_a == 0 )); then
  name_race_winner=$name_race_a
else
  name_race_winner=$name_race_b
fi
name_race_id=$(<"$name_race_winner")
[[ "$name_race_id" =~ ^[0-9a-f]{12}$ ]]
cleanup_ids+=("$name_race_id")

# Rename and a new run must share the same global name reservation, even though
# their per-container operation locks are different.
rename_race_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --init -- /bin/sh -c 'sleep 30')
cleanup_ids+=("$rename_race_id")
rename_race_output="/tmp/zerun-rename-race-${BASHPID}"
rename_race_error="/tmp/zerun-rename-race-${BASHPID}.err"
run_race_output="/tmp/zerun-run-race-${BASHPID}"
run_race_error="/tmp/zerun-run-race-${BASHPID}.err"
cleanup_paths+=("$rename_race_output" "$rename_race_error" "$run_race_output" "$run_race_error")
set +e
"${zerun[@]}" rename "$rename_race_id" ci-cross-name-race \
  >"$rename_race_output" 2>"$rename_race_error" &
rename_race_pid=$!
"${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --name ci-cross-name-race --init -- /bin/sh -c 'sleep 30' \
  >"$run_race_output" 2>"$run_race_error" &
run_race_pid=$!
wait "$rename_race_pid"
rename_race_status=$?
wait "$run_race_pid"
run_race_status=$?
set -e
if (( (rename_race_status == 0) == (run_race_status == 0) )); then
  echo "concurrent rename and named run did not elect exactly one winner" >&2
  cat "$rename_race_error" "$run_race_error" >&2
  exit 1
fi
if (( run_race_status == 0 )); then
  rename_race_new_id=$(<"$run_race_output")
  [[ "$rename_race_new_id" =~ ^[0-9a-f]{12}$ ]]
  cleanup_ids+=("$rename_race_new_id")
fi
echo "rootful-name-race-ok"

# Bridge setup covers the netlink/veth path and the child-side eth0 setup.
bridge_output=$("${zerun[@]}" run --rootfs "$rootfs" --net bridge --no-overlay --init -- \
  /bin/sh -c '/bin/busybox ip -4 addr show dev eth0 | /bin/busybox grep -q "10.88.0."; printf "bridge-ok\\n"')
grep -Fx bridge-ok <<<"$bridge_output" >/dev/null

# A container network mode joins an existing running container's netns. Use
# exec in both containers so the check also covers the persisted
# `container:<id>` network label and the exec namespace join mask.
shared_net_target_name="ci-shared-net-$BASHPID"
shared_net_target=$("${zerun[@]}" run -d --name "$shared_net_target_name" \
  --rootfs "$rootfs" --net bridge --init -- /bin/sleep 30)
shared_net_id=$("${zerun[@]}" run -d --rootfs "$rootfs" \
  --network "container:$shared_net_target_name" --init -- /bin/sleep 30)
cleanup_ids+=("$shared_net_id" "$shared_net_target")
shared_net_target_ns=$("${zerun[@]}" exec "$shared_net_target" \
  /bin/busybox readlink /proc/self/ns/net)
shared_net_joined_ns=$("${zerun[@]}" exec "$shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)
test "$shared_net_joined_ns" = "$shared_net_target_ns"
shared_net_inspect=$("${zerun[@]}" inspect "$shared_net_id")
grep -F "\"net\": \"container:$shared_net_target\"" \
  <<<"$shared_net_inspect" >/dev/null
# The resolved id, not the original target name, is retained in canonical
# launch arguments used by a later `start`.
test "$(grep -Fc "container:$shared_net_target" <<<"$shared_net_inspect")" -ge 2
# The joining container keeps the target's address in its self /etc/hosts
# entry even though it owns no IPAM lease of its own.
shared_net_target_ip=$("${zerun[@]}" exec "$shared_net_target" \
  /bin/busybox grep -o '10[.]88[.]0[.][0-9][0-9]*' /etc/hosts | /bin/busybox head -n 1)
shared_net_joined_ip=$("${zerun[@]}" exec "$shared_net_id" \
  /bin/busybox grep -o '10[.]88[.]0[.][0-9][0-9]*' /etc/hosts | /bin/busybox head -n 1)
test -n "$shared_net_target_ip"
test "$shared_net_joined_ip" = "$shared_net_target_ip"

# A shared namespace is pinned by the running joiner. Restarting the target
# must not migrate that joiner; restarting the joiner must re-open the target
# ID and attach to its new namespace.
"${zerun[@]}" stop --time 2 "$shared_net_target" >/dev/null
"${zerun[@]}" start "$shared_net_target" >/dev/null
shared_net_target_ns_after_restart=$("${zerun[@]}" exec "$shared_net_target" \
  /bin/busybox readlink /proc/self/ns/net)
test "$shared_net_target_ns_after_restart" != "$shared_net_target_ns"
test "$("${zerun[@]}" exec "$shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)" = "$shared_net_target_ns"
"${zerun[@]}" stop --time 2 "$shared_net_id" >/dev/null
"${zerun[@]}" start "$shared_net_id" >/dev/null
test "$("${zerun[@]}" exec "$shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)" = "$shared_net_target_ns_after_restart"
shared_net_target_ip=$("${zerun[@]}" exec "$shared_net_target" \
  /bin/busybox grep -o '10[.]88[.]0[.][0-9][0-9]*' /etc/hosts | /bin/busybox head -n 1)
shared_net_joined_ip=$("${zerun[@]}" exec "$shared_net_id" \
  /bin/busybox grep -o '10[.]88[.]0[.][0-9][0-9]*' /etc/hosts | /bin/busybox head -n 1)
test "$shared_net_joined_ip" = "$shared_net_target_ip"
"${zerun[@]}" stop --time 2 "$shared_net_id" >/dev/null

# A malformed target record must remain distinguishable from a target that was
# removed. Restarting the joiner must fail closed with the parsing error rather
# than silently treating the target as a normal absence.
shared_net_target_state="$runtime_root/containers/$shared_net_target/state.json"
shared_net_target_state_backup=$(mktemp "${TMPDIR:-/tmp}/zerun-shared-net-target-state.XXXXXXXX")
if ! "${privileged[@]}" cp -p -- "$shared_net_target_state" "$shared_net_target_state_backup"; then
  remove_cleanup_path "$shared_net_target_state_backup"
  shared_net_target_state_backup=
  exit 1
fi
shared_net_target_state_backup_ready=true
printf '{not valid json\n' | "${privileged[@]}" tee "$shared_net_target_state" >/dev/null
if corrupt_shared_target_output=$("${zerun[@]}" start "$shared_net_id" 2>&1); then
  corrupt_shared_target_status=0
else
  corrupt_shared_target_status=$?
fi
"${privileged[@]}" cp -p -- "$shared_net_target_state_backup" "$shared_net_target_state"
remove_cleanup_path "$shared_net_target_state_backup"
shared_net_target_state_backup=
shared_net_target_state_backup_ready=false
if (( corrupt_shared_target_status == 0 )); then
  echo "shared-network joiner started with a corrupted target state" >&2
  exit 1
fi
grep -F "parse container state" <<<"$corrupt_shared_target_output" >/dev/null
grep -F "$shared_net_target" <<<"$corrupt_shared_target_output" >/dev/null
echo "rootful-shared-net-corrupt-target-ok"

"${zerun[@]}" rm "$shared_net_id" >/dev/null
"${zerun[@]}" stop --time 2 "$shared_net_target" >/dev/null
"${zerun[@]}" rm "$shared_net_target" >/dev/null

# The detached reaper must discard its launch-time netns descriptor and reopen
# the persisted target ID before an automatic retry. Hold the first attempt in
# its old namespace until the target has been restarted, then release it and
# verify the retry runs in the target's new namespace.
auto_shared_net_target_name="ci-auto-shared-net-$BASHPID"
auto_shared_net_target=$("${zerun[@]}" run -d --name "$auto_shared_net_target_name" \
  --rootfs "$rootfs" --net bridge --init -- /bin/sleep 30)
auto_shared_net_target_ns=$("${zerun[@]}" exec "$auto_shared_net_target" \
  /bin/busybox readlink /proc/self/ns/net)
auto_shared_net_id=$("${zerun[@]}" run -d --restart=on-failure:1 \
  --rootfs "$rootfs" --network "container:$auto_shared_net_target_name" \
  --init -- /bin/sh -c \
  'if [ ! -e /shared-net-auto-retry ]; then /bin/busybox touch /shared-net-auto-retry; while [ ! -e /shared-net-auto-release ]; do /bin/sleep 0.1; done; exit 7; fi; /bin/sleep 30')
cleanup_ids+=("$auto_shared_net_id" "$auto_shared_net_target")
test "$("${zerun[@]}" exec "$auto_shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)" = "$auto_shared_net_target_ns"
"${zerun[@]}" stop --time 2 "$auto_shared_net_target" >/dev/null
"${zerun[@]}" start "$auto_shared_net_target" >/dev/null
auto_shared_net_target_ns_after_restart=$("${zerun[@]}" exec "$auto_shared_net_target" \
  /bin/busybox readlink /proc/self/ns/net)
test "$auto_shared_net_target_ns_after_restart" != "$auto_shared_net_target_ns"
test "$("${zerun[@]}" exec "$auto_shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)" = "$auto_shared_net_target_ns"
"${zerun[@]}" exec "$auto_shared_net_id" \
  /bin/busybox touch /shared-net-auto-release >/dev/null
for attempt in $(seq 1 100); do
  auto_shared_net_inspect=$("${zerun[@]}" inspect "$auto_shared_net_id")
  if grep -F '"status": "running"' <<<"$auto_shared_net_inspect" >/dev/null &&
      grep -F '"restart_count": 1' <<<"$auto_shared_net_inspect" >/dev/null; then
    break
  fi
  if (( attempt == 100 )); then
    echo "shared-network automatic retry did not start" >&2
    printf '%s\n' "$auto_shared_net_inspect" >&2
    exit 1
  fi
  sleep 0.1
done
test "$("${zerun[@]}" exec "$auto_shared_net_id" \
  /bin/busybox readlink /proc/self/ns/net)" = "$auto_shared_net_target_ns_after_restart"
grep -F '"restart_pending": false' <<<"$auto_shared_net_inspect" >/dev/null
"${zerun[@]}" stop --time 2 "$auto_shared_net_id" >/dev/null
"${zerun[@]}" rm "$auto_shared_net_id" >/dev/null
"${zerun[@]}" stop --time 2 "$auto_shared_net_target" >/dev/null
"${zerun[@]}" rm "$auto_shared_net_target" >/dev/null
echo "rootful-shared-net-lifecycle-ok"

# Bridge resolv.conf injection accepts explicit search domains and options
# without exposing them to the source rootfs.
dns_output=$("${zerun[@]}" run --rootfs "$rootfs" --net bridge \
  --dns 203.0.113.53 --dns-search svc.local --dns-search corp.example \
  --dns-option ndots:2 --dns-option rotate -- /bin/cat /etc/resolv.conf)
grep -Fx 'nameserver 203.0.113.53' <<<"$dns_output" >/dev/null
grep -Fx 'search svc.local corp.example' <<<"$dns_output" >/dev/null
grep -Fx 'options ndots:2 rotate' <<<"$dns_output" >/dev/null

# The detached reaper owns logging and port-proxy threads before it starts a
# namespace child. Repeated starts guard the supervisor/worker split that keeps
# those threads' locks from being inherited by the workload process.
rapid_port=$(find_free_tcp_port)
for attempt in $(seq 1 16); do
  if ! rapid_id=$(timeout 10 "${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay \
      --net bridge -p "$rapid_port:9" --init -- /bin/sh -c 'sleep 0.02'); then
    echo "rapid detached bridge start $attempt failed or timed out" >&2
    exit 1
  fi
  cleanup_ids+=("$rapid_id")
  "${zerun[@]}" wait "$rapid_id" >/dev/null
  "${zerun[@]}" rm "$rapid_id" >/dev/null
done

# Published ports use Zerun's built-in proxy. Keep the workload in a
# detached container so the listener remains alive while curl connects.
port=$(find_free_tcp_port)
container_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
  -p "$port:8080" --init -- /bin/httpd -f -p 8080 -h /srv)
cleanup_ids+=("$container_id")
[[ "$container_id" =~ ^[0-9a-f]{12}$ ]]
port_output=$("${zerun[@]}" port "$container_id")
grep -Eq "^8080/tcp -> .+:$port$" <<<"$port_output"

wait_for_http_body "$port" zerun-port-ok

"${zerun[@]}" kill --signal TERM "$container_id" >/dev/null
wait_status=$("${zerun[@]}" wait "$container_id")
test "$wait_status" -ne 0
"${zerun[@]}" rm "$container_id" >/dev/null

# Published ranges are expanded to concrete host/container pairs. Separate
# document roots prove that traffic for each translated host port reaches the
# intended container port rather than both reaching the same listener.
range_port=$(find_free_tcp_port_range 2)
range_port_end=$((range_port + 1))
range_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
  -p "$range_port-$range_port_end:8080-8081" --init -- /bin/sh -c \
  '/bin/httpd -f -p 8080 -h /srv/range-a & /bin/httpd -f -p 8081 -h /srv/range-b & wait')
cleanup_ids+=("$range_id")
range_output=$("${zerun[@]}" port "$range_id")
grep -Eq "^8080/tcp -> .+:$range_port$" <<<"$range_output"
grep -Eq "^8081/tcp -> .+:$range_port_end$" <<<"$range_output"
wait_for_http_body "$range_port" zerun-range-a-ok
wait_for_http_body "$range_port_end" zerun-range-b-ok
"${zerun[@]}" stop --time 2 "$range_id" >/dev/null
"${zerun[@]}" rm "$range_id" >/dev/null

# `-P` turns CLI-exposed ports into concrete random mappings before launch.
# Resolve the selected host port through `zerun port` and verify real traffic.
publish_all_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
  --expose 8080,9090 -P --init -- /bin/httpd -f -p 8080 -h /srv)
cleanup_ids+=("$publish_all_id")
publish_all_output=$("${zerun[@]}" port "$publish_all_id")
publish_all_port=$(sed -n 's|^8080/tcp -> .*:\([0-9][0-9]*\)$|\1|p' <<<"$publish_all_output")
[[ $publish_all_port =~ ^[0-9]+$ ]] || {
  echo "publish-all did not record a concrete 8080/tcp mapping: $publish_all_output" >&2
  exit 1
}
wait_for_http_body "$publish_all_port" zerun-port-ok
publish_all_inspect=$("${zerun[@]}" inspect "$publish_all_id")
grep -F '"exposed_ports"' <<<"$publish_all_inspect" >/dev/null
grep -F '"8080/tcp"' <<<"$publish_all_inspect" >/dev/null
grep -F '"9090/tcp"' <<<"$publish_all_inspect" >/dev/null
grep -F '9090/tcp' <<<"$("${zerun[@]}" ps)" >/dev/null
"${zerun[@]}" stop --time 2 "$publish_all_id" >/dev/null
"${zerun[@]}" start "$publish_all_id" >/dev/null
wait_for_http_body "$publish_all_port" zerun-port-ok
publish_all_inspect=$("${zerun[@]}" inspect "$publish_all_id")
grep -F '"9090/tcp"' <<<"$publish_all_inspect" >/dev/null
"${zerun[@]}" stop --time 2 "$publish_all_id" >/dev/null
"${zerun[@]}" rm "$publish_all_id" >/dev/null

# Service generation must retain the exact bind address, protocol, exposed
# ports and publish-all intent rather than reducing mappings to ports alone.
service_udp_port=$(find_free_tcp_port)
service_unit=$("${zerun[@]}" generate-service --rootfs "$rootfs" --net bridge \
  -p "127.0.0.1:$port:8080" -p "127.0.0.1:$service_udp_port:8081/udp" \
  --expose 9090 -P -- /bin/true)
grep -F -- "--publish 127.0.0.1:$port:8080" <<<"$service_unit" >/dev/null
grep -F -- "--publish 127.0.0.1:$service_udp_port:8081/udp" <<<"$service_unit" >/dev/null
grep -F -- "--expose 9090/tcp" <<<"$service_unit" >/dev/null
grep -F -- "--publish-all" <<<"$service_unit" >/dev/null

# UDP publishing uses the same in-binary proxy, but replies must retain the
# published host port as their source. The CI fixture includes a tiny static
# UDP echo helper; local callers with older fixtures skip this optional check.
if [[ -x "$rootfs/bin/udp-echo" ]]; then
  command -v python3 >/dev/null || {
    echo "UDP published-port check requires python3 on the host" >&2
    exit 1
  }
  udp_port=$(find_free_tcp_port)
  udp_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
    -p "$udp_port:8081/udp" --init -- /bin/udp-echo 8081)
  cleanup_ids+=("$udp_id")
  python3 - "$udp_port" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
payload = b"zerun-udp-ok"
last_error = None
for _ in range(25):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.4)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
        response, peer = sock.recvfrom(65535)
        if response == payload and peer[1] == port:
            break
        last_error = f"unexpected UDP response={response!r} peer={peer!r}"
    except OSError as error:
        last_error = error
    finally:
        sock.close()
    time.sleep(0.2)
else:
    raise SystemExit(f"published UDP port did not become ready: {last_error}")
PY
  "${zerun[@]}" kill --signal TERM "$udp_id" >/dev/null
  udp_wait_status=$("${zerun[@]}" wait "$udp_id")
  test "$udp_wait_status" -ne 0
  "${zerun[@]}" rm "$udp_id" >/dev/null
else
  echo "skipping optional UDP published-port check: $rootfs/bin/udp-echo is missing" >&2
fi

echo "rootful-runtime-ok"
