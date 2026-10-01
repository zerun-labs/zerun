#!/usr/bin/env bash
# Exercise runtime paths that ordinary unit tests cannot cover because they
# need a real rootful Linux host: overlayfs, cgroups v2, bridge networking,
# and the in-process published-port proxy.
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
  zerun=(env
    ZERUN_DATA_ROOT="$data_root"
    ZERUN_RUNTIME_ROOT="$runtime_root"
    "$binary")
else
  command -v sudo >/dev/null || {
    echo "rootful runtime tests require sudo when not already running as root" >&2
    exit 1
  }
  zerun=(sudo env
    ZERUN_DATA_ROOT="$data_root"
    ZERUN_RUNTIME_ROOT="$runtime_root"
    "$binary")
fi

# Always clean up detached records, including when a later integration check
# fails. The runner is ephemeral, but explicit cleanup makes repeated local
# runs deterministic and prevents leaked bridge listeners between checks.
cleanup_ids=()
cleanup() {
  for id in "${cleanup_ids[@]}"; do
    "${zerun[@]}" rm -f "$id" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# Pick a high, currently unused TCP port instead of assuming a shared runner
# has 18080 available. The check is intentionally only a race-avoidance hint:
# Zerun still binds the published port before cloning the container, so its
# own bind remains the authoritative conflict check.
find_free_tcp_port() {
  local candidate=$((18080 + (BASHPID % 1000)))
  local attempt
  for attempt in $(seq 1 1000); do
    if ! (echo >/dev/tcp/127.0.0.1/"$candidate") 2>/dev/null; then
      printf '%s\n' "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  echo "could not find a free TCP port for the published-port check" >&2
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

# Resource limits require an actual cgroup v2 hierarchy and exercise the
# parent-side cgroup creation/attach path.
cgroup_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --pids 32 --init -- /bin/sh -c 'printf "cgroup-ok\\n"')
grep -Fx cgroup-ok <<<"$cgroup_output" >/dev/null

# Detached exec must join the same cgroup as the container. This also guards
# the persisted cgroup-path validation used by the exec joiner.
exec_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --pids 32 --init -- /bin/sh -c 'sleep 30')
cleanup_ids+=("$exec_id")
exec_output=$("${zerun[@]}" exec "$exec_id" /bin/sh -c 'printf "exec-ok\\n"')
grep -Fx exec-ok <<<"$exec_output" >/dev/null
"${zerun[@]}" kill --signal TERM "$exec_id" >/dev/null
"${zerun[@]}" wait "$exec_id" >/dev/null
"${zerun[@]}" rm "$exec_id" >/dev/null

# Restart must stop and resume the same detached record rather than creating a
# replacement container. Verify that the workload ran once before and once
# after the restart while retaining the same id and log history.
restart_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net none \
  --init -- /bin/sh -c 'printf "restart-ok\\n"; sleep 30')
cleanup_ids+=("$restart_id")
for attempt in $(seq 1 50); do
  restart_logs=$("${zerun[@]}" logs "$restart_id" 2>/dev/null || true)
  if (( $(grep -c 'restart-ok' <<<"$restart_logs" || true) >= 1 )); then
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
  if (( $(grep -c 'restart-ok' <<<"$restart_logs" || true) >= 2 )); then
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

# Bridge setup covers the netlink/veth path and the child-side eth0 setup.
bridge_output=$("${zerun[@]}" run --rootfs "$rootfs" --net bridge --no-overlay --init -- \
  /bin/sh -c '/bin/busybox ip -4 addr show dev eth0 | /bin/busybox grep -q "10.88.0."; printf "bridge-ok\\n"')
grep -Fx bridge-ok <<<"$bridge_output" >/dev/null

# Published ports use Zerun's built-in proxy. Keep the workload in a
# detached container so the listener remains alive while curl connects.
port=$(find_free_tcp_port)
container_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
  -p "$port:8080" --init -- /bin/httpd -f -p 8080 -h /srv)
cleanup_ids+=("$container_id")
[[ "$container_id" =~ ^[0-9a-f]{12}$ ]]

for attempt in $(seq 1 50); do
  if curl --fail --silent --show-error "http://127.0.0.1:$port/" | \
      grep -Fxq zerun-port-ok; then
    break
  fi
  if (( attempt == 50 )); then
    echo "published port did not become ready" >&2
    exit 1
  fi
  sleep 0.2
done

"${zerun[@]}" kill --signal TERM "$container_id" >/dev/null
wait_status=$("${zerun[@]}" wait "$container_id")
test "$wait_status" -ne 0
"${zerun[@]}" rm "$container_id" >/dev/null

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
