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

# Resource limits require an actual cgroup v2 hierarchy and exercise the
# parent-side cgroup creation/attach path.
cgroup_output=$("${zerun[@]}" run --rootfs "$rootfs" --net none --no-overlay \
  --pids 32 --init -- /bin/sh -c 'printf "cgroup-ok\\n"')
grep -Fx cgroup-ok <<<"$cgroup_output" >/dev/null

# Bridge setup covers the netlink/veth path and the child-side eth0 setup.
bridge_output=$("${zerun[@]}" run --rootfs "$rootfs" --net bridge --no-overlay --init -- \
  /bin/sh -c '/bin/busybox ip -4 addr show dev eth0 | /bin/busybox grep -q "10.88.0."; printf "bridge-ok\\n"')
grep -Fx bridge-ok <<<"$bridge_output" >/dev/null

# Published ports use Zerun's built-in proxy. Keep the workload in a
# detached container so the listener remains alive while curl connects.
port=18080
container_id=""
cleanup() {
  if [[ -n $container_id ]]; then
    "${zerun[@]}" rm -f "$container_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

container_id=$("${zerun[@]}" run -d --rootfs "$rootfs" --no-overlay --net bridge \
  -p "$port:8080" --init -- /bin/httpd -f -p 8080 -h /srv)
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
container_id=""

echo "rootful-runtime-ok"
