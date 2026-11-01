#!/usr/bin/env bash
# Build the reproducible rootfs used by ci/rootful-runtime.sh.
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 ROOTFS" >&2
  exit 2
fi

rootfs=$1
if [[ -e $rootfs ]]; then
  [[ -d $rootfs ]] || {
    echo "fixture rootfs path is not a directory: $rootfs" >&2
    exit 1
  }
  if [[ -n $(find "$rootfs" -mindepth 1 -print -quit) ]]; then
    echo "fixture rootfs directory must be empty: $rootfs" >&2
    exit 1
  fi
fi

busybox=${BUSYBOX_PATH:-}
if [[ -z $busybox ]]; then
  busybox=$(command -v busybox || true)
fi
[[ -n $busybox && -x $busybox ]] || {
  echo "busybox is required (install busybox-static or set BUSYBOX_PATH)" >&2
  exit 1
}

cc=${CC:-cc}
command -v "$cc" >/dev/null || {
  echo "a C compiler is required to build the UDP echo fixture (set CC)" >&2
  exit 1
}

mkdir -p "$rootfs/bin" "$rootfs/etc/opaque-test" "$rootfs/srv/range-a" "$rootfs/srv/range-b"
install -m 0755 "$busybox" "$rootfs/bin/busybox"
printf 'testuser:x:4242:4344::/:/bin/sh\n' >"$rootfs/etc/passwd"
printf 'testuser:x:4344:\ntestgroup:x:4343:\n' >"$rootfs/etc/group"
printf 'old-opaque-entry\n' >"$rootfs/etc/opaque-test/old"
for applet in sh httpd ip grep cat sleep; do
  ln -s busybox "$rootfs/bin/$applet"
done
printf 'zerun-port-ok\n' >"$rootfs/srv/index.html"
printf 'zerun-range-a-ok\n' >"$rootfs/srv/range-a/index.html"
printf 'zerun-range-b-ok\n' >"$rootfs/srv/range-b/index.html"

"$cc" -static -O2 -Wall -Wextra -x c -o "$rootfs/bin/udp-echo" - <<'C_EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int port = atoi(argv[1]);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) return 1;
    for (;;) {
        unsigned char buffer[65535];
        struct sockaddr_storage peer = {0};
        socklen_t peer_len = sizeof(peer);
        ssize_t length = recvfrom(fd, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&peer, &peer_len);
        if (length < 0) {
            if (errno == EINTR) continue;
            return 1;
        }
        if (sendto(fd, buffer, (size_t)length, 0,
                   (struct sockaddr *)&peer, peer_len) != length) return 1;
    }
}
C_EOF

"$cc" -static -O2 -Wall -Wextra -x c -o "$rootfs/bin/seccomp-io-probe" - <<'C_EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    int rc = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    if (rc != 0) { errno = rc; perror("posix_fadvise"); return 2; }
    if (readahead(fd, 0, 4096) != 0) { perror("readahead"); return 3; }
    if (close(fd) != 0) { perror("close"); return 4; }
    puts("seccomp-io-ok");
    return 0;
}
C_EOF

test -x "$rootfs/bin/udp-echo"
test -x "$rootfs/bin/seccomp-io-probe"
# The integration suite drops all capabilities for one check; every fixture
# path must remain traversable without DAC override.
chmod -R a+rX "$rootfs"
echo "prepared rootful integration rootfs: $rootfs"
