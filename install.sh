#!/bin/sh
# Install the latest (or a tagged) Zerun release binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/zerun-labs/zerun/main/install.sh | sh
#   ZERUN_INSTALL_VERSION=v0.2.0 ./install.sh --prefix ~/.local
#
# The script installs a Linux musl build, verifies its SHA-256 checksum, and
# creates both `zerun` and the shorter `ze` command.
set -eu

REPO=zerun-labs/zerun
VERSION=${ZERUN_INSTALL_VERSION:-}
PREFIX=
SUDO=

usage() {
    cat <<'USAGE'
usage: install.sh [--prefix DIR]

Environment:
  ZERUN_INSTALL_VERSION=TAG   install a tagged release (default: latest)
  ZERUN_INSTALL_PREFIX=DIR    override the install prefix

The default prefix is /usr/local (using sudo when needed), or ~/.local for
unprivileged installations. Both `zerun` and `ze` are linked into PREFIX/bin.
USAGE
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --prefix)
            [ "$#" -ge 2 ] || die "option --prefix requires a directory"
            PREFIX=$2
            shift 2
            ;;
        --prefix=*)
            PREFIX=${1#*=}
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            die "unknown argument '$1' (see --help)"
            ;;
    esac
done

case "$(uname -s)" in
    Linux) ;;
    *) die "prebuilt binaries are currently provided for Linux only" ;;
esac

case "$(uname -m)" in
    x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
    armv7l|armv7) TARGET=armv7-unknown-linux-musleabihf ;;
    riscv64) TARGET=riscv64gc-unknown-linux-musl ;;
    *) die "unsupported architecture '$(uname -m)'" ;;
esac

if [ -z "$PREFIX" ]; then
    if [ -n "${ZERUN_INSTALL_PREFIX:-}" ]; then
        PREFIX=$ZERUN_INSTALL_PREFIX
    elif [ "$(id -u)" -eq 0 ]; then
        PREFIX=/usr/local
    elif command -v sudo >/dev/null 2>&1; then
        PREFIX=/usr/local
        SUDO=sudo
    else
        PREFIX=$HOME/.local
    fi
fi

case "$PREFIX" in
    /*) ;;
    *) PREFIX=$(pwd)/$PREFIX ;;
esac

archive=zerun-$TARGET.tar.gz
if [ -n "$VERSION" ]; then
    base=https://github.com/$REPO/releases/download/$VERSION
else
    base=https://github.com/$REPO/releases/latest/download
fi

command -v tar >/dev/null 2>&1 || die "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
    CHECKSUM=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    CHECKSUM="shasum -a 256"
else
    die "sha256sum or shasum is required to verify the download"
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

fetch() {
    url=$1
    output=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
    else
        die "curl or wget is required to download releases"
    fi
}

echo "==> Downloading Zerun ${VERSION:-latest} for $TARGET"
fetch "$base/$archive" "$tmpdir/$archive"
fetch "$base/$archive.sha256" "$tmpdir/$archive.sha256"

cd "$tmpdir"
$CHECKSUM -c "$archive.sha256" >/dev/null
tar -xzf "$archive"

[ -f zerun ] || die "downloaded archive did not contain a `zerun` binary"
chmod 0755 zerun

if [ -n "$SUDO" ]; then
    $SUDO mkdir -p "$PREFIX/bin"
    $SUDO install -m 0755 zerun "$PREFIX/bin/zerun"
    $SUDO ln -sfn zerun "$PREFIX/bin/ze"
else
    mkdir -p "$PREFIX/bin"
    install -m 0755 zerun "$PREFIX/bin/zerun"
    ln -sfn zerun "$PREFIX/bin/ze"
fi

echo "==> Installed $PREFIX/bin/zerun"
echo "==> Linked $PREFIX/bin/ze"
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "note: add $PREFIX/bin to PATH to use zerun/ze" ;;
esac
