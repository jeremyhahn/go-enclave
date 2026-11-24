#!/bin/sh
# toolchain-trivy.sh <dir> copies trivy out of the toolchain image after checking it against the pinned SHA-256.
set -eu

[ $# -eq 1 ] && [ -n "$1" ] || { echo "usage: $0 <dir>" >&2; exit 1; }
dir=$1
command -v docker >/dev/null 2>&1 || { echo "$0: docker is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "$0: sha256sum is required" >&2; exit 1; }

# shellcheck source=../../scripts/tool-pins.sh
. "${0%/*}/../../scripts/tool-pins.sh"
case $(uname -m) in
  x86_64)        pin=$TRIVY_BIN_SHA256_LINUX_AMD64 ;;
  aarch64|arm64) pin=$TRIVY_BIN_SHA256_LINUX_ARM64 ;;
  *) echo "$0: no pinned trivy checksum for $(uname -m)" >&2; exit 1 ;;
esac
case $pin in
  *[!0-9a-f]*|"") echo "$0: the pinned trivy SHA-256 is missing or malformed" >&2; exit 1 ;;
esac
[ "${#pin}" -eq 64 ] || { echo "$0: the pinned trivy SHA-256 is missing or malformed" >&2; exit 1; }

image=$(make --no-print-directory -s toolchain-image)
docker image inspect "$image" >/dev/null 2>&1 || make --no-print-directory docker-build
cid=$(docker create "$image")
stage=$(mktemp -d)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$stage"' EXIT
docker cp "$cid:/usr/local/bin/trivy" "$stage/trivy"
got=$(sha256sum "$stage/trivy" | cut -d' ' -f1)
if [ "$got" != "$pin" ]; then
  echo "$0: CHECKSUM MISMATCH for the trivy in $image: got $got, pinned $pin. The image is not the toolchain image this repository builds; treat it as a supply-chain event." >&2
  exit 1
fi
mkdir -p "$dir"
chmod 0755 "$stage/trivy"
mv -f "$stage/trivy" "$dir/trivy"
echo "trivy taken from $image into $dir (SHA-256 verified)"
