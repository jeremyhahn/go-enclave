#!/bin/sh
# guest-image.sh: build the SEV-SNP guest kit from the pinned inputs.
#
# Usage: scripts/amd-sev-snp/guest-image.sh [--dry-run] [inputs|qemu|initrd|all]
#
#   inputs  fetch the pinned OVMF, kernel and modules packages (pins.sh) into
#           the cache, refuse any whose sha256 differs, and extract
#           OVMF.amdsev.fd, the kernel and the guest modules into the kit
#   qemu    build the pinned QEMU release from its tarball into the cache
#           (once per version) and link the kit's qemu-system-x86_64 to it
#   initrd  build the guest's initrd: /init (test/integration/amdsev/guestinit,
#           static), /amdsev.test (the test binary of test/integration/amdsev,
#           which the guest runs as root) and the modules in load order
#   all     the three, in that order (the default)
#
# --dry-run prints the pins and the paths and changes nothing.
#
# The kit directory is $AMDSEV_CACHE/kit (AMDSEV_CACHE defaults to
# ~/.cache/go-enclave/amd-sev-snp); guest.sh and run.sh read it from there.
# Every guest boots this kit fresh: the initrd is the guest's whole root and
# nothing persists between boots. AMDSEV_SNAPSHOT and AMDSEV_QEMU_URL replace
# the download bases (the pinned hashes still apply).
set -eu
here=$(cd "${0%/*}" && pwd)
# shellcheck source=../lib.sh
. "$here/../lib.sh"
# shellcheck source=pins.sh
. "$here/pins.sh"

fail() { echo "$prog: $*" >&2; exit 2; }

repo=$(cd "$here/../.." && pwd)
module=$repo/test/integration/amdsev
cache=${AMDSEV_CACHE:-${HOME:-/nonexistent}/.cache/go-enclave/amd-sev-snp}
kit=$cache/kit
snapshot=${AMDSEV_SNAPSHOT:-$AMDSEV_SNAPSHOT_DEFAULT}
qemu_url=${AMDSEV_QEMU_URL:-$QEMU_URL_DEFAULT}
qemu_prefix=$cache/qemu-$QEMU_VERSION

dry=
step=
usage="usage: $prog [--dry-run] [inputs|qemu|initrd|all]"
for a in "$@"; do
  case $a in
    --dry-run) dry=1 ;;
    inputs | qemu | initrd | all)
      [ -z "$step" ] || fail "one step only; $usage"
      step=$a
      ;;
    *) fail "unknown argument '$a'; $usage" ;;
  esac
done
[ -n "$step" ] || step=all

if [ -n "$dry" ]; then
  echo "kit: $kit"
  echo "ovmf: $OVMF_VERSION $snapshot/$OVMF_DEB sha256:$OVMF_SHA256"
  echo "kernel: $KERNEL_PKG_VERSION $snapshot/$KERNEL_DEB sha256:$KERNEL_SHA256"
  echo "modules: $KERNEL_PKG_VERSION $snapshot/$MODULES_DEB sha256:$MODULES_SHA256"
  echo "qemu: $QEMU_VERSION $qemu_url sha256:$QEMU_SHA256"
  echo "step: $step"
  exit 0
fi

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || fail "$t: not found; the kit needs it on the host ($*)"
  done
}

sha256_of() { sha256sum -- "$1" | { read -r h _ && printf '%s\n' "$h"; }; }

# fetch URL SHA256 DEST: DEST holds the pinned bytes when it returns.
fetch() {
  if [ -f "$3" ] && [ "$(sha256_of "$3")" = "$2" ]; then
    return 0
  fi
  mkdir -p "${3%/*}"
  rm -f -- "$3.part"
  curl -fsSL --retry 3 -o "$3.part" -- "$1" || fail "cannot fetch $1"
  got=$(sha256_of "$3.part")
  if [ "$got" != "$2" ]; then
    rm -f -- "$3.part"
    fail "$1: sha256 $got, pinned $2; refusing it"
  fi
  mv -f -- "$3.part" "$3"
}

inputs() {
  need curl sha256sum dpkg-deb
  dl=$cache/downloads
  fetch "$snapshot/$OVMF_DEB" "$OVMF_SHA256" "$dl/${OVMF_DEB##*/}"
  fetch "$snapshot/$KERNEL_DEB" "$KERNEL_SHA256" "$dl/${KERNEL_DEB##*/}"
  fetch "$snapshot/$MODULES_DEB" "$MODULES_SHA256" "$dl/${MODULES_DEB##*/}"
  x=$cache/extract
  rm -rf -- "$x"
  mkdir -p "$x" "$kit/modules"
  dpkg-deb -x "$dl/${OVMF_DEB##*/}" "$x"
  dpkg-deb -x "$dl/${KERNEL_DEB##*/}" "$x"
  dpkg-deb -x "$dl/${MODULES_DEB##*/}" "$x"
  cp -f -- "$x/$OVMF_FILE" "$kit/OVMF.amdsev.fd"
  cp -f -- "$x/$KERNEL_FILE" "$kit/vmlinuz"
  rm -f -- "$kit"/modules/*
  n=0
  for m in $MODULES_LOAD; do
    src=$x/usr/lib/modules/$KERNEL_VERSION/$m
    [ -f "$src" ] || fail "$m is not in ${MODULES_DEB##*/}"
    n=$((n + 1))
    cp -f -- "$src" "$kit/modules/$n-${m##*/}"
  done
  rm -rf -- "$x"
  echo "inputs: ovmf $OVMF_VERSION, kernel $KERNEL_PKG_VERSION, $n modules"
}

qemu() {
  bin=$qemu_prefix/bin/qemu-system-x86_64
  if [ ! -x "$bin" ]; then
    need curl sha256sum tar xz make ninja python3 cc pkg-config
    tarball=$cache/downloads/qemu-$QEMU_VERSION.tar.xz
    fetch "$qemu_url" "$QEMU_SHA256" "$tarball"
    src=$cache/qemu-src
    rm -rf -- "$src"
    mkdir -p "$src"
    tar -xJf "$tarball" -C "$src" --strip-components=1
    (cd "$src" && ./configure --prefix="$qemu_prefix" --target-list=x86_64-softmmu \
      --enable-kvm --disable-docs --disable-user --disable-werror >"$cache/qemu-configure.log" 2>&1) ||
      fail "QEMU $QEMU_VERSION configure failed; see $cache/qemu-configure.log (glib, pixman and meson's other build dependencies)"
    (cd "$src" && make -j"$(nproc)" install >"$cache/qemu-build.log" 2>&1) ||
      fail "QEMU $QEMU_VERSION build failed; see $cache/qemu-build.log"
    rm -rf -- "$src"
  fi
  mkdir -p "$kit"
  ln -sf "$bin" "$kit/qemu-system-x86_64"
  echo "qemu: $("$bin" --version | { IFS= read -r l; printf '%s' "$l"; })"
}

initrd() {
  need go cpio find sort
  [ -d "$kit/modules" ] || fail "$kit/modules is missing; run the inputs step first"
  stage=$cache/initrd-stage
  rm -rf -- "$stage"
  mkdir -p "$stage/modules" "$stage/dev" "$stage/proc" "$stage/sys" "$stage/tmp"
  (cd "$module" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -o "$stage/init" ./guestinit) || fail "cannot build the guest init"
  (cd "$module" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go test -c -trimpath -o "$stage/amdsev.test" .) || fail "cannot build the guest test binary"
  cp -f -- "$kit"/modules/* "$stage/modules/"
  (cd "$stage" && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc --quiet) >"$kit/initrd.img.part"
  mv -f -- "$kit/initrd.img.part" "$kit/initrd.img"
  rm -rf -- "$stage"
  echo "initrd: $kit/initrd.img"
}

case $step in
  inputs) inputs ;;
  qemu) qemu ;;
  initrd) initrd ;;
  all) inputs; qemu; initrd ;;
esac
