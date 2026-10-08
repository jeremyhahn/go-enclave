#!/bin/sh
# install-tools.sh — install every pinned analysis tool into one directory.
#
# Usage: scripts/install-tools.sh <bindir>
#
# The devcontainer's tools stage runs this to bake the tools the toolchain
# image carries. Each one is resolved by scripts/tool.sh with TOOL_INSTALL=1,
# at the pins in scripts/tool-pins.sh, so it is built or downloaded and verified
# exactly as `make lint` would do it on a developer's machine, then copied to
# <bindir>. The scratch TOOLS_DIR is removed on exit.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"
# shellcheck source=tool-pins.sh
. "$here/tool-pins.sh"

[ $# -eq 1 ] || die "usage: $0 <bindir>"
dest=$1
case $dest in /*) ;; *) die "<bindir> '$dest' is not an absolute path" ;; esac

export TRIVY_SHA256_LINUX_AMD64 TRIVY_SHA256_LINUX_ARM64 TRIVY_BIN_SHA256_LINUX_AMD64 TRIVY_BIN_SHA256_LINUX_ARM64
export SHELLCHECK_SHA256_LINUX_AMD64 SHELLCHECK_SHA256_LINUX_ARM64 SHELLCHECK_BIN_SHA256_LINUX_AMD64 SHELLCHECK_BIN_SHA256_LINUX_ARM64
TOOL_INSTALL=1
TOOLS_DIR=$(mktemp -d)
export TOOL_INSTALL TOOLS_DIR
trap 'rm -rf "$TOOLS_DIR"' EXIT
mkdir -p "$dest"

install_tool() {
  bin=$(sh "$here/tool.sh" "$1" "$2")
  cp "$bin" "$dest/$1"
  chmod 0755 "$dest/$1"
  echo "installed $1 $2 into $dest"
}

install_tool golangci-lint "$GOLANGCI_VERSION"
install_tool gosec "$GOSEC_VERSION"
install_tool govulncheck "$GOVULNCHECK_VERSION"
install_tool actionlint "$ACTIONLINT_VERSION"
install_tool trivy "$TRIVY_VERSION"
install_tool shellcheck "$SHELLCHECK_VERSION"
