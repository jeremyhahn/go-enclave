#!/bin/sh
# install-tools.sh <bindir>: install every pinned analysis tool, verified by scripts/tool.sh, into bindir.
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
export XTOOLS_VERSION
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
