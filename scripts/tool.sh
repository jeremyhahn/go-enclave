#!/bin/sh
# tool.sh <tool> <vX.Y.Z>: resolve a pinned analysis tool and print its path; see TOOL_INSTALL, TOOLS_DIR, TOOLCHAIN, GO and the pinned hashes (TRIVY,
#                 SHELLCHECK): the archive's SHA-256 and the extracted
# binary's) in scripts/tool-pins.sh. A cached or PATH copy is used only when it verifies at the pin.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"
# shellcheck disable=SC2034  # die() in lib.sh prefixes with it
prog=tool.sh

[ $# -eq 2 ] || die "usage: $0 <tool> <vX.Y.Z>"
tool=$1
want=$2
go=${GO:-go}

matches "$want" '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "$tool: '$want' is not a pinned vX.Y.Z version"

# kind: go (built under TOOLCHAIN) or archive (verified against pinned hashes); ldflags stamp the requested version.
ldflags=
kind=go
# projectbuilt: TOOL_INSTALL=0 is ignored and the tool is built at the pin unless a PATH copy verifies.
projectbuilt=0
case $tool in
  golangci-lint) pkg=github.com/golangci/golangci-lint/v2/cmd/golangci-lint ;;
  staticcheck)   pkg=honnef.co/go/tools/cmd/staticcheck ;;
  gosec)         pkg=github.com/securego/gosec/v2/cmd/gosec
                 ldflags="-X main.Version=$want" ;;
  govulncheck)   pkg=golang.org/x/vuln/cmd/govulncheck ;;
  actionlint)    pkg=github.com/rhysd/actionlint/cmd/actionlint
                 projectbuilt=1 ;;
  trivy|shellcheck) kind=archive ;;
  *) die "unknown tool '$tool' (known: golangci-lint staticcheck gosec govulncheck actionlint trivy shellcheck)" ;;
esac

# version_of prints the version a binary reports about itself, parsed by the tool's own marker.
version_of() {
  case $tool in
    golangci-lint) out=$("$1" --version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n 's/.*has version v\{0,1\}\([0-9][^ ]*\).*/\1/p') ;;
    staticcheck)   out=$("$1" -version 2>&1) || return 0
                   # "staticcheck 2026.2.1 (0.8.1)": the year form is the
                   # release name, the parenthesised one the module version.
                   v=$(printf '%s\n' "$out" | sed -n 's/^staticcheck .*(v\{0,1\}\([0-9][^)]*\)).*/\1/p') ;;
    gosec)         out=$("$1" --version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n 's/^Version: v\{0,1\}\([0-9][^ ]*\).*/\1/p') ;;
    govulncheck)   out=$("$1" -version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n 's/^Scanner: govulncheck@v\{0,1\}\([0-9][^ ]*\).*/\1/p') ;;
    actionlint)    out=$("$1" -version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n '1s/^v\{0,1\}\([0-9][0-9.]*\)$/\1/p') ;;
    trivy)         out=$("$1" --version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n 's/^Version: v\{0,1\}\([0-9][^ ]*\).*/\1/p') ;;
    shellcheck)    out=$("$1" --version 2>&1) || return 0
                   v=$(printf '%s\n' "$out" | sed -n 's/^version: v\{0,1\}\([0-9][^ ]*\).*/\1/p') ;;
  esac
  # Zero or several matches means the output is not the shape this parser knows.
  case $v in ""|*"$NL"*) return 0 ;; esac
  printf 'v%s\n' "$v"
}

# require_version fails unless the binary at $1 reports exactly $want.
require_version() {
  got=$(version_of "$1")
  [ -n "$got" ] || die "$tool at $1 does not report a version this script can read; refusing an unversioned tool (pinned $want)"
  [ "$got" = "$want" ] || die "$tool at $1 is $got, but the Makefile pins $want. $2"
}

# built_with prints the Go toolchain recorded in a Go binary's build metadata,
# or nothing when it cannot be read.
built_with() {
  out=$("$go" version "$1" 2>/dev/null) || return 0
  case $out in "$1: "*) ;; *) return 0 ;; esac
  printf '%s\n' "${out#"$1: "}"
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# The pinned hashes for a downloaded tool on this platform, and its archive.
# Sets: artifact, member (path of the binary inside the archive), sum, binsum.
archive_pins() {
  for t in sha256sum uname; do
    command -v "$t" >/dev/null 2>&1 || die "$tool: $t is required to verify it and was not found"
  done
  case $(uname -s):$(uname -m) in
    Linux:x86_64)              arch=AMD64 ;;
    Linux:aarch64|Linux:arm64) arch=ARM64 ;;
    *) die "$tool: no pinned release checksum for $(uname -s)/$(uname -m); install $tool $want yourself and run with TOOL_INSTALL=0" ;;
  esac
  case $tool:$arch in
    trivy:AMD64)      artifact=trivy_${want#v}_Linux-64bit.tar.gz ;;
    trivy:ARM64)      artifact=trivy_${want#v}_Linux-ARM64.tar.gz ;;
    shellcheck:AMD64) artifact=shellcheck-$want.linux.x86_64.tar.xz ;;
    shellcheck:ARM64) artifact=shellcheck-$want.linux.aarch64.tar.xz ;;
  esac
  case $tool in
    trivy)      url=https://github.com/aquasecurity/trivy/releases/download/$want/$artifact
                member=trivy
                sum=$(printenv "TRIVY_SHA256_LINUX_$arch" || true)
                binsum=$(printenv "TRIVY_BIN_SHA256_LINUX_$arch" || true) ;;
    shellcheck) url=https://github.com/koalaman/shellcheck/releases/download/$want/$artifact
                member=shellcheck-$want/shellcheck
                sum=$(printenv "SHELLCHECK_SHA256_LINUX_$arch" || true)
                binsum=$(printenv "SHELLCHECK_BIN_SHA256_LINUX_$arch" || true) ;;
  esac
  matches "$binsum" '^[0-9a-f]{64}$' || die "$tool: the pinned binary SHA-256 for $artifact is missing or malformed"
}

# install_archive writes the pinned release binary to $tmp/$tool.
#
# trivy and shellcheck are NOT built with `go install`: shellcheck is not Go,
# Archive tools are trusted only through SHA-256s pinned in this repository.
install_archive() {
  for t in curl tar; do
    command -v "$t" >/dev/null 2>&1 || die "$tool: $t is required to install it and was not found"
  done
  matches "$sum" '^[0-9a-f]{64}$' || die "$tool: the pinned archive SHA-256 for $artifact is missing or malformed"
  case $artifact in *.xz) command -v xz >/dev/null 2>&1 || die "$tool: xz is required to unpack $artifact" ;; esac
  curl -sSfL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$artifact" "$url" ||
    die "$tool: downloading $artifact failed"
  got=$(sha256_of "$tmp/$artifact")
  [ "$got" = "$sum" ] || die "$tool: CHECKSUM MISMATCH for $artifact: got $got, pinned $sum. Do not work around this; treat it as a supply-chain event."
  tar -xf "$tmp/$artifact" -C "$tmp" "$member" || die "$tool: extracting $artifact failed"
  got=$(sha256_of "$tmp/$member")
  [ "$got" = "$binsum" ] || die "$tool: CHECKSUM MISMATCH for the binary in $artifact: got $got, pinned $binsum."
  if [ "$tmp/$member" != "$tmp/$tool" ]; then mv -f "$tmp/$member" "$tmp/$tool"; fi
  chmod 0755 "$tmp/$tool"
}

# retry runs "$@" up to three times from a clean $tmp.
retry() {
  attempt=0
  until rm -rf "${tmp:?}/mod" "${tmp:?}/$tool" && "$@"; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 3 ] || return 1
    sleep $((attempt * 10))
  done
}

# go_install_once makes one attempt at installing a Go tool into $tmp.
go_install_once() { GOTOOLCHAIN=$TOOLCHAIN GOBIN=$tmp "$go" install "$pkg@$want"; }

# gosec_once makes one attempt at build_gosec's throwaway-module build.
gosec_once() {
  mkdir "$tmp/mod" &&
    (
      cd "$tmp/mod" &&
        GOTOOLCHAIN=$TOOLCHAIN "$go" mod init gosec-build >&2 &&
        GOTOOLCHAIN=$TOOLCHAIN "$go" get "$pkg@$want" "golang.org/x/tools@$XTOOLS_VERSION" >&2 &&
        GOTOOLCHAIN=$TOOLCHAIN CGO_ENABLED=0 GOBIN=$tmp "$go" install -ldflags "$ldflags" "$pkg" >&2
    )
}

# build_gosec builds gosec in a throwaway module with golang.org/x/tools at XTOOLS_VERSION.
build_gosec() {
  matches "${XTOOLS_VERSION-}" '^v[0-9]+\.[0-9]+\.[0-9]+$' ||
    die "gosec: XTOOLS_VERSION '${XTOOLS_VERSION-}' is not a pinned vX.Y.Z version (scripts/tool-pins.sh)"
  retry gosec_once || die "installing $tool $want against golang.org/x/tools $XTOOLS_VERSION failed"
  rm -rf "$tmp/mod"
}

# verified reports whether the binary at $1 may be used without installing.
verified() {
  [ -x "$1" ] || return 1
  if [ "$kind" = archive ]; then
    [ "$(sha256_of "$1")" = "$binsum" ]
  else
    [ "$(built_with "$1")" = "$TOOLCHAIN" ] && [ "$(version_of "$1")" = "$want" ]
  fi
}

# A project-built tool is resolved as under TOOL_INSTALL=1 whichever of the two
# valid values is set; any other value is still refused below.
mode=${TOOL_INSTALL-}
if [ "$projectbuilt" = 1 ] && matches "$mode" '^[01]$'; then mode=1; fi

case $mode in
  0)
    bin=$(command -v "$tool" 2>/dev/null) ||
      die "$tool is not on PATH and TOOL_INSTALL=0 forbids installing it. CI expects it baked into the runner image at $want; locally, run without TOOL_INSTALL=0 to install the pinned version into the repository."
    case $bin in /*) ;; *) die "$tool resolved to '$bin', which is not an absolute path" ;; esac
    if [ "$kind" = archive ]; then
      # Checked before the binary is run for its version: a planted binary can
      # print any version, and must not be executed to find out.
      archive_pins
      [ "$(sha256_of "$bin")" = "$binsum" ] ||
        die "$tool at $bin does not hash to the pinned binary SHA-256 $binsum. A binary that reports $want is not the release that was reviewed; treat this as a supply-chain event."
    fi
    require_version "$bin" "Raise the Makefile pin and the runner image's version together, or the two drift apart; a network install is not the fix."
    if [ "$kind" = go ]; then
      # The version alone does not say which compiler built the tool: one built
      # by an older Go cannot load this module.
      TOOLCHAIN=${TOOLCHAIN:-$("$go" env GOVERSION)}
      matches "${TOOLCHAIN-}" '^go[0-9]+\.[0-9]+(\.[0-9]+)?$' ||
        die "TOOLCHAIN '${TOOLCHAIN-}' is not a Go toolchain name; the Makefile resolves it inside the module (#83)"
      built=$(built_with "$bin")
      [ "$built" = "$TOOLCHAIN" ] ||
        die "$tool at $bin was built with '${built:-an unknown Go}', but this module's toolchain is $TOOLCHAIN; rebuild the runner image's tool with $TOOLCHAIN"
    fi
    ;;
  1)
    [ -n "${TOOLS_DIR-}" ] || die "TOOLS_DIR is unset"
    case $TOOLS_DIR in /*) ;; *) die "TOOLS_DIR '$TOOLS_DIR' is not an absolute path" ;; esac
    case $TOOLS_DIR in *"$NL"*) die "TOOLS_DIR contains a newline" ;; esac
    if [ "$kind" = go ]; then
      # Resolved here, from the module in the working directory, only when a Go
      # tool is being installed: the Makefile does not pay for it per target.
      TOOLCHAIN=${TOOLCHAIN:-$("$go" env GOVERSION)}
      matches "${TOOLCHAIN-}" '^go[0-9]+\.[0-9]+(\.[0-9]+)?$' ||
        die "TOOLCHAIN '${TOOLCHAIN-}' is not a Go toolchain name; the Makefile resolves it inside the module (#83)"
      dir=$TOOLS_DIR/$tool-$want-$TOOLCHAIN
    else
      archive_pins
      dir=$TOOLS_DIR/$tool-$want
    fi
    bin=$dir/$tool
    # A copy already on PATH that proves what a cached install must is used
    # as it is: the devcontainer bakes every pin into /usr/local/bin, so a
    # gate there runs offline and writes nothing into the checkout.
    if onpath=$(command -v "$tool" 2>/dev/null) && [ "$onpath" != "$bin" ]; then
      case $onpath in
        /*) if verified "$onpath"; then
              bin=$onpath
            else
              echo "tool.sh: $tool at $onpath is not the pinned build (version, build toolchain or checksum); not using it" >&2
            fi ;;
      esac
    fi
    if ! verified "$bin"; then
      if [ "$kind" = go ]; then
        echo "tool.sh: installing $tool $want with $TOOLCHAIN into $dir" >&2
      else
        echo "tool.sh: installing $tool $want from its pinned release archive into $dir" >&2
      fi
      mkdir -p "$TOOLS_DIR"
      # Build into a private directory and rename into place, so an
      # interrupted or concurrent install never leaves a partial binary at
      # the path the next run trusts.
      tmp=$(mktemp -d "$TOOLS_DIR/.install.XXXXXX")
      trap 'rm -rf "$tmp"' EXIT
      if [ "$kind" = archive ]; then
        install_archive
      elif [ "$tool" = gosec ]; then
        build_gosec
      else
        retry go_install_once >&2 ||
          die "installing $tool $want failed"
      fi
      mkdir -p "$dir"
      mv -f "$tmp/$tool" "$bin"
      rm -rf "$tmp"
      trap - EXIT
      verified "$bin" || die "$tool: the fresh install at $bin does not verify (version, build toolchain or checksum)"
    fi
    require_version "$bin" "The install did not produce the pinned version."
    ;;
  *)
    die "TOOL_INSTALL must be 0 (require the pinned tool on PATH) or 1 (install it into the repository); got '${TOOL_INSTALL-}'"
    ;;
esac

printf '%s\n' "$bin"
