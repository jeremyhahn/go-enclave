#!/bin/sh
# consumer-check.sh — build and run a throwaway consumer of a published version.
#
# Usage: scripts/consumer-check.sh <module> <vX.Y.Z[-pre]>
#
# Handbook release-versioning §2 (ratified 2026-08-14): post-tag verification
# MUST build a throwaway consumer. Every build inside this repository resolves
# the module from the working tree, so what `go get <module>@<tag>` actually
# hands a consumer — the module zip as the forge serves it, its go.mod, its
# recorded requirements and their checksums — is exercised by nothing else.
#
# In a fresh directory outside the repository, with GOWORK=off and a fresh
# module cache, this:
#   1. `go mod init`s a scratch module and `go get`s <module>@<version>;
#   2. asserts the build list really selected <version> from the module cache
#      — not a replacement, not a different version;
#   3. `go mod verify`s the downloaded modules against go.sum;
#   4. builds scripts/testdata/consumer/main.go and runs it, requiring its
#      success marker.
#
# Resolution is whatever the environment says, deliberately untouched here
# (dependency-resolution §1, §6): on a Gitea runner the act_runner injects
# GOPRIVATE and the git insteadOf rewrite carrying a read token, so the module
# is fetched from Gitea; on GitHub and for public consumers there is no
# rewrite and it comes from the public proxy. This script sets neither, never
# prints either, and clears GOFLAGS and sets no GONOSUMDB or GOINSECURE.
#
# The fresh module cache is the point, not a cost: a cache already holding the
# module would answer from local bytes and prove nothing about the forge.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <module> <vX.Y.Z[-pre]>"
module=$1
version=$2
matches "$module" '^[a-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9._~-]+)+$' || die "'$module' is not a module path"
matches "$version" "$VERSION_RE" || die "'$version' is not vX.Y.Z[-pre]"

program=$here/testdata/consumer/main.go
[ -f "$program" ] || die "consumer program $program not found"
command -v go >/dev/null 2>&1 || die "go is not on PATH"

work=$(mktemp -d "${TMPDIR:-/tmp}/consumer-check.XXXXXX")
# The module cache is written read-only; `go clean -modcache` is the supported
# way to remove one.
cleanup() {
  GOMODCACHE=$work/modcache go clean -modcache >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

GOWORK=off
GOMODCACHE=$work/modcache
# The runner's GOFLAGS (-mod=vendor, -modfile, -tags) must not shape the consumer.
GOFLAGS=
export GOWORK GOMODCACHE GOFLAGS

mkdir "$work/consumer"
cd "$work/consumer"
echo "$prog: resolving $module@$version in a scratch module (GOWORK=off, fresh module cache)"
go mod init example.com/go-enclave-consumer-check >/dev/null 2>&1 || die "go mod init failed"
go get "$module@$version" || die "go get $module@$version failed"

selected=$(go list -m -f '{{.Version}}|{{if .Replace}}replaced{{end}}|{{.Dir}}' "$module")
case $selected in
  "$version||$GOMODCACHE/"*) ;;
  *) die "the build list does not hold $module@$version from the module cache: $selected" ;;
esac

go mod verify || die "go mod verify failed for the consumer's dependencies"

cp "$program" main.go
go build -o consumer . || die "the consumer program does not build against $module@$version"
out=$(./consumer) || die "the consumer program failed against $module@$version: $out"
[ "$out" = "consumer-check: ok" ] || die "unexpected consumer output: $out"
echo "consumer-check: $module@$version builds and runs in a fresh consumer"
