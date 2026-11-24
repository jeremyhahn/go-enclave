#!/bin/sh
# consumer-check.sh <module> <vX.Y.Z[-pre]> builds and runs a throwaway consumer of the published version in a fresh module cache.
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
