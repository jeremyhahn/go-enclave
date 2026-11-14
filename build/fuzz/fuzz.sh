#!/bin/sh
# fuzz.sh MODULE...: fuzz every native Go fuzz target in each module for a
# bounded time, one target at a time, and stop at the first failure.
#
# Run from the repository root; each MODULE is a module directory relative to
# it (`.` for the root module). Every package of each module is listed, its
# fuzz targets are found with `go test -list '^Fuzz'`, and each target runs as
#   go test -run '^$' -fuzz '^Name$' -fuzztime "$FUZZTIME" <package>
# from its module's directory.
#
# Environment:
#   GOCMD     the go command (default go)
#   FUZZTIME  how long each target fuzzes: a Go duration or Nx (default 30s)
#   FUZZ      an extended regexp; only targets whose name matches run
#   FUZZ_PKG  an extended regexp; only packages whose import path matches run
#
# Prints one line per target (ok or FAIL, package, target, seconds). A failure
# prints go's output, the package, the target and the failing input under the
# package's testdata/fuzz/, and exits 1. Nothing to fuzz exits 1; a bad
# argument or variable exits 2 before go runs.
set -eu

die() {
  printf 'fuzz: %s\n' "$1" >&2
  exit "${2:-1}"
}

[ "$#" -gt 0 ] || die "usage: fuzz.sh MODULE..." 2

go=${GOCMD:-go}
fuzztime=${FUZZTIME:-30s}
fuzz=${FUZZ:-}
fuzz_pkg=${FUZZ_PKG:-}

# FUZZTIME: what go test's -fuzztime accepts, a duration or an iteration count.
case $fuzztime in
  *[!0-9a-z.]*) die "FUZZTIME must be a Go duration or Nx: $fuzztime" 2 ;;
esac
printf '%s\n' "$fuzztime" | grep -Eqx '([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+|[0-9]+x' ||
  die "FUZZTIME must be a Go duration or Nx: $fuzztime" 2

# valid_ere NAME VALUE: VALUE is an extended regexp grep accepts.
valid_ere() {
  rc=0
  printf '' | grep -Eq -e "$2" 2> /dev/null || rc=$?
  [ "$rc" -lt 2 ] || die "$1 is not a valid extended regexp: $2" 2
}
[ -z "$fuzz" ] || valid_ere FUZZ "$fuzz"
[ -z "$fuzz_pkg" ] || valid_ere FUZZ_PKG "$fuzz_pkg"

for m in "$@"; do
  [ -d "$m" ] || die "no module directory: $m" 2
done

root=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Discovery: "<module> <package> <target>" lines in $tmp/targets.
: > "$tmp/targets"
for m in "$@"; do
  (cd "$m" && "$go" list -f '{{.ImportPath}}' ./...) > "$tmp/pkgs" ||
    die "go list failed in module $m"
  while read -r pkg; do
    [ -n "$pkg" ] || continue
    if [ -n "$fuzz_pkg" ] && ! printf '%s\n' "$pkg" | grep -Eq -e "$fuzz_pkg"; then
      continue
    fi
    if ! (cd "$m" && "$go" test -list '^Fuzz' "$pkg") > "$tmp/list" 2>&1; then
      cat "$tmp/list" >&2
      die "go test -list failed for $pkg in module $m"
    fi
    while read -r name; do
      case $name in
        Fuzz*) ;;
        *) continue ;;
      esac
      case $name in
        *[!A-Za-z0-9_]*) continue ;;
      esac
      if [ -n "$fuzz" ] && ! printf '%s\n' "$name" | grep -Eq -e "$fuzz"; then
        continue
      fi
      printf '%s %s %s\n' "$m" "$pkg" "$name" >> "$tmp/targets"
    done < "$tmp/list"
  done < "$tmp/pkgs"
done

[ -s "$tmp/targets" ] ||
  die "no fuzz targets in modules: $* (FUZZ='$fuzz' FUZZ_PKG='$fuzz_pkg')"

n=0
while read -r m pkg name; do
  start=$(date +%s)
  rc=0
  (cd "$m" && "$go" test -run '^$' -fuzz "^$name\$" -fuzztime "$fuzztime" "$pkg") \
    > "$tmp/log" 2>&1 < /dev/null || rc=$?
  secs=$(($(date +%s) - start))
  if [ "$rc" = 0 ]; then
    n=$((n + 1))
    printf 'ok   %s %s %ss\n' "$pkg" "$name" "$secs"
    continue
  fi
  printf 'FAIL %s %s %ss\n' "$pkg" "$name" "$secs"
  cat "$tmp/log"
  input=$(sed -n 's/^.*Failing input written to \(testdata\/fuzz\/[^ ]*\).*$/\1/p' "$tmp/log" | tail -n 1)
  printf 'fuzz: module %s\nfuzz: package %s\nfuzz: target %s\n' "$m" "$pkg" "$name"
  if [ -n "$input" ]; then
    dir=$(cd "$m" && "$go" list -f '{{.Dir}}' "$pkg" 2> /dev/null) || dir=
    case $dir in
      "$root") rel= ;;
      "$root"/*) rel=${dir#"$root"/}/ ;;
      *) rel= ;;
    esac
    printf 'fuzz: failing input %s%s\n' "$rel" "$input"
    printf 'fuzz: re-run it with: (cd %s && %s test -run %s %s)\n' "$m" "$go" "${input#testdata/fuzz/}" "$pkg"
  else
    printf 'fuzz: no failing input was written (a build, seed corpus or timeout failure)\n'
  fi
  exit 1
done < "$tmp/targets"

if [ "$n" = 1 ]; then
  printf 'fuzz: 1 fuzz target passed (FUZZTIME=%s)\n' "$fuzztime"
else
  printf 'fuzz: %d fuzz targets passed (FUZZTIME=%s)\n' "$n" "$fuzztime"
fi
