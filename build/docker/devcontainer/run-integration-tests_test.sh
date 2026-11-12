#!/bin/sh
# Tests for build/docker/devcontainer/run-integration-tests.sh: its usage
# refusals, its go test and covdata calls, the coverage floor it enforces
# through the real scripts/coverage-gate.sh, GO_ENCLAVE_IT_PROFILE_OUT and
# the removal of its temporary files.
#
# The runner resolves the gate relative to $0 and the suite relative to the
# working directory, so it runs as a copy in a scratch tree that holds
# test/integration/demo and copies of scripts/coverage-gate.sh and
# scripts/lib.sh. A stub `go` on PATH records every call and answers
# `go test` (exit STUB_TEST_RC), `go tool covdata textfmt` (writes the
# fixture STUB_PROFILE, or exits STUB_COVDATA_RC) and `go tool cover -func`
# (prints a fixture). The refusals run under every sh found (dash as sh,
# bash). No Docker, no network, no Go toolchain.
#
#   usage: build/docker/devcontainer/run-integration-tests_test.sh
#          (also: make check-it-runner)
set -eu

here=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd -- "$here/../../.." && pwd)
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() {
  fail=$((fail + 1))
  printf 'FAIL %s (rc=%s)\n' "$1" "$rc"
  cut -c1-200 "$D/out"
}

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
T=$D/tree
mkdir -p "$D/bin" "$D/state" "$D/fix" "$T/test/integration/demo" \
  "$T/scripts" "$T/build/docker/devcontainer"
cp "$repo/scripts/coverage-gate.sh" "$repo/scripts/lib.sh" "$T/scripts/"
cp "$here/run-integration-tests.sh" "$T/build/docker/devcontainer/"
runner=$T/build/docker/devcontainer/run-integration-tests.sh

cat > "$D/bin/go" <<'STUB'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$STUB_STATE/calls"
case $1 in
  test)
    printf '%s\n' "${GOCOVERDIR:-}" > "$STUB_STATE/gocoverdir"
    printf '%s\n' "${GOCOVERDIR:-}" >> "$STUB_STATE/paths"
    exit "${STUB_TEST_RC:-0}" ;;
  tool)
    case $2 in
      covdata)
        out=
        prev=
        for a in "$@"; do
          case $a in -i=*) printf '%s\n' "${a#-i=}" >> "$STUB_STATE/paths" ;; esac
          [ "$prev" = -o ] && out=$a
          prev=$a
        done
        [ -n "$out" ] || exit 1
        printf '%s\n' "$out" >> "$STUB_STATE/paths"
        [ "${STUB_COVDATA_RC:-0}" = 0 ] || exit "$STUB_COVDATA_RC"
        cp "$STUB_PROFILE" "$out" ;;
      cover) cat "$STUB_FUNC" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$D/bin/go"

# Fixtures: 100 statements in example.com/m/a. at90 covers 90 of them, at89
# covers 89, one statement under a floor of 90.
printf 'mode: atomic\nexample.com/m/a/a.go:1.1,9.2 90 3\nexample.com/m/a/a.go:10.1,19.2 10 0\n' > "$D/fix/at90"
printf 'mode: atomic\nexample.com/m/a/a.go:1.1,9.2 89 3\nexample.com/m/a/a.go:10.1,19.2 11 0\n' > "$D/fix/at89"
printf 'example.com/m/a/a.go:1:\tFullyCovered\t100.0%%\nexample.com/m/a/a.go:10:\tLeastCovered\t0.0%%\ntotal:\t(statements)\t89.0%%\n' > "$D/fix/func"

# run <shell> [NAME=value...]: the runner under <shell>, from the scratch
# tree, in an environment holding only PATH, HOME, the stub's state, the
# defaults and the NAME=value words given (the last assignment wins). drop_
# names one default to leave out (TESTFLAGS, FLOOR or COVERPKG); pkg_ is the
# package argument, none when nopkg_=1. Output in $D/out, status in $rc.
drop_=
pkg_=demo
nopkg_=
run() {
  sh_=$1
  shift
  rm -f "$D/state/calls" "$D/state/gocoverdir" "$D/state/paths"
  set -- PATH="$D/bin:$PATH" HOME="${HOME:-/}" STUB_STATE="$D/state" \
    STUB_FUNC="$D/fix/func" STUB_PROFILE="$D/fix/at90" "$@"
  [ "$drop_" = TESTFLAGS ] || set -- 'GO_ENCLAVE_IT_TESTFLAGS=-tags=integration -count=1' "$@"
  [ "$drop_" = FLOOR ] || set -- GO_ENCLAVE_IT_COVERAGE_FLOOR=90 "$@"
  [ "$drop_" = COVERPKG ] || set -- GO_ENCLAVE_IT_COVERPKG=example.com/m/a "$@"
  [ -n "$nopkg_" ] || set -- "$@" "$sh_" "$runner" "$pkg_"
  [ -z "$nopkg_" ] || set -- "$@" "$sh_" "$runner"
  rc=0
  (cd "$T" && env -i "$@") > "$D/out" 2>&1 || rc=$?
  drop_=
  pkg_=demo
  nopkg_=
}

has() { grep -q -- "$1" "$D/out"; }
called() { [ -f "$D/state/calls" ] && grep -q -- "$1" "$D/state/calls"; }
no_go() { [ ! -s "$D/state/calls" ]; }
# cleaned: every temporary path the stub saw is gone.
cleaned() {
  [ -f "$D/state/paths" ] || return 0
  while read -r p; do
    [ -z "$p" ] || [ ! -e "$p" ] || return 1
  done < "$D/state/paths"
}

# refused <shell> <case> <message> [NAME=value...]: exit 2, the message on
# the output, no go call.
refused() {
  r_sh=$1 r_what=$2 r_msg=$3
  shift 3
  run "$r_sh" "$@"
  if [ "$rc" = 2 ] && has "$r_msg" && no_go; then
    ok "$r_sh: refused with 2: $r_what"
  else
    bad "$r_sh: refused with 2: $r_what"
  fi
}

shells='sh'
command -v bash > /dev/null 2>&1 && shells="$shells bash"

for s in $shells; do
  nopkg_=1
  refused "$s" "no package" 'usage: run-integration-tests.sh <package>'
  pkg_=
  refused "$s" "an empty package" 'usage: run-integration-tests.sh <package>'
  drop_=FLOOR
  refused "$s" "the floor unset" 'GO_ENCLAVE_IT_COVERAGE_FLOOR is required'
  refused "$s" "the floor empty" 'GO_ENCLAVE_IT_COVERAGE_FLOOR is required' GO_ENCLAVE_IT_COVERAGE_FLOOR=
  drop_=COVERPKG
  refused "$s" "COVERPKG unset" 'GO_ENCLAVE_IT_COVERPKG is required'
  drop_=TESTFLAGS
  refused "$s" "TESTFLAGS unset" 'GO_ENCLAVE_IT_TESTFLAGS is required'
  pkg_=Demo
  refused "$s" "a capital in the package" 'invalid package name'
  pkg_=../demo
  refused "$s" "a slash in the package" 'invalid package name'
  pkg_=de.mo
  refused "$s" "a dot in the package" 'invalid package name'
  refused "$s" "a letter in the floor" 'invalid coverage floor' GO_ENCLAVE_IT_COVERAGE_FLOOR=9o
  refused "$s" "a negative floor" 'invalid coverage floor' GO_ENCLAVE_IT_COVERAGE_FLOOR=-1
  pkg_=nosuch
  refused "$s" "a missing suite directory" 'test/integration/nosuch does not exist'
  for f in 1.2.3 . 1. .5 1..2; do
    refused "$s" "the floor '$f'" 'invalid coverage floor' GO_ENCLAVE_IT_COVERAGE_FLOOR="$f"
  done
done

# A good run: the go test call and its coverage directory.
run sh
dir_=$(cat "$D/state/gocoverdir" 2>/dev/null || true)
if [ "$rc" = 0 ] && [ -n "$dir_" ] &&
  called "^test -tags=integration -count=1 -cover -coverpkg=example.com/m/a ./test/integration/demo -args -test.gocoverdir=$dir_\$" &&
  called "^tool covdata textfmt -i=$dir_ -pkg=example.com/m/a -o " &&
  has 'example.com/m/a coverage: 90.00% (90 of 100 statements, floor 90%)' &&
  ! has 'Least-covered' && cleaned; then
  ok "a profile at the floor passes; go test gets the flags and one coverage dir"
else bad "a profile at the floor passes"; fi

run sh GO_ENCLAVE_IT_COVERAGE_FLOOR=89.5
if [ "$rc" = 0 ] && cleaned; then ok "a decimal floor under the profile passes"
else bad "a decimal floor under the profile passes"; fi

run sh STUB_PROFILE="$D/fix/at89"
if [ "$rc" = 1 ] && has 'FAIL: example.com/m/a coverage 89.00% is below the 90% floor' &&
  has 'Least-covered functions (integration):' && has 'LeastCovered' &&
  ! has 'FullyCovered' && ! has '^total:' && cleaned; then
  ok "one statement under the floor fails and lists the least-covered functions"
else bad "one statement under the floor fails"; fi

run sh GO_ENCLAVE_IT_COVERPKG=example.com/m/a,example.com/m/b
if [ "$rc" = 1 ] && has 'FAIL: example.com/m/b has no coverage at all' &&
  has 'Least-covered functions' && cleaned; then
  ok "a cover package absent from the profile fails"
else bad "a cover package absent from the profile fails"; fi

run sh STUB_TEST_RC=3
if [ "$rc" = 3 ] && ! called '^tool ' && cleaned; then
  ok "go test failing fails the run with its status, no covdata call"
else bad "go test failing fails the run"; fi

run sh STUB_COVDATA_RC=4
if [ "$rc" = 4 ] && ! called '^tool cover' && ! has 'coverage:' && cleaned; then
  ok "covdata failing fails the run with its status, no gate"
else bad "covdata failing fails the run"; fi

run sh GO_ENCLAVE_IT_PROFILE_OUT="$D/copied"
if [ "$rc" = 0 ] && cmp -s "$D/fix/at90" "$D/copied" &&
  ! has 'BEGIN GO_ENCLAVE_IT_PROFILE' && cleaned; then
  ok "PROFILE_OUT as a path copies the merged profile"
else bad "PROFILE_OUT as a path copies the merged profile"; fi

run sh GO_ENCLAVE_IT_PROFILE_OUT=-
awk '/^END GO_ENCLAVE_IT_PROFILE$/ { f = 0 } f; /^BEGIN GO_ENCLAVE_IT_PROFILE$/ { f = 1 }' \
  "$D/out" > "$D/printed"
if [ "$rc" = 0 ] && cmp -s "$D/fix/at90" "$D/printed" && has '^END GO_ENCLAVE_IT_PROFILE$' && cleaned; then
  ok "PROFILE_OUT=- prints the merged profile between the markers"
else bad "PROFILE_OUT=- prints the merged profile between the markers"; fi

# A failed copy fails the run and still removes the temporary files.
run sh GO_ENCLAVE_IT_PROFILE_OUT="$D/no/such/dir/profile"
if [ "$rc" != 0 ] && cleaned; then ok "a failed PROFILE_OUT copy fails the run and cleans up"
else bad "a failed PROFILE_OUT copy fails the run and cleans up"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
