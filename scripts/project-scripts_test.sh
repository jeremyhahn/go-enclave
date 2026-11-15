#!/bin/sh
# Tests for five scripts that decide a gate: swtpm-fixture.sh,
# test-runtimesecret.sh, cross-build.sh, lint-integration.sh and
# release-verify.sh. Each runs on stub tools on a temporary PATH (go, swtpm,
# swtpm_ioctl and sleep record every call; a knob in the environment makes one
# fail), so no toolchain, TPM, network or Docker is needed. Per script: its
# refusal of bad input, the success path with the exact calls (targets, tags,
# flags, GOEXPERIMENT, CGO_ENABLED), each failure it reports and, for the ones
# that make them, that no temporary directory or swtpm process is left.
# release-verify runs the real release-check-tag.sh on a scratch git tree.
#
#   usage: scripts/project-scripts_test.sh   (also: make check-project-scripts)
#
# A case's conditions are single-quoted strings that `all` evaluates after the
# run, so their expansions are meant to wait and the values they read look
# unused to shellcheck.
# shellcheck disable=SC2016,SC2034
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() {
  fail=$((fail + 1))
  printf 'FAIL %s (rc=%s)\n' "$1" "$rc"
  cat "$D/out" 2>/dev/null || true
  [ ! -f "$D/want" ] || diff "$D/want" "$D/calls" || true
}

# The caller's toolchain settings must not reach the scripts or the stubs.
unset GOOS GOARCH CGO_ENABLED GOEXPERIMENT GOFLAGS GOCMD GO_ENCLAVE_SWTPM SWTPM_PORT SWTPM_CTRL_PORT

SH=$(command -v sh)
SLEEP=$(command -v sleep)
D=$(mktemp -d)
cleanup() {
  if [ -f "$D/swtpm.pid" ]; then kill "$(cat "$D/swtpm.pid")" 2>/dev/null || true; fi
  rm -rf "$D"
}
trap cleanup EXIT
mkdir -p "$D/bin" "$D/goroot/bin" "$D/tmp" "$D/empty" "$D/only" "$D/root/backends/tpm"
echo 'module example.com/tpm' > "$D/root/backends/tpm/go.mod"

# rec FILE PREFIX ARG...: append "PREFIX ARG..." to FILE, any path under
# TMPDIR shown as <tmp>, so a mktemp name never reaches a comparison.
cat > "$D/rec.sh" <<'STUB'
rec() {
  _f=$1 _line=$2
  shift 2
  for _a in "$@"; do
    case $_a in
      *"$TMPDIR"/*)
        _pre=${_a%%"$TMPDIR"/*}
        _rest=${_a#*"$TMPDIR"/}
        _a="$_pre<tmp>${_rest#"${_rest%%/*}"}"
        ;;
    esac
    _line="$_line $_a"
  done
  printf '%s\n' "$_line" >> "$_f"
}
STUB

# go: records its environment and arguments. STUB_FAIL is a pattern over
# "GOOS/GOARCH ARGS"; a match exits STUB_FAIL_RC (3). `env GOROOT` names
# $D/goroot, whose bin/go is this same stub. `list` answers the file selection
# (secret_erase.go on the targets in STUB_ERASE) or the integration file
# counts (STUB_WITH with the tag, STUB_WITHOUT without, each with an _RC).
# STUB_GO_HOLD makes `test` wait for HOLD.release after creating HOLD.started.
cat > "$D/bin/go" <<'STUB'
#!/bin/sh
. "$STUB_D/rec.sh"
env="${GOOS-}/${GOARCH-} cgo=${CGO_ENABLED-} exp=${GOEXPERIMENT-}"
[ -z "${GO_ENCLAVE_SWTPM-}" ] || env="$env swtpm=$GO_ENCLAVE_SWTPM dir=${PWD##*/}"
rec "$STUB_CALLS" "${0#"$STUB_D"/} $env :" "$@"
# shellcheck disable=SC2254
case "${GOOS-}/${GOARCH-} $*" in
  ${STUB_FAIL:-no-failure}) exit "${STUB_FAIL_RC:-3}" ;;
esac
case $1 in
  env) printf '%s\n' "$STUB_D/goroot" ;;
  list)
    case "$*" in
      *join*)
        case " ${STUB_ERASE-linux/amd64 linux/arm64} " in
          *" $GOOS/$GOARCH "*) echo 'secret.go secret_erase.go' ;;
          *) echo 'secret.go secret_noerase.go' ;;
        esac ;;
      *-tags=integration*) printf '%s\n' "${STUB_WITH-10}"; exit "${STUB_WITH_RC:-0}" ;;
      *) printf '%s\n' "${STUB_WITHOUT-00}"; exit "${STUB_WITHOUT_RC:-0}" ;;
    esac ;;
  test)
    if [ -n "${STUB_GO_HOLD-}" ]; then
      : > "$STUB_GO_HOLD.started"
      n=0
      until [ -e "$STUB_GO_HOLD.release" ] || [ "$n" -ge 30 ]; do "$STUB_SLEEP" 1; n=$((n + 1)); done
    fi ;;
esac
exit 0
STUB
cp "$D/bin/go" "$D/goroot/bin/go"

# swtpm: records its arguments in swtpm.calls (it runs in the background, so
# apart from the other calls), its pid in swtpm.pid, then runs until killed;
# STUB_SWTPM_EXIT makes it exit at once instead.
cat > "$D/bin/swtpm" <<'STUB'
#!/bin/sh
. "$STUB_D/rec.sh"
rec "$STUB_D/swtpm.calls" swtpm "$@"
echo "$$" > "$STUB_D/swtpm.pid"
[ -z "${STUB_SWTPM_EXIT-}" ] || exit "$STUB_SWTPM_EXIT"
exec "$STUB_SLEEP" 300
STUB
# swtpm_ioctl: fails its first STUB_IOCTL_FAILS calls, then answers.
cat > "$D/bin/swtpm_ioctl" <<'STUB'
#!/bin/sh
. "$STUB_D/rec.sh"
rec "$STUB_CALLS" swtpm_ioctl "$@"
n=$(cat "$STUB_D/ioctl.n" 2>/dev/null || echo 0)
echo $((n + 1)) > "$STUB_D/ioctl.n"
[ "$n" -ge "${STUB_IOCTL_FAILS:-0}" ]
STUB
# sleep: records, never waits.
cat > "$D/bin/sleep" <<'STUB'
#!/bin/sh
. "$STUB_D/rec.sh"
rec "$STUB_CALLS" sleep "$@"
STUB
chmod +x "$D/bin/go" "$D/goroot/bin/go" "$D/bin/swtpm" "$D/bin/swtpm_ioctl" "$D/bin/sleep"
cp "$D/bin/swtpm" "$D/only/swtpm"

reset() {
  rm -f "$D/calls" "$D/want" "$D/swtpm.calls" "$D/swtpm.pid" "$D/ioctl.n" "$D/hold".*
  : > "$D/calls"
  rc=0
}
# run DIR [VAR=VALUE...] CMD...: CMD in DIR on the stub PATH, its status in
# $rc, its output in $D/out.
run() {
  reset
  _dir=$1
  shift
  (cd "$_dir" && env PATH="$D/bin:$PATH" TMPDIR="$D/tmp" STUB_D="$D" STUB_CALLS="$D/calls" \
    STUB_SLEEP="$SLEEP" "$@") > "$D/out" 2>&1 || rc=$?
}
rc_is() { [ "$rc" = "$1" ]; }
says() { grep -qF -- "$1" "$D/out"; }
no_calls() { [ ! -s "$D/calls" ]; }
# calls_are LINE...: the recorded calls are exactly these lines, in order.
calls_are() { printf '%s\n' "$@" > "$D/want"; cmp -s "$D/want" "$D/calls"; }
tmp_empty() { [ -z "$(ls -A "$D/tmp")" ]; }
swtpm_gone() { [ -f "$D/swtpm.pid" ] && ! kill -0 "$(cat "$D/swtpm.pid")" 2>/dev/null; }
check() { if "$@"; then ok "$what"; else bad "$what"; fi; }
all() { for _c in "$@"; do eval "$_c" || return 1; done; }

# --- swtpm-fixture.sh ---------------------------------------------------------
fixture="$here/swtpm-fixture.sh"
tpm_test='test -race -count=1 -tags swtpm -run OnSWTPM -v ./...'
swtpm_line() {
  echo "swtpm socket --tpm2 --tpmstate dir=<tmp> --server type=tcp,port=$1,bindaddr=127.0.0.1 --ctrl type=tcp,port=$2,bindaddr=127.0.0.1 --flags not-need-init,startup-clear --log file=<tmp>/swtpm.log,level=1"
}
swtpm_started() { [ "$(cat "$D/swtpm.calls")" = "$(swtpm_line "$1" "$2")" ]; }

for p in abc 0 0123 -1 65536 123456; do
  run "$D/root" SWTPM_PORT="$p" "$SH" "$fixture"
  what="swtpm-fixture: SWTPM_PORT '$p' is refused before swtpm starts"
  check all 'rc_is 1' 'says "port '"'$p'"' is"' no_calls '[ ! -f "$D/swtpm.calls" ]'
done
run "$D/root" SWTPM_CTRL_PORT=99999 "$SH" "$fixture"
what="swtpm-fixture: an out-of-range SWTPM_CTRL_PORT is refused"
check all 'rc_is 1' 'says "out of range"' '[ ! -f "$D/swtpm.calls" ]'
run "$D/root" SWTPM_PORT=4000 SWTPM_CTRL_PORT=4000 "$SH" "$fixture"
what="swtpm-fixture: equal command and control ports are refused"
check all 'rc_is 1' 'says "must differ"' '[ ! -f "$D/swtpm.calls" ]'
run "$D/root" PATH="$D/empty" "$SH" "$fixture"
what="swtpm-fixture: no swtpm on PATH fails the run"
check all 'rc_is 1' 'says "swtpm is not on PATH"'
run "$D/root" PATH="$D/only" "$SH" "$fixture"
what="swtpm-fixture: no swtpm_ioctl on PATH fails the run"
check all 'rc_is 1' 'says "swtpm_ioctl is not on PATH"' '[ ! -f "$D/swtpm.calls" ]'
run "$D" "$SH" "$fixture"
what="swtpm-fixture: outside the repository root it refuses"
check all 'rc_is 1' 'says "no backends/tpm/go.mod"' '[ ! -f "$D/swtpm.calls" ]'

run "$D/root" STUB_IOCTL_FAILS=2 "$SH" "$fixture"
what="swtpm-fixture: polls the control port, runs the swtpm suite, stops swtpm, removes its state"
check all 'rc_is 0' 'swtpm_started 2321 2322' 'calls_are \
  "swtpm_ioctl --tcp 127.0.0.1:2322 -g" "sleep 1" \
  "swtpm_ioctl --tcp 127.0.0.1:2322 -g" "sleep 1" \
  "swtpm_ioctl --tcp 127.0.0.1:2322 -g" \
  "bin/go / cgo= exp= swtpm=tcp:127.0.0.1:2321 dir=tpm : $tpm_test"' \
  'says "swtpm on 127.0.0.1:2321 (control 2322)"' swtpm_gone tmp_empty

run "$D/root" SWTPM_PORT=4001 SWTPM_CTRL_PORT=4002 "$SH" "$fixture"
what="swtpm-fixture: SWTPM_PORT and SWTPM_CTRL_PORT reach swtpm, the poll and the suite"
check all 'rc_is 0' 'swtpm_started 4001 4002' 'calls_are \
  "swtpm_ioctl --tcp 127.0.0.1:4002 -g" \
  "bin/go / cgo= exp= swtpm=tcp:127.0.0.1:4001 dir=tpm : $tpm_test"' swtpm_gone tmp_empty

run "$D/root" STUB_FAIL='/ test*' STUB_FAIL_RC=7 "$SH" "$fixture"
what="swtpm-fixture: a failing suite fails the run with its status, and cleans up"
check all 'rc_is 7' swtpm_gone tmp_empty

run "$D/root" STUB_IOCTL_FAILS=99 "$SH" "$fixture"
what="swtpm-fixture: a swtpm that never answers fails after 30 polls, and cleans up"
check all 'rc_is 1' 'says "did not answer on 127.0.0.1:2322 within 30 s"' swtpm_gone tmp_empty \
  '! grep -q "^bin/go" "$D/calls"'

run "$D/root" STUB_IOCTL_FAILS=99 STUB_SWTPM_EXIT=1 "$SH" "$fixture"
what="swtpm-fixture: a swtpm that exits before it answers fails the run, and cleans up"
check all 'rc_is 1' 'says "swtpm exited before it answered"' tmp_empty '! grep -q "^bin/go" "$D/calls"'

# TERM while the suite runs: the trap stops swtpm and removes its state.
reset
(cd "$D/root" && exec env PATH="$D/bin:$PATH" TMPDIR="$D/tmp" STUB_D="$D" STUB_CALLS="$D/calls" \
  STUB_SLEEP="$SLEEP" STUB_GO_HOLD="$D/hold" "$SH" "$fixture") > "$D/out" 2>&1 &
bg=$!
n=0
until [ -e "$D/hold.started" ] || [ "$n" -ge 30 ]; do "$SLEEP" 1; n=$((n + 1)); done
kill -TERM "$bg" 2>/dev/null || true
: > "$D/hold.release"
wait "$bg" || rc=$?
what="swtpm-fixture: TERM during the suite exits 143, stops swtpm and removes its state"
check all 'rc_is 143' swtpm_gone tmp_empty

# --- test-runtimesecret.sh ----------------------------------------------------
rts="$here/test-runtimesecret.sh"
proof='^TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret$'
sel() { echo "goroot/bin/go $1 cgo=0 exp=runtimesecret : list -f {{join .GoFiles \" \"}} ."; }
selection="$(sel linux/amd64)$NL$(sel linux/arm64)$NL$(sel linux/386)$NL$(sel android/amd64)$NL$(sel android/arm64)$NL$(sel darwin/arm64)"

run "$D/root" GOEXPERIMENT=bogus CGO_ENABLED=1 "$SH" "$rts" -race -count=1
what="test-runtimesecret: resolves the toolchain with the experiment unset, checks six targets, runs suite and proof"
check all 'rc_is 0' 'calls_are "bin/go / cgo=1 exp= : env GOROOT" "$selection" \
  "goroot/bin/go / cgo=1 exp=runtimesecret : test -race -count=1 -skip $proof ./..." \
  "goroot/bin/go / cgo=1 exp=runtimesecret : test -count=5 -cpu=1,2,8 -run $proof ."' \
  'says "erasure selection darwin/arm64: secret_noerase.go"'

run "$D/root" STUB_ERASE=linux/amd64 "$SH" "$rts" -count=1
what="test-runtimesecret: linux/arm64 without secret_erase.go fails before any test"
check all 'rc_is 1' 'says "on linux/arm64 does not build secret_erase.go"' '! grep -q " : test" "$D/calls"'

run "$D/root" STUB_ERASE='linux/amd64 linux/arm64 linux/386' "$SH" "$rts" -count=1
what="test-runtimesecret: linux/386 with secret_erase.go fails before any test"
check all 'rc_is 1' 'says "on linux/386 does not build secret_noerase.go"' '! grep -q " : test" "$D/calls"'

run "$D/root" STUB_FAIL='/ env*' "$SH" "$rts" -count=1
what="test-runtimesecret: a failing go env GOROOT fails the run before any build"
check all '! rc_is 0' 'calls_are "bin/go / cgo= exp= : env GOROOT"'

run "$D/root" STUB_FAIL='/ test -count=1*' "$SH" "$rts" -count=1
what="test-runtimesecret: a failing suite fails the run and the proof does not run"
check all 'rc_is 3' '! grep -q -- "-cpu=1,2,8" "$D/calls"'

run "$D/root" STUB_FAIL='/ test -count=5*' "$SH" "$rts" -count=1
what="test-runtimesecret: a failing erasure proof fails the run"
check all 'rc_is 3' 'grep -q -- "-cpu=1,2,8" "$D/calls"'

# --- cross-build.sh -----------------------------------------------------------
xb="$here/cross-build.sh"
xcalls() {
  for _t in "$@"; do
    printf '%s\n' "bin/go $_t cgo=0 exp= : build ./... ./cmd/x" "bin/go $_t cgo=0 exp= : vet ./... ./cmd/x" \
      "bin/go $_t cgo=0 exp= : test -c -o <tmp>/ ./... ./cmd/x"
  done
}

run "$D/root" "$SH" "$xb" linux/amd64 ./...
what="cross-build: no -- is a usage error"
check all 'rc_is 1' 'says "usage:"' no_calls

run "$D/root" "$SH" "$xb" -- ./...
what="cross-build: no target is a usage error"
check all 'rc_is 1' 'says "usage:"' no_calls

run "$D/root" "$SH" "$xb" linux/amd64 --
what="cross-build: no package is a usage error"
check all 'rc_is 1' 'says "usage:"' no_calls

run "$D/root" CGO_ENABLED=1 "$SH" "$xb" linux/amd64 darwin/arm64 -- ./... ./cmd/x
what="cross-build: builds, vets and links tests per target with cgo off, and removes its output"
check all 'rc_is 0' 'calls_are "$(xcalls linux/amd64 darwin/arm64)"' 'says "cross-build darwin/arm64"' tmp_empty

run "$D/root" STUB_FAIL='darwin/arm64 vet*' "$SH" "$xb" linux/amd64 darwin/arm64 -- ./... ./cmd/x
what="cross-build: a failing vet on one target fails the run there, and removes its output"
check all 'rc_is 3' 'calls_are "$(xcalls linux/amd64)" "bin/go darwin/arm64 cgo=0 exp= : build ./... ./cmd/x" \
  "bin/go darwin/arm64 cgo=0 exp= : vet ./... ./cmd/x"' tmp_empty

run "$D/root" STUB_FAIL='linux/amd64 test*' "$SH" "$xb" linux/amd64 darwin/arm64 -- ./... ./cmd/x
what="cross-build: a test binary that does not link fails the run"
check all 'rc_is 3' '! grep -q darwin "$D/calls"' tmp_empty

# --- lint-integration.sh ------------------------------------------------------
li="$here/lint-integration.sh"
fmt='{{len .TestGoFiles}}{{len .XTestGoFiles}}'
lcalls() {
  for _p in "$@"; do
    printf '%s\n' "bin/go / cgo= exp= : list -tags=integration -f $fmt ./test/integration/$_p" \
      "bin/go / cgo= exp= : list -e -f $fmt ./test/integration/$_p"
  done
}

run "$D/root" "$SH" "$li"
what="lint-integration: no package is a usage error"
check all 'rc_is 1' 'says "usage:"' no_calls

run "$D/root" "$SH" "$li" enclave other
what="lint-integration: every package's suite needs the integration tag"
check all 'rc_is 0' 'calls_are "$(lcalls enclave other)"'

run "$D/root" STUB_WITHOUT= STUB_WITHOUT_RC=1 "$SH" "$li" enclave
what="lint-integration: a package that fails to list without the tag passes"
check all 'rc_is 0' 'calls_are "$(lcalls enclave)"'

run "$D/root" STUB_WITH=00 "$SH" "$li" enclave
what="lint-integration: a tag that selects no test files fails"
check all 'rc_is 1' 'says "-tags=integration selects no test files in test/integration/enclave"'

run "$D/root" STUB_WITH= STUB_WITH_RC=1 "$SH" "$li" enclave
what="lint-integration: a package that fails to list with the tag fails"
check all '! rc_is 0' 'calls_are "bin/go / cgo= exp= : list -tags=integration -f $fmt ./test/integration/enclave"'

run "$D/root" STUB_WITHOUT=01 "$SH" "$li" enclave
what="lint-integration: test files that build without the tag fail"
check all 'rc_is 1' 'says "test/integration/enclave has test files that build WITHOUT the integration tag (01)"'

# --- release-verify.sh --------------------------------------------------------
rv="$here/release-verify.sh"
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
R="$D/rel"
git init -q -b main "$R"
echo scratch > "$R/README"
git -C "$R" add README
git -C "$R" commit -q -m first
git -C "$R" branch old
echo 1.2.3 > "$R/VERSION"
printf '# Changelog\n\n## [Unreleased]\n\n## [v1.2.3] - 2026-01-01\n\n### Added\n\n- A thing.\n' > "$R/CHANGELOG.md"
git -C "$R" add VERSION CHANGELOG.md
git -C "$R" commit -q -m release

run "$R" "$SH" "$rv"
what="release-verify: no tag is a usage error"
check all 'rc_is 1' 'says "usage:"'

run "$R" "$SH" "$rv" ''
what="release-verify: an empty tag is refused"
check all 'rc_is 1' 'says "TAG=vX.Y.Z[-pre] is required"'

for ref in -x 'main branch' 'main;true' 'main$(id)'; do
  run "$R" "$SH" "$rv" v1.2.3 "$ref"
  what="release-verify: MAIN_REF '$ref' is refused before any check"
  check all 'rc_is 1' 'says "MAIN_REF is not a plain ref name"' '! says "agrees"'
done

run "$R" "$SH" "$rv" v1.2.3
what="release-verify: a tag that agrees with VERSION and CHANGELOG.md passes"
check all 'rc_is 0' 'says "v1.2.3 agrees with VERSION and CHANGELOG.md"' '! says "HEAD is on"'

run "$R" "$SH" "$rv" v1.2.3 main
what="release-verify: HEAD on MAIN_REF passes"
check all 'rc_is 0' 'says "release-verify: HEAD is on main"'

run "$R" "$SH" "$rv" v1.2.4 main
what="release-verify: a tag that disagrees with VERSION fails before the ref check"
check all 'rc_is 1' "says \"VERSION reads '1.2.3' but the tag is 'v1.2.4'\"" '! says "HEAD is on"'

run "$R" "$SH" "$rv" v1.2.3 nosuch
what="release-verify: a MAIN_REF that names no commit fails"
check all 'rc_is 1' "says \"MAIN_REF 'nosuch' does not name a commit\""

run "$R" "$SH" "$rv" v1.2.3 old
what="release-verify: HEAD not on MAIN_REF fails"
check all 'rc_is 1' 'says "is not on old"'

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
