#!/bin/sh
# Tests for four scripts that decide a gate: test-runtimesecret.sh,
# cross-build.sh, lint-integration.sh and release-verify.sh. Each runs on a
# stub go on a temporary PATH (it records every call; a knob in the
# environment makes one fail), so no toolchain, network or Docker is needed.
# Per script: its refusal of bad input, the success path with the exact calls
# (targets, tags, flags, GOEXPERIMENT, CGO_ENABLED), each failure it reports
# and, for the one that makes them, that no temporary directory is left.
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
unset GOOS GOARCH CGO_ENABLED GOEXPERIMENT GOFLAGS GOCMD

SH=$(command -v sh)
D=$(mktemp -d)
cleanup() { rm -rf "$D"; }
trap cleanup EXIT
mkdir -p "$D/bin" "$D/goroot/bin" "$D/tmp" "$D/root"

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
cat > "$D/bin/go" <<'STUB'
#!/bin/sh
. "$STUB_D/rec.sh"
env="${GOOS-}/${GOARCH-} cgo=${CGO_ENABLED-} exp=${GOEXPERIMENT-}"
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
esac
exit 0
STUB
cp "$D/bin/go" "$D/goroot/bin/go"
chmod +x "$D/bin/go" "$D/goroot/bin/go"

reset() {
  rm -f "$D/calls" "$D/want"
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
    "$@") > "$D/out" 2>&1 || rc=$?
}
rc_is() { [ "$rc" = "$1" ]; }
says() { grep -qF -- "$1" "$D/out"; }
no_calls() { [ ! -s "$D/calls" ]; }
# calls_are LINE...: the recorded calls are exactly these lines, in order.
calls_are() { printf '%s\n' "$@" > "$D/want"; cmp -s "$D/want" "$D/calls"; }
tmp_empty() { [ -z "$(ls -A "$D/tmp")" ]; }
check() { if "$@"; then ok "$what"; else bad "$what"; fi; }
all() { for _c in "$@"; do eval "$_c" || return 1; done; }

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
