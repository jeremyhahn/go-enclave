#!/bin/sh
# userns-test.sh: the root package's user-namespace test in the devcontainer's userns service (make integration-test-userns).
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 0 ] || die "usage: $0"
compose=${DEVCONTAINER_COMPOSE:-build/docker/devcontainer/compose.yaml}
service=userns
test_name=TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace

[ -f "$compose" ] || die "$compose not found. The user-namespace test runs in the project devcontainer, never on the host."
[ -f "${compose%/*}/seccomp-userns.json" ] || die "${compose%/*}/seccomp-userns.json not found: without its profile the test cannot create a user namespace."
{ command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; } || die "'docker compose' (Compose v2) is required to run the user-namespace test in the devcontainer."
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "the Docker daemon is not reachable (docker version cannot read the server). The user-namespace test runs in the devcontainer and cannot run without it."

if [ -z "${GO_ENCLAVE_IT_IMAGE-}" ]; then
  exec sh "$here/integration-image.sh" sh "$here/userns-test.sh"
fi
require_scanned_image

project="go-enclave-userns-$(date +%s)-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
echo "compose project: $project"

out=$(mktemp)
cleanup() {
  rc=$?
  rm -f "$out"
  if ! docker compose -f "$compose" -p "$project" down --volumes --remove-orphans >/dev/null 2>&1; then
    echo "ERROR: teardown of compose project $project failed; remove it with: docker compose -f '$compose' -p '$project' down --volumes --remove-orphans" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# -run is anchored and the output must show the test passed, so a rename of the
# test makes this fail instead of running nothing.
status=0
docker compose -f "$compose" -p "$project" run --rm --pull never "$service" \
  go test -tags=userns -race -count=1 -v -timeout=300s -run "^${test_name}\$" . >"$out" 2>&1 || status=$?
cat "$out"
[ "$status" -eq 0 ] || die "$test_name failed"
grep -q -- "^--- PASS: $test_name " "$out" || die "$test_name did not pass: nothing ran"
