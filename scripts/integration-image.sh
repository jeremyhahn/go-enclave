#!/bin/sh
# integration-image.sh — build the integration image once, scan it, and run a
# command against that exact image.
#
# Usage: scripts/integration-image.sh <command> [arg...]   (from the repository root)
#
# The command is what runs the suites: scripts/integration-test.sh and
# scripts/userns-test.sh (directly, or through make). They find the image in
# GO_ENCLAVE_IT_IMAGE, which this script sets to a tag unique to this run, and
# they neither build nor scan: the userns, default and FIPS suites all run on the
# one image that was scanned. Rebuilding per suite could produce different bytes
# (the Dockerfile upgrades packages), so a scan of the first build would say
# nothing about the later ones. The scripts run it themselves when
# GO_ENCLAVE_IT_IMAGE is unset, so a single suite is built and scanned the same way.
#
# The image is identified by its ID: it is read after the build, the scan must
# leave it unchanged, GO_ENCLAVE_IT_IMAGE_ID carries it, and each suite refuses an
# image that no longer has it (scripts/lib.sh, require_scanned_image). The image
# is removed when the command ends, on every exit.
#
# Environment (exported by the Makefile): DEVCONTAINER_COMPOSE,
# DEVCONTAINER_SERVICE and TRIVY_VERSION.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -ge 1 ] || die "usage: $0 <command> [arg...]"
[ -z "${GO_ENCLAVE_IT_IMAGE-}" ] || die "GO_ENCLAVE_IT_IMAGE is already set to '${GO_ENCLAVE_IT_IMAGE-}': the image is built and scanned here, once, not supplied"
compose=${DEVCONTAINER_COMPOSE:-build/docker/devcontainer/compose.yaml}
service=${DEVCONTAINER_SERVICE:-integration}

[ -f "$compose" ] || die "$compose not found. Integration tests run in the project devcontainer, never on the host (integration-testing §4)."
{ command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; } || die "'docker compose' (Compose v2) is required to run the integration suite in the devcontainer."
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "the Docker daemon is not reachable (docker version cannot read the server). The integration suite runs in the devcontainer and cannot run without it."

# The scanner first, so a missing or wrong trivy fails before a build.
trivy=$(sh "$here/tool.sh" trivy "${TRIVY_VERSION:?TRIVY_VERSION is required}")

suffix="$(date +%s)-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
image="go-enclave-it:$suffix"
project="go-enclave-itimg-$suffix"
echo "integration image: $image"

cleanup() {
  rc=$?
  if docker image inspect "$image" >/dev/null 2>&1 && ! docker image rm "$image" >/dev/null 2>&1; then
    echo "ERROR: removing the integration image $image failed; remove it with: docker image rm '$image'" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

GO_ENCLAVE_IT_IMAGE=$image docker compose -f "$compose" -p "$project" build "$service"
id=$(docker image inspect --format '{{.Id}}' "$image")
matches "$id" '^sha256:[0-9a-f]{64}$' || die "the built image $image has no usable ID ('$id')"

echo "trivy image $image ($id; CRITICAL,HIGH, fixable only — devops §8)"
"$trivy" image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
  --ignorefile .trivyignore --skip-version-check --format table "$image"
[ "$(docker image inspect --format '{{.Id}}' "$image")" = "$id" ] || die "the image $image changed while it was scanned"

GO_ENCLAVE_IT_IMAGE=$image GO_ENCLAVE_IT_IMAGE_ID=$id
export GO_ENCLAVE_IT_IMAGE GO_ENCLAVE_IT_IMAGE_ID
# Not exec: the image is removed after the command, whatever its status.
"$@"
