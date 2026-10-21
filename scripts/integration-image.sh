#!/bin/sh
# integration-image.sh — name the integration image by its content, build it
# when the daemon lacks it, scan it, and run a command against that exact image.
#
# Usage: scripts/integration-image.sh <command> [arg...]   (from the repository root)
#
# The command is what runs the suites: scripts/integration-test.sh and
# scripts/userns-test.sh (directly, or through make). They find the image in
# GO_ENCLAVE_IT_IMAGE, which this script sets, and they neither build nor scan:
# the userns, default and FIPS suites all run on the one image that was scanned.
# Rebuilding per suite could produce different bytes (the Dockerfile upgrades
# packages), so a scan of the first build would say nothing about the later
# ones. The scripts run it themselves when GO_ENCLAVE_IT_IMAGE is unset, so a
# single suite is built and scanned the same way.
#
# The image is IT_IMAGE when the caller names it (ci.yml passes `make -s
# it-image`), else scripts/devcontainer.sh it-tag: go-enclave-ci-it:<hash> of
# the build context (ci-standard.md §9). Every job and run of one tree on one
# Docker host names the same image, so it is built only when the daemon does
# not hold that tag, and no run removes it: CI's reap step
# (scripts/reap-stale-ci-stacks.sh) removes one that is old and unused.
#
# The image is identified by its ID: it is read before the scan, the scan must
# leave it unchanged, GO_ENCLAVE_IT_IMAGE_ID carries it, and each suite refuses an
# image that no longer has it (scripts/lib.sh, require_scanned_image).
#
# Environment (exported by the Makefile): DEVCONTAINER_COMPOSE,
# DEVCONTAINER_SERVICE, TRIVY_VERSION and IT_IMAGE.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -ge 1 ] || die "usage: $0 <command> [arg...]"
[ -z "${GO_ENCLAVE_IT_IMAGE-}" ] || die "GO_ENCLAVE_IT_IMAGE is already set to '${GO_ENCLAVE_IT_IMAGE-}': the image is named and scanned here, once, not supplied"
compose=${DEVCONTAINER_COMPOSE:-build/docker/devcontainer/compose.yaml}
service=${DEVCONTAINER_SERVICE:-integration}

[ -f "$compose" ] || die "$compose not found. Integration tests run in the project devcontainer, never on the host (integration-testing §4)."
{ command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; } || die "'docker compose' (Compose v2) is required to run the integration suite in the devcontainer."
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "the Docker daemon is not reachable (docker version cannot read the server). The integration suite runs in the devcontainer and cannot run without it."

# The scanner first, so a missing or wrong trivy fails before a build.
trivy=$(sh "$here/tool.sh" trivy "${TRIVY_VERSION:?TRIVY_VERSION is required}")

if [ -n "${IT_IMAGE:-}" ]; then image=$IT_IMAGE; else image=$(sh "$here/devcontainer.sh" it-tag); fi
matches "$image" '^go-enclave-ci-it:[0-9a-f]{12}$' || die "the integration image '$image' is not a go-enclave-ci-it:<hash> tag"
echo "integration image: $image"

if docker image inspect "$image" >/dev/null 2>&1; then
  echo "integration image $image is already held; not rebuilt"
else
  project="go-enclave-itimg-$(date +%s)-$$"
  GO_ENCLAVE_IT_IMAGE=$image docker compose -f "$compose" -p "$project" build "$service"
fi
id=$(docker image inspect --format '{{.Id}}' "$image")
matches "$id" '^sha256:[0-9a-f]{64}$' || die "the integration image $image has no usable ID ('$id')"

echo "trivy image $image ($id; CRITICAL,HIGH, fixable only — devops §8)"
"$trivy" image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
  --ignorefile .trivyignore --skip-version-check --format table "$image"
[ "$(docker image inspect --format '{{.Id}}' "$image")" = "$id" ] || die "the image $image changed while it was scanned"

GO_ENCLAVE_IT_IMAGE=$image GO_ENCLAVE_IT_IMAGE_ID=$id
export GO_ENCLAVE_IT_IMAGE GO_ENCLAVE_IT_IMAGE_ID
exec "$@"
