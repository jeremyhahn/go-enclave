#!/bin/sh
# integration-image.sh <command> [arg...]: build the content-named integration image when missing, scan it unless IT_SCAN=0, and run command against that image ID.
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
scan=1
[ "${IT_SCAN:-1}" != 0 ] || scan=0
if [ "$scan" = 1 ]; then
  trivy=$(sh "$here/tool.sh" trivy "${TRIVY_VERSION:?TRIVY_VERSION is required}")
fi

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

if [ "$scan" = 1 ]; then
  echo "trivy image $image ($id; CRITICAL,HIGH, fixable only — devops §8)"
  "$trivy" image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
    --ignorefile .trivyignore --skip-version-check --format table "$image"
  [ "$(docker image inspect --format '{{.Id}}' "$image")" = "$id" ] || die "the image $image changed while it was scanned"
else
  echo "IT_SCAN=0: $image ($id) is not scanned here; scans.yml scans it on main (ruling 742 (1))"
fi

GO_ENCLAVE_IT_IMAGE=$image GO_ENCLAVE_IT_IMAGE_ID=$id
export GO_ENCLAVE_IT_IMAGE GO_ENCLAVE_IT_IMAGE_ID
exec "$@"
