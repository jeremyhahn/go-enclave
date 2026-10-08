#!/bin/sh
# devcontainer.sh — build, run and name the devcontainer images.
#
# Usage: scripts/devcontainer.sh tag | inputs | build | run [command]
#
#   tag     print the toolchain image's content-addressed reference,
#           go-enclave-toolchain:<12 hex> (`make toolchain-image`; lane-verify's
#           VERIFY_IMAGE). It is a hash of the files that build the toolchain
#           stage, so it names the image a checkout builds without Docker, and
#           an unchanged tag means an existing image can be reused.
#   inputs  print those files, one per line.
#   build   build both shipped stages (`make docker-build`): the toolchain,
#           tagged <tag> and go-enclave-toolchain:latest, then the integration
#           image through compose (go-enclave-devcontainer-integration).
#   run     run a command in the toolchain image with the checkout mounted,
#           offline, as the invoking user (`make docker-run CMD='make lint'`);
#           the command is one string, run by bash -c. Without one, the
#           image's default command.
#
# Runs from the repository root, wherever it is called from.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

cd "$here/.."

dockerfile=build/docker/devcontainer/Dockerfile
compose=build/docker/devcontainer/compose.yaml
project=go-enclave-devcontainer
repo=go-enclave-toolchain

# Every file a COPY in the Dockerfile's tools and toolchain stages reads, plus
# the Dockerfile and its context allowlist. build/ci/buildgates holds this list to
# the Dockerfile's COPY lines.
inputs() {
  printf '%s\n' \
    "$dockerfile" \
    "$dockerfile.dockerignore" \
    go.mod \
    go.sum \
    build/ci/buildgates/go.mod \
    build/ci/buildgates/go.sum \
    scripts/lib.sh \
    scripts/tool.sh \
    scripts/tool-pins.sh \
    scripts/install-tools.sh
}

# Names and contents both count: renaming an input is a different image.
image() {
  files=$(inputs)
  for f in $files; do [ -f "$f" ] || die "toolchain input $f is missing"; done
  # $files is one path per line, none with spaces.
  # shellcheck disable=SC2086
  sum=$(sha256sum $files | sha256sum | cut -c1-12)
  matches "$sum" '^[0-9a-f]{12}$' || die "could not hash the toolchain inputs"
  printf '%s:%s\n' "$repo" "$sum"
}

docker_ok() {
  command -v docker >/dev/null 2>&1 || die "docker is required for '$1'"
}

[ $# -ge 1 ] || die "usage: $0 tag | inputs | build | run [command]"
case $1 in
  tag)
    [ $# -eq 1 ] || die "usage: $0 tag"
    image
    ;;
  inputs)
    [ $# -eq 1 ] || die "usage: $0 inputs"
    inputs
    ;;
  build)
    [ $# -eq 1 ] || die "usage: $0 build"
    docker_ok build
    ref=$(image)
    docker build -f "$dockerfile" --target toolchain -t "$ref" -t "$repo:latest" .
    docker compose -f "$compose" -p "$project" build integration
    echo "built $ref ($repo:latest) and $project-integration"
    ;;
  run)
    [ $# -le 2 ] || die "usage: $0 run [command]"
    docker_ok run
    ref=$(image)
    GO_ENCLAVE_TOOLCHAIN_TAG=${ref#*:}
    GO_ENCLAVE_UID=$(id -u)
    GO_ENCLAVE_GID=$(id -g)
    # Root on the host is still not root in the container (compose.yaml).
    if [ "$GO_ENCLAVE_UID" = 0 ]; then GO_ENCLAVE_UID=10001 GO_ENCLAVE_GID=10001; fi
    export GO_ENCLAVE_TOOLCHAIN_TAG GO_ENCLAVE_UID GO_ENCLAVE_GID
    if [ -n "${2-}" ]; then
      docker compose -f "$compose" -p "$project" run --rm toolchain bash -c "$2"
    else
      docker compose -f "$compose" -p "$project" run --rm toolchain
    fi
    ;;
  *)
    die "unknown command '$1' (tag, inputs, build, run)"
    ;;
esac
