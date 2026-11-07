#!/bin/sh
# devcontainer.sh — build, run and name the devcontainer images.
#
# Usage: scripts/devcontainer.sh tag | it-tag | inputs | build | run [command]
#
#   tag     print the toolchain image's content-addressed reference,
#           go-enclave-toolchain:<12 hex> (`make toolchain-image`; lane-verify's
#           VERIFY_IMAGE). It is a hash of the files that build the toolchain
#           stage, so it names the image a checkout builds without Docker, and
#           an unchanged tag means an existing image can be reused.
#   it-tag  print the integration image's content-addressed reference,
#           go-enclave-ci-it:<12 hex> (`make -s it-image`, ci-standard.md §9).
#           It is a hash of the build arguments and the whole build context:
#           the commit's tree, the checkout's diff against it, and every
#           untracked file .gitignore does not exclude, so every job and run
#           of one tree names one image and builds it once.
#   inputs  print the toolchain tag's files, one per line.
#   build   build both shipped stages (`make docker-build`): the toolchain,
#           tagged <tag> and go-enclave-toolchain:latest, then the integration
#           image through compose, tagged $GO_ENCLAVE_IT_IMAGE (default
#           <it-tag>). A stage whose content tag the daemon holds already
#           is not built (the toolchain's :latest is still set), and a build
#           that fails while another job tags the same content counts as built.
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
    backends/armtrustzone/go.mod \
    backends/armtrustzone/go.sum \
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

# The integration stage takes no build argument; its context is the checkout.
# Each step is checked: a hash over a failed listing would name an image that
# no tree built.
it_image() {
  command -v git >/dev/null 2>&1 || die "git is required for 'it-tag'"
  ctx=$(mktemp) || die "could not create a temporary file"
  untracked=$(mktemp) || { rm -f "$ctx"; die "could not create a temporary file"; }
  ok=1
  printf 'dockerfile %s\ntarget integration\nbuild-args APK_INDEX_SUM=%s\n' "$dockerfile" "${APK_INDEX_SUM:-}" >"$ctx" || ok=0
  [ "$ok" = 0 ] || git rev-parse 'HEAD^{tree}' >>"$ctx" || ok=0
  [ "$ok" = 0 ] || git diff --binary HEAD -- >>"$ctx" || ok=0
  [ "$ok" = 0 ] || git ls-files -z --others --exclude-standard >"$untracked" || ok=0
  if [ "$ok" = 1 ] && [ -s "$untracked" ]; then
    xargs -0 sha256sum -- <"$untracked" >>"$ctx" || ok=0
  fi
  [ "$ok" = 0 ] || sum=$(sha256sum <"$ctx" | cut -c1-12) || ok=0
  rm -f "$ctx" "$untracked"
  [ "$ok" = 1 ] || die "could not hash the integration image's build context"
  matches "$sum" '^[0-9a-f]{12}$' || die "could not hash the integration image's build context"
  printf 'go-enclave-ci-it:%s\n' "$sum"
}

docker_ok() {
  command -v docker >/dev/null 2>&1 || die "docker is required for '$1'"
}

# held <ref>: the daemon holds the tag. Every tag build makes is content
# addressed, so a held tag is the image this tree builds. Two jobs on one
# daemon race to the same content tag: the loser's BuildKit export fails with
# "already exists", and a tag held after a failed build counts as built.
held() {
  docker image inspect "$1" >/dev/null 2>&1
}

[ $# -ge 1 ] || die "usage: $0 tag | it-tag | inputs | build | run [command]"
case $1 in
  tag)
    [ $# -eq 1 ] || die "usage: $0 tag"
    image
    ;;
  it-tag)
    [ $# -eq 1 ] || die "usage: $0 it-tag"
    it_image
    ;;
  inputs)
    [ $# -eq 1 ] || die "usage: $0 inputs"
    inputs
    ;;
  build)
    [ $# -eq 1 ] || die "usage: $0 build"
    docker_ok build
    ref=$(image)
    # The backend modules' download fetches the private root module through
    # GO_BUILD_PROXY, a LAN Go module proxy in CI (#293); no forge credential
    # reaches the build. Unset, the Dockerfile's public default applies.
    set -- -f "$dockerfile" --target toolchain -t "$ref" -t "$repo:latest"
    if [ -n "${GO_BUILD_PROXY:-}" ]; then
      set -- "$@" --build-arg "GO_BUILD_PROXY=$GO_BUILD_PROXY"
    fi
    if held "$ref"; then
      docker tag "$ref" "$repo:latest"
      echo "$ref is already held; tagged $repo:latest"
    elif ! DOCKER_BUILDKIT=1 docker build "$@" .; then
      held "$ref" || die "building $ref failed"
      docker tag "$ref" "$repo:latest"
      echo "$ref was built by another job meanwhile; tagged $repo:latest"
    fi
    if [ -n "${GO_ENCLAVE_IT_IMAGE:-}" ]; then it=$GO_ENCLAVE_IT_IMAGE; else it=$(it_image); fi
    if held "$it"; then
      echo "$it is already held"
    elif ! GO_ENCLAVE_IT_IMAGE=$it docker compose -f "$compose" -p "$project" build integration; then
      held "$it" || die "building $it failed"
      echo "$it was built by another job meanwhile"
    fi
    echo "built $ref ($repo:latest) and $it"
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
    die "unknown command '$1' (tag, it-tag, inputs, build, run)"
    ;;
esac
