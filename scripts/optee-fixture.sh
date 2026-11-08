#!/bin/sh
# optee-fixture.sh — the OP-TEE fixture from the pinned trusted-firmware release.
#
# Usage: scripts/optee-fixture.sh check|harness   (from the repository root)
#
# The body of `make optee-fixture-check` (check) and of
# `make integration-test-arm-trustzone` (harness). Both clone trusted-firmware
# at TRUSTED_FIRMWARE_TAG into TRUSTED_FIRMWARE_CACHE/<tag>, outside the tree,
# and refuse unless the checkout's HEAD is TRUSTED_FIRMWARE_COMMIT: a moved tag
# is refused, never followed. check runs the checkout's
# `make integration-test-optee` (xtest and the TA's version and rng commands;
# no go-enclave code). harness takes backends/armtrustzone's optee-tagged
# conformance test, a static linux/arm64 test binary the make target compiled
# in the toolchain image ($ARM_TRUSTZONE_BIN), shares it with the aarch64 guest
# and exits with
# the status of `make optee-run`, which is the binary's.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

url=${TRUSTED_FIRMWARE_URL:-}
tag=${TRUSTED_FIRMWARE_TAG:-}
commit=${TRUSTED_FIRMWARE_COMMIT:-}
cache=${TRUSTED_FIRMWARE_CACHE:-}
[ -n "$cache" ] || cache=${HOME:?HOME is unset}/.cache/go-enclave/trusted-firmware
endpoint=${GO_ENCLAVE_OPTEE_ENDPOINT-}
seal=${GO_ENCLAVE_OPTEE_SEAL-}

[ "$#" -eq 1 ] || die "usage: $prog check|harness"
case $1 in
  check | harness) mode=$1 ;;
  *) die "unknown mode '$1': want check or harness" ;;
esac
[ -n "$url" ] || die "TRUSTED_FIRMWARE_URL is empty; set it to the forge's trusted-firmware clone URL"
[ -n "$tag" ] || die "TRUSTED_FIRMWARE_TAG is empty; scripts/tool-pins.sh pins the trusted-firmware release whose make optee-run is the fixture"
case $tag in
  .* | *[!A-Za-z0-9._-]*) die "TRUSTED_FIRMWARE_TAG '$tag' is not a release tag name" ;;
esac
case $commit in
  '') die "TRUSTED_FIRMWARE_COMMIT is empty; scripts/tool-pins.sh pins the commit TRUSTED_FIRMWARE_TAG peels to" ;;
  *[!0-9a-f]*) die "TRUSTED_FIRMWARE_COMMIT '$commit' is not a full lowercase commit id" ;;
esac
[ "${#commit}" -eq 40 ] || die "TRUSTED_FIRMWARE_COMMIT '$commit' is not a full 40-digit commit id"

# One directory per tag; a clone lands in place only when it is complete.
dir=$cache/$tag
if [ ! -e "$dir/.git" ]; then
  mkdir -p "$cache"
  tmp=$(mktemp -d "$cache/.clone.XXXXXX")
  if ! git clone --quiet --depth 1 --branch "$tag" -c advice.detachedHead=false -- "$url" "$tmp/tf"; then
    rm -rf "$tmp"
    die "cannot clone $url at $tag"
  fi
  mv "$tmp/tf" "$dir"
  rmdir "$tmp"
fi
head=$(git -C "$dir" rev-parse --verify --quiet 'HEAD^{commit}') || die "$dir has no HEAD commit; remove it and rerun"
[ "$head" = "$commit" ] || die "$dir is at $head, not TRUSTED_FIRMWARE_COMMIT $commit (tag $tag moved, or the cache was altered); refusing"
[ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ] || die "$dir has modified tracked files; remove it and rerun"
echo "trusted-firmware $tag at $commit: $dir"

# The checkout's make is its own: nothing of this make's flags reaches it.
tfmake() { env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -C "$dir" "$@"; }

if [ "$mode" = check ]; then
  tfmake integration-test-optee
  exit
fi

# The guest command is one shell line run in the share: the endpoint is a
# device path, and an empty one reaches the harness, which fails typed.
case $endpoint in
  *[!A-Za-z0-9/._-]*) die "GO_ENCLAVE_OPTEE_ENDPOINT '$endpoint' is not a device path" ;;
esac
# The pinned trusted-firmware release's TA has no SEAL: an empty knob
# declares so, as absent:<tag>, which lets the KeyProtector test skip on a
# missing SEAL only while <tag> is the release the test knows lacks it.
# "required" makes a missing SEAL fail.
case $seal in
  '') seal="absent:$tag" ;;
  required) ;;
  *) die "GO_ENCLAVE_OPTEE_SEAL '$seal' is not empty or 'required'" ;;
esac
echo "GO_ENCLAVE_OPTEE_SEAL=$seal"
share=$(mktemp -d "${TMPDIR:-/tmp}/go-enclave-optee.XXXXXX")
trap 'rm -rf "$share"' EXIT
case $share in
  *[,\ ]*) die "the share directory '$share' holds a comma or a space, which optee-run refuses; set TMPDIR" ;;
esac
# The conformance test is the nested module's: backends/armtrustzone
# registers its backend in-process. The root's optee-tagged harness is not run:
# the root go.mod never requires the nested module, so nothing can register
# the backend in that binary and its conformance test can only refuse.
# make integration-test-arm-trustzone compiles the binary in the toolchain
# image (the pinned Go and verified module cache, offline) and names it in
# ARM_TRUSTZONE_BIN; only the QEMU orchestration below runs on the host.
bin=${OPTEE_TEST_BIN:-}
case $bin in
  '' | .* | *[!A-Za-z0-9._-]*) die "OPTEE_TEST_BIN '$bin' is not a file name; make integration-test-arm-trustzone sets it to armtrustzone.test" ;;
esac
out=${ARM_TRUSTZONE_BIN:-}
[ -n "$out" ] && [ -f "$out" ] || die "ARM_TRUSTZONE_BIN '$out' is not a file; run make integration-test-arm-trustzone, which compiles it in the toolchain image"
cp "$out" "$share/$bin"
rc=0
tfmake optee-run OPTEE_SHARE="$share" \
  OPTEE_GUEST_CMD="GO_ENCLAVE_OPTEE_ENDPOINT=$endpoint GO_ENCLAVE_OPTEE_SEAL=$seal ./$bin -test.v -test.run='^(TestBackendConformance|TestKeyProtectorConformance)_OnOPTEE'" || rc=$?
exit "$rc"
