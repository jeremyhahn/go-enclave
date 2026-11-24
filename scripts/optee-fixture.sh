#!/bin/sh
# optee-fixture.sh check|harness: run the OP-TEE fixture at the pinned trusted-firmware commit, or the arm-trustzone harness in it.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

url=${TRUSTED_FIRMWARE_URL:-}
tag=${TRUSTED_FIRMWARE_TAG:-}
commit=${TRUSTED_FIRMWARE_COMMIT:-}
cache=${TRUSTED_FIRMWARE_CACHE:-}
[ -n "$cache" ] || cache=${HOME:?HOME is unset}/.cache/go-enclave/trusted-firmware
endpoint=${GO_ENCLAVE_OPTEE_ENDPOINT-}
prebuilt=${OPTEE_FIXTURE_PREBUILT:-}
seal=${GO_ENCLAVE_OPTEE_SEAL-}

[ "$#" -eq 1 ] || die "usage: $prog check|harness"
case $1 in
  check | harness) mode=$1 ;;
  *) die "unknown mode '$1': want check or harness" ;;
esac
[ -n "$tag" ] || die "TRUSTED_FIRMWARE_TAG is empty; scripts/tool-pins.sh pins the trusted-firmware release whose make optee-run is the fixture"
case $tag in
  .* | *[!A-Za-z0-9._-]*) die "TRUSTED_FIRMWARE_TAG '$tag' is not a release tag name" ;;
esac
case $commit in
  '') die "TRUSTED_FIRMWARE_COMMIT is empty; scripts/tool-pins.sh pins the commit TRUSTED_FIRMWARE_TAG peels to" ;;
  *[!0-9a-f]*) die "TRUSTED_FIRMWARE_COMMIT '$commit' is not a full lowercase commit id" ;;
esac
[ "${#commit}" -eq 40 ] || die "TRUSTED_FIRMWARE_COMMIT '$commit' is not a full 40-digit commit id"

# One directory per tag; an existing checkout is used, and OPTEE_FIXTURE_PREBUILT=1 refuses to clone.
dir=$cache/$tag
if [ ! -e "$dir/.git" ]; then
  [ "$prebuilt" != 1 ] || die "the fixture image holds no trusted-firmware checkout at $dir; see docs/backend-conformance/engineering.md#fixture-image-contract"
  [ -n "$url" ] || die "TRUSTED_FIRMWARE_URL is empty; set it to the forge's trusted-firmware clone URL"
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
# An empty knob declares the pinned release's TA has no SEAL (absent:<tag>); "required" makes a missing SEAL fail.
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
# The conformance test is the nested backends/armtrustzone module's, compiled into ARM_TRUSTZONE_BIN in the toolchain image.
bin=${OPTEE_TEST_BIN:-}
case $bin in
  '' | .* | *[!A-Za-z0-9._-]*) die "OPTEE_TEST_BIN '$bin' is not a file name; make integration-test-arm-trustzone sets it to armtrustzone.test" ;;
esac
out=${ARM_TRUSTZONE_BIN:-}
[ -n "$out" ] && [ -f "$out" ] || die "ARM_TRUSTZONE_BIN '$out' is not a file; run make integration-test-arm-trustzone, which compiles it in the toolchain image"
cp "$out" "$share/$bin"
rc=0
tfmake optee-run OPTEE_SHARE="$share" \
  OPTEE_GUEST_CMD="GO_ENCLAVE_OPTEE_ENDPOINT=$endpoint GO_ENCLAVE_OPTEE_SEAL=$seal ./$bin -test.v -test.run='^(TestBackendConformance|TestKeyProtectorConformance)_OnOPTEE' -test.bench='^Benchmark(OpenUseClose|Access)' -test.benchtime=2s" || rc=$?
exit "$rc"
