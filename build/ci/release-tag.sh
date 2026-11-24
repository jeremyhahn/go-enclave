#!/bin/sh
# release-tag.sh writes the tag and its commit to $GITHUB_OUTPUT, refusing anything but a plain version string.
set -eu

case ${GITHUB_REF:-} in
  refs/tags/v*) tag=${GITHUB_REF#refs/tags/} ;;
  *) echo "::error::release.yml ran for a ref that is not a v* tag"; exit 1 ;;
esac
case $tag in
  *[!0-9A-Za-z.-]*) echo "::error::the tag name holds characters no release version does; refusing it"; exit 1 ;;
esac

sha=$(git rev-parse HEAD)
printf 'Releasing %s from %s\n' "$tag" "$sha"
{
  echo "tag=$tag"
  echo "sha=$sha"
} >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
