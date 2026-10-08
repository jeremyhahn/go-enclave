#!/bin/sh
# release-tag.sh — name the tag a release run is for, and the commit it names.
#
# Usage: sh build/ci/release-tag.sh
#
# Reads GITHUB_REF and writes `tag=` and `sha=` to $GITHUB_OUTPUT. Git accepts
# tag names such as v`id` and v$(id), and release.yml's `v*` trigger matches
# them. The tag is DATA from here on: every later step receives it through
# `env:` and every make target reads it as a quoted shell variable. It is
# refused here too, before it is echoed or becomes an output, unless it is a
# plain version string.
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
