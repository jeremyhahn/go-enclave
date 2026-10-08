#!/bin/sh
# publish-release.sh — publish the forge release, once this job is on the commit
# the gate ran on.
#
# Usage: sh build/ci/publish-release.sh
#
# Environment: TAG, SHA (the commit the verify job saw), FORGE_TOKEN, and the
# GITHUB_API_URL and GITHUB_REPOSITORY the runner sets. Tags are immutable by
# policy (release-versioning §3); this makes it a checked property too.
set -eu

head=$(git rev-parse HEAD)
if [ "$head" != "${SHA:?SHA is required}" ]; then
  echo "::error::this job checked out $head, but the gate ran on $SHA"
  exit 1
fi
FORGE_API_URL=${GITHUB_API_URL:?GITHUB_API_URL is required} \
FORGE_REPOSITORY=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required} \
  make release-publish
