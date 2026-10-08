#!/bin/sh
# forge-resolution.sh — assert the runner configured module resolution for the
# forge (dependency-resolution §6).
#
# Usage: sh build/ci/forge-resolution.sh
#
# On our runners the module resolves from the forge only through GOPRIVATE plus
# a git insteadOf rewrite carrying a read token, both injected by act_runner.
# Without them `go get` asks the public proxy, which has never seen an internal
# tag, and fails with an unrelated-looking "unknown revision". Checked by SHAPE
# only: the rewrite's KEY contains the token, so nothing here is printed.
set -eu

if [ -z "$(go env GOPRIVATE)" ]; then
  echo "::error::GOPRIVATE is not set in this job; the runner must inject it (dependency-resolution §6)"
  exit 1
fi

n=${GIT_CONFIG_COUNT:-0}
case $n in '' | *[!0-9]*) n=0 ;; esac
found=0
i=0
while [ "$i" -lt "$n" ]; do
  key=$(printenv "GIT_CONFIG_KEY_$i" || true)
  case $key in url.*.insteadOf | url.*.insteadof) found=1 ;; esac
  i=$((i + 1))
done
if [ "$found" -ne 1 ]; then
  echo "::error::no git insteadOf rewrite is configured in this job; the runner must inject GIT_CONFIG_* (dependency-resolution §6)"
  exit 1
fi
echo "GOPRIVATE and a git insteadOf rewrite are present"
