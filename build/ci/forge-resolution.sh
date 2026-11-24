#!/bin/sh
# forge-resolution.sh asserts the runner configured GOPRIVATE and a tokened git rewrite, checking shape only and printing nothing.
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
