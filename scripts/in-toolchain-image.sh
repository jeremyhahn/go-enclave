#!/usr/bin/env bash
# in-toolchain-image.sh <image> <command...>: run a command in the toolchain image against a copy of the checkout, with the job slot's CPU and memory bounds and named cache volumes.
set -euo pipefail
# Every script shares scripts/lib.sh.
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <image> <command...>" >&2
  exit 2
fi
image=$1
shift
network=${IN_IMAGE_NETWORK:-none}
case $network in
  none | bridge) ;;
  *) echo "IN_IMAGE_NETWORK must be none or bridge: $network" >&2; exit 2 ;;
esac

uid=${IN_IMAGE_UID:-10001}
case $uid in
  "" | 0 | *[!0-9]*) echo "IN_IMAGE_UID must be a non-root numeric uid: $uid" >&2; exit 2 ;;
esac
prefix=${CI_STACK_PREFIX:-$(basename "$PWD")-ci-}
name="${prefix}tc-$$-${RANDOM}"
cache=${CI_CACHE:-on}
case $cache in
  on | off) ;;
  *) echo "CI_CACHE must be on or off: $cache" >&2; exit 2 ;;
esac
class=${CI_CACHE_CLASS:-pr}
case $class in
  pr | main) ;;
  *) echo "CI_CACHE_CLASS must be pr or main: $class" >&2; exit 2 ;;
esac
cpus=${IN_IMAGE_CPUS:-}
if [ -z "$cpus" ]; then
  quota=max period=100000
  if [ -r /sys/fs/cgroup/cpu.max ]; then read -r quota period < /sys/fs/cgroup/cpu.max; fi
  case $quota in
    max | "" | *[!0-9]*) cpus=$(nproc) ;;
    *) cpus=$(((quota + period - 1) / period)) ;;
  esac
fi
case $cpus in
  "" | 0 | *[!0-9]*) echo "IN_IMAGE_CPUS must be a positive integer: $cpus" >&2; exit 2 ;;
esac
# Cap the CPU bound at the daemon's NCPU, since the daemon refuses --cpus above it.
if ! daemon_cpus=$(docker info --format '{{.NCPU}}' 2>/dev/null); then daemon_cpus=; fi
case $daemon_cpus in
  "" | 0 | *[!0-9]*) ;;
  *) if [ "$cpus" -gt "$daemon_cpus" ]; then cpus=$daemon_cpus; fi ;;
esac
memory=${IN_IMAGE_MEMORY:-}
if [ -z "$memory" ]; then
  limit=max
  if [ -r /sys/fs/cgroup/memory.max ]; then read -r limit < /sys/fs/cgroup/memory.max; fi
  case $limit in
    max | "" | *[!0-9]*) memory=8g ;;
    *) memory=$limit ;;
  esac
fi
if ! [[ $memory =~ ^[1-9][0-9]*[mg]?$ ]]; then
  echo "IN_IMAGE_MEMORY must be a size in bytes, m or g, e.g. 16g: $memory" >&2
  exit 2
fi
cgroup_parent=${CI_CGROUP_PARENT-ci.slice}
if [ -n "$cgroup_parent" ] && ! [[ $cgroup_parent =~ ^[A-Za-z0-9][A-Za-z0-9_.@:/-]*$ ]]; then
  echo "CI_CGROUP_PARENT must be a cgroup name such as ci.slice, or empty: $cgroup_parent" >&2
  exit 2
fi
args=(
  --name "$name"
  --cpus "$cpus"
  --env GOMAXPROCS="$cpus"
  --env GOFLAGS="-p=$cpus"
  --init
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --pids-limit 4096
  --memory "$memory"
  --memory-swap "$memory"
  --ulimit memlock=16777216:16777216 # CUSTOMIZE: compose.yaml's memlock
  --ulimit core=1048576:1048576
  --ulimit nofile=4096:4096 # CUSTOMIZE: compose.yaml's nofile
  --tmpfs "/tmp:rw,exec,nosuid,nodev,size=3g,mode=1777"
  --network "$network"
  --user "$uid:$uid"
  --workdir /src
  --env HOME=/tmp
  --env CI="${CI:-}"
)
if [ -n "$cgroup_parent" ]; then
  args+=(--cgroup-parent "$cgroup_parent")
fi
modcache=/tmp/gomodcache
if [ "$cache" = on ]; then
  vols="${prefix}cache-${class}"
  docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges:true --user 0:0 \
    -v "$vols-gobuild:/c/gobuild" -v "$vols-golangci:/c/golangci" -v "$vols-gomod:/c/gomod" \
    "$image" sh -c "for d in /c/*; do [ \"\$(stat -c %u:%g \"\$d\")\" = $uid:$uid ] || chown $uid:$uid \"\$d\"; done" >/dev/null
  args+=(
    -v "$vols-gobuild:/cache/gobuild" --env GOCACHE=/cache/gobuild
    -v "$vols-golangci:/cache/golangci" --env GOLANGCI_LINT_CACHE=/cache/golangci
  )
  if [ "$network" = bridge ]; then
    args+=(-v "$vols-gomod:/cache/gomod")
    modcache=/cache/gomod
  fi
fi
if [ "$network" = bridge ]; then
  # A bridge stage gets a per-run GOPATH on the tmpfs and DEVCACHE_GOPROXY, when set, before the public proxy, with no direct entry.
  args+=(--env "GOPROXY=${DEVCACHE_GOPROXY:+$DEVCACHE_GOPROXY|}https://proxy.golang.org" --env "GOMODCACHE=$modcache"
    --env GOPATH=/tmp/gopath)
  # The runner's Trivy database repositories travel with the stage.
  for v in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 \
    TRIVY_DB_REPOSITORY TRIVY_JAVA_DB_REPOSITORY TRIVY_INSECURE; do
    if [ -n "${!v:-}" ]; then args+=(--env "$v"); fi
  done
fi

cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker create "${args[@]}" "$image" sh -c "$*" >/dev/null
tar -C "$PWD" --owner="$uid" --group="$uid" --numeric-owner -cf - . |
  docker cp -a - "$name:/src"
docker start -a "$name"
