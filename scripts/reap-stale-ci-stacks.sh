#!/usr/bin/env bash
# reap-stale-ci-stacks.sh <prefix> [min-age-seconds]: remove this repo's stale CI stacks, containers and unleased images on the runner host; REAP_DRY_RUN=1 only prints.
set -u
# Every script shares scripts/lib.sh.
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

prefix=${1:-}
min_age=${2:-11100}
case $prefix in
  '' | *[!A-Za-z0-9_.-]*) echo "usage: $0 <prefix [A-Za-z0-9_.-]> [min-age-seconds]" >&2; exit 2 ;;
esac
case $min_age in
  '' | *[!0-9]*) echo "min-age-seconds must be a number: $min_age" >&2; exit 2 ;;
esac
image_min_age=${REAP_IMAGE_MIN_AGE:-7200}
case $image_min_age in
  '' | *[!0-9]*) echo "REAP_IMAGE_MIN_AGE must be a number: $image_min_age" >&2; exit 2 ;;
esac

lock_wait=${REAP_LOCK_WAIT:-60}
case $lock_wait in
  '' | *[!0-9]*) echo "REAP_LOCK_WAIT must be a number: $lock_wait" >&2; exit 2 ;;
esac

now=$(date +%s)

# run <command...>: the command, or only its echo under REAP_DRY_RUN=1.
run() {
  if [ "${REAP_DRY_RUN:-0}" = 1 ]; then echo "dry   $*"; else "$@" >/dev/null; fi
}

# stale <container>: 0 when the container is stale (as above), 1 otherwise.
stale() {
  local state finished created t
  read -r state finished created < <(docker inspect -f '{{.State.Status}} {{.State.FinishedAt}} {{.Created}}' "$1" 2>/dev/null) || return 1
  case $state in
    exited | dead) t=$finished ;;
    created) t=$created ;;
    *) return 1 ;;
  esac
  t=$(date -d "$t" +%s 2>/dev/null) || return 1
  [ $((now - t)) -ge "$min_age" ]
}

# image_lock: take the daemon's image lock (v5, above), waiting up to
# REAP_LOCK_WAIT seconds; 1 when it is not taken. image_unlock drops it.
lock="${prefix}image-lock"
lock_id=
image_lock() {
  local base="$lock:base" held at t i
  for ((i = 0; i < lock_wait; i++)); do
    docker image inspect "$base" >/dev/null 2>&1 ||
      head -c 1024 /dev/zero | docker import - "$base" >/dev/null 2>&1
    lock_id=$(docker create --pull never --name "$lock" "$base" true 2>/dev/null) && return 0
    lock_id=
    if read -r held at < <(docker inspect -f '{{.Id}} {{.Created}}' "$lock" 2>/dev/null) &&
      t=$(date -d "$at" +%s 2>/dev/null) && [ $(($(date +%s) - t)) -ge 600 ]; then
      echo "lock  removing the stale $lock (created $at)"
      docker rm "$held" >/dev/null 2>&1
      continue
    fi
    sleep 1
  done
  return 1
}
image_unlock() {
  [ -z "$lock_id" ] || docker rm "$lock_id" >/dev/null 2>&1
  lock_id=
}
trap image_unlock EXIT

reaped=0

# Compose projects.
for project in $(docker ps -a --filter label=com.docker.compose.project \
    --format '{{.Label "com.docker.compose.project"}}' | sort -u); do
  case $project in "$prefix"*) ;; *) continue ;; esac
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  keep=0
  for id in $ids; do stale "$id" || { keep=1; break; }; done
  if [ "$keep" = 1 ]; then
    echo "keep  $project (a container is live or stopped within ${min_age}s)"
    continue
  fi
  # shellcheck disable=SC2086 # one id per word
  set -- $ids
  echo "reap  $project: $# container(s)"
  run docker rm -v "$@" || echo "warn  $project: container removal failed"
  for net in $(docker network ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker network rm "$net" || echo "warn  $project: network $net not removed"
  done
  for vol in $(docker volume ls -q --filter "label=com.docker.compose.project=$project"); do
    run docker volume rm "$vol" || echo "warn  $project: volume $vol not removed"
  done
  reaped=$((reaped + 1))
done

# Containers outside compose.
docker ps -a --filter "name=^$prefix" \
    --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}}' |
  while read -r id name project; do
    [ -z "$project" ] || continue
    case $name in "$prefix"*) ;; *) continue ;; esac
    if stale "$id"; then
      echo "reap  container $name"
      run docker rm -v "$id" || echo "warn  container $name not removed"
    fi
  done

# Content-addressed integration images (v2, above), under the image lock (v5).
images=0
refs=
if [ "${REAP_DRY_RUN:-0}" = 1 ] || image_lock; then
  refs=$(docker images --filter "reference=${prefix}it" --format '{{.Repository}}:{{.Tag}}')
else
  echo "keep  every ${prefix}it image (the image lock was not free within ${lock_wait}s)"
fi
for ref in $refs; do
  case $ref in "${prefix}it:"*) ;; *) continue ;; esac
  id='' created=''
  read -r id created < <(docker image inspect -f '{{.Id}} {{.Created}}' "$ref" 2>/dev/null)
  if [ -z "$id" ] || [ -z "$created" ]; then
    echo "keep  image $ref (docker image inspect gave no id)"
    continue
  fi
  t=$(date -d "$created" +%s 2>/dev/null) || continue
  # date -d takes Go's tag time without the fraction and zone name; a never-tagged image reports the zero time.
  tagged=$(docker image inspect -f '{{.Metadata.LastTagTime}}' "$ref" 2>/dev/null | sed -E 's/\.[0-9]+//; s/ [A-Z]+$//')
  tagged=$(date -d "$tagged" +%s 2>/dev/null) || tagged=
  case $tagged in ''|*[!0-9]*) ;; *) [ "$tagged" -le "$t" ] || t=$tagged ;; esac
  if [ $((now - t)) -lt "$image_min_age" ]; then
    echo "keep  image $ref (created or tagged within ${image_min_age}s)"
    continue
  fi
  # v4: a container on the id (a lease or a stack) keeps every tag of it.
  if ! users=$(docker ps -a -q --filter "ancestor=$id" 2>/dev/null); then
    echo "keep  image $ref (could not list the containers on $id)"
    continue
  fi
  if [ -n "$users" ]; then
    echo "keep  image $ref (in use: $(echo "$users" | wc -l) container(s) on $id)"
    continue
  fi
  echo "reap  image $ref"
  if run docker image rm "$ref"; then images=$((images + 1)); else echo "warn  image $ref not removed (in use?)"; fi
done
image_unlock

if [ "${REAP_DRY_RUN:-0}" = 1 ]; then done_as="would be removed"; else done_as=removed; fi
echo "reaper: $reaped compose project(s) and $images image(s) $done_as for prefix '$prefix'"
exit 0
