#!/usr/bin/env bash
# ci-image-history.sh <image>...: fails when an image's history or config carries a private address, naming the image, never the address.
set -euo pipefail

if [ $# -eq 0 ]; then
	echo "usage: scripts/ci-image-history.sh <image>..." >&2
	exit 2
fi

octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
private="(^|[^0-9.])(10\.$octet|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.$octet\.$octet([^0-9]|\$)"

status=0
for image in "$@"; do
	if ! history=$(docker history --no-trunc --format '{{.CreatedBy}} {{.Comment}}' "$image") ||
		! config=$(docker image inspect --format '{{json .Config}}' "$image"); then
		echo "ci-image-history: cannot read $image" >&2
		exit 1
	fi
	while IFS=: read -r entry _; do
		echo "ci-image-history: $image: history entry $entry carries a private address" >&2
		status=1
	done < <(grep -En "$private" <<<"$history" || :)
	if grep -Eq "$private" <<<"$config"; then
		echo "ci-image-history: $image: its config (env, labels, command) carries a private address" >&2
		status=1
	fi
done
exit "$status"
