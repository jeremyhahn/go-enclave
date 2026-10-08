# shellcheck shell=sh disable=SC2034
# lib.sh — the helpers every script in scripts/ shares. Sourced, never run:
#
#   set -eu
#   # shellcheck source=lib.sh
#   . "${0%/*}/lib.sh"
#
# Defines (the caller's $0 is the script, so these describe the script):
#   here                    the directory holding the scripts
#   prog                    the script's name without .sh, the prefix of die()
#   NL                      one newline
#   die MSG...              print "<prog>: MSG" to stderr and exit 1
#   require_scanned_image   die unless the integration image is the one that was scanned
#   matches VALUE ERE       the WHOLE value matches
#   VERSION_RE              vX.Y.Z[-pre]
#   RELEASE_TAG_RE          vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N
#   version_anchor VERSION  the ERE of VERSION's CHANGELOG heading
#   unreleased_pending FILE the first entry still under [Unreleased], if any
LC_ALL=C
export LC_ALL

here=$(CDPATH='' cd -- "${0%/*}" && pwd)
prog=${0##*/}
prog=${prog%.sh}

NL='
'

die() { echo "$prog: $*" >&2; exit 1; }

# require_scanned_image: fail unless GO_ENCLAVE_IT_IMAGE, set by
# scripts/integration-image.sh, still has the ID that script scanned
# (GO_ENCLAVE_IT_IMAGE_ID). A suite runs only on the image that was scanned.
require_scanned_image() {
  [ -n "${GO_ENCLAVE_IT_IMAGE-}" ] && [ -n "${GO_ENCLAVE_IT_IMAGE_ID-}" ] ||
    die "GO_ENCLAVE_IT_IMAGE and GO_ENCLAVE_IT_IMAGE_ID are required: the suite runs on the image scripts/integration-image.sh scanned"
  _got=$(docker image inspect --format '{{.Id}}' "$GO_ENCLAVE_IT_IMAGE" 2>/dev/null) ||
    die "the integration image $GO_ENCLAVE_IT_IMAGE does not exist"
  [ "$_got" = "$GO_ENCLAVE_IT_IMAGE_ID" ] ||
    die "the integration image $GO_ENCLAVE_IT_IMAGE is $_got, not the $GO_ENCLAVE_IT_IMAGE_ID that was scanned"
}

# `grep` alone is line-oriented, so a value with an embedded newline would pass
# on any one matching line.
matches() {
  case $1 in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq "$2"
}

VERSION_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

# The release tags this repository cuts (release-versioning §1/§1a): vX.Y.Z,
# vX.Y.Z-alpha or vX.Y.Z-rc.N, with no leading zeros, and N from 1. Anything
# else is a typo or an unsanctioned kind.
RELEASE_TAG_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-alpha|-rc\.[1-9][0-9]*)?$'

# The version heading, bracketed or not, so a version is never matched by a
# longer one that starts with it (v0.6.2 is not v0.6.20).
version_anchor() {
  printf '^## +\\[?%s\\]?( |$)\n' "$(printf '%s' "$1" | sed 's/[.]/\\./g')"
}

# A bare `### ` heading is not an entry (assembly drops empty subsections), but
# any other non-blank line under `## [Unreleased]` is, stray text included.
unreleased_pending() {
  awk '
    /^## +\[Unreleased\][ \t]*$/ { inside = 1; next }
    inside && /^## / { exit }
    inside && /^### / { next }
    inside && !/^[ \t]*$/ { print; exit }
  ' "$1"
}
