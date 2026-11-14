#!/bin/sh
# clean-tools.sh — remove the repository-local pinned-tool cache (bin/tools).
#
# Usage: TOOLS_DIR=/abs/path scripts/clean-tools.sh   (from the repository root)
#
# Refuses a relative TOOLS_DIR, or one resolving to /, the checkout or $HOME
# (itself resolved, so a symlinked HOME is still caught).
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

tools=${TOOLS_DIR-}
case $tools in
  /*) ;;
  *) die "TOOLS_DIR must be an absolute path; refusing to delete it" ;;
esac
if [ -d "$tools" ]; then
  real=$(cd -P -- "$tools" && pwd)
  repo=$(pwd -P)
  home=${HOME:-/}
  if [ -d "$home" ]; then home=$(cd -P -- "$home" && pwd); fi
  case $real in
    /|"$repo"|"$home") die "TOOLS_DIR resolves to $real; refusing to delete it" ;;
  esac
fi
rm -rf -- "$tools"
