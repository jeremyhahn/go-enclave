#!/bin/sh
# deps-check.sh — fail when a module a go.mod requires is behind its latest
# release without a documented reason (handbook devops.md §9).
#
# Usage: scripts/deps-check.sh [module-dir ...]   (from the repository root;
#        default: the root module and build/ci/buildgates)
#
# Every module each go.mod requires, direct and indirect, first-party and
# third-party, is compared with its latest release by `go list -m -u`. One held
# below latest passes only when its require or replace line in that go.mod ends
# in the comment
#
#     // held: <reason>
#
# and the reason is not empty. One behind without a reason whose latest release
# was published under 7 days ago is reported and passes; once that release is 7
# days old, or its publish time is unknown, it fails. It needs the module proxy: with GOPROXY off, the
# devcontainer's default, it uses https://proxy.golang.org,direct.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
GOWORK=off
export GOWORK
case ${GOPROXY:-} in off) GOPROXY=https://proxy.golang.org,direct; export GOPROXY ;; esac

# held_reason GOMOD MODULE: prints "held <reason>" when MODULE's require or
# replace line in GOMOD carries the comment, "listed" when it has a line
# without one, and nothing when GOMOD does not require MODULE.
held_reason() {
  _state=
  while IFS= read -r _line || [ -n "$_line" ]; do
    _rest=${_line#"${_line%%[![:space:]]*}"}
    case $_rest in
      require[[:space:]]* | replace[[:space:]]*)
        _rest=${_rest#*[[:space:]]}
        _rest=${_rest#"${_rest%%[![:space:]]*}"}
        ;;
    esac
    case $_rest in "$2"[[:space:]]*) ;; *) continue ;; esac
    case $_line in
      *'// held:'*)
        _why=${_line#*// held:}
        _why=${_why#"${_why%%[![:space:]]*}"}
        if [ -n "$_why" ]; then
          echo "held $_why"
          return 0
        fi
        ;;
    esac
    _state=listed
  done <"$1"
  [ -z "$_state" ] || echo "$_state"
}

[ $# -gt 0 ] || set -- . build/ci/buildgates
bad=0
now=$(date +%s)
for dir in "$@"; do
  gomod=$dir/go.mod
  [ -f "$gomod" ] || die "$gomod: no such file"
  behind=$(cd "$dir" && "$go" list -m -u \
    -f '{{if and (not .Main) .Update}}{{.Path}} {{.Version}} {{.Update.Version}} {{with .Update.Time}}{{.Unix}} {{.UTC.Format "2006-01-02T15:04:05Z"}}{{else}}0 unknown{{end}}{{end}}' all) ||
    die "go list -m -u all failed in $dir"
  while read -r mod cur latest released when; do
    [ -n "$mod" ] || continue
    state=$(held_reason "$gomod" "$mod")
    case $state in
      '') ;;
      held*) echo "$prog: $gomod: $mod $cur is held below $latest: ${state#held }" ;;
      *)
        if [ "${released:-0}" -gt 0 ] && [ $((now - released)) -lt 604800 ]; then
          echo "$prog: $gomod: $mod $cur is behind $latest, released $when, under 7 days ago"
        else
          echo "$prog: $gomod: $mod $cur is behind $latest, with no '// held: <reason>' comment" >&2
          bad=$((bad + 1))
        fi
        ;;
    esac
  done <<EOF
$behind
EOF
done
[ "$bad" -eq 0 ] || die "$bad module(s) behind their latest release without a documented reason"
echo "$prog: every required module is at its latest release, held with a reason, or behind one under 7 days old"
