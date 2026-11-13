#!/bin/sh
# features.sh — the features a change touches, one per line; and the feature
# mapping, for the Makefile.
#
# Usage: scripts/features.sh <base> <tip>              (from the repository root)
#        scripts/features.sh list
#        scripts/features.sh field <feature> <unit-package|suite|test-prefix>
#
# The <base> <tip> form lets a test runner run only the features a change
# needs. A feature is a
# directory docs/<feature>/, with a line in scripts/features.map (override with
# FEATURES_MAP) that gives its unit package, its integration suite, the name
# prefix of its integration tests and the globs of its source files. A change
# touches a feature when it changes a file under docs/<feature>/, a source file
# the map gives the feature, or a test file whose source file that is (the name
# without _test.go, then without each trailing _<goos> or _<goarch>, and nothing
# else: provider_software_test.go is provider_software.go's). A change to the integration
# suite or to the map itself touches every feature. Prints nothing when no
# feature is touched. The Makefile maps each feature to `test-<pkg>` and
# `integration-test-<feature>`, which runs only the feature's tests.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

map=${FEATURES_MAP:-$here/features.map}
[ -f "$map" ] || die "$map not found"

# The map's lines: comments and blank lines dropped, and every line checked, so
# nothing downstream parses a malformed one.
map_lines() {
  awk '
    /^[ \t]*(#|$)/ { next }
    NF < 5 { printf "features.map:%d: want <feature> <unit-package> <suite> <test-prefix> <source-glob>...\n", NR > "/dev/stderr"; bad = 1; next }
    $4 !~ /^Test[A-Za-z0-9]+_$/ { printf "features.map:%d: test prefix %s must be Test<Name>_\n", NR, $4 > "/dev/stderr"; bad = 1 }
    { for (i = 5; i <= NF; i++) if ($i !~ /^[A-Za-z0-9_.\/*-]+$/) { printf "features.map:%d: glob %s may hold only letters, digits, _ . / * and -\n", NR, $i > "/dev/stderr"; bad = 1 } print }
    END { exit bad }
  ' "$map"
}

case ${1-} in
  list)
    [ $# -eq 1 ] || die "usage: $0 list"
    lines=$(map_lines) # not piped: a malformed map must fail the script
    printf '%s\n' "$lines" | awk '{ print $1 }'
    exit 0
    ;;
  field)
    [ $# -eq 3 ] || die "usage: $0 field <feature> <unit-package|suite|test-prefix>"
    case $3 in
      unit-package) col=2 ;;
      suite) col=3 ;;
      test-prefix) col=4 ;;
      *) die "unknown field '$3'" ;;
    esac
    lines=$(map_lines)
    value=$(printf '%s\n' "$lines" | awk -v f="$2" -v c="$col" '$1 == f { print $c }')
    [ -n "$value" ] || die "'$2' is not a feature in $map"
    printf '%s\n' "$value"
    exit 0
    ;;
esac

[ $# -eq 2 ] || die "usage: $0 <base> <tip>"
for ref in "$1" "$2"; do
  case $ref in -*) die "'$ref' is not a revision" ;; esac
  git rev-parse --verify --quiet --end-of-options "$ref^{commit}" >/dev/null || die "'$ref' does not name a commit"
done

lines=$(map_lines)
{
  printf '%s\n' "$lines"
  echo "--changed--"
  git -c core.quotePath=false diff --name-only --no-renames "$1" "$2"
} | awk '
  BEGIN {
    # GOOS and GOARCH values of the go tool (go/build knownOS, knownArch).
    n_plat = split("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos " \
      "386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm", names, " ")
    for (i = 1; i <= n_plat; i++) plat[names[i]] = 1
  }
  function emit(f) { print f }
  function owners(path,   i) {
    for (i = 1; i <= np; i++) if (path ~ pat[i]) emit(owner[i])
  }
  !changed && $0 == "--changed--" { changed = 1; next }
  !changed {
    feats[++n] = $1
    for (i = 5; i <= NF; i++) {
      g = $i
      gsub(/[.]/, "[.]", g)
      gsub(/[*]/, ".*", g)
      pat[++np] = "^" g "$"
      owner[np] = $1
    }
    next
  }
  {
    p = $0
    if (split(p, a, "/") > 2 && a[1] == "docs") { emit(a[2]); next }
    if (p ~ /^test\/integration\// || p ~ /(^|\/)features[.]map$/) {
      for (i = 1; i <= n; i++) emit(feats[i])
      next
    }
    if (p !~ /[.]go$/) next
    if (p !~ /_test[.]go$/) { owners(p); next }
    q = p
    sub(/_test[.]go$/, "", q)
    owners(q ".go")
    # Strip only the suffixes the go tool reads as build constraints, one at a
    # time: provider_software_test.go belongs to provider_software.go, not to
    # provider.go, but memlock_linux_amd64_test.go reaches memlock.go.
    while (match(q, /_[a-z0-9]+$/) && (substr(q, RSTART + 1) in plat)) {
      q = substr(q, 1, RSTART - 1)
      owners(q ".go")
    }
  }
' | sort -u
