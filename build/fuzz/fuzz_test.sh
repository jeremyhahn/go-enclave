#!/bin/sh
# Drives build/fuzz/fuzz.sh offline on a stub `go`: discovery across a root
# module and two backend modules, the FUZZ and FUZZ_PKG selectors, FUZZTIME,
# the first failure (package, target, failing input path), and the refusals.
set -u

here=$(cd "$(dirname "$0")" && pwd)
pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/bin" "$D/state" "$D/fix" "$D/src/sub" "$D/src/m/a" "$D/src/m/b"

# Each module directory lists its packages: "<import path> <dir>".
printf 'ex.com/r .\nex.com/r/sub sub\n' > "$D/src/.pkgs"
printf 'ex.com/a .\n' > "$D/src/m/a/.pkgs"
printf 'ex.com/b .\n' > "$D/src/m/b/.pkgs"
# Each package's tests, as `go test -list` prints them; ex.com/r/sub has no fuzz target.
printf 'FuzzRoot\nTestRoot\n' > "$D/fix/ex.com_r"
printf 'TestSub\n' > "$D/fix/ex.com_r_sub"
printf 'FuzzA1\nFuzzA2\nExampleA\n' > "$D/fix/ex.com_a"
printf 'FuzzB\n' > "$D/fix/ex.com_b"

cat > "$D/bin/go" <<'STUB'
#!/bin/sh
printf '%s|%s\n' "$PWD" "$*" >> "$STUB_STATE/calls"
cmd=$1
shift
case $cmd in
  list)
    [ "$1" = -f ] || exit 1
    form=$2 pat=$3
    while read -r ip rel; do
      if [ "$pat" = ./... ] && [ "$form" = '{{.ImportPath}}' ]; then
        printf '%s\n' "$ip"
      elif [ "$pat" = "$ip" ] && [ "$form" = '{{.Dir}}' ]; then
        if [ "$rel" = . ]; then printf '%s\n' "$PWD"; else printf '%s/%s\n' "$PWD" "$rel"; fi
      fi
    done < "$PWD/.pkgs"
    ;;
  test)
    if [ "$1" = -list ]; then
      pkg=$3
      [ "$pkg" = "${STUB_LIST_FAIL:-}" ] && { echo "build failed: $pkg"; exit 1; }
      f="$STUB_FIX/$(printf '%s' "$pkg" | tr / _)"
      [ -f "$f" ] && cat "$f"
      printf 'ok  \t%s\t0.01s\n' "$pkg"
      exit 0
    fi
    # test -run ^$ -fuzz ^Name$ -fuzztime T pkg
    name=${4#^}
    name=${name%$}
    pkg=$7
    if [ "$name" = "${STUB_FAIL:-}" ]; then
      printf -- '--- FAIL: %s (0.05s)\n    --- FAIL: %s (0.00s)\n        x_test.go:10: boom\n\n' "$name" "$name"
      printf '    Failing input written to testdata/fuzz/%s/deadbeef\n    To re-run:\n    go test -run=%s/deadbeef\n' "$name" "$name"
      printf 'FAIL\nexit status 1\nFAIL\t%s\t0.10s\n' "$pkg"
      exit 1
    fi
    printf 'fuzz: elapsed: 1s, execs: 100\nPASS\nok  \t%s\t1.00s\n' "$pkg"
    ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$D/bin/go"

# run [env...]: fuzz.sh over the three modules, its status in $rc.
run() {
  rm -f "$D/state/calls"
  : > "$D/state/calls"
  rc=0
  (cd "$D/src" && env -u FUZZ -u FUZZ_PKG -u FUZZTIME PATH="$D/bin:$PATH" GOCMD=go \
    STUB_STATE="$D/state" STUB_FIX="$D/fix" "$@" \
    sh "$here/fuzz.sh" . m/a m/b) > "$D/out" 2>&1 || rc=$?
}
called() { grep -q -- "$1" "$D/state/calls"; }
fuzzed() { grep -c -- '|test -run ^\$ -fuzz ' "$D/state/calls"; }
said() { grep -q -- "$1" "$D/out"; }
show() { cat "$D/out" "$D/state/calls" 2>/dev/null || true; }

# Every target in every module, each fuzzed from its own module for FUZZTIME.
run FUZZTIME=1s
if [ "$rc" = 0 ] && [ "$(fuzzed)" = 4 ] &&
  called "^$D/src|test -run ^\\\$ -fuzz ^FuzzRoot\\\$ -fuzztime 1s ex.com/r\$" &&
  called "^$D/src/m/a|test -run ^\\\$ -fuzz ^FuzzA1\\\$ -fuzztime 1s ex.com/a\$" &&
  called "^$D/src/m/a|test -run ^\\\$ -fuzz ^FuzzA2\\\$ -fuzztime 1s ex.com/a\$" &&
  called "^$D/src/m/b|test -run ^\\\$ -fuzz ^FuzzB\\\$ -fuzztime 1s ex.com/b\$" &&
  called "^$D/src/m/a|test -list ^Fuzz ex.com/a\$" &&
  said '^ok .*ex.com/r .*FuzzRoot' && said '^ok .*ex.com/a .*FuzzA1' &&
  said '^ok .*ex.com/a .*FuzzA2' && said '^ok .*ex.com/b .*FuzzB' &&
  said '4 fuzz targets passed'; then
  ok "every target in the root and backend modules is fuzzed from its module"
else
  bad "every target in the root and backend modules is fuzzed from its module (rc=$rc)"
  show
fi

# FUZZTIME defaults to 30s.
run
if [ "$rc" = 0 ] && [ "$(fuzzed)" = 4 ] && called '-fuzztime 30s ex.com/b$' && ! called '-fuzztime 1s'; then
  ok "FUZZTIME defaults to 30s"
else
  bad "FUZZTIME defaults to 30s (rc=$rc)"
  show
fi

# FUZZ selects targets by name.
run FUZZTIME=1s FUZZ=A1
if [ "$rc" = 0 ] && [ "$(fuzzed)" = 1 ] && called '-fuzz ^FuzzA1\$ ' && said '1 fuzz target passed'; then
  ok "FUZZ selects targets by name"
else
  bad "FUZZ selects targets by name (rc=$rc)"
  show
fi

# FUZZ_PKG selects packages by import path.
run FUZZTIME=1s FUZZ_PKG='^ex\.com/b$'
if [ "$rc" = 0 ] && [ "$(fuzzed)" = 1 ] && called '-fuzz ^FuzzB\$ ' && ! called '|test -list ^Fuzz ex.com/a$'; then
  ok "FUZZ_PKG selects packages by import path"
else
  bad "FUZZ_PKG selects packages by import path (rc=$rc)"
  show
fi

# Both selectors together.
run FUZZTIME=1s FUZZ='A2|B' FUZZ_PKG='/a$'
if [ "$rc" = 0 ] && [ "$(fuzzed)" = 1 ] && called '-fuzz ^FuzzA2\$ '; then
  ok "FUZZ and FUZZ_PKG combine"
else
  bad "FUZZ and FUZZ_PKG combine (rc=$rc)"
  show
fi

# The first failure stops the run and names the package, target and input.
run FUZZTIME=1s STUB_FAIL=FuzzA1
if [ "$rc" != 0 ] && [ "$(fuzzed)" = 2 ] && ! called '-fuzz ^FuzzA2\$ ' && ! called '-fuzz ^FuzzB\$ ' &&
  said '^FAIL .*ex.com/a .*FuzzA1' && said 'package ex.com/a' && said 'target FuzzA1' &&
  said 'failing input m/a/testdata/fuzz/FuzzA1/deadbeef' && said 'x_test.go:10: boom'; then
  ok "the first failure stops the run and names package, target and input"
else
  bad "the first failure stops the run and names package, target and input (rc=$rc)"
  show
fi

# A failing input in a package below the module root is named from the root.
printf 'FuzzSub\n' > "$D/fix/ex.com_r_sub"
run FUZZTIME=1s STUB_FAIL=FuzzSub FUZZ=Sub
if [ "$rc" != 0 ] && said 'failing input sub/testdata/fuzz/FuzzSub/deadbeef'; then
  ok "a failing input below the module root is named from the root"
else
  bad "a failing input below the module root is named from the root (rc=$rc)"
  show
fi
printf 'TestSub\n' > "$D/fix/ex.com_r_sub"

# Nothing to fuzz is refused.
run FUZZTIME=1s FUZZ=NoSuchTarget
if [ "$rc" != 0 ] && [ "$(fuzzed)" = 0 ] && said 'no fuzz targets'; then
  ok "no matching target is refused"
else
  bad "no matching target is refused (rc=$rc)"
  show
fi

# A package that does not build fails discovery.
run FUZZTIME=1s STUB_LIST_FAIL=ex.com/a
if [ "$rc" != 0 ] && [ "$(fuzzed)" = 0 ] && said 'build failed: ex.com/a'; then
  ok "a package that does not build fails discovery"
else
  bad "a package that does not build fails discovery (rc=$rc)"
  show
fi

# A bad FUZZTIME, FUZZ or FUZZ_PKG is refused before go is run.
for bad_env in FUZZTIME=abc FUZZTIME='1s;x' FUZZ='(' FUZZ_PKG='['; do
  run "$bad_env"
  if [ "$rc" = 2 ] && [ ! -s "$D/state/calls" ]; then
    ok "$bad_env is refused with no go call"
  else
    bad "$bad_env is refused with no go call (rc=$rc)"
    show
  fi
done

# Iteration counts are accepted as go accepts them.
run FUZZTIME=100x FUZZ=FuzzB
if [ "$rc" = 0 ] && called '-fuzztime 100x ex.com/b$'; then
  ok "FUZZTIME accepts an iteration count"
else
  bad "FUZZTIME accepts an iteration count (rc=$rc)"
  show
fi

# No module is refused.
rc=0
(cd "$D/src" && PATH="$D/bin:$PATH" STUB_STATE="$D/state" sh "$here/fuzz.sh") > "$D/out" 2>&1 || rc=$?
if [ "$rc" = 2 ] && said 'usage'; then
  ok "no module is refused"
else
  bad "no module is refused (rc=$rc)"
  show
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
