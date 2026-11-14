package buildgates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGoBody is a `go` that answers `go list [-tags T] ...` from fixture
// files: the -tags value, whitespace-normalised, names the file
// "$FAKE_GO_DIR/list.<tags>" ("list.none" without -tags). A tag set with no
// fixture fails like a broken `go list` (exit 1). Every call logs its
// normalised tag set, one line per call, to $FAKE_GO_LOG.
const fakeGoBody = `#!/bin/sh
tags=""
while [ $# -gt 0 ]; do
	case "$1" in
	-tags) tags=$2; shift ;;
	esac
	shift
done
# shellcheck disable=SC2086 # word-split on purpose: normalise whitespace
key=$(echo $tags)
printf '[%s]\n' "$key" >>"$FAKE_GO_LOG"
f="$FAKE_GO_DIR/list.${key:-none}"
[ -f "$f" ] || { echo "go: no fixture for -tags '$key'" >&2; exit 1; }
cat "$f"
`

// runAssertBuildTags runs scripts/assert-build-tags.sh with GO_BUILD_TAGS set
// to tags and a fake go first on PATH whose `go list` output per tag set is
// lists (key "" is the untagged list). It returns the output, whether the
// script exited 0, and the tag sets go was called with, in order.
func runAssertBuildTags(t *testing.T, tags string, lists map[string][]string) (string, bool, []string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	fixtures := filepath.Join(dir, "fixtures")
	for _, d := range []string{bin, fixtures} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	writeExecutable(t, filepath.Join(bin, "go"), []byte(fakeGoBody))
	for key, files := range lists {
		name := "list." + key
		if key == "" {
			name = "list.none"
		}
		body := strings.Join(files, "\n")
		if body != "" {
			body += "\n"
		}
		if err := os.WriteFile(filepath.Join(fixtures, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	logPath := filepath.Join(dir, "go.log")
	out, ok := runScript(t, dir, map[string]string{
		"GO_BUILD_TAGS": tags,
		"FAKE_GO_DIR":   fixtures,
		"FAKE_GO_LOG":   logPath,
		"PATH":          bin + string(os.PathListSeparator) + os.Getenv("PATH"),
	}, "assert-build-tags.sh")
	var calls []string
	if raw, err := os.ReadFile(logPath); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			calls = append(calls, strings.TrimSuffix(strings.TrimPrefix(l, "["), "]"))
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("read go log: %v", err)
	}
	return out, ok, calls
}

func wantCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("go list calls = %q, want %q", got, want)
	}
}

func TestAssertBuildTagsEmptyAssertsNothing(t *testing.T) {
	out, ok, calls := runAssertBuildTags(t, "", nil)
	if !ok || !strings.Contains(out, "GO_BUILD_TAGS is empty: nothing to assert") {
		t.Fatalf("ok=%v out=%q", ok, out)
	}
	wantCalls(t, calls)
}

func TestAssertBuildTagsEveryTagSelects(t *testing.T) {
	out, ok, calls := runAssertBuildTags(t, "a b", map[string][]string{
		"":    {"m/x.go"},
		"a b": {"m/a.go", "m/b_test.go", "m/x.go"},
		"a":   {"m/a.go", "m/x.go"},
		"b":   {"m/b_test.go", "m/x.go"},
	})
	if !ok {
		t.Fatalf("exit != 0: %q", out)
	}
	for _, want := range []string{
		"files selected: untagged=1 tagged=3 (tags: a b)",
		"OK: every declared tag selects code",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %q", want, out)
		}
	}
	if strings.Contains(out, "::error::") {
		t.Errorf("unexpected error: %q", out)
	}
	// Dropping a leaves b, dropping b leaves a.
	wantCalls(t, calls, "", "a b", "b", "a")
}

func TestAssertBuildTagsChangedNothing(t *testing.T) {
	out, ok, _ := runAssertBuildTags(t, "zz", map[string][]string{
		"":   {"m/x.go"},
		"zz": {"m/x.go"},
	})
	if ok {
		t.Fatalf("exit 0 for a tag set that changes nothing: %q", out)
	}
	for _, want := range []string{
		"::error::-tags 'zz' changed nothing",
		"::error::build tag 'zz' selects nothing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %q", want, out)
		}
	}
	if strings.Contains(out, "OK:") {
		t.Errorf("OK line on failure: %q", out)
	}
}

func TestAssertBuildTagsNamesOnlyTheDeadTag(t *testing.T) {
	out, ok, _ := runAssertBuildTags(t, "a b", map[string][]string{
		"":    {"m/x.go"},
		"a b": {"m/a.go", "m/x.go"},
		"a":   {"m/a.go", "m/x.go"},
		"b":   {"m/x.go"},
	})
	if ok {
		t.Fatalf("exit 0 with a dead tag: %q", out)
	}
	if !strings.Contains(out, "::error::build tag 'b' selects nothing") {
		t.Errorf("b not named: %q", out)
	}
	for _, bad := range []string{"build tag 'a'", "changed nothing", "OK:"} {
		if strings.Contains(out, bad) {
			t.Errorf("output has %q: %q", bad, out)
		}
	}
}

// A repeated tag is dropped whole: removing "a" from "a a" leaves no tag, so
// both copies count as selecting code and the run passes.
func TestAssertBuildTagsRepeatedTag(t *testing.T) {
	out, ok, calls := runAssertBuildTags(t, "a a", map[string][]string{
		"":    {"m/x.go"},
		"a a": {"m/a.go", "m/x.go"},
	})
	if !ok || !strings.Contains(out, "OK: every declared tag selects code") {
		t.Fatalf("ok=%v out=%q", ok, out)
	}
	wantCalls(t, calls, "", "a a", "", "")
}

// A tag is dropped by exact string, not as a pattern: removing "go1.2" must
// keep "go132", so a dead go1.2 beside a live go132 is named.
func TestAssertBuildTagsDropIsLiteral(t *testing.T) {
	out, ok, calls := runAssertBuildTags(t, "go1.2 go132", map[string][]string{
		"":            {"m/x.go"},
		"go1.2 go132": {"m/q.go", "m/x.go"},
		"go132":       {"m/q.go", "m/x.go"},
		"go1.2":       {"m/x.go"},
	})
	wantCalls(t, calls, "", "go1.2 go132", "go132", "go1.2")
	if ok {
		t.Fatalf("exit 0 with a dead go1.2: %q", out)
	}
	if !strings.Contains(out, "::error::build tag 'go1.2' selects nothing") {
		t.Errorf("go1.2 not named: %q", out)
	}
	if strings.Contains(out, "build tag 'go132'") {
		t.Errorf("go132 named: %q", out)
	}
}

// A failed go list is not an empty file set: the script stops with its own
// error instead of comparing lists it never got.
func TestAssertBuildTagsGoListFails(t *testing.T) {
	for name, tc := range map[string]struct {
		tags  string
		lists map[string][]string
	}{
		"every list fails":  {"a", nil},
		"tagged list fails": {"a", map[string][]string{"": {"m/x.go"}}},
		"drop list fails": {"a b", map[string][]string{
			"":    {"m/x.go"},
			"a b": {"m/a.go", "m/b.go", "m/x.go"},
			"a":   {"m/a.go", "m/x.go"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			out, ok, _ := runAssertBuildTags(t, tc.tags, tc.lists)
			if ok {
				t.Fatalf("exit 0 after a failed go list: %q", out)
			}
			if !strings.Contains(out, "::error::go list") {
				t.Errorf("no go list error: %q", out)
			}
			for _, bad := range []string{"changed nothing", "selects nothing", "OK:"} {
				if strings.Contains(out, bad) {
					t.Errorf("output has %q after a failed go list: %q", bad, out)
				}
			}
		})
	}
}
