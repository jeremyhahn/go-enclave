package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestScriptsFeatures_PrintsTheFeaturesAChangeTouches(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"docs/README.md":                   "index\n",
		"docs/alpha/a.md":                  "a\n",
		"docs/beta/deep/b.md":              "b\n",
		"docs/gamma/c.md":                  "c\n",
		"enclave.go":                       "package x\n",
		"test/integration/alpha/x_test.go": "package x\n",
	})
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	for name, body := range map[string]string{
		"docs/beta/deep/b.md": "b2\n",
		"docs/alpha/new.md":   "n\n",
		"docs/README.md":      "index2\n",
		"enclave.go":          "package y\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "change")
	tip := gitIn(t, dir, "rev-parse", "HEAD")

	out, ok := runScript(t, dir, nil, "features.sh", base, tip)
	if !ok || out != "alpha\nbeta\n" {
		t.Fatalf("features.sh %s %s = %q (ok=%v); want the touched features only, sorted, one per line", base, tip, out, ok)
	}
	out, ok = runScript(t, dir, nil, "features.sh", tip, tip)
	if !ok || out != "" {
		t.Fatalf("features.sh on an empty change = %q (ok=%v); want nothing", out, ok)
	}
}

func TestScriptsFeatures_RefusesWhatIsNotARevision(t *testing.T) {
	dir := writeTree(t, map[string]string{"docs/alpha/a.md": "a\n"})
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	for _, args := range [][]string{{}, {"HEAD"}, {"HEAD", "no-such-ref"}, {"--output=x", "HEAD"}} {
		if out, ok := runScript(t, dir, nil, "features.sh", args...); ok {
			t.Errorf("features.sh %q succeeded:\n%s", args, out)
		}
	}
}

// Every docs/<feature>/ directory is mapped in the Makefile to a package, and
// the mapping resolves to test-<pkg> and integration-test-<pkg>.
func TestScriptsMakefile_EveryFeatureIsMapped(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatal(err)
	}
	var features []string
	for _, e := range entries {
		if e.IsDir() {
			features = append(features, e.Name())
		}
	}
	sort.Strings(features)
	if len(features) == 0 {
		t.Fatal("docs/ holds no feature directory")
	}
	for _, f := range features {
		for _, prefix := range []string{"test-", "integration-test-"} {
			cmd := exec.Command("make", "-n", "--no-print-directory", prefix+f)
			cmd.Dir = root
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("make %s%s: docs/%s is not in the Makefile's feature mapping: %v\n%s", prefix, f, f, err, out)
			}
		}
	}
}

func TestScriptsCoverageGate(t *testing.T) {
	const profile = "mode: atomic\n" +
		"example.com/m/a/x.go:1.1,2.2 9 1\n" + // a: 9 of 10 covered
		"example.com/m/a/x.go:3.1,4.2 1 0\n" +
		"example.com/m/a/x.go:3.1,4.2 1 0\n" + // the same block twice counts once
		"example.com/m/b/y.go:1.1,2.2 1 1\n" // b: all
	dir := writeTree(t, map[string]string{"cover.out": profile, "empty.out": "mode: atomic\n"})

	for _, tc := range []struct {
		name string
		args []string
		ok   bool
		want string
	}{
		{"floor met", []string{"90", "cover.out"}, true, "example.com/m/a coverage: 90.00% (9 of 10 statements, floor 90%)"},
		{"floor missed in one package", []string{"90.5", "cover.out"}, false, "FAIL: example.com/m/a coverage 90.00% is below the 90.5% floor"},
		{"named package met", []string{"100", "cover.out", "example.com/m/b"}, true, "example.com/m/b coverage: 100.00%"},
		{"named package missed", []string{"100", "cover.out", "example.com/m/a"}, false, "is below the 100% floor"},
		{"named package absent is zero", []string{"1", "cover.out", "example.com/m/c"}, false, "FAIL: example.com/m/c has no coverage at all"},
		{"empty profile", []string{"1", "empty.out"}, false, "FAIL: no package in empty.out"},
		{"floor only", []string{"90"}, true, ""},
		{"floor is not a number", []string{"9$(id)0"}, false, "must be a number"},
		{"floor with a newline", []string{"90\n91"}, false, "must be a number"},
		{"no profile", []string{"90", "missing.out"}, false, "missing.out not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := runScript(t, dir, nil, "coverage-gate.sh", tc.args...)
			if ok != tc.ok || !strings.Contains(out, tc.want) {
				t.Fatalf("coverage-gate.sh %q: ok=%v, want %v and %q:\n%s", tc.args, ok, tc.ok, tc.want, out)
			}
		})
	}

	t.Run("merge", func(t *testing.T) {
		if out, ok := runScript(t, dir, nil, "coverage-gate.sh", "merge", "all.out", "cover.out", "cover.out"); !ok {
			t.Fatalf("merge: %s", out)
		}
		got, err := os.ReadFile(filepath.Join(dir, "all.out"))
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(got), "mode:"); n != 1 || strings.Count(string(got), "\n") != 9 {
			t.Fatalf("merged profile has the wrong shape:\n%s", got)
		}
	})
}

// A helper lives in scripts/lib.sh and nowhere else: a copy in a script is the
// drift lib.sh exists to prevent. A file with no #! line is sourced, never run
// (lib.sh, tool-pins.sh), so only the definitions rule binds it.
func TestScriptsLib_HelpersAreDefinedOnce(t *testing.T) {
	root := repoRoot(t)
	scripts, err := filepath.Glob(filepath.Join(root, "scripts", "*.sh"))
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	def := regexp.MustCompile(`(?m)^(die|matches|version_anchor|unreleased_pending)\(\)|^(NL|here|VERSION_RE)=`)
	source := regexp.MustCompile(`(?m)^\. "\$\{0%/\*\}/lib\.sh"$`)
	for _, s := range scripts {
		body, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(s)
		if name == "lib.sh" {
			continue
		}
		if m := def.FindString(string(body)); m != "" {
			t.Errorf("%s defines %q, which scripts/lib.sh owns", name, m)
		}
		if strings.HasPrefix(string(body), "#!") && !source.Match(body) {
			t.Errorf("%s does not source scripts/lib.sh", name)
		}
	}
}
