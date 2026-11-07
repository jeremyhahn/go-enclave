package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// gitIn runs git in dir with no user or system configuration.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
		"-c", "commit.gpgSign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = layerEnv(os.Environ(), map[string]string{"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestScriptsFeatures_PrintsTheFeaturesAChangeTouches(t *testing.T) {
	const featureMap = "# a map of its own: the script reads FEATURES_MAP\n" +
		"alpha pkga suitea TestAlpha_ alpha.go lib/*.go\n" +
		"\n" +
		"beta  pkgb suiteb TestBeta_  beta.go\n" +
		// gamma owns a file named like alpha's with a word added: its test
		// is gamma's, and the word is not a platform to strip.
		"gamma pkgc suitec TestGamma_ gamma*.go alpha_software.go\n"
	tree := map[string]string{
		"docs/README.md":               "index\n",
		"docs/alpha/a.md":              "a\n",
		"docs/beta/deep/b.md":          "b\n",
		"docs/gamma/c.md":              "c\n",
		"alpha.go":                     "package x\n",
		"alpha_test.go":                "package x\n",
		"alpha_linux_test.go":          "package x\n",
		"alpha_linux_arm64_test.go":    "package x\n",
		"alpha_software.go":            "package x\n",
		"alpha_software_test.go":       "package x\n",
		"alpha_software_linux_test.go": "package x\n",
		"lib/deep/d.go":                "package x\n",
		"beta.go":                      "package x\n",
		"gamma_linux.go":               "package x\n",
		"unmapped.go":                  "package x\n",
		"README.md":                    "r\n",
		"test/integration/s/x_test.go": "package x\n",
		"features.map":                 featureMap,
	}

	for _, tc := range []struct {
		name string
		file string
		want string
	}{
		{"a doc of a feature", "docs/beta/deep/b.md", "beta\n"},
		{"a new doc of a feature", "docs/alpha/new.md", "alpha\n"},
		{"the docs index", "docs/README.md", ""},
		{"a source file", "alpha.go", "alpha\n"},
		{"its test", "alpha_test.go", "alpha\n"},
		{"its platform test", "alpha_linux_test.go", "alpha\n"},
		{"its GOOS and GOARCH test", "alpha_linux_arm64_test.go", "alpha\n"},
		{"a word that is not a platform", "alpha_software_test.go", "gamma\n"},
		{"a platform test of that file", "alpha_software_linux_test.go", "gamma\n"},
		{"a glob crosses a directory", "lib/deep/d.go", "alpha\n"},
		{"a glob with a wildcard", "gamma_linux.go", "gamma\n"},
		{"a file no feature owns", "unmapped.go", ""},
		{"a file that is not Go", "README.md", ""},
		{"the integration suite", "test/integration/s/x_test.go", "alpha\nbeta\ngamma\n"},
		{"the map", "features.map", "alpha\nbeta\ngamma\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tree)
			env := map[string]string{"FEATURES_MAP": filepath.Join(dir, "features.map")}
			gitIn(t, dir, "init", "-q")
			gitIn(t, dir, "add", "-A")
			gitIn(t, dir, "commit", "-q", "-m", "base")
			base := gitIn(t, dir, "rev-parse", "HEAD")
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, tc.file)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tree[tc.file]+"# changed\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			gitIn(t, dir, "add", "-A")
			gitIn(t, dir, "commit", "-q", "-m", "change")
			tip := gitIn(t, dir, "rev-parse", "HEAD")

			out, ok := runScript(t, dir, env, "features.sh", base, tip)
			if !ok || out != tc.want {
				t.Fatalf("features.sh after changing %s = %q (ok=%v); want %q: the touched features only, sorted, one per line", tc.file, out, ok, tc.want)
			}
			if out, ok := runScript(t, dir, env, "features.sh", tip, tip); !ok || out != "" {
				t.Fatalf("features.sh on an empty change = %q (ok=%v); want nothing", out, ok)
			}
		})
	}
}

func TestScriptsFeatures_ListAndFieldReadTheMap(t *testing.T) {
	dir := writeTree(t, map[string]string{"features.map": "# header\n" +
		"alpha pkga suitea TestAlpha_ alpha.go lib/*.go\n\n" +
		"beta pkgb suiteb TestBeta_ beta.go\n"})
	env := map[string]string{"FEATURES_MAP": filepath.Join(dir, "features.map")}

	if out, ok := runScript(t, dir, env, "features.sh", "list"); !ok || out != "alpha\nbeta\n" {
		t.Errorf("list = %q (ok=%v), want the features in map order", out, ok)
	}
	for _, tc := range []struct{ feature, field, want string }{
		{"alpha", "unit-package", "pkga\n"},
		{"alpha", "suite", "suitea\n"},
		{"beta", "test-prefix", "TestBeta_\n"},
	} {
		if out, ok := runScript(t, dir, env, "features.sh", "field", tc.feature, tc.field); !ok || out != tc.want {
			t.Errorf("field %s %s = %q (ok=%v), want %q", tc.feature, tc.field, out, ok, tc.want)
		}
	}
	for _, args := range [][]string{
		{"field", "nope", "suite"},
		{"field", "alpha", "globs"},
		{"field", "alpha"},
		{"list", "extra"},
	} {
		if out, ok := runScript(t, dir, env, "features.sh", args...); ok {
			t.Errorf("features.sh %q succeeded:\n%s", args, out)
		}
	}
}

// A line the script cannot read fails every use of the map; nothing downstream
// sees half a line.
func TestScriptsFeatures_RefusesAMalformedMap(t *testing.T) {
	for name, line := range map[string]string{
		"too few fields":     "alpha pkga suitea TestAlpha_",
		"a prefix with no _": "alpha pkga suitea TestAlpha alpha.go",
		"a lowercase prefix": "alpha pkga suitea testAlpha_ alpha.go",
		"a glob with $":      "alpha pkga suitea TestAlpha_ $(id).go",
		"a glob with ?":      "alpha pkga suitea TestAlpha_ al?ha.go",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"features.map": line + "\n"})
			env := map[string]string{"FEATURES_MAP": filepath.Join(dir, "features.map")}
			if out, ok := runScript(t, dir, env, "features.sh", "list"); ok {
				t.Fatalf("list accepted %q:\n%s", line, out)
			}
		})
	}
	dir := writeTree(t, nil)
	if out, ok := runScript(t, dir, map[string]string{"FEATURES_MAP": filepath.Join(dir, "missing.map")}, "features.sh", "list"); ok {
		t.Errorf("list with no map succeeded:\n%s", out)
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

// Every feature of scripts/features.map resolves, in the Makefile, to
// test-<feature> and integration-test-<feature>, and the integration target
// runs only that feature's tests. (That docs/ and the map agree is
// TestFeatureMap_EveryDocsDirectoryIsAFeatureAndBack.)
func TestScriptsMakefile_EveryFeatureIsMapped(t *testing.T) {
	root := repoRoot(t)
	for _, fl := range readFeatureMap(t, root) {
		for _, prefix := range []string{"test-", "integration-test-"} {
			cmd := exec.Command("make", "-n", "--no-print-directory", prefix+fl.Feature)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("make %s%s: feature %s is not in the Makefile's feature mapping: %v\n%s", prefix, fl.Feature, fl.Feature, err, out)
				continue
			}
			if prefix == "integration-test-" && !strings.Contains(string(out), "-run ^"+fl.Prefix) {
				t.Errorf("make %s%s does not select its tests with -run ^%s:\n%s", prefix, fl.Feature, fl.Prefix, out)
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
	// These scripts ship with ci-template and are copied verbatim: the template,
	// not lib.sh, governs their drift, so neither rule binds them.
	templateScripts := map[string]bool{"apk-index-sum.sh": true, "ci-image-cache.sh": true}
	for _, s := range scripts {
		body, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(s)
		if name == "lib.sh" || templateScripts[name] {
			continue
		}
		if m := def.FindString(string(body)); m != "" {
			t.Errorf("%s defines %q, which scripts/lib.sh owns", name, m)
		}
		if strings.HasPrefix(string(body), "#!") && !templateScripts[name] && !source.Match(body) {
			t.Errorf("%s does not source scripts/lib.sh", name)
		}
	}
}
