package buildgates

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests for the Makefile and scripts fixes of #136 (T3b).

func TestChangelogAssemble_FoldsFragmentsInNameOrder(t *testing.T) {
	dir := assembleTree(t, assembleHeader+"\n"+assemblePrevious, map[string]string{
		"sealing.md":        "### Added\n\n- FRAG-SEALING\n",
		"backends.md":       "### Added\n\n- FRAG-BACKENDS\n",
		"memory-enclave.md": "### Added\n\n- FRAG-MEMORY\n",
	})
	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("assembly failed:\n%s", out)
	}
	got := readFile(t, filepath.Join(dir, "CHANGELOG.md"))
	ib, im, is := strings.Index(got, "FRAG-BACKENDS"), strings.Index(got, "FRAG-MEMORY"), strings.Index(got, "FRAG-SEALING")
	if ib < 0 || im < 0 || is < 0 || ib > im || im > is {
		t.Fatalf("fragments are not folded in file-name order (backends, memory-enclave, sealing):\n%s", got)
	}
}

func TestScriptsDepsLatest_FailsWhenGoListFails(t *testing.T) {
	dir := t.TempDir()
	goCmd := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\n" +
		"if [ \"$1 $2\" = \"list -m\" ] && [ $# -eq 2 ]; then echo example.com/self; exit 0; fi\n" +
		"echo \"go list failed\" >&2\nexit 1\n"
	writeExecutable(t, goCmd, []byte(script))
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-latest.sh")
	if ok {
		t.Fatalf("succeeded although go list failed:\n%s", out)
	}
	if !strings.Contains(out, "go list -m all failed") {
		t.Fatalf("does not say which go list failed:\n%s", out)
	}
}

// depsCheckTree writes gomod to a scratch module and a fake go whose
// `list -m -u` prints listing, and returns the module directory and the fake.
func depsCheckTree(t *testing.T, gomod, listing string) (string, string) {
	t.Helper()
	dir := writeTree(t, map[string]string{"go.mod": gomod})
	goCmd := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\n" +
		"[ \"$GOWORK\" = off ] || { echo \"GOWORK is not off\" >&2; exit 1; }\n" +
		"if [ \"$1 $2 $3\" = \"list -m -u\" ]; then printf '%s' '" + listing + "'; exit 0; fi\n" +
		"echo \"go list failed\" >&2\nexit 1\n"
	writeExecutable(t, goCmd, []byte(script))
	return dir, goCmd
}

const depsCheckGoMod = "module example.com/self\n\ngo 1.27.2\n\n" +
	"require example.com/direct v1.0.0\n\n" +
	"require (\n\texample.com/held v1.0.0 // held: v1.1.0 breaks the build\n" +
	"\texample.com/indirect v1.0.0 // indirect\n\texample.com/current v1.2.0\n)\n\n" +
	"replace example.com/swapped v1.0.0 => example.com/fork v1.0.0 // held: the fork carries a fix\n"

func TestScriptsDepsCheck_PassesWhenEveryModuleIsCurrentOrHeld(t *testing.T) {
	dir, goCmd := depsCheckTree(t, depsCheckGoMod,
		"\nexample.com/held v1.0.0 v1.1.0 0 unknown\nexample.com/swapped v1.0.0 v1.3.0 0 unknown\n"+
			"example.com/graph-only v1.0.0 v2.0.0 0 unknown\n\n")
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if !ok {
		t.Fatalf("failed although every module behind is held:\n%s", out)
	}
	for _, want := range []string{
		"example.com/held v1.0.0 is held below v1.1.0: v1.1.0 breaks the build",
		"example.com/swapped v1.0.0 is held below v1.3.0: the fork carries a fix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "graph-only") {
		t.Errorf("reports a module go.mod does not require:\n%s", out)
	}
}

func TestScriptsDepsCheck_FailsOnAnUndocumentedModuleBehind(t *testing.T) {
	gomod := depsCheckGoMod + "\nrequire example.com/empty v1.0.0 // held:\n"
	dir, goCmd := depsCheckTree(t, gomod,
		"example.com/direct v1.0.0 v1.4.0 "+depsCheckReleased(8*24*time.Hour)+"\n"+
			"example.com/indirect v1.0.0 v1.0.1 "+depsCheckReleased(30*24*time.Hour)+"\n"+
			"example.com/empty v1.0.0 v1.1.0 0 unknown\n")
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if ok {
		t.Fatalf("succeeded although modules are behind without a reason:\n%s", out)
	}
	for _, want := range []string{
		"example.com/direct v1.0.0 is behind v1.4.0",
		"example.com/indirect v1.0.0 is behind v1.0.1",
		"example.com/empty v1.0.0 is behind v1.1.0",
		"3 module(s) behind",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// depsCheckReleased returns the listing's release-time fields for a release
// published age ago: its Unix time and its UTC time.
func depsCheckReleased(age time.Duration) string {
	at := time.Now().Add(-age).UTC()
	return strconv.FormatInt(at.Unix(), 10) + " " + at.Format("2006-01-02T15:04:05Z")
}

func TestScriptsDepsCheck_ReportsARecentReleaseWithoutFailing(t *testing.T) {
	dir, goCmd := depsCheckTree(t, depsCheckGoMod,
		"example.com/direct v1.0.0 v1.4.0 "+depsCheckReleased(24*time.Hour)+"\n")
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if !ok {
		t.Fatalf("failed on a release under 7 days old:\n%s", out)
	}
	if !strings.Contains(out, "example.com/direct v1.0.0 is behind v1.4.0") || !strings.Contains(out, "under 7 days") {
		t.Fatalf("does not report the module behind a release under 7 days old:\n%s", out)
	}
}

func TestScriptsDepsCheck_FailsOnAReleaseOlderThan7Days(t *testing.T) {
	dir, goCmd := depsCheckTree(t, depsCheckGoMod,
		"example.com/direct v1.0.0 v1.4.0 "+depsCheckReleased(8*24*time.Hour)+"\n")
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if ok || !strings.Contains(out, "example.com/direct v1.0.0 is behind v1.4.0, with no '// held: <reason>' comment") {
		t.Fatalf("does not fail on a release 8 days old (ok=%v):\n%s", ok, out)
	}
}

func TestScriptsDepsCheck_FailsWhenTheReleaseTimeIsUnknown(t *testing.T) {
	dir, goCmd := depsCheckTree(t, depsCheckGoMod, "example.com/direct v1.0.0 v1.4.0 0 unknown\n")
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if ok || !strings.Contains(out, "1 module(s) behind") {
		t.Fatalf("does not fail when the release time is unknown (ok=%v):\n%s", ok, out)
	}
}

func TestScriptsDepsCheck_FailsWhenGoListFails(t *testing.T) {
	dir, _ := depsCheckTree(t, depsCheckGoMod, "")
	goCmd := filepath.Join(t.TempDir(), "go")
	writeExecutable(t, goCmd, []byte("#!/bin/sh\necho \"go list failed\" >&2\nexit 1\n"))
	out, ok := runScript(t, dir, map[string]string{"GOCMD": goCmd}, "deps-check.sh", ".")
	if ok || !strings.Contains(out, "go list -m -u all failed") {
		t.Fatalf("does not fail saying go list failed (ok=%v):\n%s", ok, out)
	}
}

func TestScriptsMakefile_T3bContract(t *testing.T) {
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))
	for _, want := range []string{
		"TEST_RACE    := -race",
		"test $(TEST_RACE) $(TESTFLAGS)",
		"BENCH_PACKAGES   := enclave",
		"ci-lint: tidy-check lint lint-runtimesecret ",
		"ci-security: gosec gosec-runtimesecret govulncheck govulncheck-runtimesecret ",
		"check-scripts: vet-buildgates",
	} {
		if !strings.Contains(mk, want) {
			t.Errorf("Makefile lacks %q", want)
		}
	}
	for _, banned := range []string{"check-action-pins:", "TESTFLAGS    := -race"} {
		if strings.Contains(mk, banned) {
			t.Errorf("Makefile still holds %q", banned)
		}
	}
	if strings.Contains(mk, `"$$GOCMD" vet $(PKG) && "$$GOCMD" test`) {
		t.Error("the gates macro vets again on every check; vet runs once, in vet-buildgates")
	}
}

// gosecUnscanned names the trees `make gosec` skips: test/, which is never
// shipped, and the nested modules, which gosec from v2.30.0 walks into from
// `./...` where go list does not.
var gosecUnscanned = []string{"test", "backends", "build/ci/buildgates"}

// makeVarValue returns the value of the simply expanded Makefile variable
// name, with its backslash continuation lines joined.
func makeVarValue(t *testing.T, mk, name string) string {
	t.Helper()
	var b strings.Builder
	found := false
	for _, line := range strings.Split(mk, "\n") {
		if !found {
			rest, ok := strings.CutPrefix(line, name+" := ")
			if !ok {
				continue
			}
			found, line = true, rest
		}
		more := strings.HasSuffix(line, `\`)
		b.WriteString(strings.TrimSuffix(line, `\`) + " ")
		if !more {
			break
		}
	}
	if !found {
		t.Fatalf("Makefile defines no %s", name)
	}
	return b.String()
}

// gosecExcludes compiles each -exclude-dir value of flags the way gosec's
// ExcludedDirsRegExp does: the value is an unanchored regular expression
// matched against the slash-separated directory gosec walks from `./...`.
func gosecExcludes(t *testing.T, flags string) map[string]*regexp.Regexp {
	t.Helper()
	res := map[string]*regexp.Regexp{}
	for _, f := range strings.Fields(flags) {
		v, ok := strings.CutPrefix(f, "-exclude-dir=")
		if !ok {
			continue
		}
		re, err := regexp.Compile(fmt.Sprintf(`([\\/])?%s([\\/])?`, strings.ReplaceAll(v, "/", `\/`)))
		if err != nil {
			t.Fatalf("-exclude-dir=%s is no regular expression gosec accepts: %v", v, err)
		}
		res[v] = re
	}
	return res
}

// TestScriptsMakefile_GosecScansEveryShippedPackage walks the repository as
// gosec does and holds the -exclude-dir values of both gosec passes to the
// unscanned trees: a bare word such as `test` also matched providertest/ and
// backendtest/, so the standalone scan skipped two shipped packages.
func TestScriptsMakefile_GosecScansEveryShippedPackage(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "Makefile"))
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") || rel == "bin") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(rel) == ".go" {
			dirs = append(dirs, filepath.ToSlash(filepath.Dir(rel)))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	for _, must := range []string{"providertest", "backendtest", "test/integration/enclave", "backends/tpm", "build/ci/buildgates"} {
		if !slices.Contains(dirs, must) {
			t.Fatalf("the walk found no Go files in %s", must)
		}
	}
	for _, name := range []string{"GOSEC_FLAGS", "GOSEC_RUNTIMESECRET_FLAGS"} {
		excludes := gosecExcludes(t, makeVarValue(t, mk, name))
		if len(excludes) == 0 {
			t.Errorf("%s excludes nothing; test/ and the nested modules must stay out", name)
		}
		for _, dir := range dirs {
			want := false
			for _, tree := range gosecUnscanned {
				if dir == tree || strings.HasPrefix(dir, tree+"/") {
					want = true
				}
			}
			var by []string
			for v, re := range excludes {
				if re.MatchString(dir) {
					by = append(by, v)
				}
			}
			switch {
			case want && len(by) == 0:
				t.Errorf("%s scans %s, which is outside the shipped tree", name, dir)
			case !want && len(by) > 0:
				t.Errorf("%s skips %s, outside test/ and the nested modules (-exclude-dir=%s)", name, dir, strings.Join(by, ", "))
			}
		}
	}
}

// TestScriptsMakefile_DepsCheckCoversEveryModule holds make deps-check to
// every module of the repository: the root, build/ci/buildgates and each of
// the Makefile's BACKEND_MODULES, so a stale requirement in any of them fails
// the gate.
func TestScriptsMakefile_DepsCheckCoversEveryModule(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "Makefile"))
	m := regexp.MustCompile(`(?m)^BACKEND_MODULES := (.+)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("Makefile: no BACKEND_MODULES := line")
	}
	modules := strings.Fields(m[1])
	if len(modules) == 0 {
		t.Fatal("Makefile: BACKEND_MODULES is empty")
	}
	for _, mod := range modules {
		readFile(t, filepath.Join(root, mod, "go.mod"))
	}
	r := regexp.MustCompile(`(?m)^deps-check:\n\t@?sh scripts/deps-check\.sh(.*)$`).FindStringSubmatch(mk)
	if r == nil {
		t.Fatal("Makefile: the deps-check recipe does not run scripts/deps-check.sh")
	}
	args := map[string]bool{}
	for _, a := range strings.Fields(r[1]) {
		args[a] = true
	}
	for _, want := range []string{".", "build/ci/buildgates", "$(BACKEND_MODULES)"} {
		if !args[want] {
			t.Errorf("make deps-check does not pass %q to scripts/deps-check.sh", want)
		}
	}
}
