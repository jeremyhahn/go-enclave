package buildgates

import (
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the Makefile and scripts fixes of #136 (T3b).

func TestChangelogAssemble_FoldsFragmentsInIssueOrder(t *testing.T) {
	dir := assembleTree(t, assembleHeader+"\n"+assemblePrevious, map[string]string{
		"100-c.md": "### Added\n\n- FRAG-100\n",
		"9-a.md":   "### Added\n\n- FRAG-9\n",
		"20-b.md":  "### Added\n\n- FRAG-20\n",
	})
	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("assembly failed:\n%s", out)
	}
	got := readFile(t, filepath.Join(dir, "CHANGELOG.md"))
	i9, i20, i100 := strings.Index(got, "FRAG-9"), strings.Index(got, "FRAG-20"), strings.Index(got, "FRAG-100")
	if i9 < 0 || i20 < 0 || i100 < 0 || i9 > i20 || i20 > i100 {
		t.Fatalf("fragments are not folded in numeric issue order (9, 20, 100):\n%s", got)
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
		"\nexample.com/held v1.0.0 v1.1.0\nexample.com/swapped v1.0.0 v1.3.0\nexample.com/graph-only v1.0.0 v2.0.0\n\n")
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
		"example.com/direct v1.0.0 v1.4.0\nexample.com/indirect v1.0.0 v1.0.1\nexample.com/empty v1.0.0 v1.1.0\n")
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
