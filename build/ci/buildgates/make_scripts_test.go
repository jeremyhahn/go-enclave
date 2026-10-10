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
