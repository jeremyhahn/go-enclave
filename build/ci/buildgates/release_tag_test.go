package buildgates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for build/ci/release-tag.sh, which release.yml runs (with sh) to turn
// GITHUB_REF into the tag= and sha= step outputs. Git and the `v*` trigger
// accept tag names such as v`id` and v$(id); the script must refuse every
// name that is not a plain version string before it is echoed or written.

// releaseTagScript is the script's path relative to scripts/, where
// runScript looks.
const releaseTagScript = "../build/ci/release-tag.sh"

// releaseTagRepo makes a scratch git repository with one commit and returns
// its directory and the commit's sha.
func releaseTagRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "release")
	return dir, gitIn(t, dir, "rev-parse", "HEAD")
}

// runReleaseTag runs the script in dir with ref as GITHUB_REF (unset when
// ref is nil) and an empty output file, and returns the combined output,
// whether it exited 0 and what it wrote to the output file.
func runReleaseTag(t *testing.T, dir string, ref *string) (string, bool, string) {
	t.Helper()
	outFile := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(outFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GITHUB_OUTPUT": outFile}
	if ref != nil {
		env["GITHUB_REF"] = *ref
	} else {
		t.Setenv("GITHUB_REF", "")
		if err := os.Unsetenv("GITHUB_REF"); err != nil {
			t.Fatal(err)
		}
	}
	out, ok := runScript(t, dir, env, releaseTagScript)
	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	return out, ok, string(written)
}

func TestReleaseTag_APlainVersionTagBecomesTheOutputs(t *testing.T) {
	dir, sha := releaseTagRepo(t)
	for _, tag := range []string{"v1.2.3", "v1.2.3-alpha.1", "v0.10.0-rc.2"} {
		t.Run(tag, func(t *testing.T) {
			ref := "refs/tags/" + tag
			out, ok, written := runReleaseTag(t, dir, &ref)
			if !ok {
				t.Fatalf("refused %s:\n%s", ref, out)
			}
			if want := "tag=" + tag + "\nsha=" + sha + "\n"; written != want {
				t.Fatalf("outputs for %s = %q, want %q", ref, written, want)
			}
		})
	}
}

func TestReleaseTag_RefusesEveryRefThatIsNotAPlainVersionTag(t *testing.T) {
	dir, _ := releaseTagRepo(t)
	refs := []string{
		"refs/heads/main",
		"refs/heads/v1.2.3",
		"refs/pull/1/merge",
		"v1.2.3",
		"refs/tags/1.2.3",
		"refs/tags/-v1.2.3",
		"refs/tags/v1.2.3;id",
		"refs/tags/v1.2.3&&id",
		"refs/tags/v1.2.3|id",
		"refs/tags/v1.2.3>x",
		"refs/tags/v1.2.3<x",
		"refs/tags/v1.2.3*",
		"refs/tags/v1.2.3?",
		"refs/tags/v1.2.3[a]",
		"refs/tags/v1.2.3~1",
		"refs/tags/v1.2.3^",
		"refs/tags/v1.2.3#x",
		"refs/tags/v1.2.3%x",
		"refs/tags/v1.2.3=x",
		"refs/tags/v1.2.3+meta",
		"refs/tags/v1.2.3_x",
		"refs/tags/v1.2.3\\x",
		"refs/tags/v1.2.3 x",
		"refs/tags/v1.2.3\tx",
		"refs/tags/v1.2.3/x",
		"refs/tags/v1/2",
		"refs/tags/v1.2.3'x'",
		"refs/tags/v1.2.3\"x\"",
		"refs/tags/v`id`",
		"refs/tags/v$(id)",
		"refs/tags/v${HOME}",
		"refs/tags/v$HOME",
		"refs/tags/v1.2.3\nsha=0000",
		"refs/tags/v1.2.3\r",
		"refs/tags/v1.2.\u00e9",
	}
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			out, ok, written := runReleaseTag(t, dir, &ref)
			assertReleaseTagRefused(t, ref, out, ok, written)
		})
	}
	for name, ref := range map[string]*string{"empty": new(string), "unset": nil} {
		t.Run(name, func(t *testing.T) {
			out, ok, written := runReleaseTag(t, dir, ref)
			assertReleaseTagRefused(t, name, out, ok, written)
		})
	}
}

func assertReleaseTagRefused(t *testing.T, ref, out string, ok bool, written string) {
	t.Helper()
	if ok {
		t.Fatalf("accepted %q:\n%s", ref, out)
	}
	if written != "" {
		t.Fatalf("refused %q but wrote outputs %q", ref, written)
	}
	if name := strings.TrimPrefix(ref, "refs/tags/"); strings.HasPrefix(ref, "refs/") && strings.Contains(out, name) {
		t.Fatalf("refusing %q echoed the raw name:\n%s", ref, out)
	}
	if !strings.Contains(out, "::error::") {
		t.Fatalf("refused %q without an ::error:: line:\n%s", ref, out)
	}
}
