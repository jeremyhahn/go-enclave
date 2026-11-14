package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// releaseTagScript (release_tag_test.go) names the script both files drive.

// releaseTagTableRepo returns a temporary git repository holding one commit, and
// that commit's sha.
func releaseTagTableRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{
			"-c", "user.name=release-tag-test",
			"-c", "user.email=release-tag-test@example.invalid",
			"-c", "commit.gpgsign=false",
		}, args...)...)
		cmd.Dir = dir
		cmd.Env = layerEnv(os.Environ(), map[string]string{"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1"})
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "release tag fixture")
	return dir, git("rev-parse", "HEAD")
}

// runReleaseTagTable runs release-tag.sh in dir with GITHUB_REF set to ref (empty
// for unset) and GITHUB_OUTPUT set to a new file in dir unless noOutput, and
// returns the script's output, whether it exited 0 and the output file's
// contents.
func runReleaseTagTable(t *testing.T, dir, ref string, noOutput bool) (string, bool, string) {
	t.Helper()
	outFile := filepath.Join(dir, "github-output")
	if err := os.WriteFile(outFile, nil, 0o644); err != nil {
		t.Fatalf("write %s: %v", outFile, err)
	}
	env := map[string]string{"GITHUB_REF": ref, "GITHUB_OUTPUT": outFile}
	if noOutput {
		env["GITHUB_OUTPUT"] = ""
	}
	out, ok := runScript(t, dir, env, releaseTagScript)
	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read %s: %v", outFile, err)
	}
	return out, ok, string(written)
}

func TestReleaseTagRefusesARefThatIsNotAVTag(t *testing.T) {
	dir, _ := releaseTagTableRepo(t)
	for name, ref := range map[string]string{
		"unset":         "",
		"branch":        "refs/heads/main",
		"tag without v": "refs/tags/x1",
		"v branch":      "refs/heads/v1.2.3",
	} {
		t.Run(name, func(t *testing.T) {
			out, ok, written := runReleaseTagTable(t, dir, ref, false)
			if ok {
				t.Fatalf("release-tag.sh accepted %q:\n%s", ref, out)
			}
			if !strings.Contains(out, "::error::release.yml ran for a ref that is not a v* tag") {
				t.Errorf("no ::error:: line for %q:\n%s", ref, out)
			}
			if written != "" {
				t.Errorf("GITHUB_OUTPUT written for %q: %q", ref, written)
			}
		})
	}
}

func TestReleaseTagRefusesATagHoldingShellOrPathCharacters(t *testing.T) {
	dir, _ := releaseTagTableRepo(t)
	for name, tag := range map[string]string{
		"command substitution": "v$(id)",
		"backtick":             "v`id`",
		"space":                "v1 2",
		"slash":                "v1/2",
		"newline":              "v1\n2",
		"semicolon":            "v1;id",
		"underscore":           "v1_2",
		"plus":                 "v1+2",
	} {
		t.Run(name, func(t *testing.T) {
			out, ok, written := runReleaseTagTable(t, dir, "refs/tags/"+tag, false)
			if ok {
				t.Fatalf("release-tag.sh accepted %q:\n%s", tag, out)
			}
			if !strings.Contains(out, "::error::the tag name holds characters no release version does; refusing it") {
				t.Errorf("no ::error:: line for %q:\n%s", tag, out)
			}
			if strings.Contains(out, "Releasing") {
				t.Errorf("the refused tag %q was echoed:\n%s", tag, out)
			}
			if written != "" {
				t.Errorf("GITHUB_OUTPUT written for %q: %q", tag, written)
			}
		})
	}
}

func TestReleaseTagWritesTagAndSha(t *testing.T) {
	dir, sha := releaseTagTableRepo(t)
	for _, tag := range []string{"v1.2.3", "v1.2.3-alpha.1", "v0.10.0-ALPHA"} {
		t.Run(tag, func(t *testing.T) {
			out, ok, written := runReleaseTagTable(t, dir, "refs/tags/"+tag, false)
			if !ok {
				t.Fatalf("release-tag.sh refused %q:\n%s", tag, out)
			}
			if want := "tag=" + tag + "\nsha=" + sha + "\n"; written != want {
				t.Errorf("GITHUB_OUTPUT = %q, want %q", written, want)
			}
			if want := "Releasing " + tag + " from " + sha + "\n"; out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
		})
	}
}

func TestReleaseTagRequiresGithubOutput(t *testing.T) {
	dir, _ := releaseTagTableRepo(t)
	out, ok, written := runReleaseTagTable(t, dir, "refs/tags/v1.2.3", true)
	if ok {
		t.Fatalf("release-tag.sh passed with GITHUB_OUTPUT unset:\n%s", out)
	}
	if !strings.Contains(out, "GITHUB_OUTPUT is required") {
		t.Errorf("no GITHUB_OUTPUT message:\n%s", out)
	}
	if written != "" {
		t.Errorf("output file written with GITHUB_OUTPUT unset: %q", written)
	}
}

func TestReleaseTagFailsOutsideAGitRepository(t *testing.T) {
	dir := t.TempDir()
	out, ok, written := runReleaseTagTable(t, dir, "refs/tags/v1.2.3", false)
	if ok {
		t.Fatalf("release-tag.sh passed outside a git repository:\n%s", out)
	}
	if strings.Contains(out, "Releasing") || written != "" {
		t.Errorf("release-tag.sh named a release with no commit: %q, output file %q", out, written)
	}
}
