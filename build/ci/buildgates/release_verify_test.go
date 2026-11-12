package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// releaseVerifyTag is the one tag the fixture repository's VERSION and
// CHANGELOG.md agree with.
const releaseVerifyTag = "v1.2.3"

// gitFixtureEnv keeps the fixture repository's git away from the runner's
// own configuration (signing keys, hooks, default branch).
var gitFixtureEnv = map[string]string{
	"GIT_CONFIG_GLOBAL":   os.DevNull,
	"GIT_CONFIG_NOSYSTEM": "1",
	"GIT_AUTHOR_NAME":     "fixture",
	"GIT_AUTHOR_EMAIL":    "fixture@example.invalid",
	"GIT_COMMITTER_NAME":  "fixture",
	"GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}

func fixtureGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), gitFixtureEnv)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// releaseVerifyRepo is a git repository whose tree satisfies
// release-check-tag.sh for releaseVerifyTag: branch main holds one commit,
// branch side one more commit on top of it. HEAD is on main.
func releaseVerifyRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"VERSION":      strings.TrimPrefix(releaseVerifyTag, "v") + "\n",
		"CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\n## [" + releaseVerifyTag + "] - 2026-11-12\n\n### Added\n\n- The first release.\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	fixtureGit(t, dir, "init", "-q", "-b", "main")
	fixtureGit(t, dir, "add", "VERSION", "CHANGELOG.md")
	fixtureGit(t, dir, "commit", "-q", "-m", "release")
	fixtureGit(t, dir, "checkout", "-q", "-b", "side")
	fixtureGit(t, dir, "commit", "-q", "--allow-empty", "-m", "side work")
	fixtureGit(t, dir, "checkout", "-q", "main")
	return dir
}

func TestReleaseVerifyArguments(t *testing.T) {
	dir := releaseVerifyRepo(t)

	out, ok := runScript(t, dir, gitFixtureEnv, "release-verify.sh")
	if ok || !strings.Contains(out, "usage:") || !strings.Contains(out, "<tag> [<main-ref>]") {
		t.Errorf("no arguments: ok=%v, want the usage and a failure:\n%s", ok, out)
	}

	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", "")
	if ok || !strings.Contains(out, "TAG=vX.Y.Z[-pre] is required") {
		t.Errorf("empty tag: ok=%v, want a failure naming TAG:\n%s", ok, out)
	}

	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", "v1.2")
	if ok || !strings.Contains(out, "tag 'v1.2' is not vX.Y.Z") {
		t.Errorf("malformed tag: ok=%v, want release-check-tag.sh's refusal:\n%s", ok, out)
	}

	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", "v1.2.4")
	if ok || !strings.Contains(out, "VERSION reads '1.2.3' but the tag is 'v1.2.4'") {
		t.Errorf("tag VERSION disagrees with: ok=%v, want release-check-tag.sh's refusal:\n%s", ok, out)
	}
}

// TestReleaseVerifyRefusesUnplainRef: a MAIN_REF that could be read as an
// option or carries shell metacharacters is refused before git ever runs. A
// fake git first on PATH announces itself if it is called.
func TestReleaseVerifyRefusesUnplainRef(t *testing.T) {
	dir := releaseVerifyRepo(t)
	bin := filepath.Join(t.TempDir(), "bin")
	const called = "fake git was called"
	fakeTool(t, bin, "git", called)
	over := map[string]string{"PATH": bin + string(os.PathListSeparator) + isolatedPath(t)}
	for k, v := range gitFixtureEnv {
		over[k] = v
	}
	for _, ref := range []string{"-x", "--all", "a;b", "a b", "$(id)", "main~1", "main^", "a:b", "a\nb"} {
		out, ok := runScript(t, dir, over, "release-verify.sh", releaseVerifyTag, ref)
		if ok || !strings.Contains(out, "MAIN_REF is not a plain ref name; refusing it") {
			t.Errorf("MAIN_REF %q: ok=%v, want the refusal:\n%s", ref, ok, out)
		}
		if strings.Contains(out, called) {
			t.Errorf("MAIN_REF %q: git ran before the refusal:\n%s", ref, out)
		}
	}
}

func TestReleaseVerifyAncestry(t *testing.T) {
	dir := releaseVerifyRepo(t)

	out, ok := runScript(t, dir, gitFixtureEnv, "release-verify.sh", releaseVerifyTag)
	if !ok || !strings.Contains(out, "v1.2.3 agrees with VERSION and CHANGELOG.md") || strings.Contains(out, "HEAD is on") {
		t.Errorf("no main ref: ok=%v, want a pass with no ancestry line:\n%s", ok, out)
	}

	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", releaseVerifyTag, "main")
	if !ok || !strings.Contains(out, "release-verify: HEAD is on main") {
		t.Errorf("HEAD on main: ok=%v, want a pass saying HEAD is on main:\n%s", ok, out)
	}

	// HEAD on main is an ancestor of side too.
	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", releaseVerifyTag, "side")
	if !ok || !strings.Contains(out, "HEAD is on side") {
		t.Errorf("HEAD behind side: ok=%v, want a pass:\n%s", ok, out)
	}

	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", releaseVerifyTag, "nosuch/ref")
	if ok || !strings.Contains(out, "MAIN_REF 'nosuch/ref' does not name a commit") {
		t.Errorf("unknown ref: ok=%v, want a failure naming it:\n%s", ok, out)
	}

	fixtureGit(t, dir, "checkout", "-q", "side")
	out, ok = runScript(t, dir, gitFixtureEnv, "release-verify.sh", releaseVerifyTag, "main")
	if ok || !strings.Contains(out, "is not on main") || strings.Contains(out, "HEAD is on") {
		t.Errorf("HEAD on a side branch: ok=%v, want a failure:\n%s", ok, out)
	}
}

// TestReleaseVerifyChecksTagBeforeRef: a refused tag fails the run even when
// HEAD is on the ref, and the ancestry check never reports a pass.
func TestReleaseVerifyChecksTagBeforeRef(t *testing.T) {
	dir := releaseVerifyRepo(t)
	out, ok := runScript(t, dir, gitFixtureEnv, "release-verify.sh", "v1.2.3-beta", "main")
	if ok || !strings.Contains(out, "tag 'v1.2.3-beta' is not vX.Y.Z") || strings.Contains(out, "HEAD is on") {
		t.Errorf("refused tag with a good ref: ok=%v, want release-check-tag.sh's refusal only:\n%s", ok, out)
	}
}
