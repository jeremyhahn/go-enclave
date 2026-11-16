package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// releaseLock is the ref on dev that release-tag.sh moves, in the same atomic
// push as the tag and leased on the value it read before its precedence check.
const releaseLock = "refs/heads/release-lock"

// beforePush makes the releaseRepo's AGENT_GIT run script once, just before
// the next push it is asked for: after every read release-tag.sh makes, and
// before the push. It is a test's stand-in for another maintainer's release
// landing in that window.
func (r *releaseRepo) beforePush(script string) {
	r.t.Helper()
	if err := os.WriteFile(r.env["AGENT_GIT"]+".before-push", []byte(script), 0o600); err != nil {
		r.t.Fatalf("write the before-push hook: %v", err)
	}
}

// TestScriptsReleaseTag_RefusesWhenAHigherReleaseMovesTheLockBeforeThePush
// interleaves a second release with release-tag.sh after its last read of
// dev: rc.1 passes its precedence check, then another maintainer's release
// tags rc.2 on dev and moves the release lock, and only then does rc.1's push
// run. Pushing rc.1 would publish a lower version after a higher one, so the
// push must be refused on dev itself, writing neither the tag nor the lock.
func TestScriptsReleaseTag_RefusesWhenAHigherReleaseMovesTheLockBeforeThePush(t *testing.T) {
	const version, newer = "v1.5.0-rc.1", "v1.5.0-rc.2"
	for _, tc := range []struct {
		name string
		lock bool // a release before this one already set the lock
	}{
		{"first release, no lock on dev yet", false},
		{"the lock already set", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReleaseRepo(t)
			if tc.lock {
				r.git(r.bare, "update-ref", releaseLock, r.git(r.bare, "rev-parse", "main"))
			}
			if out, ok := r.run("candidate", version); !ok {
				t.Fatalf("first step refused:\n%s", out)
			}
			mergeSHA, _ := r.merge(version)
			lockBefore := r.git(r.bare, "for-each-ref", "--format=%(objectname)", releaseLock)
			// The other release: its tag and its lock move, on another commit.
			other := r.git(r.bare, "commit-tree", "-p", mergeSHA, "-m", "another release", mergeSHA+"^{tree}")
			r.beforePush("set -e\ngit --git-dir='" + r.bare + "' tag " + newer + " " + other +
				"\ngit --git-dir='" + r.bare + "' update-ref " + releaseLock + " " + other + "\n")

			out, ok := r.tag(version)
			if _, err := os.Stat(r.env["AGENT_GIT"] + ".before-push"); err == nil {
				t.Fatalf("release-tag never pushed, so nothing interleaved:\n%s", out)
			}
			if ok {
				t.Fatalf("tagged %s after %s and the lock moved on dev, want a refusal:\n%s", version, newer, out)
			}
			for _, dir := range []string{r.dir, r.bare} {
				if got := r.git(dir, "tag", "-l", version); got != "" {
					t.Fatalf("a refused release-tag left tag %s in %s:\n%s", version, dir, out)
				}
			}
			if got := r.git(r.bare, "for-each-ref", "--format=%(objectname)", releaseLock); got != other {
				t.Fatalf("dev's release lock is %q, want the other release's %s (before: %q):\n%s", got, other, lockBefore, out)
			}
			if got := r.git(r.bare, "tag", "-l", newer); got != newer {
				t.Fatalf("dev lost %s: %q", newer, got)
			}
		})
	}
}

// TestScriptsReleaseTag_SetsTheReleaseLockAndMovesIt requires the first
// release to create the lock on dev (the lease expects it absent) and each
// later release to move it to the commit it tagged.
func TestScriptsReleaseTag_SetsTheReleaseLockAndMovesIt(t *testing.T) {
	r := newReleaseRepo(t)
	if got := r.git(r.bare, "for-each-ref", releaseLock); got != "" {
		t.Fatalf("a fresh dev already has %s: %q", releaseLock, got)
	}
	lockAt := func(version string) {
		t.Helper()
		want := r.git(r.bare, "rev-parse", version+"^{commit}")
		if got := r.git(r.bare, "for-each-ref", "--format=%(objectname)", releaseLock); got != want {
			t.Fatalf("after %s dev's release lock is %q, want the tagged commit %s", version, got, want)
		}
	}
	r.cut("candidate", "v1.5.0-rc.1")
	lockAt("v1.5.0-rc.1")
	if err := os.WriteFile(filepath.Join(r.dir, "changelog.d", "134-y.md"), []byte("### Fixed\n\n- a second candidate\n"), 0o600); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	r.git(r.dir, "add", "-A")
	r.git(r.dir, "commit", "-q", "-m", "fix")
	r.git(r.dir, "push", "-q", "dev", "main")
	r.cut("candidate", "v1.5.0-rc.2")
	lockAt("v1.5.0-rc.2")
}

// TestScriptsReleaseWorkflow_OrdersEveryTagInItsOwnRun requires release.yml's
// concurrency group to be keyed by the pushed tag, so no tag's run displaces
// another's pending one (GitHub keeps one pending run per group), never to
// cancel a run in progress, and to order the tag before anything else runs:
// Verify fetches every v* tag from the forge, sets the pushed tag aside, and
// runs scripts/release-version-check.sh, and every other job needs Verify.
// Nothing publishes: the retired forge's release publisher is gone.
func TestScriptsReleaseWorkflow_OrdersEveryTagInItsOwnRun(t *testing.T) {
	type step struct {
		Run string `yaml:"run"`
	}
	type job struct {
		Needs []string `yaml:"needs"`
		Steps []step   `yaml:"steps"`
	}
	var wf struct {
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress any    `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
		Jobs map[string]job `yaml:"jobs"`
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	if c := wf.Concurrency.CancelInProgress; c != nil && c != false {
		t.Fatalf("release.yml's concurrency cancels in progress (%v); a tag run must finish, not be canceled", c)
	}
	group := wf.Concurrency.Group
	if !strings.Contains(group, "${{ github.ref }}") {
		t.Fatalf("release.yml's concurrency group %q is not keyed by the tag ref (github.ref)", group)
	}
	groups := map[string]string{}
	for _, tag := range []string{"v1.5.0-rc.1", "v1.5.0-rc.2", "v1.5.0"} {
		g := strings.NewReplacer("${{ github.ref }}", "refs/tags/"+tag, "${{ github.repository }}", "owner/repo", "${{ github.workflow }}", "Release").Replace(group)
		if strings.Contains(g, "${{") {
			t.Fatalf("concurrency group %q depends on more than the tag ref and the repository", group)
		}
		if prev, ok := groups[g]; ok {
			t.Fatalf("tags %s and %s share concurrency group %q", prev, tag, g)
		}
		groups[g] = tag
	}

	verify, ok := wf.Jobs["verify"]
	if !ok {
		t.Fatal("release.yml has no verify job")
	}
	ordered := false
	for _, s := range verify.Steps {
		i := strings.Index(s.Run, "sh scripts/release-version-check.sh")
		if i < 0 {
			continue
		}
		before := s.Run[:i]
		if !strings.Contains(before, "git fetch") || !strings.Contains(before, "refs/tags/v*") {
			t.Fatalf("verify runs release-version-check.sh without first fetching the forge's v* tags:\n%s", s.Run)
		}
		if !strings.Contains(before, `git tag -d "$TAG"`) {
			t.Fatalf("verify orders the tag against itself (no git tag -d \"$TAG\" before the check):\n%s", s.Run)
		}
		ordered = true
	}
	if !ordered {
		t.Fatal("release.yml's verify job does not run sh scripts/release-version-check.sh")
	}
	// The retired publisher's names, built from parts so that a search of the
	// tree for them finds only the changelog that records their removal.
	publisher := strings.Join([]string{"release", "publish"}, "-")
	ciPublisher := strings.Join([]string{"publish", "release"}, "-") + ".sh"
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, ciPublisher) || strings.Contains(s.Run, publisher) {
				t.Fatalf("job %s still runs the retired forge's release publisher:\n%s", name, s.Run)
			}
		}
		if name == "verify" {
			continue
		}
		needs := false
		for _, n := range j.Needs {
			needs = needs || n == "verify"
		}
		if !needs {
			t.Fatalf("job %s does not need verify, so it can run on a tag not yet ordered (needs: %v)", name, j.Needs)
		}
	}
	for _, gone := range []string{filepath.Join("scripts", publisher+".sh"), filepath.Join("build", "ci", ciPublisher)} {
		if _, err := os.Stat(filepath.Join(repoRoot(t), gone)); err == nil {
			t.Fatalf("%s, the retired forge's release publisher, is still in the tree", gone)
		}
	}
}

// verifyPrecedenceStep returns the run script of release.yml's Verify step
// that orders the pushed tag: the one that runs release-version-check.sh.
func verifyPrecedenceStep(t *testing.T) string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	for _, s := range wf.Jobs["verify"].Steps {
		if strings.Contains(s.Run, "sh scripts/release-version-check.sh") {
			return s.Run
		}
	}
	t.Fatal("release.yml's verify job does not run sh scripts/release-version-check.sh")
	return ""
}

// verifyForge is a forge with one line of commits, each setting VERSION and
// carrying the scripts Verify runs, and the v* tags pushed on them: what
// release.yml's Verify job fetches from when a tag's run starts.
type verifyForge struct {
	t          *testing.T
	bare, work string
	env        map[string]string
}

func newVerifyForge(t *testing.T) *verifyForge {
	t.Helper()
	root := t.TempDir()
	f := &verifyForge{t: t, bare: filepath.Join(root, "forge.git"), work: filepath.Join(root, "work"), env: map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
	}}
	f.git(root, "init", "-q", "--bare", f.bare)
	f.git(root, "init", "-q", f.work)
	f.git(f.work, "remote", "add", "origin", f.bare)
	for _, name := range []string{"release-version-check.sh", "lib.sh"} {
		body, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", name))
		if err != nil {
			t.Fatalf("read scripts/%s: %v", name, err)
		}
		if err := os.MkdirAll(filepath.Join(f.work, "scripts"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(f.work, "scripts", name), body, 0o644); err != nil {
			t.Fatalf("write scripts/%s: %v", name, err)
		}
	}
	return f
}

func (f *verifyForge) git(dir string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), f.env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit records a commit that sets VERSION to version on top of the line,
// tags it with each of tags and pushes the commit and the tags to the forge.
func (f *verifyForge) commit(version string, tags ...string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.work, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		f.t.Fatalf("write VERSION: %v", err)
	}
	f.git(f.work, "add", "-A")
	f.git(f.work, "commit", "-q", "-m", "VERSION "+version)
	for _, tag := range tags {
		f.git(f.work, "tag", "-a", tag, "-m", tag)
	}
	f.git(f.work, "push", "-q", "--tags", "origin", "HEAD:refs/heads/main")
}

// verify runs the Verify precedence step for tag, as a run of release.yml
// would now: in a fresh checkout of the tagged commit, against every tag the
// forge holds at this moment.
func (f *verifyForge) verify(run, tag string) (string, bool) {
	f.t.Helper()
	dir := filepath.Join(f.t.TempDir(), "runner")
	f.git(filepath.Dir(dir), "clone", "-q", f.bare, dir)
	sha := f.git(dir, "rev-parse", tag+"^{commit}")
	f.git(dir, "checkout", "-q", "--detach", sha)
	env := map[string]string{"TAG": tag, "SHA": sha}
	for k, v := range f.env {
		env[k] = v
	}
	cmd := exec.Command("bash", "-e", "-c", run)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			f.t.Fatalf("run the verify step: %v", err)
		}
		return string(out), false
	}
	return string(out), true
}

// TestScriptsReleaseWorkflow_VerifyPassesAnEarlierTagAfterALaterOne pushes
// rc.1 and then rc.2, in order, on successive commits before rc.1's run
// verifies. rc.2 is on a descendant of rc.1's commit, so it is not part of
// the release state rc.1 was published in: rc.1's Verify must pass (and a
// rerun of it later), and so must rc.2's. The leased push of the release
// lock, not Verify, is what orders releases.
func TestScriptsReleaseWorkflow_VerifyPassesAnEarlierTagAfterALaterOne(t *testing.T) {
	run := verifyPrecedenceStep(t)
	f := newVerifyForge(t)
	f.commit("1.4.0", "v1.4.0")
	f.commit("1.5.0-rc.1", "v1.5.0-rc.1")
	f.commit("1.5.0-rc.2", "v1.5.0-rc.2")
	for _, tag := range []string{"v1.5.0-rc.1", "v1.5.0-rc.2", "v1.5.0-rc.1"} {
		if out, ok := f.verify(run, tag); !ok {
			t.Fatalf("Verify refused %s, pushed in order before v1.5.0-rc.2 on a descendant commit:\n%s", tag, out)
		}
	}
}

// TestScriptsReleaseWorkflow_VerifyRefusesATagBelowAnAncestorTag requires
// Verify to refuse a tag when a tag on an ancestor of its commit outranks it:
// that tag was in the release state the pushed tag was cut from.
func TestScriptsReleaseWorkflow_VerifyRefusesATagBelowAnAncestorTag(t *testing.T) {
	run := verifyPrecedenceStep(t)
	f := newVerifyForge(t)
	f.commit("1.4.0", "v1.4.0", "v1.6.0")
	f.commit("1.5.0-rc.1", "v1.5.0-rc.1")
	out, ok := f.verify(run, "v1.5.0-rc.1")
	if ok {
		t.Fatalf("Verify passed v1.5.0-rc.1 below v1.6.0 on an ancestor commit, want a refusal:\n%s", out)
	}
	if !strings.Contains(out, "v1.6.0") {
		t.Fatalf("Verify's refusal does not name the ancestor tag v1.6.0:\n%s", out)
	}
}
