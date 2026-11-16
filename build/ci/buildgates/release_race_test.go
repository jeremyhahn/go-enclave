package buildgates

import (
	"os"
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
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "publish-release.sh") || strings.Contains(s.Run, "release-publish") {
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
	for _, gone := range []string{"scripts/release-publish.sh", "build/ci/publish-release.sh"} {
		if _, err := os.Stat(filepath.Join(repoRoot(t), gone)); err == nil {
			t.Fatalf("%s, the retired forge's release publisher, is still in the tree", gone)
		}
	}
}
