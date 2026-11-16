package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// TestScriptsReleaseTag_RefusesWhenDevsTagsMoveBeforeThePush interleaves a
// second release with release-tag.sh: rc.1 passes its precedence check, and
// while release-tag waits on the forge's pull requests another maintainer
// tags rc.2 on dev. Pushing rc.1 then would publish a lower version after a
// higher one, so release-tag must notice dev's tags changed since its check
// and refuse, leaving rc.1 neither on dev nor in the clone.
func TestScriptsReleaseTag_RefusesWhenDevsTagsMoveBeforeThePush(t *testing.T) {
	const version, newer = "v1.5.0-rc.1", "v1.5.0-rc.2"
	r := newReleaseRepo(t)
	if out, ok := r.run("candidate", version); !ok {
		t.Fatalf("first step refused:\n%s", out)
	}
	mergeSHA, _ := r.merge(version)
	var hookErr error
	hooked := false
	r.forge.mu.Lock()
	r.forge.onPulls = func() {
		hooked = true
		cmd := exec.Command("git", "tag", newer, mergeSHA)
		cmd.Dir = r.bare
		if out, err := cmd.CombinedOutput(); err != nil {
			hookErr = fmt.Errorf("git tag %s in dev: %w\n%s", newer, err, out)
		}
	}
	r.forge.mu.Unlock()

	out, ok := r.tag(version)
	r.forge.mu.Lock()
	defer r.forge.mu.Unlock()
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !hooked {
		t.Fatalf("release-tag never read the forge's pull requests, so nothing interleaved:\n%s", out)
	}
	if ok {
		t.Fatalf("tagged %s after %s appeared on dev, want a refusal:\n%s", version, newer, out)
	}
	if !strings.Contains(out, "dev's tags changed") {
		t.Fatalf("refusal does not say dev's tags changed:\n%s", out)
	}
	for _, dir := range []string{r.dir, r.bare} {
		if got := r.git(dir, "tag", "-l", version); got != "" {
			t.Fatalf("a refused release-tag left tag %s in %s", version, dir)
		}
	}
	if got := r.git(r.bare, "tag", "-l", newer); got != newer {
		t.Fatalf("dev lost %s: %q", newer, got)
	}
}

// TestScriptsReleaseWorkflow_OrdersTheTagBeforePublishing requires release.yml
// to be the receive-time guard for version precedence: runs are serialized by
// a workflow-level concurrency group that never cancels a run in progress,
// and a job publish needs (and whose result it checks) fetches every v* tag
// from the forge, sets the pushed tag itself aside, and runs
// scripts/release-version-check.sh, the one implementation of the order.
func TestScriptsReleaseWorkflow_OrdersTheTagBeforePublishing(t *testing.T) {
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
	if strings.TrimSpace(wf.Concurrency.Group) == "" {
		t.Fatal("release.yml has no workflow-level concurrency group, so two tag runs are not serialized")
	}
	if c := wf.Concurrency.CancelInProgress; c != nil && c != false {
		t.Fatalf("release.yml's concurrency cancels in progress (%v); a tag run must finish, not be canceled", c)
	}
	publish, ok := wf.Jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	var checks string
	for _, s := range publish.Steps {
		checks += s.Run
		if strings.Contains(s.Run, "release-version-check.sh") {
			t.Fatal("publish runs the precedence check itself; it must pass before publish starts")
		}
	}
	var orderJob string
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			i := strings.Index(s.Run, "sh scripts/release-version-check.sh")
			if i < 0 {
				continue
			}
			before := s.Run[:i]
			if !strings.Contains(before, "git fetch") || !strings.Contains(before, "refs/tags/v*") {
				t.Fatalf("job %s runs release-version-check.sh without first fetching the forge's v* tags:\n%s", name, s.Run)
			}
			if !strings.Contains(before, `git tag -d "$TAG"`) {
				t.Fatalf("job %s orders the tag against itself (no git tag -d \"$TAG\" before the check):\n%s", name, s.Run)
			}
			orderJob = name
		}
	}
	if orderJob == "" {
		t.Fatal("no release.yml job runs sh scripts/release-version-check.sh")
	}
	needed := false
	for _, n := range publish.Needs {
		needed = needed || n == orderJob
	}
	if !needed {
		t.Fatalf("publish does not need %q, the job that orders the tag (needs: %v)", orderJob, publish.Needs)
	}
	if !strings.Contains(checks, "needs."+orderJob+".result") {
		t.Fatalf("publish does not check needs.%s.result before publishing", orderJob)
	}
}
