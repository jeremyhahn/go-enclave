package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The runner-label step (ci.yml, job preflight) reads every workflow and
// fails on a job that may run off a standard GitHub-hosted image without a
// reason on its runs-on line. Two ways it must not fail open:
//
//   - a runs-on expression whose value hangs on something the step cannot
//     know (a repository variable, say) may pick any runner, whatever
//     constant stands beside it in `||` or `&&`;
//   - the credential category of `# self-hosted:` belongs to the review job
//     of code-review.yml alone; hardware and oversize hold on any job;
//   - an unknown value stays unknown through every operator, so an `if:`
//     built on one may be true, and a runs-on that tests the event or the
//     ref may pick its other runner on an event the step did not try;
//   - a workflow whose jobs it cannot list is a finding, not a pass.
//
// The script is taken out of the real ci.yml and run with bash, as CI runs
// it, in a directory whose .github/workflows holds one fixture from
// testdata/runner_labels, and once more on the repository itself.
const runnerLabelsStep = "Runner labels (ruling 633)"

// runnerLabelsWorkflow is the part of a workflow the gate reads: each step's
// name and script.
type runnerLabelsWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// runnerLabelsCases names each fixture directory and whether the step must
// report it. A fixture holds one workflow file, ci.yml or code-review.yml.
var runnerLabelsCases = []struct {
	dir      string
	findings bool
}{
	{"fail-vars-or-hosted", true},
	{"fail-event-and-vars-or-hosted", true},
	{"fail-vars-and-hosted-or-other", true},
	{"fail-credential-on-ci", true},
	{"fail-credential-on-other-review-job", true},
	{"fail-unknown-or-in-comparison", true},
	{"fail-jobs-single-quoted", true},
	{"fail-jobs-double-quoted", true},
	{"fail-jobs-flow-mapping", true},
	{"fail-pull-request-target-self-hosted", true},
	// Any event but the four named: release, a tag push, pull_request_target.
	{"fail-unsampled-event-self-hosted", true},
	{"fail-tag-ref-self-hosted", true},
	{"pass-plain-hosted", false},
	{"pass-server-url-hosted", false},
	{"pass-hardware-waiver", false},
	{"pass-oversize-waiver", false},
	{"pass-credential-on-review", false},
}

// runnerLabelsScript returns the step's script from ci.yml.
func runnerLabelsScript(t *testing.T, root string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf runnerLabelsWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	var scripts []string
	for _, job := range wf.Jobs {
		for _, st := range job.Steps {
			if st.Name == runnerLabelsStep {
				scripts = append(scripts, st.Run)
			}
		}
	}
	if len(scripts) != 1 || !strings.Contains(scripts[0], "python3") {
		t.Fatalf("ci.yml has %d steps named %q with a python3 script, want 1", len(scripts), runnerLabelsStep)
	}
	return scripts[0]
}

// runRunnerLabels runs the step's script in dir and returns its output and
// whether it failed.
func runRunnerLabels(t *testing.T, script, dir string) (string, bool) {
	t.Helper()
	return runStepScript(t, script, dir, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()})
}

func TestCIRunnerLabelsStep(t *testing.T) {
	// The step runs python3; a gate that cannot run it fails.
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("python3, which the step runs, is not in PATH: %v", err)
	}
	root := repoRoot(t)
	script := runnerLabelsScript(t, root)

	for _, c := range runnerLabelsCases {
		t.Run(c.dir, func(t *testing.T) {
			src := filepath.Join("testdata", "runner_labels", c.dir)
			entries, err := os.ReadDir(src)
			if err != nil || len(entries) != 1 {
				t.Fatalf("fixture %s: want one workflow file, got %d (%v)", src, len(entries), err)
			}
			name := entries[0].Name()
			body, err := os.ReadFile(filepath.Join(src, name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			dir := t.TempDir()
			wfDir := filepath.Join(dir, ".github", "workflows")
			if err := os.MkdirAll(wfDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wfDir, name), body, 0o644); err != nil {
				t.Fatal(err)
			}
			out, failed := runRunnerLabels(t, script, dir)
			finding := strings.Contains(out, "::error::.github/workflows/"+name+":")
			switch {
			case c.findings && (!failed || !finding):
				t.Errorf("the step passed %s/%s (failed: %v), want a finding; output:\n%s", c.dir, name, failed, out)
			case !c.findings && failed:
				t.Errorf("the step reported %s/%s, want no finding; output:\n%s", c.dir, name, out)
			}
		})
	}

	t.Run("repository", func(t *testing.T) {
		out, failed := runRunnerLabels(t, script, root)
		if failed || !strings.HasPrefix(strings.TrimSpace(out), "OK:") {
			t.Errorf("the step reports this repository's workflows, want 0 findings; output:\n%s", out)
		}
	})
}
