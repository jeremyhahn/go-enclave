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
	// A runner group routes the job off the hosted pool, whatever labels
	// stand beside it.
	{"fail-runner-group-hosted-labels", true},
	// A release job's `if:` must prove push to main or a tag, or
	// workflow_dispatch on main; a branch, ref or event outside that is
	// a finding, however it is spelled.
	{"fail-release-push-other-branch", true},
	{"fail-release-pull-request-unsampled-ref", true},
	{"fail-release-issue-comment-unsampled-ref", true},
	{"fail-release-unsampled-event", true},
	// A release job is a self-hosted job first: it names a category and a
	// reason, and the credential category stays on code-review.yml's review
	// job, before its `if:` is read at all.
	{"fail-release-push-main-no-reason", true},
	{"fail-release-credential-on-ci", true},
	{"pass-release-hardware-reason", false},
	// Actions compares arrays and objects by instance, so two fromJSON
	// results are never equal; the step cannot know identity and treats
	// the comparison as unknown.
	{"fail-fromjson-array-equality", true},
	{"fail-fromjson-object-inequality", true},
	// Actions writes a number without a fraction when it is integral, null
	// as the empty string, and `{{` in a format string as `{`.
	{"fail-format-number-string", true},
	{"fail-format-null-string", true},
	{"fail-format-escaped-brace", true},
	// A waiver is a real trailing YAML comment. The same text inside a
	// quoted scalar or an expression string is data, not a reason.
	{"fail-waiver-in-quoted-expression", true},
	{"fail-waiver-in-plain-expression", true},
	{"fail-waiver-in-double-quoted-escape", true},
	{"pass-waiver-after-quoted-expression", false},
	// Relational operators bind tighter than == and !=, as in Actions:
	// 0 == 2 < 3 is 0 == true, which is false.
	{"fail-mixed-comparison-precedence", true},
	{"pass-mixed-comparison-precedence", false},
	// A release label counts after YAML decoding and expression
	// evaluation, and a label the step cannot evaluate counts as one.
	{"fail-release-escaped-label", true},
	{"fail-release-format-label", true},
	{"fail-release-unknown-label", true},
	{"pass-release-push-main", false},
	{"pass-release-push-tag", false},
	{"pass-release-push-main-or-tag", false},
	{"pass-plain-hosted", false},
	{"pass-server-url-hosted", false},
	{"pass-hardware-waiver", false},
	{"pass-oversize-waiver", false},
	{"pass-credential-on-review", false},
}

// runnerLabelsWant names, for a fixture that must be reported, text the
// step's output must hold. The release fixtures carry a hardware reason, so
// only the release-condition check can report them; each must report the
// condition, not merely fail.
var runnerLabelsWant = map[string][]string{
	"fail-release-push-other-branch": {
		"publish: (b) names `release` and its `if:` does not prove it runs only on",
	},
	"fail-release-pull-request-unsampled-ref": {
		"publish: (a) names `release` and a pull_request event can run it",
		"publish: (b) names `release` and its `if:` does not prove it runs only on",
	},
	"fail-release-issue-comment-unsampled-ref": {
		"publish: (b) names `release` and its `if:` does not prove it runs only on",
	},
	"fail-release-unsampled-event": {
		"publish: (b) names `release` and its `if:` does not prove it runs only on",
	},
	"fail-unknown-or-in-comparison": {
		"build: (b) names `release` and its `if:` does not prove it runs only on",
	},
	"fail-waiver-in-quoted-expression": {
		"build: (c) does not run on a standard GitHub-hosted image",
	},
	"fail-waiver-in-plain-expression": {
		"build: (c) does not run on a standard GitHub-hosted image",
	},
	"fail-waiver-in-double-quoted-escape": {
		"build: (c) does not run on a standard GitHub-hosted image",
	},
	"fail-mixed-comparison-precedence": {
		"build: (c) does not run on a standard GitHub-hosted image",
	},
	"fail-release-escaped-label": {
		"publish: (a) names `release` in a workflow with a pull_request trigger",
	},
	"fail-release-format-label": {
		"publish: (a) names `release` in a workflow with a pull_request trigger",
	},
	"fail-release-unknown-label": {
		"publish: (a) names `release` in a workflow with a pull_request trigger",
	},
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

	// A diagnostic named for a fixture the table does not run, or one that
	// must pass, would assert nothing.
	for dir := range runnerLabelsWant {
		found := false
		for _, c := range runnerLabelsCases {
			found = found || (c.dir == dir && c.findings)
		}
		if !found {
			t.Errorf("runnerLabelsWant names %s, which is not a fixture the step must report", dir)
		}
	}

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
			t.Logf("the step on %s/%s:\n%s", c.dir, name, out)
			finding := strings.Contains(out, "::error::.github/workflows/"+name+":")
			switch {
			case c.findings && (!failed || !finding):
				t.Errorf("the step passed %s/%s (failed: %v), want a finding; output:\n%s", c.dir, name, failed, out)
			case !c.findings && failed:
				t.Errorf("the step reported %s/%s, want no finding; output:\n%s", c.dir, name, out)
			}
			for _, want := range runnerLabelsWant[c.dir] {
				if !strings.Contains(out, "::error::.github/workflows/"+name+":"+want) {
					t.Errorf("the step on %s/%s does not report %q; output:\n%s", c.dir, name, want, out)
				}
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
