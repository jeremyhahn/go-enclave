package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
)

// runnerLabelsStep is the preflight step of ci.yml that checks every
// workflow's runs-on. It fails every CI run on any finding, so a workflow of
// this repository that it rejects turns the whole CI red before any other
// job starts.
const runnerLabelsStep = "Runner labels (ruling 633)"

// runnerLabelsScript returns the run script of the one step named
// runnerLabelsStep in ci.yml.
func runnerLabelsScript(t *testing.T, root string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
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
	if len(scripts) != 1 || scripts[0] == "" {
		t.Fatalf("ci.yml: %d steps named %q with a run script, want 1", len(scripts), runnerLabelsStep)
	}
	return scripts[0]
}

// TestRunnerLabelsPassOnOwnWorkflows runs ci.yml's runner-label check over
// this repository's own workflows, as preflight does, and expects no finding.
func TestRunnerLabelsPassOnOwnWorkflows(t *testing.T) {
	root := repoRoot(t)
	script := runnerLabelsScript(t, root)
	cmd := exec.Command("bash", "-e", "-c", script)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the runner-label check rejects this repository's workflows (%v):\n%s", err, out)
	}
}
