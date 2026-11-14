package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// A write-capable job must not run repository code it has not verified, and
// must not leave its token in the checkout. release.yml's publish job runs under
// always() so a failed stage turns it red, which also starts it after a failed
// Verify: its first step must therefore check every stage inline, before any
// checkout, and its checkouts must not persist the job token.

func workflowJobs(src []byte) (map[string]map[string]any, error) {
	var doc struct {
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	return doc.Jobs, nil
}

func jobSteps(job map[string]any) []map[string]any {
	var steps []map[string]any
	list, _ := job["steps"].([]any)
	for _, s := range list {
		if m, ok := s.(map[string]any); ok {
			steps = append(steps, m)
		}
	}
	return steps
}

func isCheckout(step map[string]any) bool {
	uses, _ := step["uses"].(string)
	return strings.HasPrefix(uses, "actions/checkout@")
}

// jobIsWriteCapable reports whether the job's own permissions grant any write.
func jobIsWriteCapable(job map[string]any) bool {
	switch p := job["permissions"].(type) {
	case string:
		return p == "write-all"
	case map[string]any:
		for _, level := range p {
			if l, _ := level.(string); l == "write" {
				return true
			}
		}
	}
	return false
}

// writeCheckoutViolations returns each checkout in a write-capable job that does
// not set persist-credentials to false. A job without its own permissions
// block is judged by the workflow-level block it inherits.
func writeCheckoutViolations(src []byte) ([]string, error) {
	jobs, err := workflowJobs(src)
	if err != nil {
		return nil, err
	}
	// A job with no permissions block runs with the workflow's.
	var top struct {
		Permissions any `yaml:"permissions"`
	}
	if err := yaml.Unmarshal(src, &top); err != nil {
		return nil, err
	}
	var bad []string
	for name, job := range jobs {
		effective := job
		if _, own := job["permissions"]; !own {
			effective = map[string]any{"permissions": top.Permissions}
		}
		if !jobIsWriteCapable(effective) {
			continue
		}
		for i, step := range jobSteps(job) {
			if !isCheckout(step) {
				continue
			}
			with, _ := step["with"].(map[string]any)
			if v := fmt.Sprint(with["persist-credentials"]); v != "false" {
				bad = append(bad, fmt.Sprintf("job %s step %d: a checkout in a write-capable job must set `persist-credentials: false`", name, i+1))
			}
		}
	}
	return bad, nil
}

// publishGateViolations returns what is wrong with the order of the named job's
// steps: a step that runs no repository code must check every need's result for
// success before the first checkout.
func publishGateViolations(src []byte, job string) ([]string, error) {
	jobs, err := workflowJobs(src)
	if err != nil {
		return nil, err
	}
	j, ok := jobs[job]
	if !ok {
		return []string{fmt.Sprintf("no job %q", job)}, nil
	}
	var needs []string
	switch n := j["needs"].(type) {
	case string:
		needs = []string{n}
	case []any:
		for _, v := range n {
			needs = append(needs, fmt.Sprint(v))
		}
	}
	if len(needs) == 0 {
		return []string{fmt.Sprintf("job %s has no needs to gate on", job)}, nil
	}
	steps := jobSteps(j)
	first := -1
	for i, s := range steps {
		if isCheckout(s) {
			first = i
			break
		}
	}
	if first < 0 {
		return []string{fmt.Sprintf("job %s has no checkout", job)}, nil
	}

	// Every need's result must be read, and success required, by steps before
	// the checkout that run inline commands and use no action.
	var text strings.Builder
	for _, s := range steps[:first] {
		if _, usesAction := s["uses"]; usesAction {
			continue
		}
		run, _ := s["run"].(string)
		env, _ := s["env"].(map[string]any)
		fmt.Fprintf(&text, "%s\n%v\n", run, env)
		for _, repo := range []string{"build/", "scripts/", "make ", "./"} {
			if strings.Contains(run, repo) {
				return []string{fmt.Sprintf("job %s: the results check before the checkout runs repository code (%q); the checkout is not there yet", job, repo)}, nil
			}
		}
	}
	var bad []string
	for _, n := range needs {
		if !strings.Contains(text.String(), "needs."+n+".result") {
			bad = append(bad, fmt.Sprintf("job %s: no step before the first checkout reads needs.%s.result", job, n))
		}
	}
	if !strings.Contains(text.String(), "success") {
		bad = append(bad, fmt.Sprintf("job %s: the step before the first checkout never requires `success`", job))
	}
	return bad, nil
}

func TestReleasePublishGatesOnEveryNeedBeforeCheckout(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := publishGateViolations(src, "publish")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestWorkflowsWriteCapableCheckoutsDoNotPersistCredentials(t *testing.T) {
	root := repoRoot(t)
	files := workflowFiles(t, root)
	if len(files) < minWorkflowFiles {
		t.Fatalf("discovery floor: found %d workflow file(s), want at least %d", len(files), minWorkflowFiles)
	}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		bad, err := writeCheckoutViolations(src)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", f, b)
		}
	}
}

const publishWorkflowHead = `
jobs:
  publish:
    needs: [verify, lint]
    permissions:
      contents: write
    steps:
`

func TestPublishGate_RefusesWhatItMustRefuse(t *testing.T) {
	const ck = "      - uses: actions/checkout@abc # v7\n        with:\n          persist-credentials: false\n"
	const check = "      - name: gate\n        env:\n          R: verify=${{ needs.verify.result }} lint=${{ needs.lint.result }}\n        run: |\n          case $R in *=success) ;; *) exit 1 ;; esac\n"
	for _, tc := range []struct {
		name  string
		steps string
		want  bool // acceptable
	}{
		{"check then checkout", check + ck, true},
		{"checkout first", ck + check, false},
		{"no check", ck, false},
		{"misses a need", strings.ReplaceAll(check, " lint=${{ needs.lint.result }}", "") + ck, false},
		{"never requires success", strings.ReplaceAll(check, "success", "x") + ck, false},
		{"check runs repository code", "      - run: sh build/ci/summary.sh needs.verify.result needs.lint.result success\n" + ck, false},
		{"check is an action", "      - uses: some/action@abc\n" + ck, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := publishGateViolations([]byte(publishWorkflowHead+tc.steps), "publish")
			if err != nil {
				t.Fatal(err)
			}
			if (len(bad) == 0) != tc.want {
				t.Errorf("acceptable=%v, violations %v", tc.want, bad)
			}
		})
	}
}

func TestWriteCheckoutGate_RefusesWhatItMustRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool // acceptable
	}{
		{"write job persists by default", "jobs:\n  p:\n    permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n", false},
		{"write job persists explicitly", "jobs:\n  p:\n    permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n        with: {persist-credentials: true}\n", false},
		{"write job does not persist", "jobs:\n  p:\n    permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n        with: {persist-credentials: false}\n", true},
		{"write-all persists", "jobs:\n  p:\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@abc\n", false},
		{"read job may persist", "jobs:\n  p:\n    permissions: {contents: read}\n    steps:\n      - uses: actions/checkout@abc\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := writeCheckoutViolations([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if (len(bad) == 0) != tc.want {
				t.Errorf("acceptable=%v, violations %v", tc.want, bad)
			}
		})
	}
}
