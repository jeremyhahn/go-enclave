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

// Runner selection picks hosted or self-hosted once per run; a fork's PR always runs hosted.
const (
	runnerSelectStep  = "Balanced runner pool (ruling 1137)"
	runnerSelectOld   = "Hosted or overflow runner (ruling 1024)"
	ciHistoryV154Line = "# v1.54 (2026-11-22, Tenant Agent ruling 1137, owner order: the Dells and"

	// preflightRunsOn: hosted off github.com and for a fork's pull request;
	// the pool CI_PREFLIGHT_RUNS_ON names otherwise.
	preflightRunsOn = `${{ github.server_url == 'https://github.com' && ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`
	// dockerRunsOn and gateRunsOn read the step's outputs.
	dockerRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk' }}`
	gateRunsOn   = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner || '"ubuntu-latest"') || 'ci-gate' }}`
	// publishIf: publishJob, the one job off the selection, runs on a push to
	// main only, never on a pull request.
	publishIf     = `${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && (github.server_url != 'https://github.com' || vars.RELEASE_RUNNER == 'true') }}`
	hostedRunsOn  = "ubuntu-latest"
	hostedDefault = `"ubuntu-latest"`
)

// runnerSelectEnv is the step's env as v1.54 writes it.
var runnerSelectEnv = map[string]string{
	"SERVER":    "${{ github.server_url }}",
	"EVENT":     "${{ github.event_name }}",
	"HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
	"REF":       "${{ github.ref }}",
	"REPO":      "${{ github.repository }}",
	"API":       "${{ github.api_url }}/repos/${{ github.repository }}/actions",
	"RUN_ID":    "${{ github.run_id }}",
	"JOB_TOKEN": "${{ github.token }}",
	"HS":        "${{ vars.CI_HOSTED_SHARE }}",
	"C1":        "${{ vars.CI_SELF_HOSTED_BIGDISK }}",
	"C2":        "${{ vars.CI_SELF_HOSTED_BIGDISK_DOCKER }}",
}

type runnerSelectWorkflow struct {
	Env  map[string]any `yaml:"env"`
	Jobs map[string]struct {
		RunsOn  any               `yaml:"runs-on"`
		If      string            `yaml:"if"`
		Needs   any               `yaml:"needs"`
		Outputs map[string]string `yaml:"outputs"`
		Steps   []struct {
			Name string            `yaml:"name"`
			ID   string            `yaml:"id"`
			Env  map[string]string `yaml:"env"`
			Run  string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// needsPreflight reports whether a job's needs names preflight.
func needsPreflight(needs any) bool {
	switch n := needs.(type) {
	case string:
		return n == "preflight"
	case []any:
		for _, v := range n {
			if v == "preflight" {
				return true
			}
		}
	}
	return false
}

// runnerSelectViolations checks ci.yml's runner selection against v1.54 and
// returns the step's run script.
func runnerSelectViolations(src []byte) (script string, bad []string, err error) {
	var wf runnerSelectWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return "", nil, err
	}
	lines := strings.SplitN(string(src), "\n", 3)
	if len(lines) < 3 || lines[0] != ciTemplateHeader || lines[1] != ciHistoryV154Line {
		bad = append(bad, "ci.yml does not open with the v1.54 header and its history block")
	}
	for _, k := range []string{"HOSTED_JOBS_PER_REPO", "HOSTED_QUEUE_GRACE_SECONDS"} {
		if _, ok := wf.Env[k]; ok {
			bad = append(bad, fmt.Sprintf("top-level env still sets %s (removed in v1.54)", k))
		}
	}
	pre, ok := wf.Jobs["preflight"]
	if !ok {
		return "", append(bad, "no preflight job"), nil
	}
	if got := fmt.Sprint(pre.RunsOn); got != preflightRunsOn {
		bad = append(bad, fmt.Sprintf("preflight runs-on is %q, want %q", got, preflightRunsOn))
	}
	for k, want := range map[string]string{
		"runner":        "${{ steps.runner.outputs.runner }}",
		"runner_docker": "${{ steps.runner.outputs.runner_docker }}",
	} {
		if pre.Outputs[k] != want {
			bad = append(bad, fmt.Sprintf("preflight output %s is %q, want %q", k, pre.Outputs[k], want))
		}
	}
	n := 0
	for _, st := range pre.Steps {
		if st.Name == runnerSelectOld {
			bad = append(bad, fmt.Sprintf("preflight still has the step %q", runnerSelectOld))
		}
		if st.Name != runnerSelectStep {
			continue
		}
		n++
		script = st.Run
		if st.ID != "runner" {
			bad = append(bad, fmt.Sprintf("step %q has id %q, want runner", runnerSelectStep, st.ID))
		}
		for k, want := range runnerSelectEnv {
			if st.Env[k] != want {
				bad = append(bad, fmt.Sprintf("step %q env %s is %q, want %q", runnerSelectStep, k, st.Env[k], want))
			}
		}
		for k := range st.Env {
			if _, ok := runnerSelectEnv[k]; !ok {
				bad = append(bad, fmt.Sprintf("step %q env sets %s, which v1.54 does not", runnerSelectStep, k))
			}
		}
	}
	if n != 1 || script == "" {
		bad = append(bad, fmt.Sprintf("preflight has %d steps named %q with a run script, want 1", n, runnerSelectStep))
	}
	for name, job := range wf.Jobs {
		if name == "preflight" {
			continue
		}
		got := fmt.Sprint(job.RunsOn)
		switch {
		case got == hostedRunsOn:
		case got == dockerRunsOn || got == gateRunsOn:
			if !needsPreflight(job.Needs) {
				bad = append(bad, fmt.Sprintf("job %s reads preflight's runner output without needing preflight", name))
			}
		case name == publishJob && job.If == publishIf:
		default:
			bad = append(bad, fmt.Sprintf("job %s runs-on %q: not hosted and not preflight's runner selection", name, got))
		}
	}
	return script, bad, nil
}

func TestRunnerSelectionIsTheBalancedPool(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	if _, bad, err := runnerSelectViolations(src); err != nil || len(bad) > 0 {
		t.Fatalf("ci.yml runner selection (err %v):\n%s", err, strings.Join(bad, "\n"))
	}
}

func TestRunnerSelectionIsTheBalancedPool_RefusesWhatItMustRefuse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	src := string(raw)
	for _, tc := range []struct{ name, old, new string }{
		{"header back at v1.53", ciTemplateHeader, "# ci-template: v1.53 — canonical CI for all first-party Go repos."},
		{"step renamed back", "- name: " + runnerSelectStep, "- name: " + runnerSelectOld},
		{"HS from env again", "HS: ${{ vars.CI_HOSTED_SHARE }}", "LIMIT: ${{ env.HOSTED_JOBS_PER_REPO }}"},
		{"preflight forgets the fork guard", "((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && ", ""},
		{"a docker job on bigdisk outright", "    runs-on: " + dockerRunsOn, "    runs-on: [self-hosted, linux, x64, bigdisk]"},
		{"gate output renamed", "runner: ${{ steps.runner.outputs.runner }}", "runner: ${{ steps.pool.outputs.runner }}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(src, tc.old) {
				t.Fatalf("fixture: ci.yml has no %q", tc.old)
			}
			_, bad, err := runnerSelectViolations([]byte(strings.Replace(src, tc.old, tc.new, 1)))
			if err == nil && len(bad) == 0 {
				t.Fatalf("no violation for %s", tc.name)
			}
		})
	}
}

// runSelect runs the step script with env over a curl stub that records each
// call and fails; it returns the step's output file, its log and whether
// curl was called.
func runSelect(t *testing.T, script string, env map[string]string) (outputs, log string, called bool) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "curl-called")
	stub := "#!/bin/sh\necho called >> " + marker + "\nexit 7\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "github-output")
	cmd := exec.Command("bash", "-e", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_OUTPUT="+out, "RUNNER_TEMP="+dir)
	base := map[string]string{
		"SERVER": "https://github.com", "EVENT": "pull_request", "HEAD_REPO": "o/r", "REF": "refs/pull/1/merge",
		"REPO": "o/r", "API": "https://api.github.invalid/repos/o/r/actions",
		"RUN_ID": "100", "JOB_TOKEN": "t", "HS": "12", "C1": "4", "C2": "4",
	}
	for k, v := range env {
		base[k] = v
	}
	for k, v := range base {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	logb, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("step failed (%v):\n%s", err, logb)
	}
	o, _ := os.ReadFile(out)
	_, statErr := os.Stat(marker)
	return string(o), string(logb), statErr == nil
}

func TestRunnerSelectionKeepsForksHosted(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	script, _, err := runnerSelectViolations(src)
	if err != nil || script == "" {
		t.Fatalf("ci.yml has no step %q (err %v)", runnerSelectStep, err)
	}
	hosted := "runner=" + hostedDefault + "\nrunner_docker=" + hostedDefault + "\n"
	for _, tc := range []struct {
		name     string
		env      map[string]string
		wantCall bool
		wantLog  string
	}{
		{"fork pull_request", map[string]string{"HEAD_REPO": "fork/r"}, false, "::notice::"},
		{"fork pull_request_target", map[string]string{"EVENT": "pull_request_target", "HEAD_REPO": "fork/r"}, false, "::notice::"},
		{"fork since deleted", map[string]string{"HEAD_REPO": ""}, false, "::notice::"},
		{"fork with all limits unset", map[string]string{"HEAD_REPO": "fork/r", "HS": "", "C1": "", "C2": ""}, false, "::notice::"},
		{"same repository, CI_SELF_HOSTED_BIGDISK unset", map[string]string{"C1": ""}, false, "CI_SELF_HOSTED_BIGDISK=''"},
		{"same repository, CI_SELF_HOSTED_BIGDISK_DOCKER 0", map[string]string{"C2": "0"}, false, "CI_SELF_HOSTED_BIGDISK_DOCKER='0'"},
		{"same repository, the API unreachable", nil, true, "::warning::"},
		{"schedule, which the self-hosted runners refuse", map[string]string{"EVENT": "schedule", "REF": "refs/heads/main"}, false, "which the self-hosted runners refuse"},
		{"workflow_dispatch, which the self-hosted runners refuse", map[string]string{"EVENT": "workflow_dispatch", "REF": "refs/heads/main"}, false, "which the self-hosted runners refuse"},
		{"push of another branch", map[string]string{"EVENT": "push", "REF": "refs/heads/feature"}, false, "which the self-hosted runners refuse"},
		{"off github.com", map[string]string{"SERVER": "https://forge.invalid", "HEAD_REPO": "fork/r"}, false, "no selection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, log, called := runSelect(t, script, tc.env)
			if out != hosted {
				t.Errorf("outputs %q, want the hosted default\n%s", out, log)
			}
			if called != tc.wantCall {
				t.Errorf("curl called: %v, want %v\n%s", called, tc.wantCall, log)
			}
			if !strings.Contains(log, tc.wantLog) {
				t.Errorf("log lacks %q:\n%s", tc.wantLog, log)
			}
		})
	}
}
