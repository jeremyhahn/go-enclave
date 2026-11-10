package buildgates

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The schedule guard (ci.yml, job schedule-guard, step `guard`) decides
// whether a run may start the jobs that check out the branch. Every such job
// needs the guard and requires its `run` verdict (ciTierViolations); this
// file holds the decision itself, in two kinds of check:
//
//   - the job's text: the verdict the other jobs read is the guard step's
//     output, and the step reads the event, the server, the ref and the pull
//     request's head branch from the run (scheduleGuardViolations);
//   - what the script does: it is taken out of the real ci.yml and run with
//     bash once per scheduleGuardRuns row, with the step's environment set as
//     the runner sets it, and the verdict is read from the file GITHUB_OUTPUT
//     names. The programs that could reach an API are stubs first in PATH
//     that record the call and fail, so a run that must make no API call is
//     one that leaves no record.
const (
	scheduleGuardStep = "guard"
	// scheduleGuardVerdict is what the job hands the jobs that need it.
	scheduleGuardVerdict = "${{ steps.guard.outputs.verdict }}"
	scheduleGuardWrite   = `echo "verdict=$verdict" >> "$GITHUB_OUTPUT"`
	githubServer         = "https://github.com"
	// otherServer stands for a server that is not github.com: there the
	// guard asks the API, which the stubs record.
	otherServer = "https://forge.example"
	mainRef     = "refs/heads/main"
	branchRef   = "refs/heads/ci/some-branch"
	pullRef     = "refs/pull/7/merge"
	// checkpointHead is a head branch under the prefix the guard refuses.
	checkpointHead = "lane-ckpt/some-branch"
	// The tokens a run holds; no run may print them.
	scheduleGuardJobToken = "job-token-value"
	scheduleGuardBotToken = "bot-token-value"
)

// scheduleGuardEnv is what the guard step must read from the run: a constant
// in place of one of these would decide the verdict before the script ran.
var scheduleGuardEnv = [][2]string{
	{"EVENT", "${{ github.event_name }}"},
	{"SERVER", "${{ github.server_url }}"},
	{"REF", "${{ github.ref }}"},
	{"HEAD_REF", "${{ github.head_ref }}"},
}

// scheduleGuardAPITools are the programs a step could reach an API with.
var scheduleGuardAPITools = []string{"curl", "gh", "wget"}

// scheduleGuardStub stands in for each of them: it records the call and
// fails, as a server that gives no answer.
const scheduleGuardStub = "#!/bin/sh\necho \"${0##*/} $*\" >> \"$API_CALLS\"\nexit 7\n"

// workflowJobLine is the line that opens a job in a workflow's text.
var workflowJobLine = regexp.MustCompile(`(?m)^  [A-Za-z_][A-Za-z0-9_-]*:[ \t]*$`)

type scheduleGuardWorkflow struct {
	Jobs map[string]struct {
		Outputs map[string]string `yaml:"outputs"`
		Steps   []struct {
			ID  string            `yaml:"id"`
			Env map[string]string `yaml:"env"`
			Run string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// scheduleGuardViolations returns the guard step's script and what is wrong
// with the text of the job around it.
func scheduleGuardViolations(src []byte) (script string, bad []string, err error) {
	var wf scheduleGuardWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return "", nil, err
	}
	job, ok := wf.Jobs[scheduleGuardJob]
	if !ok {
		return "", []string{fmt.Sprintf("no %s job", scheduleGuardJob)}, nil
	}
	if got := job.Outputs["verdict"]; got != scheduleGuardVerdict {
		bad = append(bad, fmt.Sprintf("job %s: output verdict is %q, want %q: the verdict is the script's, not a constant", scheduleGuardJob, got, scheduleGuardVerdict))
	}
	found := 0
	for _, st := range job.Steps {
		if st.ID != scheduleGuardStep {
			continue
		}
		found++
		script = st.Run
		for _, e := range scheduleGuardEnv {
			if got := st.Env[e[0]]; got != e[1] {
				bad = append(bad, fmt.Sprintf("job %s, step %s: env %s is %q, want %q", scheduleGuardJob, scheduleGuardStep, e[0], got, e[1]))
			}
		}
	}
	if found != 1 {
		bad = append(bad, fmt.Sprintf("job %s: %d steps with id %q, want 1", scheduleGuardJob, found, scheduleGuardStep))
	}
	return script, bad, nil
}

// scheduleGuardRun is one run of the guard's script: the run the runner
// describes to it, the verdict it must write, and whether it may call an API.
type scheduleGuardRun struct {
	name                        string
	event, server, ref, headRef string
	want                        string
	wantAPI                     bool
}

// scheduleGuardRuns are the runs the script is held to. On github.com, where
// this repository's CI runs, no row may call an API. The rows on another
// server show that the stubs see a call: there the guard asks for a count or
// a proof and gets no answer.
var scheduleGuardRuns = []scheduleGuardRun{
	{"a dispatch off main is refused", "workflow_dispatch", githubServer, branchRef, "", "refused", false},
	{"a dispatch on a tag is refused", "workflow_dispatch", githubServer, "refs/tags/v1.0.0", "", "refused", false},
	{"a dispatch on main runs", "workflow_dispatch", githubServer, mainRef, "", "run", false},
	{"a pull request from a checkpoint branch is refused", "pull_request", githubServer, pullRef, checkpointHead, "refused", false},
	{"an ordinary pull request runs", "pull_request", githubServer, pullRef, "ci/some-branch", "run", false},
	{"a push to main runs", "push", githubServer, mainRef, "", "run", false},
	{"a schedule run runs", "schedule", githubServer, mainRef, "", "run", false},
	{"a dispatch off main on another server is refused before any call", "workflow_dispatch", otherServer, branchRef, "", "refused", false},
	{"a schedule run on another server that gets no count is unreadable", "schedule", otherServer, mainRef, "", "unreadable", true},
	{"a push to main on another server that gets no proof runs", "push", otherServer, mainRef, "", "run", true},
}

// scheduleGuardFixture is where the guard's script runs: a directory of
// stubs for scheduleGuardAPITools, first in PATH.
type scheduleGuardFixture struct{ stubs string }

// newScheduleGuardFixture builds the fixture. skip says why it could not,
// and is "" when it could: the script needs bash to run.
func newScheduleGuardFixture(t *testing.T) (fx scheduleGuardFixture, skip string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		return fx, fmt.Sprintf("the guard's script is not run: %v", err)
	}
	fx.stubs = t.TempDir()
	for _, tool := range scheduleGuardAPITools {
		writeExecutable(t, filepath.Join(fx.stubs, tool), []byte(scheduleGuardStub))
	}
	return fx, ""
}

// stepOutputs reads the name=value lines a step wrote to the file
// GITHUB_OUTPUT named; a file that was never written holds none.
func stepOutputs(file string) (map[string][]string, error) {
	b, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	outs := map[string][]string{}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			outs[name] = append(outs[name], value)
		}
	}
	return outs, nil
}

// violations runs script once per scheduleGuardRuns row (runStepScript) and
// lists what each run did wrong.
func (fx scheduleGuardFixture) violations(t *testing.T, script string) []string {
	t.Helper()
	var bad []string
	for _, r := range scheduleGuardRuns {
		tmp := t.TempDir()
		output, calls := filepath.Join(tmp, "github-output"), filepath.Join(tmp, "api-calls")
		api := r.server + "/api/v1/repos/owner/name"
		out, failed := runStepScript(t, script, tmp, []string{
			"PATH=" + fx.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
			"GITHUB_OUTPUT=" + output, "RUNNER_TEMP=" + tmp, "API_CALLS=" + calls,
			"EVENT=" + r.event, "SERVER=" + r.server, "REF=" + r.ref, "HEAD_REF=" + r.headRef,
			"SHA=0123456789abcdef0123456789abcdef01234567",
			"RUNS_API=" + api + "/actions/workflows/ci.yml/runs", "REPO_API=" + api,
			// Both tokens are set in every run, so a run that makes no call
			// is one that chose not to, not one that had no token.
			"JOB_TOKEN=" + scheduleGuardJobToken, "BOT=" + scheduleGuardBotToken,
		})
		if failed {
			bad = append(bad, fmt.Sprintf("%s: the step failed; the guard answers with its verdict, and CI Gate reads it. Output:\n%s", r.name, out))
		}
		outs, err := stepOutputs(output)
		if err != nil {
			t.Fatal(err)
		}
		if got := outs["verdict"]; len(got) != 1 || got[0] != r.want {
			bad = append(bad, fmt.Sprintf("%s: verdict written: %q, want one %q; output:\n%s", r.name, got, r.want, out))
		}
		if got := outs["proof"]; len(got) != 1 || got[0] != "" {
			bad = append(bad, fmt.Sprintf("%s: proof written: %q, want one empty value: no run proved the tree", r.name, got))
		}
		switch said := strings.Contains(out, "::error::"); {
		case r.want != "run" && !said:
			bad = append(bad, fmt.Sprintf("%s: no ::error:: line; a verdict that stops the run says why. Output:\n%s", r.name, out))
		case r.want == "run" && said:
			bad = append(bad, fmt.Sprintf("%s: an ::error:: line beside a run verdict:\n%s", r.name, out))
		}
		for _, token := range []string{scheduleGuardJobToken, scheduleGuardBotToken} {
			if strings.Contains(out, token) {
				bad = append(bad, fmt.Sprintf("%s: the output holds a token", r.name))
			}
		}
		called, err := os.ReadFile(calls)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		switch {
		case len(called) > 0 && !r.wantAPI:
			bad = append(bad, fmt.Sprintf("%s: the run called an API, want no call:\n%s", r.name, called))
		case len(called) == 0 && r.wantAPI:
			bad = append(bad, fmt.Sprintf("%s: the run called no API; this row is the one that shows the stubs see a call", r.name))
		}
	}
	return bad
}

// scheduleGuardSpan returns where the guard job's text starts and ends in a
// workflow, so an edit made there lands in no other job.
func scheduleGuardSpan(wf string) (start, end int, ok bool) {
	open := "\n  " + scheduleGuardJob + ":\n"
	at := strings.Index(wf, open)
	if at < 0 {
		return 0, 0, false
	}
	start, body := at+1, at+len(open)
	if next := workflowJobLine.FindStringIndex(wf[body:]); next != nil {
		return start, body + next[0], true
	}
	return start, len(wf), true
}

func TestScheduleGuardDecidesTheVerdict(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	script, bad, err := scheduleGuardViolations(src)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}
	t.Run("the script, run", func(t *testing.T) {
		fx, skip := newScheduleGuardFixture(t)
		if skip != "" {
			t.Skip(skip)
		}
		for _, b := range fx.violations(t, script) {
			t.Errorf("%s: %s", ciWorkflowFile, b)
		}
	})
}

// TestScheduleGuardDecidesTheVerdict_RefusesWhatItMustRefuse pins the check
// against edits of the real guard job: each is refused by the job's text or,
// when the text passes, by a run of the edited script.
func TestScheduleGuardDecidesTheVerdict_RefusesWhatItMustRefuse(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	wf := string(src)
	start, end, ok := scheduleGuardSpan(wf)
	if !ok {
		t.Fatalf("%s: no %s job", ciWorkflowFile, scheduleGuardJob)
	}
	job := wf[start:end]
	fx, skip := newScheduleGuardFixture(t)
	const (
		offMain    = `[ "$REF" != refs/heads/main ]; then`
		checkpoint = `[ "${HEAD_REF#lane-ckpt/}" != "$HEAD_REF" ]; then`
	)
	for _, tc := range []struct{ name, old, new string }{
		{"the verdict output is a constant", "verdict: " + scheduleGuardVerdict, "verdict: run"},
		{"the event is a constant", "EVENT: ${{ github.event_name }}", "EVENT: push"},
		{"the ref is the default branch's", "REF: ${{ github.ref }}", "REF: refs/heads/main"},
		{"the head branch is not the pull request's", "HEAD_REF: ${{ github.head_ref }}", "HEAD_REF: ${{ github.ref_name }}"},
		{"the script writes run whatever it decided", scheduleGuardWrite, `echo "verdict=run" >> "$GITHUB_OUTPUT"`},
		{"the script writes no verdict", scheduleGuardWrite, ":"},
		{"a dispatch off main runs", offMain, `[ "$REF" = refs/heads/never ]; then`},
		{"a dispatch on main is refused", offMain, "true; then"},
		{"a dispatch refusal that only prints", "verdict=refused\n", ":\n"},
		{"a checkpoint pull request runs", checkpoint, "false; then"},
		{"every pull request is refused", checkpoint, "true; then"},
		{"a schedule run on github.com asks the API", `elif [ "$SERVER" = https://github.com ]; then`, `elif [ "$SERVER" = https://example.invalid ]; then`},
		{"a push to main on github.com reads the tree proof", ` && [ "$SERVER" != https://github.com ]; then`, "; then"},
		{"a count that cannot be read runs", "verdict=unreadable", "verdict=run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(job, tc.old) {
				t.Fatalf("%s: job %s no longer contains %q; update this case", ciWorkflowFile, scheduleGuardJob, tc.old)
			}
			edited := []byte(wf[:start] + strings.Replace(job, tc.old, tc.new, 1) + wf[end:])
			script, bad, err := scheduleGuardViolations(edited)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) > 0 {
				return
			}
			if skip != "" {
				t.Skip(skip)
			}
			if len(fx.violations(t, script)) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}
	// The whole script replaced by a run verdict: the text of the job still
	// passes, and only a run of the script shows it.
	t.Run("the script is nothing but a run verdict", func(t *testing.T) {
		if skip != "" {
			t.Skip(skip)
		}
		always := "echo \"verdict=run\" >> \"$GITHUB_OUTPUT\"\necho \"proof=\" >> \"$GITHUB_OUTPUT\"\n"
		if len(fx.violations(t, always)) == 0 {
			t.Fatal("no violation; want a refusal")
		}
	})
}
