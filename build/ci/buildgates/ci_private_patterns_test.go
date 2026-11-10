package buildgates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ci.yml's lint job carries the template's v1.31 private-pattern gate (#277).
// The patterns are values that must not appear in a public tree, so they are
// not in the repository: the step takes them from the RELEASABILITY_PATTERNS
// secret, searches the tracked tree for them and prints the path and line of
// a match, never the matched text. A push without the secret fails; any other
// run without it (a pull request from a fork) passes with a notice. A search
// that fails is not a search without a match: only git grep's status 1 passes,
// and any status above it fails the step. The tracked releasability test
// still runs; this step is beside it, not in its place.
//
// The step is checked twice: its text by privatePatternGateViolations, and
// what it does by running its script in a repository that tracks one private
// value (privatePatternRuns).
const (
	ciTemplateHeader     = "# ci-template: v1.31 (customized)"
	privatePatternStep   = "Releasability (private patterns)"
	privatePatternSecret = "${{ secrets.RELEASABILITY_PATTERNS }}"
	privatePatternSearch = `git grep -n -I -i -F -f "$pf" -- .`
	privatePatternCut    = "cut -d: -f1,2"
	// privatePatternIf runs the step after a failed lint step too.
	privatePatternIf = "${{ !cancelled() }}" //nolint:misspell // the Actions cancelled() function
)

type privatePatternWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string            `yaml:"name"`
			If   string            `yaml:"if"`
			Env  map[string]string `yaml:"env"`
			Run  string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// privatePatternGateViolations lists what is wrong with the private-pattern
// step of one ci.yml.
func privatePatternGateViolations(src []byte) ([]string, error) {
	var bad []string
	if first, _, _ := strings.Cut(string(src), "\n"); first != ciTemplateHeader {
		bad = append(bad, fmt.Sprintf("line 1 is %q, want %q", first, ciTemplateHeader))
	}
	var wf privatePatternWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	found := 0
	for name, job := range wf.Jobs {
		for _, st := range job.Steps {
			if strings.Contains(st.Run, "RELEASABILITY_PATTERNS") && st.Name != privatePatternStep {
				bad = append(bad, fmt.Sprintf("job %s: step %q reads RELEASABILITY_PATTERNS; only %q does", name, st.Name, privatePatternStep))
			}
			if st.Name != privatePatternStep {
				continue
			}
			found++
			if name != lintJob {
				bad = append(bad, fmt.Sprintf("job %s: runs %q; want it in the %s job only", name, privatePatternStep, lintJob))
			}
			if st.If != privatePatternIf {
				bad = append(bad, fmt.Sprintf("step if is %q; want it to run whenever the job is not canceled", st.If))
			}
			if st.Env["RELEASABILITY_PATTERNS"] != privatePatternSecret {
				bad = append(bad, fmt.Sprintf("RELEASABILITY_PATTERNS is %q, want %s", st.Env["RELEASABILITY_PATTERNS"], privatePatternSecret))
			}
			if st.Env["EVENT"] != "${{ github.event_name }}" {
				bad = append(bad, fmt.Sprintf("EVENT is %q, want the event name", st.Env["EVENT"]))
			}
			if strings.Contains(st.Run, "${{") {
				bad = append(bad, "the script interpolates an expression; the secret reaches it through env only")
			}
			if !strings.Contains(st.Run, privatePatternSearch+" | "+privatePatternCut) {
				bad = append(bad, fmt.Sprintf("the search is not `%s` cut to path and line with `%s`", privatePatternSearch, privatePatternCut))
			}
			if strings.Contains(st.Run, "|| true") {
				bad = append(bad, "the script discards a command's status with `|| true`; a search that fails must fail the step")
			}
			if !strings.Contains(st.Run, "if [ \"$EVENT\" = push ]; then\n    echo \"::error::") || !strings.Contains(st.Run, "    exit 1\n  fi\n  echo \"::notice::") {
				bad = append(bad, "a push without the secret does not fail before the notice")
			}
			if !strings.Contains(st.Run, "chmod 600 \"$pf\"") || !strings.Contains(st.Run, "trap 'rm -f \"$pf\"' EXIT") {
				bad = append(bad, "the pattern file is not private to the step and removed on exit")
			}
			for _, line := range strings.Split(st.Run, "\n") {
				l := strings.TrimSpace(line)
				if strings.HasPrefix(l, "printf '%s\\n' \"$RELEASABILITY_PATTERNS\" | sed ") && strings.HasSuffix(l, "> \"$pf\"") {
					continue
				}
				if l == "if [ -z \"$RELEASABILITY_PATTERNS\" ]; then" {
					continue
				}
				if strings.Contains(l, "$RELEASABILITY_PATTERNS") || strings.Contains(l, "${RELEASABILITY_PATTERNS") {
					bad = append(bad, fmt.Sprintf("%q uses the patterns outside the pattern file", l))
				}
				if strings.Contains(l, "cat \"$pf\"") || strings.Contains(l, "set -x") {
					bad = append(bad, fmt.Sprintf("%q would print the patterns", l))
				}
			}
		}
	}
	if found != 1 {
		bad = append(bad, fmt.Sprintf("%d steps named %q, want 1", found, privatePatternStep))
	}
	return bad, nil
}

// privatePatternScript returns the `run:` of the private-pattern step.
func privatePatternScript(src []byte) (string, error) {
	var wf privatePatternWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return "", err
	}
	for _, job := range wf.Jobs {
		for _, st := range job.Steps {
			if st.Name == privatePatternStep {
				return st.Run, nil
			}
		}
	}
	return "", fmt.Errorf("no step named %q", privatePatternStep)
}

// The fixture tree tracks privatePatternValue once, on line 2 of
// privatePatternFile and in another letter case than its pattern.
const (
	privatePatternValue = "private-value-seven"
	privatePatternFile  = "docs/notes.txt"
	privatePatternTree  = "a public line\nreach it at Private-Value-Seven today\n"
)

// The ways a run's search is made to fail, without a change to the script.
const (
	gitExits2       = "git exits 2"
	gitNoRepository = "git finds no repository"
)

// privatePatternRun is one run of the step's script: what the runner gives
// it and what it must do.
type privatePatternRun struct {
	name     string
	patterns string // RELEASABILITY_PATTERNS; "" is a run without the secret
	event    string
	git      string // "" for git as it is, else gitExits2 or gitNoRepository
	wantFail bool
	want     []string // each is in the output
	wantNot  []string // none is in the output, in any letter case
}

var privatePatternRuns = []privatePatternRun{
	{"a match fails and shows path and line only", "# private names\n\nnot-in-the-tree\n" + privatePatternValue + "\n", "pull_request", "", true,
		[]string{"::error::", privatePatternFile + ":2"}, []string{privatePatternValue, "0 matches"}},
	{"no match passes", "# private names\nnot-in-the-tree\nnor-this\n", "push", "", false,
		[]string{"releasability: 2 private patterns, 0 matches"}, []string{"::error::"}},
	{"a search that exits 2 fails", "not-in-the-tree\n", "push", gitExits2, true,
		[]string{"::error::", "search failed"}, []string{"0 matches"}},
	{"a search outside a repository fails", "not-in-the-tree\n", "pull_request", gitNoRepository, true,
		[]string{"::error::", "search failed"}, []string{"0 matches"}},
	{"a secret with no pattern fails", "# no pattern yet\n\n", "push", "", true,
		[]string{"::error::"}, []string{"0 matches"}},
	{"no secret on a push fails", "", "push", "", true,
		[]string{"::error::RELEASABILITY_PATTERNS is not set"}, []string{"0 matches"}},
	{"no secret on a pull request is a notice", "", "pull_request", "", false,
		[]string{"::notice::"}, []string{"::error::", "0 matches"}},
}

// privatePatternFixture is where the step's script runs: a repository that
// tracks privatePatternFile, and a bash start-up file whose `git` exits 2.
type privatePatternFixture struct{ repo, gitExits2 string }

// newPrivatePatternFixture builds the fixture. skip says why it could not,
// and is "" when it could: the script needs bash and git to run.
func newPrivatePatternFixture(t *testing.T) (fx privatePatternFixture, skip string) {
	t.Helper()
	for _, tool := range []string{"bash", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fx, fmt.Sprintf("the step's script is not run: %v", err)
		}
	}
	fx.repo = t.TempDir()
	file := filepath.Join(fx.repo, privatePatternFile)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(privatePatternTree), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", privatePatternFile}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = fx.repo
		cmd.Env = privatePatternEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	fx.gitExits2 = filepath.Join(t.TempDir(), "git-exits-2.sh")
	if err := os.WriteFile(fx.gitExits2, []byte("git() { return 2; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return fx, ""
}

// privatePatternEnv is the environment of the fixture's commands: the
// caller's PATH, no git configuration but the repository's own, then extra.
func privatePatternEnv(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}, extra...)
}

// violations runs script once per privatePatternRuns row, the way the runner
// runs a step with no shell key (bash -e), and lists what each run did wrong.
func (fx privatePatternFixture) violations(t *testing.T, script string) []string {
	t.Helper()
	var bad []string
	for _, r := range privatePatternRuns {
		tmp := t.TempDir()
		env := privatePatternEnv("TMPDIR="+tmp, "RELEASABILITY_PATTERNS="+r.patterns, "EVENT="+r.event)
		switch r.git {
		case gitExits2:
			// A non-interactive bash reads BASH_ENV first, so the script's
			// `git` is the start-up file's function.
			env = append(env, "BASH_ENV="+fx.gitExits2)
		case gitNoRepository:
			env = append(env, "GIT_DIR="+filepath.Join(tmp, "no-repository"))
		}
		cmd := exec.Command("bash", "-e", "-c", script)
		cmd.Dir = fx.repo
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("%s: bash: %v", r.name, err)
		}
		out := string(b)
		if failed := err != nil; failed != r.wantFail {
			bad = append(bad, fmt.Sprintf("%s: the step failed: %v, want %v; output:\n%s", r.name, failed, r.wantFail, out))
		}
		for _, w := range r.want {
			if !strings.Contains(out, w) {
				bad = append(bad, fmt.Sprintf("%s: the output lacks %q:\n%s", r.name, w, out))
			}
		}
		for _, w := range r.wantNot {
			if strings.Contains(strings.ToLower(out), strings.ToLower(w)) {
				bad = append(bad, fmt.Sprintf("%s: the output holds %q:\n%s", r.name, w, out))
			}
		}
		left, err := os.ReadDir(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) > 0 {
			bad = append(bad, fmt.Sprintf("%s: the step left %d file(s) in its temporary directory; the pattern file must not outlive it", r.name, len(left)))
		}
	}
	return bad
}

func TestLintJobRunsThePrivatePatternGate(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	bad, err := privatePatternGateViolations(src)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}
	t.Run("the script, run", func(t *testing.T) {
		fx, skip := newPrivatePatternFixture(t)
		if skip != "" {
			t.Skip(skip)
		}
		script, err := privatePatternScript(src)
		if err != nil {
			t.Fatalf("%s: %v", ciWorkflowFile, err)
		}
		for _, b := range fx.violations(t, script) {
			t.Errorf("%s: %s", ciWorkflowFile, b)
		}
	})
}

// TestLintJobRunsThePrivatePatternGate_RefusesWhatItMustRefuse pins the check
// against edits of the real workflow: each is refused by the step's text or,
// when the text passes, by a run of the edited script.
func TestLintJobRunsThePrivatePatternGate_RefusesWhatItMustRefuse(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	wf := string(src)
	fx, skip := newPrivatePatternFixture(t)
	const searchStatus = `; exit "${PIPESTATUS[0]}")`
	for _, tc := range []struct{ name, old, new string }{
		{"header back at v1.30", ciTemplateHeader, "# ci-template: v1.30 (customized)"},
		{"step renamed away", "- name: " + privatePatternStep, "- name: Releasability"},
		{"step skipped after a failure", "- name: " + privatePatternStep + "\n        if: " + privatePatternIf, "- name: " + privatePatternStep + "\n        if: ${{ success() }}"},
		{"patterns from a variable", privatePatternSecret, "${{ vars.RELEASABILITY_PATTERNS }}"},
		{"matched text printed", " | " + privatePatternCut, ""},
		{"search without fixed strings", privatePatternSearch, `git grep -n -f "$pf" -- .`},
		{"push without the secret passes", "if [ \"$EVENT\" = push ]; then\n              echo \"::error::", "if [ \"$EVENT\" = never ]; then\n              echo \"::warning::"},
		{"a match passes", "printf '%s\\n' \"$hits\"\n            exit 1", "printf '%s\\n' \"$hits\""},
		{"patterns echoed", "pf=$(mktemp)", "echo \"$RELEASABILITY_PATTERNS\"\n          pf=$(mktemp)"},
		{"pattern file printed", "pf=$(mktemp)", "pf=$(mktemp)\n          cat \"$pf\""},
		{"pattern file left behind", "trap 'rm -f \"$pf\"' EXIT", "true"},
		{"a failed search counted as no match", searchStatus, " || true)"},
		{"the search's status lost in the pipe", searchStatus, ")"},
		{"the search's status never read", ") || rc=$?", ") || :"},
		{"a search error passes", `if [ "$rc" -gt 1 ]; then`, `if [ "$rc" -gt 2 ]; then`},
		{"a search error is a warning", "(git grep status $rc)\"\n            exit 1", "(git grep status $rc)\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(wf, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			edited := []byte(strings.Replace(wf, tc.old, tc.new, 1))
			bad, err := privatePatternGateViolations(edited)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) > 0 {
				return
			}
			if skip != "" {
				t.Skip(skip)
			}
			script, err := privatePatternScript(edited)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(fx.violations(t, script)) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}
}
