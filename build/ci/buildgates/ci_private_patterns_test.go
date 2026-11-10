package buildgates

import (
	"fmt"
	"os"
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
// run without it (a pull request from a fork) passes with a notice. The
// tracked releasability test still runs; this step is beside it, not in its
// place.
const (
	ciTemplateHeader     = "# ci-template: v1.31 (customized)"
	privatePatternStep   = "Releasability (private patterns)"
	privatePatternSecret = "${{ secrets.RELEASABILITY_PATTERNS }}"
	privatePatternSearch = `git grep -n -I -i -F -f "$pf" -- .`
	privatePatternCut    = "cut -d: -f1,2"
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
			if st.If != "${{ !cancelled() }}" {
				bad = append(bad, fmt.Sprintf("step if is %q; want it to run whenever the job is not cancelled", st.If))
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
			if !strings.Contains(st.Run, "("+privatePatternSearch+" || true) | "+privatePatternCut) {
				bad = append(bad, fmt.Sprintf("the search is not `%s` cut to path and line with `%s`", privatePatternSearch, privatePatternCut))
			}
			if !strings.Contains(st.Run, "if [ \"$EVENT\" = push ]; then\n    echo \"::error::") || !strings.Contains(st.Run, "    exit 1\n  fi\n  echo \"::notice::") {
				bad = append(bad, "a push without the secret does not fail before the notice")
			}
			if !strings.Contains(st.Run, "if [ -n \"$hits\" ]; then") || strings.Count(st.Run, "exit 1") != 2 {
				bad = append(bad, "a match does not fail the step")
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
}

// TestLintJobRunsThePrivatePatternGate_RefusesWhatItMustRefuse pins the check
// against edits of the real workflow.
func TestLintJobRunsThePrivatePatternGate_RefusesWhatItMustRefuse(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	wf := string(src)
	for _, tc := range []struct{ name, old, new string }{
		{"header back at v1.30", ciTemplateHeader, "# ci-template: v1.30 (customized)"},
		{"step renamed away", "- name: " + privatePatternStep, "- name: Releasability"},
		{"step skipped after a failure", "- name: " + privatePatternStep + "\n        if: ${{ !cancelled() }}", "- name: " + privatePatternStep + "\n        if: ${{ success() }}"},
		{"patterns from a variable", privatePatternSecret, "${{ vars.RELEASABILITY_PATTERNS }}"},
		{"matched text printed", " | " + privatePatternCut, ""},
		{"search without fixed strings", privatePatternSearch, `git grep -n -f "$pf" -- .`},
		{"push without the secret passes", "if [ \"$EVENT\" = push ]; then\n              echo \"::error::", "if [ \"$EVENT\" = never ]; then\n              echo \"::warning::"},
		{"a match passes", "printf '%s\\n' \"$hits\"\n            exit 1", "printf '%s\\n' \"$hits\""},
		{"patterns echoed", "pf=$(mktemp)", "echo \"$RELEASABILITY_PATTERNS\"\n          pf=$(mktemp)"},
		{"pattern file printed", "pf=$(mktemp)", "pf=$(mktemp)\n          cat \"$pf\""},
		{"pattern file left behind", "trap 'rm -f \"$pf\"' EXIT", "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(wf, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			bad, err := privatePatternGateViolations([]byte(strings.Replace(wf, tc.old, tc.new, 1)))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}
}
