package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The changed-files step (ci.yml, job changes, step `diff`) decides what a
// pull request may skip: docs_only=true skips the build and test steps of the
// PR tier, lint_gates=false skips the lint-gates job (CI Gate reads that skip
// as passed) and tpm=false skips the TPM suite. Each answer is a search of
// the changed files for a pattern, so only a search that ran and selected no
// file may give the answer that skips. A search that could not run (a
// pattern that is no regular expression, or an empty one) must keep the
// answer that runs the jobs and say so in a warning, or fail the step.
//
// Two kinds of check, as for the schedule guard:
//
//   - the job's text: the outputs the other jobs read are the step's, and the
//     step reads the event and the pull request's two commits from the run
//     (changesStepViolations);
//   - what the script does: it is taken out of the real ci.yml and run with
//     bash once per changesRuns row (runStepScript), with a stub `git` first
//     in PATH that lists the row's changed files, and the answers are read
//     from the file GITHUB_OUTPUT names.
const (
	changesStep = "diff"
	// The patterns the rows search with, unless a row sets its own. They are
	// the test's, not the workflow's, so a row's answer does not move when
	// the workflow's values do.
	changesDocsPattern = `(\.md$|^docs/)`
	changesLintPattern = `^(scripts/|Makefile$)`
	changesTPMPattern  = `^backends/tpm/`
	// unusablePattern is no regular expression: grep exits 2 on it.
	unusablePattern = "["
)

// changesOutputs are the step's answers, in the order of changesRun.want.
var changesOutputs = [3]string{"docs_only", "lint_gates", "tpm"}

// changesEnv is what the step must read from the run.
var changesEnv = [][2]string{
	{"EVENT", "${{ github.event_name }}"},
	{"BASE", "${{ github.event.pull_request.base.sha }}"},
	{"HEAD", "${{ github.event.pull_request.head.sha }}"},
}

// changesGitStub stands in for `git diff --name-only`: it prints the file
// CHANGED_FILES names, and fails as git does on a range it cannot resolve
// when the variable is not set.
const changesGitStub = "#!/bin/sh\n" +
	"[ \"$1\" = diff ] || { echo \"git stub: unexpected: $*\" >&2; exit 64; }\n" +
	"[ -n \"$CHANGED_FILES\" ] || exit 128\n" +
	"cat \"$CHANGED_FILES\"\n"

// changesStepViolations returns the changed-files step's script and what is
// wrong with the text of the job around it.
func changesStepViolations(src []byte) (script string, bad []string, err error) {
	var wf scheduleGuardWorkflow // the same three keys of a job: outputs, and each step's id, env and run
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return "", nil, err
	}
	job, ok := wf.Jobs[changesJob]
	if !ok {
		return "", []string{fmt.Sprintf("no %s job", changesJob)}, nil
	}
	for _, name := range changesOutputs {
		want := "${{ steps." + changesStep + ".outputs." + name + " }}"
		if got := job.Outputs[name]; got != want {
			bad = append(bad, fmt.Sprintf("job %s: output %s is %q, want %q: the answer is the script's, not a constant", changesJob, name, got, want))
		}
	}
	found := 0
	for _, st := range job.Steps {
		if st.ID != changesStep {
			continue
		}
		found++
		script = st.Run
		for _, e := range changesEnv {
			if got := st.Env[e[0]]; got != e[1] {
				bad = append(bad, fmt.Sprintf("job %s, step %s: env %s is %q, want %q", changesJob, changesStep, e[0], got, e[1]))
			}
		}
	}
	if found != 1 {
		bad = append(bad, fmt.Sprintf("job %s: %d steps with id %q, want 1", changesJob, found, changesStep))
	}
	return script, bad, nil
}

// changesRun is one run of the step's script: the event, what git lists as
// changed, the three patterns, and the answers the script must write.
type changesRun struct {
	name  string
	event string
	// files is what `git diff --name-only` lists. noDiff is a diff git
	// cannot take: the stub fails.
	files    []string
	noDiff   bool
	fullTier bool
	// The patterns: DOCS_ONLY_PATTERN, LINT_GATES_PATTERN, TPM_PATTERN.
	docs, lint, tpm string
	// want is docs_only, lint_gates and tpm, in changesOutputs' order.
	want [3]string
	// unusable names the pattern variable the row's search cannot run with;
	// "" when every search runs. On such a row the step may fail instead of
	// answering, and an answer needs a warning that names the variable.
	unusable string
}

// longChangedList is a diff whose first file decides every search and whose
// remaining files are many: grep -q stops reading at the first line, and a
// search that stopped early is not a search that failed.
func longChangedList() []string {
	files := []string{"backends/tpm/tpm.go"}
	for i := 0; i < 20000; i++ {
		files = append(files, "docs/reference/page-"+strconv.Itoa(i)+".md")
	}
	return files
}

// changesRuns are the runs the script is held to. The first rows are the
// answers of searches that run; the last rows are searches that cannot.
var changesRuns = []changesRun{
	{"a changed file matches the lint-gates pattern", "pull_request", []string{"enclave.go", "scripts/lib.sh"}, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "true", "false"}, ""},
	{"no changed file matches the lint-gates pattern", "pull_request", []string{"enclave.go", "backends/memory/memory.go"}, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "false", "false"}, ""},
	{"every changed file is docs or markdown", "pull_request", []string{"README.md", "docs/build-and-release.md"}, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"true", "false", "false"}, ""},
	{"one changed file is neither docs nor markdown", "pull_request", []string{"README.md", "enclave.go"}, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "false", "false"}, ""},
	{"a changed file matches the TPM pattern", "pull_request", []string{"backends/tpm/tpm.go"}, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "false", "true"}, ""},
	{"the full tier is never docs only and never skips lint-gates", "pull_request", []string{"README.md"}, false, true,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "true", "false"}, ""},
	{"a diff that cannot be taken skips nothing", "pull_request", nil, true, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "true", "true"}, ""},
	{"an empty diff", "pull_request", nil, false, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "true", "false"}, ""},
	{"a push takes no diff", "push", nil, true, false,
		changesDocsPattern, changesLintPattern, changesTPMPattern, [3]string{"false", "true", "false"}, ""},
	{"a long diff whose first file decides every search", "pull_request", longChangedList(), false, false,
		changesDocsPattern, `^backends/`, changesTPMPattern, [3]string{"false", "true", "true"}, ""},
	{"a lint-gates pattern that is no regular expression", "pull_request", []string{"enclave.go"}, false, false,
		changesDocsPattern, unusablePattern, changesTPMPattern, [3]string{"false", "true", "false"}, "LINT_GATES_PATTERN"},
	{"a docs-only pattern that is no regular expression", "pull_request", []string{"README.md"}, false, false,
		unusablePattern, changesLintPattern, changesTPMPattern, [3]string{"false", "false", "false"}, "DOCS_ONLY_PATTERN"},
	{"a TPM pattern that is no regular expression", "pull_request", []string{"enclave.go"}, false, false,
		changesDocsPattern, changesLintPattern, unusablePattern, [3]string{"false", "false", "true"}, "TPM_PATTERN"},
	{"an empty docs-only pattern", "pull_request", []string{"enclave.go"}, false, false,
		"", changesLintPattern, changesTPMPattern, [3]string{"false", "false", "false"}, "DOCS_ONLY_PATTERN"},
}

// changesFixture is where the step's script runs: a directory holding the
// stub git, first in PATH.
type changesFixture struct{ stubs string }

// newChangesFixture builds the fixture. skip says why it could not, and is
// "" when it could: the script needs bash to run.
func newChangesFixture(t *testing.T) (fx changesFixture, skip string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		return fx, fmt.Sprintf("the changed-files script is not run: %v", err)
	}
	fx.stubs = t.TempDir()
	writeExecutable(t, filepath.Join(fx.stubs, "git"), []byte(changesGitStub))
	return fx, ""
}

// warns reports whether out holds a ::warning:: line that names variable.
func warns(out, variable string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "::warning::") && strings.Contains(line, variable) {
			return true
		}
	}
	return false
}

// violations runs script once per changesRuns row (runStepScript) and lists
// what each run did wrong.
func (fx changesFixture) violations(t *testing.T, script string) []string {
	t.Helper()
	var bad []string
	for _, r := range changesRuns {
		tmp := t.TempDir()
		output := filepath.Join(tmp, "github-output")
		env := []string{
			"PATH=" + fx.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
			"GITHUB_OUTPUT=" + output, "RUNNER_TEMP=" + tmp,
			"EVENT=" + r.event,
			"BASE=0123456789abcdef0123456789abcdef01234567", "HEAD=89abcdef0123456789abcdef0123456789abcdef",
			"CI_FULL_TIER=" + strconv.FormatBool(r.fullTier),
			"DOCS_ONLY_PATTERN=" + r.docs, "LINT_GATES_PATTERN=" + r.lint, "TPM_PATTERN=" + r.tpm,
		}
		if !r.noDiff {
			list := filepath.Join(tmp, "changed-files")
			var content string
			if len(r.files) > 0 {
				content = strings.Join(r.files, "\n") + "\n"
			}
			if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			env = append(env, "CHANGED_FILES="+list)
		}
		out, failed := runStepScript(t, script, tmp, env)
		// The step prints the changed files; a finding quotes its last lines.
		said := out
		if lines := strings.Split(strings.TrimRight(out, "\n"), "\n"); len(lines) > 12 {
			said = "...\n" + strings.Join(lines[len(lines)-12:], "\n")
		}
		if failed {
			if r.unusable == "" {
				bad = append(bad, fmt.Sprintf("%s: the step failed; every search of this row can run. Output:\n%s", r.name, said))
			}
			// A step that fails on a search it cannot run skips no job: the
			// jobs that need this one do not start and CI Gate fails.
			continue
		}
		outs, err := stepOutputs(output)
		if err != nil {
			t.Fatal(err)
		}
		for i, name := range changesOutputs {
			if got := outs[name]; len(got) != 1 || got[0] != r.want[i] {
				bad = append(bad, fmt.Sprintf("%s: %s written: %q, want one %q; output:\n%s", r.name, name, got, r.want[i], said))
			}
		}
		switch {
		case r.unusable != "" && !warns(out, r.unusable):
			bad = append(bad, fmt.Sprintf("%s: no ::warning:: line names %s; a search that cannot run says so. Output:\n%s", r.name, r.unusable, said))
		case r.unusable == "" && (strings.Contains(out, "::warning::") || strings.Contains(out, "::error::")):
			bad = append(bad, fmt.Sprintf("%s: a ::warning:: or ::error:: line, and every search of this row ran:\n%s", r.name, said))
		}
	}
	return bad
}

func TestChangedFilesStepSkipsOnlyOnASearchThatRan(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	script, bad, err := changesStepViolations(src)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}
	t.Run("the script, run", func(t *testing.T) {
		fx, skip := newChangesFixture(t)
		if skip != "" {
			t.Skip(skip)
		}
		for _, b := range fx.violations(t, script) {
			t.Errorf("%s: %s", ciWorkflowFile, b)
		}
	})
}

// changesNegatedSearches is a script that answers each search by negating or
// taking grep's status as it stands, so a search that cannot run reads as one
// that selected no file. The check must refuse it.
const changesNegatedSearches = `docs_only=false lint_gates=true tpm=false
if [ "$EVENT" = pull_request ]; then
  if files=$(git diff --name-only --no-renames "$BASE...$HEAD"); then
    if [ -n "$files" ]; then
      if [ "$CI_FULL_TIER" != true ] && ! grep -qvE "$DOCS_ONLY_PATTERN" <<< "$files"; then docs_only=true; fi
      if [ "$CI_FULL_TIER" != true ] && ! grep -qE "$LINT_GATES_PATTERN" <<< "$files"; then lint_gates=false; fi
      if grep -qE "$TPM_PATTERN" <<< "$files"; then tpm=true; fi
    fi
  else
    tpm=true
  fi
fi
echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"
echo "lint_gates=$lint_gates" >> "$GITHUB_OUTPUT"
echo "tpm=$tpm" >> "$GITHUB_OUTPUT"
`

// TestChangedFilesStepSkipsOnlyOnASearchThatRan_RefusesWhatItMustRefuse pins
// the check against edits of the real workflow: each is refused by the job's
// text or, when the text passes, by a run of the edited script.
func TestChangedFilesStepSkipsOnlyOnASearchThatRan_RefusesWhatItMustRefuse(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	wf := string(src)
	fx, skip := newChangesFixture(t)
	for _, tc := range []struct{ name, old, new string }{
		{"the lint-gates answer is a constant", "lint_gates: ${{ steps.diff.outputs.lint_gates }}", "lint_gates: 'false'"},
		{"the docs-only answer is another step's", "docs_only: ${{ steps.diff.outputs.docs_only }}", "docs_only: ${{ steps.optee.outputs.optee }}"},
		{"the script writes docs only whatever it found", `echo "docs_only=$docs_only" >> "$GITHUB_OUTPUT"`, `echo "docs_only=true" >> "$GITHUB_OUTPUT"`},
		{"the script skips lint-gates whatever it found", `echo "lint_gates=$lint_gates" >> "$GITHUB_OUTPUT"`, `echo "lint_gates=false" >> "$GITHUB_OUTPUT"`},
		{"the script writes no TPM answer", `echo "tpm=$tpm" >> "$GITHUB_OUTPUT"`, ":"},
		{"a diff that cannot be taken skips the TPM suite", "tpm=true   # an unknown diff runs", "tpm=false   # an unknown diff runs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if n := strings.Count(wf, tc.old); n != 1 {
				t.Fatalf("%s holds %q %d times, want once; update this case", ciWorkflowFile, tc.old, n)
			}
			script, bad, err := changesStepViolations([]byte(strings.Replace(wf, tc.old, tc.new, 1)))
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
	// A script whose text of the job passes and whose searches read a failed
	// search as no match: only a run shows it.
	t.Run("a failed search reads as no match", func(t *testing.T) {
		if skip != "" {
			t.Skip(skip)
		}
		bad := fx.violations(t, changesNegatedSearches)
		for _, variable := range []string{"LINT_GATES_PATTERN", "DOCS_ONLY_PATTERN", "TPM_PATTERN"} {
			named := false
			for _, b := range bad {
				named = named || strings.Contains(b, variable)
			}
			if !named {
				t.Errorf("no violation names %s; want one for each search that cannot run. Violations:\n%s", variable, strings.Join(bad, "\n"))
			}
		}
	})
}
