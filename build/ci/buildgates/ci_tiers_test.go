package buildgates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// CI runs in two tiers (#175). The PR tier runs on every event; the full tier
// runs on push to main, on workflow_dispatch and on a PR labeled `ci:full`
// (from its next push or update-branch: a label event starts no run).
// CI Gate, the one required check, needs every job and names each one in its
// script with its tier, and build/ci/summary.sh lets a full job's skip pass
// only in a run that did not select the full tier. These tests hold ci.yml's
// jobs, `if:`s and gate tags to one another, so a job cannot be added, moved
// between tiers or dropped from the gate without the rest following: a PR-tier
// job given an `if:` would be skipped and fail the gate, and a full-tier job
// tagged `pr` would fail every plain PR, but a full job with a looser `if:`
// or an untagged gate line would pass quietly.
//
// Every workflow that runs on pull_request also cancels the superseded run of
// its ref (devops §9b), and no workflow but automerge.yml is scheduled: the
// coordinator dispatches the nightly runs.

const (
	ciWorkflowFile = ".github/workflows/ci.yml"
	ciGateJob      = "ci-gate"
	// ciGateRunner is the gate's runner label, reserved so the gate never
	// queues behind PR jobs. Its runners are 1-CPU slots: the gate uses no
	// action (no checkout, no toolchain) and carries summary.sh inline.
	ciGateRunner = "ci-gate"
	// gateSummaryHeredoc delimits the inline copy of build/ci/summary.sh.
	gateSummaryHeredoc = "SUMMARY"
	// fullTierIf is the `if:` every full-tier job carries, written out, and
	// the gate's FULL value inside ${{ }}.
	fullTierIf = "github.event_name == 'push' || github.event_name == 'workflow_dispatch' || contains(github.event.pull_request.labels.*.name, 'ci:full')"
	// refConcurrencyGroup is the ref-keyed group of every pull_request workflow.
	refConcurrencyGroup = "${{ github.workflow }}-${{ github.ref }}"
	// refCancelInProgress cancels a superseded run on every ref but main, so
	// a push to main never cancels an in-flight main run (ci-template v1.22.1).
	refCancelInProgress = "${{ github.ref != 'refs/heads/main' }}"
	// scheduledWorkflow is the one workflow allowed a `schedule:` trigger.
	scheduledWorkflow = "automerge.yml"
)

// ciPullRequestTypes are ci.yml's pull_request activity types. `labeled` is
// absent (DS-2281): Gitea maps every label add and remove to it, so each label
// change started a run that canceled the PR's run in progress. A `ci:full`
// label takes effect on the PR's next push or update-branch.
var ciPullRequestTypes = []string{"opened", "synchronize", "reopened"}

var (
	// gateCheckLine is one tagged result in the gate script:
	//   pr:image="${{ needs.image.result }}" \
	gateCheckLine = regexp.MustCompile(`^\s*([a-z]+):([A-Za-z0-9_-]+)="\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}"\s*\\?\s*$`)
	// needsResult finds every result the gate reads, tagged or not.
	needsResult = regexp.MustCompile(`needs\.([A-Za-z0-9_-]+)\.result`)
)

type tieredWorkflow struct {
	On          any                  `yaml:"on"`
	Concurrency any                  `yaml:"concurrency"`
	Jobs        map[string]tieredJob `yaml:"jobs"`
}

type tieredJob struct {
	If     any      `yaml:"if"`
	RunsOn any      `yaml:"runs-on"`
	Needs  []string `yaml:"needs"`
	Steps  []struct {
		Uses string            `yaml:"uses"`
		Env  map[string]string `yaml:"env"`
		Run  string            `yaml:"run"`
	} `yaml:"steps"`
}

// workflowEvents returns the events a workflow's `on:` names, in any of its
// three shapes: a scalar, a list or a mapping.
func workflowEvents(on any) (map[string]any, error) {
	switch o := on.(type) {
	case string:
		return map[string]any{o: nil}, nil
	case []any:
		ev := map[string]any{}
		for _, e := range o {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("`on:` lists a %T, want event names", e)
			}
			ev[s] = nil
		}
		return ev, nil
	case map[string]any:
		return o, nil
	default:
		return nil, fmt.Errorf("`on:` is a %T, want an event, a list or a mapping", on)
	}
}

// ciTierViolations returns what is wrong with ci.yml's tiers and gate, or nil.
func ciTierViolations(src []byte) ([]string, error) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	var bad []string

	events, err := workflowEvents(wf.On)
	if err != nil {
		return nil, err
	}
	var types []string
	if pr, ok := events["pull_request"].(map[string]any); ok {
		if ts, ok := pr["types"].([]any); ok {
			for _, ty := range ts {
				types = append(types, fmt.Sprint(ty))
			}
		}
	}
	if !slices.Equal(types, ciPullRequestTypes) {
		bad = append(bad, fmt.Sprintf("on.pull_request.types is %v, want %v", types, ciPullRequestTypes))
	}

	gate, ok := wf.Jobs[ciGateJob]
	if !ok {
		return append(bad, fmt.Sprintf("no %s job", ciGateJob)), nil
	}
	if gate.If != "always()" {
		bad = append(bad, fmt.Sprintf("job %s: if is %v, want always()", ciGateJob, gate.If))
	}
	if gate.RunsOn != ciGateRunner {
		bad = append(bad, fmt.Sprintf("job %s: runs-on is %v, want the reserved label %s", ciGateJob, gate.RunsOn, ciGateRunner))
	}
	for i, st := range gate.Steps {
		if st.Uses != "" {
			bad = append(bad, fmt.Sprintf("job %s step %d: uses %s; the gate runner is too small for actions, run shell only", ciGateJob, i+1, st.Uses))
		}
	}
	var jobs []string
	for name := range wf.Jobs {
		if name != ciGateJob {
			jobs = append(jobs, name)
		}
	}
	slices.Sort(jobs)
	needs := slices.Sorted(slices.Values(gate.Needs))
	if !slices.Equal(needs, slices.Compact(slices.Clone(needs))) || !slices.Equal(needs, jobs) {
		bad = append(bad, fmt.Sprintf("job %s: needs %v, want every other job once: %v", ciGateJob, gate.Needs, jobs))
	}

	// The tagged check lines, and the FULL flag beside them.
	tier := map[string]string{}
	seen := map[string]int{}
	fullFlag := false
	for _, st := range gate.Steps {
		if st.Env["FULL"] == "${{ "+fullTierIf+" }}" && strings.Contains(st.Run, `"$FULL"`) {
			fullFlag = true
		}
		for line := range strings.SplitSeq(st.Run, "\n") {
			refs := needsResult.FindAllStringSubmatch(line, -1)
			if len(refs) == 0 {
				continue
			}
			m := gateCheckLine.FindStringSubmatch(line)
			switch {
			case m == nil || len(refs) != 1:
				bad = append(bad, fmt.Sprintf("job %s: %q is not one `<tier>:<job>=\"${{ needs.<job>.result }}\"` check", ciGateJob, strings.TrimSpace(line)))
				continue
			case m[1] != "pr" && m[1] != "full":
				bad = append(bad, fmt.Sprintf("job %s: %s is tagged %q, want pr or full", ciGateJob, m[3], m[1]))
			case m[2] != m[3]:
				bad = append(bad, fmt.Sprintf("job %s: the check named %s reads needs.%s.result", ciGateJob, m[2], m[3]))
			}
			if _, ok := wf.Jobs[m[3]]; !ok || m[3] == ciGateJob {
				bad = append(bad, fmt.Sprintf("job %s: checks %s, which is not a job it gates", ciGateJob, m[3]))
			}
			tier[m[3]] = m[1]
			seen[m[3]]++
		}
	}
	if !fullFlag {
		bad = append(bad, fmt.Sprintf("job %s: no step passes \"$FULL\" with env FULL: ${{ %s }}", ciGateJob, fullTierIf))
	}

	for _, name := range jobs {
		job := wf.Jobs[name]
		if seen[name] != 1 {
			bad = append(bad, fmt.Sprintf("job %s: the gate checks it %d times, want exactly once", name, seen[name]))
		}
		switch tier[name] {
		case "full":
			if job.If != fullTierIf {
				bad = append(bad, fmt.Sprintf("job %s is tagged full but its if is %v, want %s", name, job.If, fullTierIf))
			}
		case "pr":
			if job.If != nil {
				bad = append(bad, fmt.Sprintf("job %s is tagged pr but has a job-level if: %v", name, job.If))
			}
			for _, n := range job.Needs {
				if tier[n] == "full" {
					bad = append(bad, fmt.Sprintf("job %s is tagged pr but needs the full-tier job %s", name, n))
				}
			}
		}
	}
	return bad, nil
}

// workflowTriggerViolations returns what is wrong with one workflow's triggers
// and concurrency, or nil.
// gateSummaryViolations returns how ci.yml's gate departs from running its
// inline copy of build/ci/summary.sh: the gate has no checkout, so the script
// travels in its step as a heredoc, and that copy must be the file exactly
// (the file is what TestCIGateSummaryPassesOnlyUnselectedFullSkips drives)
// and must be what the step runs.
func gateSummaryViolations(src, summary []byte) ([]string, error) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	open := `cat > "$script" <<'` + gateSummaryHeredoc + "'\n"
	end := "\n" + gateSummaryHeredoc + "\n"
	var bad []string
	copies := 0
	for i, st := range wf.Jobs[ciGateJob].Steps {
		_, rest, ok := strings.Cut(st.Run, open)
		if !ok {
			continue
		}
		copies++
		body, after, ok := strings.Cut(rest, end)
		switch {
		case !ok:
			bad = append(bad, fmt.Sprintf("job %s step %d: the %s heredoc is not closed", ciGateJob, i+1, gateSummaryHeredoc))
		case body+"\n" != string(summary):
			bad = append(bad, fmt.Sprintf("job %s step %d: the inline summary.sh differs from build/ci/summary.sh; copy the file verbatim", ciGateJob, i+1))
		case !strings.HasPrefix(after, `sh "$script" `):
			bad = append(bad, fmt.Sprintf("job %s step %d: the line after the heredoc does not run the copy (`sh \"$script\" ...`)", ciGateJob, i+1))
		}
	}
	if copies != 1 {
		bad = append(bad, fmt.Sprintf("job %s: %d steps write the inline summary.sh (`%s`), want exactly one", ciGateJob, copies, strings.TrimSpace(open)))
	}
	return bad, nil
}

func workflowTriggerViolations(file string, src []byte) ([]string, error) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	events, err := workflowEvents(wf.On)
	if err != nil {
		return nil, err
	}
	var bad []string
	if _, ok := events["pull_request"]; ok {
		c, _ := wf.Concurrency.(map[string]any)
		if c == nil || c["group"] != refConcurrencyGroup || c["cancel-in-progress"] != refCancelInProgress {
			bad = append(bad, fmt.Sprintf("runs on pull_request but its workflow-level concurrency is %v, want group: %s, cancel-in-progress: %s", wf.Concurrency, refConcurrencyGroup, refCancelInProgress))
		}
	}
	if _, ok := events["schedule"]; ok && filepath.Base(file) != scheduledWorkflow {
		bad = append(bad, fmt.Sprintf("has a schedule: trigger; only %s may (the coordinator dispatches nightly runs)", scheduledWorkflow))
	}
	return bad, nil
}

func TestCIGateTiersMatchTheJobs(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	bad, err := ciTierViolations(src)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}
	bad, err = gateSummaryViolations(src, []byte(readFile(t, filepath.Join(root, "build", "ci", "summary.sh"))))
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}

	files := workflowFiles(t, root)
	if len(files) < minWorkflowFiles {
		t.Fatalf("discovery floor: found %d workflow file(s), want at least %d; the gate would check nothing", len(files), minWorkflowFiles)
	}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		bad, err := workflowTriggerViolations(f, src)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", f, b)
		}
	}
}

// TestCIGateTiers_RefusesWhatItMustRefuse pins the checks against edits of
// the real ci.yml, so a rewrite that stops looking cannot pass.
func TestCIGateTiers_RefusesWhatItMustRefuse(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	ci := string(src)
	const fullIf = "    if: " + fullTierIf + "\n"
	for _, tc := range []struct{ name, old, new string }{
		{"full job tagged pr", "full:fips=", "pr:fips="},
		{"pr job tagged full", "pr:arch-gates=", "full:arch-gates="},
		{"unknown tag", "pr:image=", "nightly:image="},
		{"untagged check", "pr:image=", "image="},
		{"check names another job", `pr:arch-gates="${{ needs.arch-gates`, `pr:arch-gates="${{ needs.image`},
		{"job missing from the gate", "            pr:image=\"${{ needs.image.result }}\" \\\n", ""},
		{"job checked twice", "            pr:image=\"${{ needs.image.result }}\" \\\n", "            pr:image=\"${{ needs.image.result }}\" \\\n            pr:image=\"${{ needs.image.result }}\" \\\n"},
		{"gate misses a need", "needs: [image, fips, integration, arch-gates]", "needs: [image, fips, integration]"},
		{"gate not always", "    runs-on: " + ciGateRunner + "\n    if: always()\n", "    runs-on: " + ciGateRunner + "\n    if: success()\n"},
		{"full job without its if", "    name: FIPS\n" + fullIf, "    name: FIPS\n"},
		{"full job with a looser if", "    name: FIPS\n" + fullIf, "    name: FIPS\n    if: github.event_name == 'push' || github.event_name == 'pull_request'\n"},
		{"pr job with an if", "    name: Architecture Gates\n", "    name: Architecture Gates\n    if: always()\n"},
		{"pr job needs a full job", "    name: Architecture Gates\n", "    name: Architecture Gates\n    needs: [fips]\n"},
		{"gate FULL flag differs", "          FULL: ${{ " + fullTierIf, "          FULL: ${{ github.event_name == 'push'"},
		{"labeled type added back", "types: [opened, synchronize, reopened]", "types: [opened, synchronize, reopened, labeled]"},
		{"gate on the shared runner", "    runs-on: " + ciGateRunner + "\n", "    runs-on: ubuntu-latest\n"},
		{"gate uses an action", "      - name: Fail closed on any non-success\n", "      - uses: actions/checkout@abc # v7\n      - name: Fail closed on any non-success\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(ci, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			bad, err := ciTierViolations([]byte(strings.Replace(ci, tc.old, tc.new, 1)))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}

	summary := []byte(readFile(t, filepath.Join(repoRoot(t), "build", "ci", "summary.sh")))
	for _, tc := range []struct{ name, old, new string }{
		{"copy drifts", "pr:skipped) printf 'SKIP", "pr:skipped) printf 'OK  "},
		{"copy not run", `sh "$script" "a CI job`, `sh build/ci/summary.sh "a CI job`},
		{"heredoc not closed", "\n          SUMMARY\n", "\n          EOF\n"},
		{"no copy", `cat > "$script" <<'SUMMARY'`, `cat > "$script" <<'EOF'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(ci, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			bad, err := gateSummaryViolations([]byte(strings.Replace(ci, tc.old, tc.new, 1)), summary)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}

	const wantConc = "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}\n"
	for _, tc := range []struct {
		name, file, src string
		wantBad         bool
	}{
		{"pull_request without concurrency", "x.yml", "on: [pull_request]\njobs: {}\n", true},
		{"pull_request, global group", "x.yml", "on: pull_request\nconcurrency:\n  group: ci\n  cancel-in-progress: true\njobs: {}\n", true},
		{"pull_request, no cancel", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\njobs: {}\n", true},
		{"pull_request, cancels main", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\njobs: {}\n", true},
		{"pull_request, ref-keyed", "x.yml", "on:\n  pull_request:\n" + wantConc + "jobs: {}\n", false},
		{"push only, no concurrency", "x.yml", "on:\n  push:\njobs: {}\n", false},
		{"scheduled", "nightly.yml", "on:\n  schedule:\n    - cron: '0 3 * * *'\n  workflow_dispatch:\njobs: {}\n", true},
		{"scheduled automerge", "automerge.yml", "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs: {}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := workflowTriggerViolations(tc.file, []byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if (len(bad) > 0) != tc.wantBad {
				t.Fatalf("violations = %v, want a refusal: %v", bad, tc.wantBad)
			}
		})
	}
}

// TestCIGateSummaryPassesOnlyUnselectedFullSkips drives build/ci/summary.sh,
// the gate's script: a skip passes only for a full job in a run that did not
// select the full tier.
func TestCIGateSummaryPassesOnlyUnselectedFullSkips(t *testing.T) {
	script := filepath.Join(repoRoot(t), "build", "ci", "summary.sh")
	for _, tc := range []struct {
		name   string
		args   []string
		wantOK bool
	}{
		{"all pass, full tier", []string{"true", "pr:lint=success", "full:fips=success"}, true},
		{"full skipped, not selected", []string{"false", "pr:lint=success", "full:fips=skipped"}, true},
		{"full skipped, selected", []string{"true", "pr:lint=success", "full:fips=skipped"}, false},
		{"pr skipped", []string{"false", "pr:lint=skipped", "full:fips=skipped"}, false},
		{"full failed, not selected", []string{"false", "pr:lint=success", "full:fips=failure"}, false},
		{"full cancelled", []string{"false", "pr:lint=success", "full:fips=cancelled"}, false}, //nolint:misspell // the forge's result value is spelled "cancelled"
		{"pr failed", []string{"true", "pr:lint=failure", "full:fips=success"}, false},
		{"untagged", []string{"false", "lint=success"}, false},
		{"unknown tier", []string{"false", "nightly:fips=skipped"}, false},
		{"empty result", []string{"true", "pr:lint="}, false},
		{"full flag not a boolean", []string{"", "pr:lint=success"}, false},
		{"no jobs", []string{"false"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", append([]string{script, "a CI job did not pass"}, tc.args...)...)
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("running %s: %v", script, err)
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("exit ok = %v, want %v; output:\n%s", err == nil, tc.wantOK, out)
			}
		})
	}
}
