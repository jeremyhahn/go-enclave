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

// CI runs in three tiers (ci-template v1.29.2). The PR tier runs on every
// event; the full tier runs on every event but a pull_request, and on a PR
// labeled `ci:full` (from its next push or update-branch: a label event starts
// no run); the nightly tier runs on the schedule and on workflow_dispatch.
// A draft pull request runs no job (v1.26): every job but CI Gate skips, and
// CI Gate fails on a draft, so no skipped gate reads as passed. A PR whose
// every changed file is docs runs the PR tier's lint class only, and the
// lint-gates job (v1.27.0), the repository's own gates beside lint, is in it.
// CI Gate, the one required check, needs every job and names each one in its
// script with its tier, and build/ci/summary.sh lets a full or nightly job's
// skip pass only in a run that did not select its tier. These tests hold
// ci.yml's jobs, `if:`s and gate tags to one another, so a job cannot be
// added, moved between tiers or dropped from the gate without the rest
// following: a PR-tier job given an `if:` would be skipped and fail the gate,
// and a full-tier job tagged `pr` would fail every plain PR, but a full job
// with a looser `if:` or an untagged gate line would pass quietly.
//
// Every workflow that runs on pull_request also cancels the superseded run of
// its ref (devops §9b), and exactly one CI schedule exists, ci.yml's, which
// runs the full tier and Soak nightly; automerge.yml's merge sweep is the one
// other scheduled workflow.

const (
	ciWorkflowFile = ".github/workflows/ci.yml"
	ciGateJob      = "ci-gate"
	// ciGateRunner is the gate's runner label: a GitHub-hosted runner, like
	// every CI job. The gate uses no action (no checkout, no toolchain) and
	// carries summary.sh inline.
	ciGateRunner = "ubuntu-latest"
	// gateSummaryHeredoc delimits the inline copy of build/ci/summary.sh.
	gateSummaryHeredoc = "SUMMARY"
	// fullTierIf is the `if:` every full-tier job carries, and ci.yml's
	// workflow-level CI_FULL_TIER, which the gate's FULL_TIER reads.
	fullTierIf = "${{ github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full') }}"
	// draftIf is the `if:` that skips a job on a draft pull request (v1.26),
	// which every PR-tier job carries or inherits through `needs:`.
	draftIf = "${{ !github.event.pull_request.draft }}"
	// fullTierJobIf is the `if:` every full-tier job carries (v1.26): the
	// full tier, and never on a draft, ci:full or not.
	fullTierJobIf = "${{ (github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full')) && !github.event.pull_request.draft }}"
	// gateDraftEnv is the gate's DRAFT value, and gateDraftCheck the guard
	// that fails the gate on a draft before it reads any result.
	gateDraftEnv   = "${{ github.event.pull_request.draft == true }}"
	gateDraftCheck = `[ "${DRAFT}" = true ]`
	// lintGatesJob is the v1.27.0 job that runs the repository's own gates.
	lintGatesJob = "lint-gates"
	// fullTierEnv is the gate's FULL_TIER value.
	fullTierEnv = "${{ env.CI_FULL_TIER }}"
	// nightlyTierIf is the `if:` every nightly-tier job carries, and the
	// gate's NIGHTLY value.
	nightlyTierIf = "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}"
	// refConcurrencyGroup is the group of every pull_request workflow: keyed
	// by ref, and on main by event and commit, so a main run never cancels
	// another main run (issue #246) while a PR's newer run cancels the older.
	refConcurrencyGroup = "${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}"
	// ciSchedule is the one CI schedule, ci.yml's weekly cron: Tuesday night
	// in the nightly rotation (CA m1919), 04:00 UTC Wednesday.
	ciSchedule = "0 4 * * 3"
	// mergeSweepWorkflow is the one other workflow allowed a `schedule:`.
	mergeSweepWorkflow = "automerge.yml"
)

// lintGatesTargets are the make targets `make lint-gates` runs (Makefile): no
// job but lint-gates runs one, so each gate runs once per PR.
var lintGatesTargets = []string{"lint-gates", "check-buildgates", "check-releasability", "check-changelog-assembly", "check-scripts"}

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
	Env         map[string]string    `yaml:"env"`
	Jobs        map[string]tieredJob `yaml:"jobs"`
}

type tieredJob struct {
	If     any      `yaml:"if"`
	RunsOn any      `yaml:"runs-on"`
	Needs  jobNeeds `yaml:"needs"`
	Steps  []struct {
		If   any               `yaml:"if"`
		Uses string            `yaml:"uses"`
		Env  map[string]string `yaml:"env"`
		Run  string            `yaml:"run"`
	} `yaml:"steps"`
}

// jobNeeds is a job's `needs:`, in either shape: one job name or a list.
type jobNeeds []string

func (n *jobNeeds) UnmarshalYAML(unmarshal func(any) error) error {
	var one string
	if err := unmarshal(&one); err == nil {
		*n = jobNeeds{one}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return err
	}
	*n = list
	return nil
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

	if wf.Env["CI_FULL_TIER"] != fullTierIf {
		bad = append(bad, fmt.Sprintf("env CI_FULL_TIER is %q, want %s", wf.Env["CI_FULL_TIER"], fullTierIf))
	}

	gate, ok := wf.Jobs[ciGateJob]
	if !ok {
		return append(bad, fmt.Sprintf("no %s job", ciGateJob)), nil
	}
	if gate.If != "always()" {
		bad = append(bad, fmt.Sprintf("job %s: if is %v, want always()", ciGateJob, gate.If))
	}
	if gate.RunsOn != ciGateRunner {
		bad = append(bad, fmt.Sprintf("job %s: runs-on is %v, want the hosted runner %s", ciGateJob, gate.RunsOn, ciGateRunner))
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

	// The tagged check lines, and the FULL_TIER and NIGHTLY flags beside them.
	tier := map[string]string{}
	seen := map[string]int{}
	tierFlags := false
	draftGuard := false
	for _, st := range gate.Steps {
		// v1.26: the gate fails on a draft before it reads any result.
		if g := strings.Index(st.Run, gateDraftCheck); g >= 0 && st.Env["DRAFT"] == gateDraftEnv {
			block := st.Run[g:]
			if end := strings.Index(block, "\nfi"); end >= 0 && strings.Contains(block[:end], "exit 1") {
				if s := strings.Index(st.Run, `sh "$script"`); s < 0 || g < s {
					draftGuard = true
				}
			}
		}
		if st.Env["FULL_TIER"] == fullTierEnv && st.Env["NIGHTLY"] == nightlyTierIf && strings.Contains(st.Run, `"$FULL_TIER" "$NIGHTLY"`) {
			tierFlags = true
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
			case m[1] != "pr" && m[1] != "full" && m[1] != "nightly":
				bad = append(bad, fmt.Sprintf("job %s: %s is tagged %q, want pr, full or nightly", ciGateJob, m[3], m[1]))
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
	if !tierFlags {
		bad = append(bad, fmt.Sprintf("job %s: no step passes \"$FULL_TIER\" \"$NIGHTLY\" with env FULL_TIER: %s, NIGHTLY: %s", ciGateJob, fullTierEnv, nightlyTierIf))
	}

	if !draftGuard {
		bad = append(bad, fmt.Sprintf("job %s: no step fails on a draft pull request first: env DRAFT: %s and a `%s` block that exits 1 before the summary runs", ciGateJob, gateDraftEnv, gateDraftCheck))
	}

	// v1.26: a PR-tier job is skipped on a draft by its own `if:` or by a
	// needed job that is, so no job of a draft run reaches a docker daemon.
	var skipsOnDraft func(name string, depth int) bool
	skipsOnDraft = func(name string, depth int) bool {
		j := wf.Jobs[name]
		if j.If == draftIf {
			return true
		}
		return depth < len(wf.Jobs) && slices.ContainsFunc(j.Needs, func(n string) bool { return skipsOnDraft(n, depth+1) })
	}

	// v1.27.0: the lint-gates job runs the repository's own gates, on every
	// PR (a docs-only PR included, so it never waits on the changes job),
	// and nowhere else, so each gate runs once.
	for _, name := range jobs {
		job := wf.Jobs[name]
		runsLintGates := false
		for _, st := range job.Steps {
			for _, target := range lintGatesTargets {
				if name != lintGatesJob && strings.Contains(st.Run, target) {
					bad = append(bad, fmt.Sprintf("job %s runs `%s`, which the %s job runs; the gates would run twice", name, target, lintGatesJob))
				}
			}
			// v1.29.1: no -k, so the first failing gate ends the step.
			if name == lintGatesJob && strings.Contains(st.Run, "make lint-gates") {
				runsLintGates = true
			}
			if strings.Contains(st.Run, "make -k lint-gates") {
				bad = append(bad, fmt.Sprintf("job %s runs `make -k lint-gates`; v1.29.1 runs it without -k, so the first failing gate ends the step", name))
			}
			if name == lintGatesJob && strings.Contains(fmt.Sprint(st.If), "docs_only") {
				bad = append(bad, fmt.Sprintf("job %s: a step is conditioned on docs_only; a docs-only PR runs the lint class", name))
			}
		}
		if name == lintGatesJob {
			if !runsLintGates {
				bad = append(bad, fmt.Sprintf("job %s: no step runs `make lint-gates`", name))
			}
			if len(job.Needs) != 0 {
				bad = append(bad, fmt.Sprintf("job %s: needs %v, want none: it runs on a docs-only PR too", name, []string(job.Needs)))
			}
			if tier[name] != "pr" {
				bad = append(bad, fmt.Sprintf("job %s is tagged %q, want pr", name, tier[name]))
			}
		}
	}
	if _, ok := wf.Jobs[lintGatesJob]; !ok {
		bad = append(bad, fmt.Sprintf("no %s job", lintGatesJob))
	}

	// v1.28.0: deps-check is a lint-class gate on the PR tier and runs on
	// every event, so its step sits in a pr job and is not conditioned on
	// the full tier.
	runsDepsCheck := false
	for _, name := range jobs {
		for _, st := range wf.Jobs[name].Steps {
			if !strings.Contains(st.Run, "make deps-check") {
				continue
			}
			runsDepsCheck = true
			if tier[name] != "pr" {
				bad = append(bad, fmt.Sprintf("job %s runs `make deps-check` but is tagged %q, want pr", name, tier[name]))
			}
			if strings.Contains(fmt.Sprint(st.If), "CI_FULL_TIER") {
				bad = append(bad, fmt.Sprintf("job %s: the `make deps-check` step is conditioned on CI_FULL_TIER; it runs on every event", name))
			}
		}
	}
	if !runsDepsCheck {
		bad = append(bad, "no step runs `make deps-check`")
	}

	// v1.29.0: every job that names the integration image reads the Alpine
	// package index into APK_INDEX_SUM first, so each names the same tag.
	for _, name := range jobs {
		readIndex := false
		for _, st := range wf.Jobs[name].Steps {
			if strings.Contains(st.Run, "scripts/apk-index-sum.sh") && strings.Contains(st.Run, "APK_INDEX_SUM=") {
				readIndex = true
			}
			if strings.Contains(st.Run, "make -s it-image") && !readIndex {
				bad = append(bad, fmt.Sprintf("job %s names the integration image before it reads the Alpine package index (scripts/apk-index-sum.sh into APK_INDEX_SUM)", name))
			}
		}
	}

	// v1.24 and v1.26.1: the docs-only pattern and the releasability test's
	// arguments are declared, so a docs-only PR has a reduced set to run.
	for _, k := range []string{"DOCS_ONLY_PATTERN", "RELEASABILITY_TEST"} {
		if _, ok := wf.Env[k]; !ok {
			bad = append(bad, fmt.Sprintf("env %s is not declared", k))
		}
	}

	for _, name := range jobs {
		job := wf.Jobs[name]
		if seen[name] != 1 {
			bad = append(bad, fmt.Sprintf("job %s: the gate checks it %d times, want exactly once", name, seen[name]))
		}
		switch tier[name] {
		case "full":
			if job.If != fullTierJobIf {
				bad = append(bad, fmt.Sprintf("job %s is tagged full but its if is %v, want %s", name, job.If, fullTierJobIf))
			}
		case "nightly":
			if job.If != nightlyTierIf {
				bad = append(bad, fmt.Sprintf("job %s is tagged nightly but its if is %v, want %s", name, job.If, nightlyTierIf))
			}
		case "pr":
			if job.If != nil && job.If != draftIf {
				bad = append(bad, fmt.Sprintf("job %s is tagged pr but has a job-level if: %v, want none or %s", name, job.If, draftIf))
			}
			if !skipsOnDraft(name, 0) {
				bad = append(bad, fmt.Sprintf("job %s is tagged pr and would run on a draft: want if: %s, or a needed job that has it", name, draftIf))
			}
			for _, n := range job.Needs {
				if tier[n] == "full" || tier[n] == "nightly" {
					bad = append(bad, fmt.Sprintf("job %s is tagged pr but needs the %s-tier job %s", name, tier[n], n))
				}
			}
		}
	}
	return bad, nil
}

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

// workflowTriggerViolations returns what is wrong with one workflow's triggers
// and concurrency, or nil.
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
		if c == nil || c["group"] != refConcurrencyGroup || c["cancel-in-progress"] != true {
			bad = append(bad, fmt.Sprintf("runs on pull_request but its workflow-level concurrency is %v, want group: %s, cancel-in-progress: true", wf.Concurrency, refConcurrencyGroup))
		}
	}
	sched, ok := events["schedule"]
	switch base := filepath.Base(file); {
	case base == filepath.Base(ciWorkflowFile):
		crons, _ := sched.([]any)
		if len(crons) != 1 || fmt.Sprint(crons[0]) != fmt.Sprint(map[string]any{"cron": ciSchedule}) {
			bad = append(bad, fmt.Sprintf("schedule is %v, want exactly one cron: '%s' (the one CI schedule)", sched, ciSchedule))
		}
	case ok && base != mergeSweepWorkflow:
		bad = append(bad, fmt.Sprintf("has a schedule: trigger; the one CI schedule is %s's (and %s's merge sweep)", ciWorkflowFile, mergeSweepWorkflow))
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
	const fullIf = "    # v1.26: never on a draft PR, ci:full or not.\n    if: " + fullTierJobIf + "\n"
	const archIf = "    runs-on: ubuntu-latest\n    if: " + draftIf + "   # v1.26\n"
	const nightlyIf = "    if: " + nightlyTierIf + "\n"
	for _, tc := range []struct{ name, old, new string }{
		{"full job tagged pr", "full:fips=", "pr:fips="},
		{"pr job tagged full", "pr:arch-gates=", "full:arch-gates="},
		{"unknown tag", "pr:image=", "soon:image="},
		{"nightly job tagged full", "nightly:soak=", "full:soak="},
		{"full job tagged nightly", "full:fips=", "nightly:fips="},
		{"untagged check", "pr:image=", "image="},
		{"check names another job", `pr:arch-gates="${{ needs.arch-gates`, `pr:arch-gates="${{ needs.image`},
		{"job missing from the gate", "            pr:image=\"${{ needs.image.result }}\" \\\n", ""},
		{"job checked twice", "            pr:image=\"${{ needs.image.result }}\" \\\n", "            pr:image=\"${{ needs.image.result }}\" \\\n            pr:image=\"${{ needs.image.result }}\" \\\n"},
		{"gate misses a need", "needs: [changes, image, lint-gates, fips, integration, soak, arch-gates]", "needs: [changes, image, lint-gates, fips, integration, arch-gates]"},
		{"gate misses lint-gates", "needs: [changes, image, lint-gates, fips,", "needs: [changes, image, fips,"},
		{"lint-gates missing from the gate checks", "            pr:lint-gates=\"${{ needs.lint-gates.result }}\" \\\n", ""},
		{"lint-gates tagged full", "pr:lint-gates=", "full:lint-gates="},
		{"lint-gates job does not run make lint-gates", "make lint-gates GO_BUILD_TAGS", "make lint GO_BUILD_TAGS"},
		{"lint-gates job runs make -k", "make lint-gates GO_BUILD_TAGS", "make -k lint-gates GO_BUILD_TAGS"},
		{"image job names the image before reading the apk index", "          sum=$(scripts/apk-index-sum.sh)\n", "          sum=none\n"},
		{"lint-gates waits on the changes job", "    name: Lint Gates [toolchain image]\n", "    name: Lint Gates [toolchain image]\n    needs: changes\n"},
		{"lint-gates skipped on a docs-only PR", "      - name: make lint-gates\n        if: ${{ !cancelled() &&", "      - name: make lint-gates\n        if: ${{ needs.changes.outputs.docs_only != 'true' && !cancelled() &&"}, //nolint:misspell // the Actions cancelled() function
		{"lint-gates job without its draft if", "    name: Lint Gates [toolchain image]\n    runs-on: ubuntu-latest\n    if: " + draftIf + "   # v1.26\n", "    name: Lint Gates [toolchain image]\n    runs-on: ubuntu-latest\n"},
		{"the image job runs a lint-gates gate too", "\"$TOOLCHAIN_IMAGE\" make tidy-check lint-runtimesecret lint-integration\n", "\"$TOOLCHAIN_IMAGE\" make tidy-check lint-runtimesecret lint-integration check-scripts\n"},
		{"changes job without its draft if", "    if: " + draftIf + "\n    steps:\n", "    steps:\n"},
		{"arch-gates job without its draft if", archIf, "    runs-on: ubuntu-latest\n"},
		{"arch-gates job on a draft's looser if", archIf, "    runs-on: ubuntu-latest\n    if: always()\n"},
		{"full job runs on a draft", "    if: " + fullTierJobIf + "\n", "    if: " + fullTierIf + "\n"},
		{"gate does not fail on a draft", gateDraftCheck, `[ "${DRAFT}" = never ]`},
		{"gate DRAFT flag differs", "          DRAFT: " + gateDraftEnv, "          DRAFT: ${{ github.event.pull_request.draft == false }}"},
		{"gate draft check does not exit", "            exit 1\n          fi\n          script=$(mktemp)", "            :\n          fi\n          script=$(mktemp)"},
		{"docs-only pattern undeclared", "  DOCS_ONLY_PATTERN:", "  DOCS_ONLY_PATTERN_X:"},
		{"releasability test undeclared", "  RELEASABILITY_TEST:", "  RELEASABILITY_TEST_X:"},
		{"gate not always", "    runs-on: " + ciGateRunner + "\n    if: always()\n", "    runs-on: " + ciGateRunner + "\n    if: success()\n"},
		{"full job without its if", "    name: FIPS\n" + fullIf, "    name: FIPS\n"},
		{"full job with a looser if", "    name: FIPS\n" + fullIf, "    name: FIPS\n    if: github.event_name == 'push' || github.event_name == 'pull_request'\n"},
		{"nightly job without its if", "    name: Soak [integration image]\n" + nightlyIf, "    name: Soak [integration image]\n"},
		{"nightly job on the full tier's if", "    name: Soak [integration image]\n" + nightlyIf, "    name: Soak [integration image]\n" + fullIf},
		{"pr job needs a full job", "    name: Architecture Gates\n", "    name: Architecture Gates\n    needs: [fips]\n"},
		{"pr job needs a nightly job", "    name: Architecture Gates\n", "    name: Architecture Gates\n    needs: [soak]\n"},
		{"gate FULL_TIER flag differs", "          FULL_TIER: " + fullTierEnv, "          FULL_TIER: ${{ github.event_name == 'push' }}"},
		{"gate NIGHTLY flag differs", "          NIGHTLY: " + nightlyTierIf, "          NIGHTLY: ${{ github.event_name == 'schedule' }}"},
		{"gate drops NIGHTLY", `"$FULL_TIER" "$NIGHTLY"`, `"$FULL_TIER"`},
		{"workflow CI_FULL_TIER differs", "  CI_FULL_TIER: " + fullTierIf, "  CI_FULL_TIER: ${{ github.event_name == 'push' }}"},
		{"labeled type added back", "types: [opened, synchronize, reopened]", "types: [opened, synchronize, reopened, labeled]"},
		{"gate on a self-hosted label", "    name: CI Gate\n    runs-on: " + ciGateRunner + "\n", "    name: CI Gate\n    runs-on: ci-gate\n"},
		{"deps-check back on the full tier", "env.TOOLCHAIN_IMAGE != '' }}\n        env:\n          IN_IMAGE_NETWORK: bridge\n        run: scripts/in-toolchain-image.sh \"$TOOLCHAIN_IMAGE\" make deps-check\n", "env.TOOLCHAIN_IMAGE != '' && env.CI_FULL_TIER == 'true' }}\n        env:\n          IN_IMAGE_NETWORK: bridge\n        run: scripts/in-toolchain-image.sh \"$TOOLCHAIN_IMAGE\" make deps-check\n"},
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

	const wantConc = "concurrency:\n  group: " + refConcurrencyGroup + "\n  cancel-in-progress: true\n"
	for _, tc := range []struct {
		name, file, src string
		wantBad         bool
	}{
		{"pull_request without concurrency", "x.yml", "on: [pull_request]\njobs: {}\n", true},
		{"pull_request, global group", "x.yml", "on: pull_request\nconcurrency:\n  group: ci\n  cancel-in-progress: true\njobs: {}\n", true},
		{"pull_request, no cancel", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\njobs: {}\n", true},
		{"pull_request, main shares the ref group", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\njobs: {}\n", true},
		{"pull_request, cancel by expression", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: " + refConcurrencyGroup + "\n  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}\njobs: {}\n", true},
		{"pull_request, main pushes share a group", "x.yml", "on:\n  pull_request:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref == 'refs/heads/main' && format('main-{0}', github.event_name) || github.ref }}\n  cancel-in-progress: true\njobs: {}\n", true},
		{"pull_request, per-commit main group", "x.yml", "on:\n  pull_request:\n" + wantConc + "jobs: {}\n", false},
		{"push only, no concurrency", "x.yml", "on:\n  push:\njobs: {}\n", false},
		{"scheduled", "nightly.yml", "on:\n  schedule:\n    - cron: '0 3 * * *'\n  workflow_dispatch:\njobs: {}\n", true},
		{"scheduled automerge", "automerge.yml", "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs: {}\n", false},
		{"ci.yml scheduled", "ci.yml", "on:\n  schedule:\n    - cron: '" + ciSchedule + "'\njobs: {}\n", false},
		{"ci.yml unscheduled", "ci.yml", "on:\n  push:\njobs: {}\n", true},
		{"ci.yml scheduled twice", "ci.yml", "on:\n  schedule:\n    - cron: '" + ciSchedule + "'\n    - cron: '0 16 * * *'\njobs: {}\n", true},
		{"ci.yml on another cron", "ci.yml", "on:\n  schedule:\n    - cron: '0 3 * * *'\njobs: {}\n", true},
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
// the gate's script: a skip passes only for a full or nightly job in a run
// that did not select its tier.
func TestCIGateSummaryPassesOnlyUnselectedFullSkips(t *testing.T) {
	script := filepath.Join(repoRoot(t), "build", "ci", "summary.sh")
	for _, tc := range []struct {
		name   string
		args   []string
		wantOK bool
	}{
		{"all pass, every tier", []string{"true", "true", "pr:lint=success", "full:fips=success", "nightly:soak=success"}, true},
		{"full skipped, not selected", []string{"false", "false", "pr:lint=success", "full:fips=skipped", "nightly:soak=skipped"}, true},
		{"full skipped, selected", []string{"true", "false", "pr:lint=success", "full:fips=skipped"}, false},
		{"nightly skipped, not selected", []string{"true", "false", "pr:lint=success", "full:fips=success", "nightly:soak=skipped"}, true},
		{"nightly skipped, selected", []string{"true", "true", "pr:lint=success", "nightly:soak=skipped"}, false},
		{"pr skipped", []string{"false", "false", "pr:lint=skipped", "full:fips=skipped"}, false},
		{"full failed, not selected", []string{"false", "false", "pr:lint=success", "full:fips=failure"}, false},
		{"nightly failed, not selected", []string{"false", "false", "pr:lint=success", "nightly:soak=failure"}, false},
		{"full cancelled", []string{"false", "false", "pr:lint=success", "full:fips=cancelled"}, false}, //nolint:misspell // the forge's result value is spelled "cancelled"
		{"pr failed", []string{"true", "true", "pr:lint=failure", "full:fips=success"}, false},
		{"untagged", []string{"false", "false", "lint=success"}, false},
		{"unknown tier", []string{"false", "false", "soon:fips=skipped"}, false},
		{"empty result", []string{"true", "true", "pr:lint="}, false},
		{"full flag not a boolean", []string{"", "false", "pr:lint=success"}, false},
		{"nightly flag not a boolean", []string{"false", "", "pr:lint=success"}, false},
		{"no jobs", []string{"false", "false"}, false},
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
