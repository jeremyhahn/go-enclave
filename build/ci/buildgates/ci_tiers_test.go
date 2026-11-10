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

// CI runs in three tiers (ci-template v1.30). The PR tier runs on every
// event; the full tier runs on every event but a pull_request (a
// workflow_dispatch only on main), and on a PR labeled `ci:full` (from its
// next push or update-branch: a label event starts no run); the nightly tier
// runs on the schedule and on workflow_dispatch. A draft pull request runs no
// job (v1.26): every job but CI Gate skips, and CI Gate fails on a draft, so
// no skipped gate reads as passed. A PR whose every changed file is docs skips
// the `code` jobs, and the lint-gates job (v1.27.0), the repository's own
// gates, is `scoped` to LINT_GATES_PATTERN (v1.30). CI Gate, the one required
// check, needs every job but publish-images and names each one in a
// `check <job> <result> <tier>` line; its check() lets a skip pass only when
// the run did not select the job's tier, the PR was docs-only (code), no file
// matched (scoped), or the schedule guard proved the tree. These tests hold
// ci.yml's jobs, `if:`s and gate tags to one another, so a job cannot be
// added, moved between tiers or dropped from the gate without the rest
// following: a PR-tier job given an `if:` would be skipped and fail the gate,
// and a full-tier job tagged `pr` would fail every plain PR, but a full job
// with a looser `if:` or an untagged gate line would pass quietly.
//
// Every workflow that runs on pull_request also cancels the superseded run of
// its ref (devops §9b), and exactly one CI schedule exists, ci.yml's, which
// runs the full tier and Soak weekly; no other workflow has a schedule.

const (
	ciWorkflowFile = ".github/workflows/ci.yml"
	ciGateJob      = "ci-gate"
	// ciGateRunner is the gate's runner label: a GitHub-hosted runner, like
	// every CI job. The gate uses no action (no checkout, no toolchain) and
	// carries summary.sh inline.
	ciGateRunner = "ubuntu-latest"
	// gateIf is the gate's `if:` (v1.29.3): always, but on a schedule run the
	// guard's `busy` skips it, so a nightly never posts a green gate.
	gateIf = "${{ always() && (github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict != 'busy') }}"
	// gateCheckFunc opens the gate's check() (v1.30), which judges each job's
	// result against its tier.
	gateCheckFunc = "check() {"
	// fullTierIf is ci.yml's workflow-level CI_FULL_TIER (v1.30), which the
	// gate's FULL_TIER reads.
	fullTierIf = "${{ (github.event_name != 'pull_request' && (github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main')) || contains(github.event.pull_request.labels.*.name, 'ci:full') }}"
	// draftIf is the `if:` that skips a job on a draft pull request (v1.26),
	// which every PR-tier job carries or inherits through `needs:`.
	draftIf = "${{ !github.event.pull_request.draft }}"
	// fullTierJobIf is the `if:` a full-tier job carries (v1.26): the full
	// tier, never on a draft, ci:full or not, and only on the schedule
	// guard's run verdict (#277).
	fullTierJobIf = "${{ (" + termFull + ") && " + termDraft + " && " + termRun + " }}"
	// guardedPRJobIf is the `if:` of a PR-tier job that reads nothing from
	// the changes job: never on a draft, and only on the guard's run verdict.
	guardedPRJobIf = "${{ " + termDraft + " && " + termRun + " }}"
	// gateDraftEnv is the gate's DRAFT value, and gateDraftCheck the guard
	// that fails the gate on a draft before it reads any result.
	gateDraftEnv   = "${{ github.event.pull_request.draft == true }}"
	gateDraftCheck = `[ "${DRAFT}" = true ]`
	// lintGatesJob is the v1.27.0 job that runs the repository's own gates.
	lintGatesJob = "lint-gates"
	// lintJob is the v1.30 job that runs lint, moved from the image job.
	lintJob = "lint"
	// scheduleGuardJob is the v1.29.3 job whose verdict gates the bigdisk jobs.
	scheduleGuardJob = "schedule-guard"
	// changesJob lists the changed files for the jobs with a path scope.
	changesJob = "changes"
	// publishJob is the one job outside the gate (v1.30); its if holds
	// publishGuard, so it never runs on github.com, where go-enclave lives and
	// no `release` runner serves it (#277).
	publishJob = "publish-images"
	// publishGuard is the template's term that skips publishJob on github.com.
	publishGuard = "github.server_url != 'https://github.com'"
	// fullTierEnv is the gate's FULL_TIER value.
	fullTierEnv = "${{ env.CI_FULL_TIER }}"
	// nightlyTierIf is the gate's NIGHTLY value.
	nightlyTierIf = "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}"
	// refConcurrencyGroup is the group of every pull_request workflow: keyed
	// by ref, on main by event and commit, so a main run never cancels
	// another main run (issue #246) while a PR's newer run cancels the older,
	// and by repository on a schedule (v1.30).
	refConcurrencyGroup = "${{ github.workflow }}-${{ github.event_name == 'schedule' && format('schedule-{0}', github.repository) || github.ref == 'refs/heads/main' && format('main-{0}-{1}', github.event_name, github.sha) || github.ref }}"
	// ciSchedule is the one CI schedule, ci.yml's weekly cron: Tuesday night,
	// 04:00 UTC Wednesday.
	ciSchedule = "0 4 * * 3"
)

// The terms a job's `if:` is built from (v1.30), each without its outer
// parentheses: a tier's required terms, and the two any job may add.
const (
	termDraft   = "!github.event.pull_request.draft"
	termRun     = "needs.schedule-guard.outputs.verdict == 'run'"
	termFull    = "github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full')"
	termNightly = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
	termCode    = "needs.changes.outputs.docs_only != 'true'"
	termScoped  = "needs.changes.outputs.lint_gates != 'false'"
)

// tierTerms are the terms each gate tier's job `if:` must hold; termDraft and
// termRun may join any of them.
var tierTerms = map[string][]string{
	"pr":      nil,
	"code":    {termCode},
	"scoped":  {termScoped},
	"full":    {termFull, termDraft},
	"nightly": {termNightly},
}

// ciJobTimeouts is every ci.yml job's timeout-minutes (#277): the measured
// jobs at ceil(1.5 x p95), lint and publish-images at the template's value,
// the swtpm and OP-TEE jobs at the values they had before the template, the
// rest at 5.
var ciJobTimeouts = map[string]int{
	"changes": 5, scheduleGuardJob: 5, publishJob: 60, lintJob: 30, "image": 32,
	lintGatesJob: 20, "fips": 11, "integration": 22, "soak": 56, "arch-gates": 5, ciGateJob: 5,
	"tpm-swtpm": 30, "optee": 180,
}

// lintSteps are go-enclave's four lint steps, which v1.30 moved from the
// image job into the lint job (#277), and v1.31's private-pattern search
// after make lint: they run there, in this order, and in no other job.
var lintSteps = []string{"make lint GO_BUILD_TAGS", privatePatternSearch, "$RELEASABILITY_TEST", "make tidy-check lint-runtimesecret lint-integration", "scripts/assert-build-tags.sh"}

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
	//   check image       "${{ needs.image.result }}" code
	gateCheckLine = regexp.MustCompile(`^\s*check\s+([A-Za-z0-9_-]+)\s+"\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}"\s+([a-z]+)\s*$`)
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
	If      any      `yaml:"if"`
	RunsOn  any      `yaml:"runs-on"`
	Needs   jobNeeds `yaml:"needs"`
	Timeout int      `yaml:"timeout-minutes"`
	Steps   []struct {
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
	if gate.If != gateIf {
		bad = append(bad, fmt.Sprintf("job %s: if is %v, want %s", ciGateJob, gate.If, gateIf))
	}
	if gate.RunsOn != ciGateRunner {
		bad = append(bad, fmt.Sprintf("job %s: runs-on is %v, want the hosted runner %s", ciGateJob, gate.RunsOn, ciGateRunner))
	}
	for i, st := range gate.Steps {
		if st.Uses != "" {
			bad = append(bad, fmt.Sprintf("job %s step %d: uses %s; the gate runner is too small for actions, run shell only", ciGateJob, i+1, st.Uses))
		}
	}
	var jobs, gated []string
	for name := range wf.Jobs {
		if name != ciGateJob {
			jobs = append(jobs, name)
		}
		if name != ciGateJob && name != publishJob {
			gated = append(gated, name)
		}
	}
	slices.Sort(jobs)
	slices.Sort(gated)
	needs := slices.Sorted(slices.Values(gate.Needs))
	if !slices.Equal(needs, slices.Compact(slices.Clone(needs))) || !slices.Equal(needs, gated) {
		bad = append(bad, fmt.Sprintf("job %s: needs %v, want every job but %s once: %v", ciGateJob, gate.Needs, publishJob, gated))
	}

	// v1.30: publish-images is the one job outside the gate; no release
	// runner serves this repository on github.com, so it never runs there (#277).
	if pub, ok := wf.Jobs[publishJob]; !ok || !slices.Contains(ifTerms(pub.If), publishGuard) {
		bad = append(bad, fmt.Sprintf("job %s: if is %v, want a top-level %s term: no release runner serves this repository on github.com (#277)", publishJob, pub.If, publishGuard))
	}
	if _, ok := wf.Jobs[scheduleGuardJob]; !ok {
		bad = append(bad, fmt.Sprintf("no %s job", scheduleGuardJob))
	}

	// #277: go-enclave's lint steps run in the lint job, in order, and in no
	// other job.
	if lint, ok := wf.Jobs[lintJob]; !ok {
		bad = append(bad, fmt.Sprintf("no %s job", lintJob))
	} else {
		next := 0
		for _, st := range lint.Steps {
			if next < len(lintSteps) && strings.Contains(st.Run, lintSteps[next]) {
				next++
			}
		}
		if next < len(lintSteps) {
			bad = append(bad, fmt.Sprintf("job %s: no step runs %q after the ones before it; want %q in this order", lintJob, lintSteps[next], lintSteps))
		}
	}
	for _, name := range jobs {
		for _, st := range wf.Jobs[name].Steps {
			for _, s := range lintSteps {
				if name != lintJob && strings.Contains(st.Run, s) {
					bad = append(bad, fmt.Sprintf("job %s runs %q, which the %s job runs", name, s, lintJob))
				}
			}
		}
	}

	for _, name := range append(slices.Clone(jobs), ciGateJob) {
		if want, got := ciJobTimeouts[name], wf.Jobs[name].Timeout; want == 0 || got != want {
			bad = append(bad, fmt.Sprintf("job %s: timeout-minutes is %d, want %d (ciJobTimeouts, #277)", name, got, want))
		}
	}

	// The tagged check lines, and the FULL_TIER and NIGHTLY flags beside them.
	tier := map[string]string{}
	tierFlags := false
	draftGuard := false
	for _, st := range gate.Steps {
		// v1.26: the gate fails on a draft before it reads any result.
		if g := strings.Index(st.Run, gateDraftCheck); g >= 0 && st.Env["DRAFT"] == gateDraftEnv {
			block := st.Run[g:]
			if end := strings.Index(block, "\nfi"); end >= 0 && strings.Contains(block[:end], "exit 1") {
				if s := strings.Index(st.Run, gateCheckFunc); s < 0 || g < s {
					draftGuard = true
				}
			}
		}
		if st.Env["FULL_TIER"] == fullTierEnv && st.Env["NIGHTLY"] == nightlyTierIf && strings.Contains(st.Run, gateCheckFunc) {
			tierFlags = true
		}
		for line := range strings.SplitSeq(st.Run, "\n") {
			refs := needsResult.FindAllStringSubmatch(line, -1)
			if len(refs) == 0 {
				continue
			}
			m := gateCheckLine.FindStringSubmatch(line)
			if m == nil || len(refs) != 1 {
				bad = append(bad, fmt.Sprintf("job %s: %q is not one `check <job> \"${{ needs.<job>.result }}\" <tier>` line", ciGateJob, strings.TrimSpace(line)))
				continue
			}
			if _, ok := tierTerms[m[3]]; !ok {
				bad = append(bad, fmt.Sprintf("job %s: %s is tagged %q, want pr, code, scoped, full or nightly", ciGateJob, m[2], m[3]))
			}
			tier[m[2]] = m[3]
		}
	}
	if !tierFlags {
		bad = append(bad, fmt.Sprintf("job %s: no step defines `%s` with env FULL_TIER: %s, NIGHTLY: %s", ciGateJob, gateCheckFunc, fullTierEnv, nightlyTierIf))
	}

	if !draftGuard {
		bad = append(bad, fmt.Sprintf("job %s: no step fails on a draft pull request first: env DRAFT: %s and a `%s` block that exits 1 before check() runs", ciGateJob, gateDraftEnv, gateDraftCheck))
	}

	// v1.26: a PR-tier job is skipped on a draft by its own `if:` or by a
	// needed job that is, so no job of a draft run reaches a docker daemon.
	var skipsOnDraft func(name string, depth int) bool
	skipsOnDraft = func(name string, depth int) bool {
		j := wf.Jobs[name]
		if slices.Contains(ifTerms(j.If), termDraft) {
			return true
		}
		return depth < len(wf.Jobs) && slices.ContainsFunc(j.Needs, func(n string) bool { return skipsOnDraft(n, depth+1) })
	}

	// v1.27.0: the lint-gates job runs the repository's own gates, on every
	// PR whose changed files match LINT_GATES_PATTERN (v1.30: scoped), and
	// nowhere else, so each gate runs once.
	for _, name := range jobs {
		job := wf.Jobs[name]
		runsLintGates := false
		for _, st := range job.Steps {
			for _, target := range lintGatesTargets {
				if name != lintGatesJob && runsMakeTarget(st.Run, target) {
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
			if tier[name] != "scoped" {
				bad = append(bad, fmt.Sprintf("job %s is tagged %q, want scoped (v1.30)", name, tier[name]))
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
	for _, k := range []string{"DOCS_ONLY_PATTERN", "RELEASABILITY_TEST", "LINT_GATES_PATTERN"} {
		if _, ok := wf.Env[k]; !ok {
			bad = append(bad, fmt.Sprintf("env %s is not declared", k))
		}
	}

	// Each gated job's `if:` holds its tier's terms and adds none but the
	// draft and schedule-guard terms (v1.30).
	for _, name := range gated {
		job := wf.Jobs[name]
		t, ok := tier[name]
		if !ok {
			continue // gateCheckViolations reports the missing check line
		}
		terms := ifTerms(job.If)
		for _, want := range tierTerms[t] {
			if !slices.Contains(terms, want) {
				bad = append(bad, fmt.Sprintf("job %s is tagged %s but its if (%v) lacks %q", name, t, job.If, want))
			}
		}
		for _, term := range terms {
			if !slices.Contains(tierTerms[t], term) && term != termDraft && term != termRun {
				bad = append(bad, fmt.Sprintf("job %s is tagged %s but its if has %q, which the tier does not allow", name, t, term))
			}
		}
		if t == "full" || t == "nightly" {
			continue
		}
		if !skipsOnDraft(name, 0) {
			bad = append(bad, fmt.Sprintf("job %s is tagged %s and would run on a draft: want %s in its if, or a needed job that has it", name, t, termDraft))
		}
		for _, n := range job.Needs {
			if tier[n] == "full" || tier[n] == "nightly" {
				bad = append(bad, fmt.Sprintf("job %s is tagged %s but needs the %s-tier job %s", name, t, tier[n], n))
			}
		}
	}

	// #277: the guard refuses a workflow_dispatch off main, and a refused run
	// starts no job that checks out and runs the branch. So every gated job
	// but the changes job and the guard itself needs the guard and requires
	// its run verdict, in its own `needs:` and `if:`: a job skipped only
	// through another job's skip would run again once that job's `if:` moved.
	for _, name := range gated {
		if name == changesJob || name == scheduleGuardJob {
			continue
		}
		job := wf.Jobs[name]
		if !slices.Contains(job.Needs, scheduleGuardJob) {
			bad = append(bad, fmt.Sprintf("job %s: needs %v, want %s in it: a refused run must not start the job", name, job.Needs, scheduleGuardJob))
		}
		if !slices.Contains(ifTerms(job.If), termRun) {
			bad = append(bad, fmt.Sprintf("job %s: if (%v) lacks the top-level term %q: a refused run must not start the job", name, job.If, termRun))
		}
	}
	return bad, nil
}

// ifTerms splits an `if:` into its top-level && terms, each without its outer
// parentheses; nil when there is no `if:`.
func ifTerms(v any) []string {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	s = strings.TrimSuffix(strings.TrimPrefix(s, "${{"), "}}")
	var terms []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '(':
			depth++
		case s[i] == ')':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], "&&"):
			terms = append(terms, unparen(s[start:i]))
			start = i + 2
		}
	}
	return append(terms, unparen(s[start:]))
}

// unparen trims a term and drops the parentheses that wrap all of it.
func unparen(s string) string {
	s = strings.TrimSpace(s)
	for len(s) > 1 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		for i := 0; i < len(s)-1; i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				return s
			}
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// runsMakeTarget reports whether a step's script runs target through make.
func runsMakeTarget(run, target string) bool {
	unquote := strings.NewReplacer(`"`, " ", `'`, " ")
	for line := range strings.SplitSeq(run, "\n") {
		if _, args, ok := strings.Cut(line, "make "); ok && slices.Contains(strings.Fields(unquote.Replace(args)), target) {
			return true
		}
	}
	return false
}

// gateCheckViolations returns how ci.yml's gate departs from v1.30's check()
// form (#277): one step sets BAD=0, defines check(), runs exactly one
// `check <job> "${{ needs.<job>.result }}" <tier>` line for every job in the
// gate's needs and none for a job outside them, and ends with `exit $BAD`.
// TestCIGateCheckPassesOnlyExplainedSkips drives the check() it defines.
func gateCheckViolations(src []byte) ([]string, error) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	gate := wf.Jobs[ciGateJob]
	var bad []string
	seen := map[string]int{}
	defs := 0
	for i, st := range gate.Steps {
		def := strings.Index(st.Run, gateCheckFunc)
		if def < 0 {
			continue
		}
		defs++
		for line := range strings.SplitSeq(st.Run[:def], "\n") {
			if gateCheckLine.MatchString(line) {
				bad = append(bad, fmt.Sprintf("job %s step %d: %q runs before %s defines it", ciGateJob, i+1, strings.TrimSpace(line), gateCheckFunc))
			}
		}
		if b := strings.Index(st.Run, "BAD=0\n"); b < 0 || b > def {
			bad = append(bad, fmt.Sprintf("job %s step %d: no BAD=0 before %s", ciGateJob, i+1, gateCheckFunc))
		}
		if !strings.HasSuffix(strings.TrimSpace(st.Run), "\nexit $BAD") {
			bad = append(bad, fmt.Sprintf("job %s step %d: the step does not end with `exit $BAD`", ciGateJob, i+1))
		}
		for line := range strings.SplitSeq(st.Run[def:], "\n") {
			m := gateCheckLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if m[1] != m[2] {
				bad = append(bad, fmt.Sprintf("job %s: the check named %s reads needs.%s.result", ciGateJob, m[1], m[2]))
			}
			if !slices.Contains(gate.Needs, m[1]) {
				bad = append(bad, fmt.Sprintf("job %s: checks %s, which is not in its needs", ciGateJob, m[1]))
			}
			seen[m[1]]++
		}
	}
	if defs != 1 {
		bad = append(bad, fmt.Sprintf("job %s: %d steps define `%s`, want exactly one", ciGateJob, defs, gateCheckFunc))
	}
	for _, name := range gate.Needs {
		if seen[name] != 1 {
			bad = append(bad, fmt.Sprintf("job %s: the gate checks %s %d times, want exactly once", ciGateJob, name, seen[name]))
		}
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
	case ok:
		bad = append(bad, fmt.Sprintf("has a schedule: trigger; the one schedule is %s's", ciWorkflowFile))
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
	bad, err = gateCheckViolations(src)
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
	const fullIf = "    if: " + fullTierJobIf + "\n"
	const archIf = "    runs-on: ubuntu-latest\n    if: " + guardedPRJobIf + "   # v1.26\n"
	const archNeeds = "    name: Architecture Gates\n    needs: schedule-guard\n"
	const nightlyIf = "    if: ${{ (" + termNightly + ") && " + termRun + " }}\n"
	const scopedIf = " && " + termScoped + " }}\n"
	for _, tc := range []struct{ name, old, new string }{
		{"full job tagged pr", `needs.fips.result }}" full`, `needs.fips.result }}" pr`},
		{"pr job tagged full", `needs.arch-gates.result }}" pr`, `needs.arch-gates.result }}" full`},
		{"unknown tag", `needs.image.result }}" code`, `needs.image.result }}" soon`},
		{"nightly job tagged full", `needs.soak.result }}" nightly`, `needs.soak.result }}" full`},
		{"full job tagged nightly", `needs.fips.result }}" full`, `needs.fips.result }}" nightly`},
		{"code job tagged pr", `needs.image.result }}" code`, `needs.image.result }}" pr`},
		{"untagged check", `needs.image.result }}" code`, `needs.image.result }}"`},
		{"gate misses a need", "needs: [changes, schedule-guard, lint, image, lint-gates, fips, integration, soak, tpm-swtpm, optee, arch-gates]", "needs: [changes, schedule-guard, lint, image, lint-gates, fips, integration, tpm-swtpm, optee, arch-gates]"},
		{"gate misses lint-gates", "lint, image, lint-gates, fips,", "lint, image, fips,"},
		{"gate needs publish-images", "lint, image, lint-gates, fips,", "lint, image, lint-gates, publish-images, fips,"},
		{"lint-gates tagged pr", `needs.lint-gates.result }}" scoped`, `needs.lint-gates.result }}" pr`},
		{"lint-gates tagged full", `needs.lint-gates.result }}" scoped`, `needs.lint-gates.result }}" full`},
		{"lint-gates without its scope", scopedIf, " }}\n"},
		{"lint-gates job does not run make lint-gates", "make lint-gates GO_BUILD_TAGS", "make lint GO_BUILD_TAGS"},
		{"lint-gates job runs make -k", "make lint-gates GO_BUILD_TAGS", "make -k lint-gates GO_BUILD_TAGS"},
		{"image job names the image before reading the apk index", "          sum=$(scripts/apk-index-sum.sh)\n", "          sum=none\n"},
		{"lint-gates skipped on a docs-only PR", "      - name: make lint-gates\n        if: ${{ !cancelled() &&", "      - name: make lint-gates\n        if: ${{ needs.changes.outputs.docs_only != 'true' && !cancelled() &&"}, //nolint:misspell // the Actions cancelled() function
		{"the lint job runs a lint-gates gate too", "\"$TOOLCHAIN_IMAGE\" make tidy-check lint-runtimesecret lint-integration\n", "\"$TOOLCHAIN_IMAGE\" make tidy-check lint-runtimesecret lint-integration check-scripts\n"},
		{"a lint step dropped", "\"$TOOLCHAIN_IMAGE\" make tidy-check lint-runtimesecret lint-integration\n", "\"$TOOLCHAIN_IMAGE\" make tidy-check\n"},
		{"a lint step back in the image job", "      - name: make build\n", "      - name: make lint\n        run: make lint GO_BUILD_TAGS=x\n      - name: make build\n"},
		{"changes job without its draft if", "    if: " + draftIf + "\n    timeout-minutes: 5", "    timeout-minutes: 5"},
		{"arch-gates job without its draft if", archIf, "    runs-on: ubuntu-latest\n"},
		{"arch-gates job on a draft's looser if", archIf, "    runs-on: ubuntu-latest\n    if: always()\n"},
		{"full job runs on a draft", fullIf, "    if: ${{ (" + termFull + ") && " + termRun + " }}\n"},
		{"full job runs a refused dispatch", fullIf, "    if: ${{ (" + termFull + ") && " + termDraft + " }}\n"},
		{"full job's run verdict ored away", fullIf, "    if: ${{ ((" + termFull + ") && " + termDraft + ") || " + termRun + " }}\n"},
		{"fips without the guard in needs", "    name: FIPS\n    needs: schedule-guard\n", "    name: FIPS\n"},
		{"swtpm without the guard in needs", fullIf + "    needs: [changes, schedule-guard]\n", fullIf + "    needs: changes\n"},
		{"optee guarded through the image job only", "    needs: [changes, image, schedule-guard]\n", "    needs: [changes, image]\n"},
		{"arch-gates without the guard in needs", archNeeds, "    name: Architecture Gates\n"},
		{"arch-gates runs a refused dispatch", archIf, "    runs-on: ubuntu-latest\n    if: " + draftIf + "   # v1.26\n"},
		{"gate does not fail on a draft", gateDraftCheck, `[ "${DRAFT}" = never ]`},
		{"gate DRAFT flag differs", "          DRAFT: " + gateDraftEnv, "          DRAFT: ${{ github.event.pull_request.draft == false }}"},
		{"gate draft check does not exit", "            exit 1\n          fi\n          BAD=0", "            :\n          fi\n          BAD=0"},
		{"docs-only pattern undeclared", "  DOCS_ONLY_PATTERN:", "  DOCS_ONLY_PATTERN_X:"},
		{"releasability test undeclared", "  RELEASABILITY_TEST:", "  RELEASABILITY_TEST_X:"},
		{"lint-gates pattern undeclared", "  LINT_GATES_PATTERN:", "  LINT_GATES_PATTERN_X:"},
		{"gate not always", "    if: " + gateIf + "\n", "    if: ${{ success() }}\n"},
		{"full job without its if", fullIf, ""},
		{"full job with a looser if", fullIf, "    if: github.event_name == 'push' || github.event_name == 'pull_request'\n"},
		{"nightly job without its if", nightlyIf, ""},
		{"nightly job on the full tier's if", nightlyIf, fullIf},
		{"pr job needs a full job", archNeeds, "    name: Architecture Gates\n    needs: [schedule-guard, fips]\n"},
		{"pr job needs a nightly job", archNeeds, "    name: Architecture Gates\n    needs: [schedule-guard, soak]\n"},
		{"gate FULL_TIER flag differs", "          FULL_TIER: " + fullTierEnv, "          FULL_TIER: ${{ github.event_name == 'push' }}"},
		{"gate NIGHTLY flag differs", "          NIGHTLY: " + nightlyTierIf, "          NIGHTLY: ${{ github.event_name == 'schedule' }}"},
		{"gate drops check()", gateCheckFunc, "chk() {"},
		{"workflow CI_FULL_TIER differs", "  CI_FULL_TIER: " + fullTierIf, "  CI_FULL_TIER: ${{ github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full') }}"},
		{"labeled type added back", "types: [opened, synchronize, reopened]", "types: [opened, synchronize, reopened, labeled]"},
		{"gate on a self-hosted label", "    name: CI Gate\n    runs-on: " + ciGateRunner + "\n", "    name: CI Gate\n    runs-on: ci-gate\n"},
		{"deps-check back on the full tier", "env.TOOLCHAIN_IMAGE != '' }}\n        env:\n          IN_IMAGE_NETWORK: bridge\n        run: scripts/in-toolchain-image.sh \"$TOOLCHAIN_IMAGE\" make deps-check\n", "env.TOOLCHAIN_IMAGE != '' && env.CI_FULL_TIER == 'true' }}\n        env:\n          IN_IMAGE_NETWORK: bridge\n        run: scripts/in-toolchain-image.sh \"$TOOLCHAIN_IMAGE\" make deps-check\n"},
		{"gate uses an action", "      - name: Fail closed on any non-success\n", "      - uses: actions/checkout@abc # v7\n      - name: Fail closed on any non-success\n"},
		{"publish-images runs", "    if: ${{ " + publishGuard + " && ", "    if: ${{ "},
		{"publish-images guard ored away", "    if: ${{ " + publishGuard + " && ", "    if: ${{ " + publishGuard + " || "},
		{"publish-images dropped", "  publish-images:\n", "  publish-images-x:\n"},
		{"timeout off its value", "    timeout-minutes: 56 ", "    timeout-minutes: 90 "},
		{"job without a timeout", "    timeout-minutes: 5        # v1.30\n", ""},
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

	const imageCheck = "          check image       \"${{ needs.image.result }}\" code\n"
	for _, tc := range []struct{ name, old, new string }{
		{"job missing from the gate checks", imageCheck, ""},
		{"lint-gates missing from the gate checks", "          check lint-gates  \"${{ needs.lint-gates.result }}\" scoped\n", ""},
		{"job checked twice", imageCheck, imageCheck + imageCheck},
		{"check names another job", `check arch-gates  "${{ needs.arch-gates`, `check arch-gates  "${{ needs.image`},
		{"check names a job outside needs", imageCheck, imageCheck + "          check publish-images \"${{ needs.publish-images.result }}\" pr\n"},
		{"check before check()", "          BAD=0\n", "          BAD=0\n" + imageCheck},
		{"check() defined twice", "      - name: Fail closed on any non-success\n", "      - name: Twice\n        run: |\n          check() { :; }\n      - name: Fail closed on any non-success\n"},
		{"no check()", gateCheckFunc, "chk() {"},
		{"no BAD=0", "          BAD=0\n", ""},
		{"no exit $BAD", "          exit $BAD\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(ci, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			bad, err := gateCheckViolations([]byte(strings.Replace(ci, tc.old, tc.new, 1)))
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

// TestCIGateCheckPassesOnlyExplainedSkips drives the gate's check() as ci.yml
// carries it (v1.30): a skip passes only when the run did not select the
// job's tier, the PR was docs-only (code), no changed file matched
// LINT_GATES_PATTERN (scoped), or the schedule guard proved the tree by a
// named run (any tier but nightly); every other result but success fails.
func TestCIGateCheckPassesOnlyExplainedSkips(t *testing.T) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ciWorkflowFile))), &wf); err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	var fn string
	for _, st := range wf.Jobs[ciGateJob].Steps {
		if def := strings.Index(st.Run, gateCheckFunc); def >= 0 {
			if end := strings.Index(st.Run[def:], "\n}\n"); end >= 0 {
				fn = st.Run[def : def+end+3]
			}
		}
	}
	if fn == "" {
		t.Fatalf("%s: job %s defines no `%s ... }`", ciWorkflowFile, ciGateJob, gateCheckFunc)
	}
	script := fn + "BAD=0\ncheck job \"$RESULT\" \"$TIER\"\nexit $BAD\n"
	// plain is a plain PR's run: no optional tier selected, the guard's `run`.
	plain := map[string]string{"FULL_TIER": "false", "NIGHTLY": "false", "SCHEDULE_GUARD": "run", "PROOF": "", "DOCS_ONLY": "false", "LINT_GATES_SEL": "true"}
	proven := map[string]string{"SCHEDULE_GUARD": "proven", "PROOF": "42"}
	for _, tc := range []struct {
		name, result, tier string
		env                map[string]string
		wantOK             bool
	}{
		{"pr passed", "success", "pr", nil, true},
		{"pr skipped", "skipped", "pr", nil, false},
		{"pr failed", "failure", "pr", nil, false},
		{"full skipped, not selected", "skipped", "full", nil, true},
		{"full skipped, selected", "skipped", "full", map[string]string{"FULL_TIER": "true"}, false},
		{"full failed, not selected", "failure", "full", nil, false},
		{"full cancelled", "cancelled", "full", nil, false}, //nolint:misspell // the forge's result value is spelled "cancelled"
		{"nightly skipped, not selected", "skipped", "nightly", nil, true},
		{"nightly skipped, selected", "skipped", "nightly", map[string]string{"NIGHTLY": "true"}, false},
		{"nightly skipped on a proven tree", "skipped", "nightly", map[string]string{"NIGHTLY": "true", "SCHEDULE_GUARD": "proven", "PROOF": "42"}, false},
		{"code skipped, docs-only", "skipped", "code", map[string]string{"DOCS_ONLY": "true"}, true},
		{"code skipped, not docs-only", "skipped", "code", nil, false},
		{"scoped skipped, no file matched", "skipped", "scoped", map[string]string{"LINT_GATES_SEL": "false"}, true},
		{"scoped skipped, a file matched", "skipped", "scoped", nil, false},
		{"pr skipped on a proven tree", "skipped", "pr", proven, true},
		{"pr skipped, proven without a run", "skipped", "pr", map[string]string{"SCHEDULE_GUARD": "proven"}, false},
		{"empty result", "", "pr", nil, false},
		{"unknown tier skipped", "skipped", "soon", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "RESULT="+tc.result, "TIER="+tc.tier)
			for k, v := range plain {
				if o, ok := tc.env[k]; ok {
					v = o
				}
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("running check(): %v", err)
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("exit ok = %v, want %v; output:\n%s", err == nil, tc.wantOK, out)
			}
		})
	}
}
