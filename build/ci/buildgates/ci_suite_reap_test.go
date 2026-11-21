package buildgates

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The scripts that start the integration suites' compose projects. Each
// names its project `project="<prefix>$..."`; a CI job that runs one of them
// must reap that prefix before it starts, or a stack a cancelled run left
// behind keeps its containers and volumes on the runner host.
var suiteScripts = []string{"scripts/integration-test.sh", "scripts/userns-test.sh"}

var (
	suiteProjectRE = regexp.MustCompile(`(?m)^\s*project="([^"$]+)\$`)
	suiteReapRE    = regexp.MustCompile(`scripts/reap-stale-ci-stacks\.sh\s+("?)([^"\s]+)`)
	suiteMakeRE    = regexp.MustCompile(`^(ci-integration|integration-test(-[a-z0-9-]+)?)$`)
)

// suiteMakeTarget reports whether a make target reaches integration-test.sh
// or userns-test.sh: ci-integration and the integration-test targets, but not
// the TPM and arm-trustzone suites, which start no compose project.
func suiteMakeTarget(target string) bool {
	if target == "integration-test-tpm" || target == "integration-test-arm-trustzone" {
		return false
	}
	return suiteMakeRE.MatchString(target)
}

// runsSuite reports whether a step's run text, with the job's env values put
// in for $NAME and ${NAME}, runs a suite script or a make target that does.
func runsSuite(run string, env map[string]string) bool {
	for k, v := range env {
		run = strings.NewReplacer("${"+k+"}", v, "$"+k, v).Replace(run)
	}
	for _, s := range suiteScripts {
		if strings.Contains(run, s) {
			return true
		}
	}
	unquote := strings.NewReplacer(`"`, " ", `'`, " ")
	for line := range strings.SplitSeq(run, "\n") {
		if _, args, ok := strings.Cut(line, "make "); ok {
			if slices.ContainsFunc(strings.Fields(unquote.Replace(args)), suiteMakeTarget) {
				return true
			}
		}
	}
	return false
}

// suiteProjectPrefixes reads each suite script's project name prefix.
func suiteProjectPrefixes(scripts map[string]string) ([]string, error) {
	var out []string
	for _, name := range suiteScripts {
		m := suiteProjectRE.FindStringSubmatch(scripts[name])
		if m == nil {
			return nil, fmt.Errorf("%s: no project=\"<prefix>$...\" line", name)
		}
		out = append(out, m[1])
	}
	return out, nil
}

// suiteReapViolations lists each job of the workflow that runs a suite but
// reaps no literal prefix of a suite's project name. It fails when no job
// runs a suite, so it cannot pass on a workflow it did not read.
func suiteReapViolations(src []byte, scripts map[string]string) ([]string, error) {
	prefixes, err := suiteProjectPrefixes(scripts)
	if err != nil {
		return nil, err
	}
	var wf struct {
		Jobs map[string]struct {
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	var bad []string
	suites := 0
	for name, job := range wf.Jobs {
		runs := false
		var reaped []string
		for _, st := range job.Steps {
			runs = runs || runsSuite(st.Run, job.Env)
			for _, m := range suiteReapRE.FindAllStringSubmatch(st.Run, -1) {
				if m[1] == "" && !strings.HasPrefix(m[2], "$") {
					reaped = append(reaped, m[2])
				}
			}
		}
		if !runs {
			continue
		}
		suites++
		for _, p := range prefixes {
			if !slices.ContainsFunc(reaped, func(r string) bool { return strings.HasPrefix(p, r) }) {
				bad = append(bad, fmt.Sprintf("job %s runs an integration suite but reaps no prefix of its compose project %s*", name, p))
			}
		}
	}
	if suites == 0 {
		return nil, fmt.Errorf("no job runs %s", strings.Join(suiteScripts, " or "))
	}
	sort.Strings(bad)
	return bad, nil
}

func readSuiteScripts(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, s := range suiteScripts {
		out[s] = readFile(t, filepath.Join(repoRoot(t), s))
	}
	return out
}

func TestCISuiteJobsReapTheSuiteProjects(t *testing.T) {
	src := readFile(t, filepath.Join(repoRoot(t), ciWorkflowFile))
	bad, err := suiteReapViolations([]byte(src), readSuiteScripts(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestCISuiteReap_RefusesWhatItMustRefuse(t *testing.T) {
	scripts := map[string]string{
		"scripts/integration-test.sh": "project=\"go-enclave-it-$pkg-$(date +%s)\"\n",
		"scripts/userns-test.sh":      "project=\"go-enclave-userns-$(date +%s)\"\n",
	}
	full := "          scripts/reap-stale-ci-stacks.sh \"$CI_STACK_PREFIX\"\n" +
		"          scripts/reap-stale-ci-stacks.sh go-enclave-it\n" +
		"          scripts/reap-stale-ci-stacks.sh go-enclave-userns-\n"
	wf := func(reap, run string) string {
		return "jobs:\n  it:\n    env:\n      SOAK_TARGET: ci-integration\n    steps:\n" +
			"      - run: |\n" + reap +
			"      - run: " + run + "\n"
	}
	cases := []struct {
		name, src string
		want      int
	}{
		{"all three reaped", wf(full, `make "$SOAK_TARGET"`), 0},
		{"only the CI prefix", wf("          scripts/reap-stale-ci-stacks.sh \"$CI_STACK_PREFIX\"\n", "make ci-integration"), 2},
		{"userns prefix missing", wf("          scripts/reap-stale-ci-stacks.sh go-enclave-it\n", "make integration-test-userns"), 1},
		{"soak target through env", wf("          scripts/reap-stale-ci-stacks.sh \"$CI_STACK_PREFIX\"\n", `make "$SOAK_TARGET"`), 2},
		{"script run directly", wf("          true\n", "sh scripts/userns-test.sh"), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad, err := suiteReapViolations([]byte(c.src), scripts)
			if err != nil {
				t.Fatal(err)
			}
			if len(bad) != c.want {
				t.Fatalf("got %d findings, want %d: %q", len(bad), c.want, bad)
			}
		})
	}
	if _, err := suiteReapViolations([]byte("jobs:\n  x:\n    steps:\n      - run: make integration-test-tpm\n"), scripts); err == nil {
		t.Error("a workflow with no suite job passed")
	}
}
