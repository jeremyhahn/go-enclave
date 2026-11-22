package buildgates

import (
	"strings"
	"testing"
)

// ciPythonSuites are the CI template's own regression suites the repository
// carries: Go does not discover them, so a make target runs them and
// lint-gates depends on it.
var ciPythonSuites = []string{
	"testdata/ci-mask-lan-tests.py",
	"testdata/job-output-handoff-tests.py",
	// The runner selector (the preflight step that picks a hosted or an
	// overflow runner): its fork isolation, overflow and lookup failures run
	// against a stub Actions API.
	"testdata/runner-select-tests.py",
}

// TestCIPythonSuitesShip fails when a suite lint-gates must run is not in the
// tree.
func TestCIPythonSuitesShip(t *testing.T) {
	for _, suite := range ciPythonSuites {
		if src := readRepoFile(t, suite); !strings.Contains(src, "ci.yml") {
			t.Errorf("%s does not read ci.yml", suite)
		}
	}
}

// makeRule returns the prerequisites and the recipe of target in mk, and
// whether mk defines it.
func makeRule(mk, target string) (prereqs []string, recipe string, ok bool) {
	_, rest, ok := strings.Cut(mk, "\n"+target+":")
	if !ok {
		return nil, "", false
	}
	head, body, _ := strings.Cut(rest, "\n")
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "\t") {
			break
		}
		lines = append(lines, line)
	}
	return strings.Fields(head), strings.Join(lines, "\n"), true
}

// ciPythonSuiteViolations lists what is wrong with how lint-gates runs the
// template's Python suites: one of its prerequisites must run each suite
// under `python3 -I`.
func ciPythonSuiteViolations(mk string) []string {
	prereqs, _, ok := makeRule(mk, "lint-gates")
	if !ok {
		return []string{"no lint-gates target"}
	}
	var bad []string
	for _, suite := range ciPythonSuites {
		run := "python3 -I " + suite
		found := false
		for _, p := range prereqs {
			if _, recipe, ok := makeRule(mk, p); ok && strings.Contains(recipe, run) {
				found = true
				break
			}
		}
		if !found {
			bad = append(bad, "no lint-gates prerequisite runs `"+run+"`")
		}
	}
	return bad
}

func TestLintGatesRunsTheCIPythonSuites(t *testing.T) {
	mk := readRepoFile(t, "Makefile")
	for _, b := range ciPythonSuiteViolations(mk) {
		t.Errorf("Makefile: %s", b)
	}
}

// TestLintGatesRunsTheCIPythonSuites_RefusesWhatItMustRefuse pins the check.
func TestLintGatesRunsTheCIPythonSuites_RefusesWhatItMustRefuse(t *testing.T) {
	good := "\nlint-gates: check-a check-py\n\t@echo ok\n\ncheck-py:\n" +
		"\t@python3 -I " + ciPythonSuites[0] + "\n" +
		"\t@python3 -I " + ciPythonSuites[1] + "\n" +
		"\t@python3 -I " + ciPythonSuites[2] + "\n\ncheck-a:\n\t@true\n"
	if b := ciPythonSuiteViolations(good); len(b) != 0 {
		t.Fatalf("a good Makefile is refused: %v", b)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"target not in lint-gates", "check-a check-py\n", "check-a\n"},
		{"a suite dropped", "\t@python3 -I " + ciPythonSuites[1] + "\n", ""},
		{"the runner-select suite dropped", "\t@python3 -I " + ciPythonSuites[2] + "\n", ""},
		{"without -I", "python3 -I " + ciPythonSuites[0], "python3 " + ciPythonSuites[0]},
		{"no lint-gates", "\nlint-gates:", "\nlint-all:"},
	} {
		if len(ciPythonSuiteViolations(strings.Replace(good, tc.old, tc.new, 1))) == 0 {
			t.Errorf("%s: no violation; want a refusal", tc.name)
		}
	}
}
