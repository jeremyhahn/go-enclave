package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// mergeGuardStems are the workflows that guard what reaches main: the review
// gate, the signature check, automerge and the release. A pull
// request that edits one must take a review round, so code-review.yml's scope
// guard must name each one that exists in PROTECTED or match it by a word of
// PROTECTED_WORDS; otherwise a signed same-repository pull request could
// weaken it with no review.
var mergeGuardStems = []string{"signatures", "code-review", "automerge", "release"}

// reviewGuardLists returns PROTECTED and PROTECTED_WORDS from the scope
// guard's script in code-review.yml.
func reviewGuardLists(t *testing.T, src string) (protected, words []string) {
	t.Helper()
	quoted := regexp.MustCompile(`"([^"]*)"`)
	read := func(re string) []string {
		m := regexp.MustCompile(re).FindAllStringSubmatch(src, -1)
		if len(m) != 1 {
			t.Fatalf("code-review.yml: %s found %d times, want 1", re, len(m))
		}
		var out []string
		for _, q := range quoted.FindAllStringSubmatch(m[0][1], -1) {
			out = append(out, strings.ToLower(q[1]))
		}
		return out
	}
	return read(`(?m)^\s+PROTECTED = \[([^\]]*)\]$`), read(`(?m)^\s+PROTECTED_WORDS = \(([^)]*)\)$`)
}

// guarded reports whether the scope guard takes a review round for STEM, as
// its check does: the stem is in PROTECTED or contains a PROTECTED_WORDS word.
func guarded(stem string, protected, words []string) bool {
	for _, p := range protected {
		if p == stem {
			return true
		}
	}
	for _, w := range words {
		if strings.Contains(stem, w) {
			return true
		}
	}
	return false
}

func TestReviewGuard_MergeGuardWorkflowsAreProtected(t *testing.T) {
	root := repoRoot(t)
	protected, words := reviewGuardLists(t, readFile(t, filepath.Join(root, ".github/workflows/code-review.yml")))
	seen := 0
	for _, stem := range mergeGuardStems {
		found := false
		for _, ext := range []string{".yml", ".yaml"} {
			if _, err := os.Stat(filepath.Join(root, ".github/workflows", stem+ext)); err == nil {
				found = true
			}
		}
		if !found {
			continue
		}
		seen++
		if !guarded(stem, protected, words) {
			t.Errorf("%s: a merge-guarding workflow neither in code-review.yml's PROTECTED nor matched by PROTECTED_WORDS; a change to it would skip the review", stem)
		}
	}
	if seen == 0 {
		t.Fatal("no merge-guarding workflow found under .github/workflows; the check read nothing")
	}
}

func TestReviewGuard_GuardedMatchesTheScript(t *testing.T) {
	protected := []string{"code-review"}
	words := []string{"release"}
	for _, tc := range []struct {
		stem string
		want bool
	}{
		{"code-review", true},
		{"release", true},
		{"pre-release", true},
		{"signatures", false},
	} {
		if got := guarded(tc.stem, protected, words); got != tc.want {
			t.Errorf("guarded(%q) = %v, want %v", tc.stem, got, tc.want)
		}
	}
}
