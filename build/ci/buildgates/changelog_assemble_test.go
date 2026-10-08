package buildgates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for scripts/changelog-assemble.sh, the step `make release` runs
// before tagging. The release must fold every fragment into the version's
// section exactly once and delete it: a fragment left behind is a missing
// entry, and one folded twice is a duplicate. The tests drive the real script
// on scratch trees.

const assembleVersion = "v9.9.9-alpha"
const assembleDate = "2026-01-02"

// assembleTree writes a CHANGELOG.md and changelog.d/ (with .gitkeep and the
// given fragments) into a fresh directory and returns it.
func assembleTree(t *testing.T, changelog string, fragments map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("CHANGELOG.md", changelog)
	write("changelog.d/.gitkeep", "")
	for name, body := range fragments {
		write(filepath.Join("changelog.d", name), body)
	}
	return dir
}

// runAssemble runs the script in dir and returns its combined output and
// whether it succeeded.
func runAssemble(t *testing.T, dir string, args ...string) (string, bool) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "changelog-assemble.sh")
	if len(args) == 0 {
		args = []string{assembleVersion, assembleDate}
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		return string(out), false
	}
	return string(out), true
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// fragmentNames lists what is left in changelog.d/.
func fragmentNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "changelog.d"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

const assemblePrevious = `## [v0.1.0-alpha] - 2025-01-01

### Added

- OLD-ENTRY shipped in the previous release.
`

const assembleHeader = `# Changelog

Preamble.

## [Unreleased]
`

func TestChangelogAssemble_FoldsEveryEntryExactlyOnce(t *testing.T) {
	changelog := assembleHeader + `
### Fixed

- UNRELEASED-FIX written before fragments were adopted.

` + assemblePrevious
	dir := assembleTree(t, changelog, map[string]string{
		"20-b.md": "### Changed — BREAKING: renamed a thing\n\n- FRAG-B-BREAKING\n\n### Added\n\n- FRAG-B-ADDED\n",
		"10-a.md": "\n### Added\n\n- FRAG-A-ADDED\n  continued line of A\n\n- FRAG-A-SECOND\n\n### Fixed\n\n- FRAG-A-FIX\n",
	})

	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("assembly failed:\n%s", out)
	}
	got := readFile(t, filepath.Join(dir, "CHANGELOG.md"))

	want := assembleHeader + `
## [v9.9.9-alpha] - 2026-01-02

### Fixed

- UNRELEASED-FIX written before fragments were adopted.

- FRAG-A-FIX

### Added

- FRAG-A-ADDED
  continued line of A

- FRAG-A-SECOND

- FRAG-B-ADDED

### Changed — BREAKING: renamed a thing

- FRAG-B-BREAKING

` + assemblePrevious
	if got != want {
		t.Fatalf("assembled CHANGELOG differs.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	for _, marker := range []string{"UNRELEASED-FIX", "FRAG-A-ADDED", "FRAG-A-SECOND", "FRAG-A-FIX", "FRAG-B-ADDED", "FRAG-B-BREAKING", "OLD-ENTRY", "## [v9.9.9-alpha]", "### Added\n\n- FRAG"} {
		if n := strings.Count(got, marker); n != 1 {
			t.Errorf("%q appears %d times, want exactly 1", marker, n)
		}
	}
	if names := fragmentNames(t, dir); len(names) != 1 || names[0] != ".gitkeep" {
		t.Errorf("changelog.d/ after assembly holds %v, want only .gitkeep: a folded fragment must be deleted or the next release folds it again", names)
	}

	// A second run for the same version is a no-op: nothing is folded twice.
	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("re-running for an assembled version failed:\n%s", out)
	}
	if again := readFile(t, filepath.Join(dir, "CHANGELOG.md")); again != got {
		t.Fatalf("re-running changed the CHANGELOG:\n%s", again)
	}
}

func TestChangelogAssemble_RefusesFragmentsLeftOutOfAHandWrittenSection(t *testing.T) {
	changelog := assembleHeader + "\n## [v9.9.9-alpha] - 2026-01-01\n\n### Added\n\n- HAND-WRITTEN\n\n" + assemblePrevious
	dir := assembleTree(t, changelog, map[string]string{"30-c.md": "### Fixed\n\n- WAITING\n"})

	out, ok := runAssemble(t, dir)
	if ok {
		t.Fatalf("assembly succeeded with a fragment waiting behind an existing section; the release would omit it:\n%s", out)
	}
	if !strings.Contains(out, "30-c.md") {
		t.Errorf("the refusal does not name the waiting fragment:\n%s", out)
	}
	if got := readFile(t, filepath.Join(dir, "CHANGELOG.md")); got != changelog {
		t.Errorf("a refused assembly modified CHANGELOG.md")
	}
	if names := fragmentNames(t, dir); len(names) != 2 {
		t.Errorf("a refused assembly deleted fragments: %v", names)
	}
}

func TestChangelogAssemble_HandWrittenSectionWithNoFragmentsStillReleases(t *testing.T) {
	changelog := assembleHeader + "\n## [v9.9.9-alpha] - 2026-01-01\n\n### Added\n\n- HAND-WRITTEN\n\n" + assemblePrevious
	dir := assembleTree(t, changelog, nil)
	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("assembly refused a hand-written section with nothing waiting:\n%s", out)
	}
	if got := readFile(t, filepath.Join(dir, "CHANGELOG.md")); got != changelog {
		t.Errorf("a no-op assembly modified CHANGELOG.md:\n%s", got)
	}
}

// TestChangelogAssemble_RefusesUnreleasedEntriesLeftOutOfAHandWrittenSection
// pins that, with the version section already written and no fragment
// waiting, the script refuses while [Unreleased] still holds entries. A bare
// subsection heading is not an entry and must not block.
func TestChangelogAssemble_RefusesUnreleasedEntriesLeftOutOfAHandWrittenSection(t *testing.T) {
	section := "\n## [v9.9.9-alpha] - 2026-01-01\n\n### Added\n\n- HAND-WRITTEN\n\n" + assemblePrevious
	cases := []struct {
		name       string
		unreleased string
		wantOK     bool
	}{
		{"an entry under a subsection", "\n### Fixed\n\n- STILL-UNRELEASED\n", false},
		{"stray text with no subsection", "\n- STILL-UNRELEASED\n", false},
		{"only an empty subsection heading", "\n### Fixed\n\n", true},
		{"only blank lines", "\n\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changelog := assembleHeader + tc.unreleased + section
			dir := assembleTree(t, changelog, nil)
			out, ok := runAssemble(t, dir)
			if ok != tc.wantOK {
				t.Fatalf("assembly ok = %v, want %v:\n%s", ok, tc.wantOK, out)
			}
			if !ok && !strings.Contains(out, "STILL-UNRELEASED") {
				t.Errorf("the refusal does not quote the entry it would leave out:\n%s", out)
			}
			if got := readFile(t, filepath.Join(dir, "CHANGELOG.md")); got != changelog {
				t.Errorf("assembly against an existing section modified CHANGELOG.md:\n%s", got)
			}
		})
	}
}

func TestChangelogAssemble_RefusesWhatItCannotPlace(t *testing.T) {
	good := assembleHeader + "\n" + assemblePrevious
	cases := []struct {
		name      string
		changelog string
		fragments map[string]string
		args      []string
		mention   string
	}{
		{"text before a subsection", good, map[string]string{"1-x.md": "- ORPHAN\n\n### Added\n\n- OK\n"}, nil, "outside a ### subsection"},
		{"fragment with a version heading", good, map[string]string{"1-x.md": "## [v1.0.0]\n\n### Added\n\n- OK\n"}, nil, "### subsections only"},
		{"orphan text in Unreleased", assembleHeader + "\n- ORPHAN\n\n" + assemblePrevious, map[string]string{"1-x.md": "### Added\n\n- OK\n"}, nil, "outside a ### subsection"},
		{"no Unreleased heading", "# Changelog\n\n" + assemblePrevious, map[string]string{"1-x.md": "### Added\n\n- OK\n"}, nil, "no ## [Unreleased]"},
		{"nothing to release", good, nil, nil, "nothing to release"},
		{"malformed version", good, map[string]string{"1-x.md": "### Added\n\n- OK\n"}, []string{"9.9.9", assembleDate}, "is not vX.Y.Z"},
		{"malformed date", good, map[string]string{"1-x.md": "### Added\n\n- OK\n"}, []string{assembleVersion, "tomorrow"}, "is not YYYY-MM-DD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := assembleTree(t, tc.changelog, tc.fragments)
			before := fragmentNames(t, dir)
			out, ok := runAssemble(t, dir, tc.args...)
			if ok {
				t.Fatalf("assembly succeeded, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.mention) {
				t.Errorf("refusal does not say %q:\n%s", tc.mention, out)
			}
			if got := readFile(t, filepath.Join(dir, "CHANGELOG.md")); got != tc.changelog {
				t.Errorf("a refused assembly modified CHANGELOG.md:\n%s", got)
			}
			if after := fragmentNames(t, dir); len(after) != len(before) {
				t.Errorf("a refused assembly changed changelog.d/: %v -> %v", before, after)
			}
			if left, _ := filepath.Glob(filepath.Join(dir, "CHANGELOG.md.*")); len(left) != 0 {
				t.Errorf("temporary file left behind: %v", left)
			}
		})
	}
}

// gateVersion is one no real CHANGELOG carries, so the release-queue check
// always exercises the fold rather than the "section already exists" no-op.
const gateVersion = "v999.0.0-gate"

// checkReleaseQueue asserts that a tree (CHANGELOG.md plus changelog.d/
// fragments) is in a releasable state. Two states are valid:
//
//   - the queue is empty: no fragment is waiting and [Unreleased] holds no
//     entry, as straight after `make release`. The script must report
//     "nothing to release" and change nothing.
//   - entries are waiting: assembly must succeed, every entry line must
//     appear as many times as before plus once per fragment carrying it, and
//     every fragment must be deleted.
//
// Anything else (a malformed fragment, a missing [Unreleased] heading, a
// whitespace-only fragment) fails.
func checkReleaseQueue(t *testing.T, changelog string, fragments map[string]string) {
	t.Helper()
	for _, p := range releaseQueueProblems(t, changelog, fragments) {
		t.Error(p)
	}
}

// releaseQueueProblems returns what makes the tree unreleasable; none means
// it is in one of the two valid states checkReleaseQueue describes.
func releaseQueueProblems(t *testing.T, changelog string, fragments map[string]string) []string {
	t.Helper()
	dir := assembleTree(t, changelog, fragments)
	out, ok := runAssemble(t, dir, gateVersion, assembleDate)
	if !ok {
		if len(fragments) == 0 && strings.Contains(out, "nothing to release") {
			if got := readFile(t, filepath.Join(dir, "CHANGELOG.md")); got != changelog {
				return []string{"an empty-queue run modified CHANGELOG.md:\n" + got}
			}
			return nil
		}
		return []string{"the release queue does not assemble:\n" + out}
	}
	var problems []string
	got := readFile(t, filepath.Join(dir, "CHANGELOG.md"))
	for name, body := range fragments {
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "### ") {
				continue
			}
			want := strings.Count(changelog, line+"\n")
			for _, other := range fragments {
				want += strings.Count(other, line+"\n")
			}
			if n := strings.Count(got, line+"\n"); n != want {
				problems = append(problems, fmt.Sprintf("%s: line %q appears %d times after assembly, want %d", name, line, n, want))
			}
		}
	}
	if names := fragmentNames(t, dir); len(names) != 1 || names[0] != ".gitkeep" {
		problems = append(problems, fmt.Sprintf("changelog.d/ after assembly holds %v, want only .gitkeep", names))
	}
	return problems
}

// treeFragments reads every changelog.d/*.md under root.
func treeFragments(t *testing.T, root string) map[string]string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "changelog.d", "*.md"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fragments := map[string]string{}
	for _, m := range matches {
		fragments[filepath.Base(m)] = readFile(t, m)
	}
	return fragments
}

// TestChangelogAssemble_RealTree applies checkReleaseQueue to this
// repository's own CHANGELOG.md and changelog.d/: waiting fragments fold in
// exactly once, or, on the release commit itself, the empty queue is accepted.
func TestChangelogAssemble_RealTree(t *testing.T) {
	root := repoRoot(t)
	checkReleaseQueue(t, readFile(t, filepath.Join(root, "CHANGELOG.md")), treeFragments(t, root))
}

// TestChangelogAssemble_RealTreeAfterRelease runs the release assembly on a
// copy of this repository's tree and then applies the same gate to what it
// produced, proving the gate stays green on the commit `make release`
// creates (an emptied [Unreleased] and no fragments).
func TestChangelogAssemble_RealTreeAfterRelease(t *testing.T) {
	root := repoRoot(t)
	dir := assembleTree(t, readFile(t, filepath.Join(root, "CHANGELOG.md")), treeFragments(t, root))
	if out, ok := runAssemble(t, dir); !ok {
		if !strings.Contains(out, "nothing to release") {
			t.Fatalf("assembly of this repository's tree failed:\n%s", out)
		}
	}
	checkReleaseQueue(t, readFile(t, filepath.Join(dir, "CHANGELOG.md")), treeFragments(t, dir))
}

// TestChangelogAssemble_GateAcceptsTheTreeAssemblyProduces pins the
// post-release state on a synthetic tree independent of this repository's
// current queue, and keeps the gate strict about what it must still reject.
func TestChangelogAssemble_GateAcceptsTheTreeAssemblyProduces(t *testing.T) {
	dir := assembleTree(t, assembleHeader+"\n### Fixed\n\n- PENDING\n\n"+assemblePrevious,
		map[string]string{"1-x.md": "### Added\n\n- FRAG\n"})
	if out, ok := runAssemble(t, dir); !ok {
		t.Fatalf("assembly failed:\n%s", out)
	}
	checkReleaseQueue(t, readFile(t, filepath.Join(dir, "CHANGELOG.md")), treeFragments(t, dir))

	// The empty-queue acceptance must not swallow real defects.
	for name, tc := range map[string]struct {
		changelog string
		fragments map[string]string
	}{
		"malformed fragment":    {assembleHeader + "\n" + assemblePrevious, map[string]string{"1-x.md": "- ORPHAN\n"}},
		"whitespace-only":       {assembleHeader + "\n" + assemblePrevious, map[string]string{"1-x.md": "\n\n"}},
		"no Unreleased heading": {"# Changelog\n\n" + assemblePrevious, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if len(releaseQueueProblems(t, tc.changelog, tc.fragments)) == 0 {
				t.Errorf("the gate accepted a tree it must reject")
			}
		})
	}
}
