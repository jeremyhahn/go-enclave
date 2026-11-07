package buildgates

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"
)

// The public-releasability gate: no tracked file may name the private
// development fleet, and no tracked file may exist only for the fleet's own
// agents, except the agent-instruction files the publish step strips.
//
// The public tree is byte-identical to the release tag, and the module zip
// consumers hash is that same tree, so nothing can be scrubbed from what is
// published: the scrub has to happen in the source, before tagging, and a gate
// keeps the next commit from undoing it. The one exception is the set of agent
// instruction files (CLAUDE.md, AGENTS.md, .claude/), which scaffold §7 has the
// publish step strip from the public tree. They are tracked, reported by this
// gate as strip-at-publish, and their content is not scanned, because it is
// not published.
//
// Classes reported:
//
//   - lab-address: an address anywhere in the 192.168/16 private block. It is
//     unreachable for public readers and publishes the network layout. The
//     whole /16 is matched because a site network can span many /24s and this
//     repository uses no RFC 1918 literal as an opaque test address.
//   - lab-host: a site hostname or a private DNS zone.
//   - owner-path: a path under a developer's home directory or a site mount.
//   - internal-file: a tracked file that exists for the fleet's agents and is
//     not stripped at publication: agent tool state, local Makefile overrides,
//     and the retired `task-worker.yml` workflow.
//
// Reported, not refused: strip-at-publish files (CLAUDE.md, AGENTS.md,
// .claude/), logged by the main test so the publish step's input is visible.
//
// The lab-address rule is generic and built in. The lab-host and owner-path
// rules are site-specific, so they do not live in this public source: the
// file the RELEASABILITY_PATTERNS environment variable names supplies them,
// one `<class><TAB><regex>` rule per line, `#` comments and blank lines
// skipped (see loadSitePatterns). Unset, only the built-in rules run and the
// main test logs that it ran without the site rules.
//
// To fix a finding, in order of preference:
//
//   - Use a documentation value: RFC 5737 addresses (192.0.2.0/24,
//     198.51.100.0/24, 203.0.113.0/24), RFC 2606 names (example.com,
//     *.example, *.invalid), or the role instead of the machine ("a factory
//     runner", "an 8-core host").
//   - Move the value out of the tree (a CI repository variable, the private
//     infra repository).
//   - If the value is the point, waive the line in place: the text
//     `lab-string-ok: <reason>` on the offending line or the line immediately
//     above it, in any comment syntax. An empty reason is not a waiver. There
//     is no file-level allow list.
//
// The file list is the git index (a file is published because it is tracked);
// content is read from the working tree, so a local edit is judged before it
// is committed. Matching is textual, so it covers every file type and works on
// a tree that does not compile.
//
// Test names share the `TestReleasability` prefix, which `make
// check-releasability` selects and `make check-buildgates` skips.

// leakClass says what a finding leaks.
type leakClass string

const (
	classLabAddress   leakClass = "lab-address"
	classLabHost      leakClass = "lab-host"
	classOwnerPath    leakClass = "owner-path"
	classInternalFile leakClass = "internal-file"
)

// waiverPrefix marks a line whose lab value is the point of the line. The text
// after it is the reason and must not be empty.
const waiverPrefix = "lab-string-ok:"

// leakPattern is one content rule. expr matches the VALUE, not the whole line,
// so the report quotes exactly what has to change.
type leakPattern struct {
	class    leakClass
	expr     *regexp.Regexp
	guidance string
}

// leakPatterns is the built-in content rule set: generic rules only. The
// site-specific rules (host names, private DNS zones, home and mount paths)
// live outside the tree, in the file RELEASABILITY_PATTERNS names, so this
// public source names no site host; see loadSitePatterns. The expressions are
// written so their own source text does not match them.
var leakPatterns = []leakPattern{
	{
		class:    classLabAddress,
		expr:     regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
		guidance: classGuidance[classLabAddress],
	},
}

// patternsEnv names the environment variable that points at the site pattern
// file. Unset or empty, only the built-in rules run.
const patternsEnv = "RELEASABILITY_PATTERNS"

// classGuidance is the fix each content class gets in a finding; a site rule
// takes its class's text.
var classGuidance = map[leakClass]string{
	classLabAddress: "use an RFC 5737 documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or a name under example.com",
	classLabHost:    "name the role, not the machine (\"a factory runner\", \"an 8-core host\", ci-runner-01, gpu-host.internal); a private DNS zone resolves nowhere else, use a name under example.com",
	classOwnerPath:  "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
}

var (
	errUnknownClass = errors.New("unknown class: want lab-address, lab-host or owner-path")
	errMissingField = errors.New("want <class><TAB><regex>")
)

// patternFileError reports a site pattern file that cannot be used, with the
// 1-based line at fault (0 when the file itself cannot be read).
type patternFileError struct {
	path string
	line int
	err  error
}

func (e *patternFileError) Error() string {
	if e.line == 0 {
		return fmt.Sprintf("site patterns %s: %v", e.path, e.err)
	}
	return fmt.Sprintf("site patterns %s:%d: %v", e.path, e.line, e.err)
}

func (e *patternFileError) Unwrap() error { return e.err }

// loadSitePatterns reads a site pattern file: one rule per line,
// `<class><TAB><regex>`, the class one of lab-address, lab-host or owner-path.
// Blank lines and lines starting with `#` are skipped. Any other malformed
// line is an error, never a dropped rule.
func loadSitePatterns(path string) ([]leakPattern, error) {
	content, err := os.ReadFile(path) //nolint:gosec // the operator names the file
	if err != nil {
		return nil, &patternFileError{path: path, err: err}
	}
	var rules []leakPattern
	for i, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		class, expr, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		class, expr = strings.TrimSpace(class), strings.TrimSpace(expr)
		if !ok || class == "" || expr == "" {
			return nil, &patternFileError{path: path, line: i + 1, err: errMissingField}
		}
		guidance, known := classGuidance[leakClass(class)]
		if !known {
			return nil, &patternFileError{path: path, line: i + 1, err: errUnknownClass}
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, &patternFileError{path: path, line: i + 1, err: err}
		}
		rules = append(rules, leakPattern{class: leakClass(class), expr: re, guidance: guidance})
	}
	return rules, nil
}

// contentRules is the built-in rule set plus, when path is not empty, the
// site pattern file's rules.
func contentRules(path string) ([]leakPattern, error) {
	rules := append([]leakPattern(nil), leakPatterns...)
	if path == "" {
		return rules, nil
	}
	site, err := loadSitePatterns(path)
	if err != nil {
		return nil, err
	}
	return append(rules, site...), nil
}

// internalFileRule marks a tracked path that must not be published at all. A
// rule matches the path's basename, or, for a directory, any path component.
type internalFileRule struct {
	name string
	dir  bool
	// path, when set, matches that one repository-relative path instead.
	path     string
	guidance string
}

// stripAtPublishRules are the agent-instruction files the publish step removes
// from the public tree (scaffold §7). They may be tracked; they are reported.
var stripAtPublishRules = []internalFileRule{
	{name: "CLAUDE.md", guidance: "agent instructions: stripped from the public tree at publish (scaffold §7)"},
	{name: "AGENTS.md", guidance: "agent instructions: stripped from the public tree at publish (scaffold §7)"},
	{name: ".claude", dir: true, guidance: "agent configuration: stripped from the public tree at publish (scaffold §7)"},
}

var internalFileRules = []internalFileRule{
	{name: ".serena", dir: true, guidance: "local agent tool state: untrack it, it is in .gitignore"},
	{name: "scheduled_tasks.lock", guidance: "agent scheduler state: untrack it, it is in .gitignore"},
	{name: "lane-records", dir: true, guidance: "agent run records: untrack them, they are in .gitignore"},
	{name: "local.mk", guidance: "per-machine Makefile overrides: untrack it, it is in .gitignore"},
	{name: "task-worker.yml", guidance: "the retired internal fabric workflow (handbook sdlc.md §8); it has no place in a public tree"},
}

// leakFinding is one thing that must change before this tree can be published.
type leakFinding struct {
	path     string // slash-separated, relative to the repository root
	line     int    // 1-based; 0 for a finding about the file itself
	class    leakClass
	match    string
	guidance string
}

// String renders a finding in the file:line: form editors can jump to.
func (f leakFinding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %q -- %s", f.path, f.line, f.class, f.match, f.guidance)
}

// binarySniff is how much of a file is examined for a NUL byte before deciding
// it is binary (git's own test and threshold).
const binarySniff = 8000

// Discovery floor: an empty listing would report a clean tree. The floor sits
// well below the current count (~70) so deleting files is not a failure; the
// anchors prove the listing is this repository's.
const minTrackedFiles = 40

var trackedAnchors = []string{"go.mod", "VERSION", "CHANGELOG.md", "README.md", "Makefile"}

func TestReleasability_TrackedTreeIsPubliclyReleasable(t *testing.T) {
	root := repoRoot(t)
	files, err := trackedFiles(root)
	if err != nil {
		t.Fatalf("list tracked files: %v\n"+
			"This gate reads the git index because the index is what gets published. "+
			"Without one it cannot say anything, and that is a failure, not a skip.", err)
	}
	if len(files) < minTrackedFiles {
		t.Fatalf("discovery floor: git lists %d tracked file(s) under %s, want at least %d.\n"+
			"The listing collapsed, so every check below would pass on nothing. Do NOT "+
			"lower the floor to make this pass.", len(files), root, minTrackedFiles)
	}
	listed := make(map[string]bool, len(files))
	for _, f := range files {
		listed[f] = true
	}
	for _, a := range trackedAnchors {
		if !listed[a] {
			t.Fatalf("discovery anchor %q is not in the index at %s: this is not the "+
				"go-enclave tree, or the listing is wrong", a, root)
		}
	}

	site := os.Getenv(patternsEnv)
	rules, err := contentRules(site)
	if err != nil {
		t.Fatalf("load the site rules %s names: %v", patternsEnv, err)
	}
	if site == "" {
		t.Logf("%s is unset: only the generic built-in rules ran; set it to the site pattern file for the site-specific rules", patternsEnv)
	}
	findings, err := scanTree(root, files, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d finding(s) in tracked files -- this tree ships publicly:\n\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(&b, "%s\n", f)
		}
		b.WriteString("\nReplace the value, move it to CI or infra configuration, or -- if the value\n")
		b.WriteString("is the point -- waive the line with a `" + waiverPrefix + " <reason>` comment.\n")
		b.WriteString("Rules and rationale: build/ci/buildgates/releasability_test.go.")
		t.Error(b.String())
	}
	for _, name := range files {
		if f, ok := stripAtPublish(name); ok {
			t.Logf("strip-at-publish: %s -- %s", f.path, f.guidance)
		}
	}
	t.Logf("scanned %d tracked file(s)", len(files))
}

// plant assembles a lab value from pieces, so this file's own source never
// contains the literal it tests for and does not trip the gate it defines.
func plant(parts ...string) string { return strings.Join(parts, "") }

// sitePatterns is a site pattern file in the RELEASABILITY_PATTERNS format,
// written with generic stand-ins: the tests exercise the loader and the rules
// it yields without this file naming any real site.
const sitePatterns = "# site rules for the tests: generic stand-ins only\n" +
	"\n" +
	"lab-host\t(?i)\\b(?:buildhost|edgeswitch)-\\d{2}\\b\n" +
	"lab-host\t(?i)\\bgpuhost\\b\n" +
	"lab-host\t(?i)\\bsite\\.internal\\b\n" +
	"owner-path\t/home/owner\\b\n"

// writePatterns writes content to a pattern file in a temporary directory and
// returns its path.
func writePatterns(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "patterns")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// siteRules is the built-in rule set plus the rules sitePatterns adds, loaded
// the way the tracked-tree test loads the file RELEASABILITY_PATTERNS names.
func siteRules(t *testing.T) []leakPattern {
	t.Helper()
	rules, err := contentRules(writePatterns(t, sitePatterns))
	if err != nil {
		t.Fatalf("load the test site patterns: %v", err)
	}
	return rules
}

func TestReleasability_PlantedValuesAreCaught(t *testing.T) {
	rules := siteRules(t)
	cases := []struct {
		name  string
		line  string
		class leakClass
		match string
	}{
		{"forge address in a link", "[v0.1.0]: http://" + plant("192.168", ".1.91") + ":3001/x/y", classLabAddress, plant("192.168", ".1.91")},
		{"management subnet", "ipmi at " + plant("192.168", ".0.102"), classLabAddress, plant("192.168", ".0.102")},
		{"cluster subnet", plant("192.168", ".1.20"), classLabAddress, plant("192.168", ".1.20")},
		{"measurement host", "// Measured on buildhost-04 at load ~26", classLabHost, "buildhost-04"},
		{"runner host, shouted", "RUNNER=BUILDHOST-01", classLabHost, "BUILDHOST-01"},
		{"edge switch", "edgeswitch-01 Eth1/35", classLabHost, "edgeswitch-01"},
		{"gpu host", "ssh gpuhost", classLabHost, "gpuhost"},
		{"private zone", "mgmt.site.internal", classLabHost, "site.internal"},
		{"owner home", "cd /home/owner/sources/x", classOwnerPath, "/home/owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanContent("f.md", []byte("prose\n"+tc.line+"\nmore prose\n"), rules)
			if len(got) != 1 {
				t.Fatalf("want exactly one finding in %q, got %d: %v", tc.line, len(got), got)
			}
			f := got[0]
			if f.class != tc.class || f.match != tc.match || f.line != 2 || f.path != "f.md" {
				t.Errorf("got %v, want [%s] %q at f.md:2", f, tc.class, tc.match)
			}
		})
	}
}

// TestReleasability_DocumentationValuesPass pins that the documentation values
// the gate recommends do not fire.
func TestReleasability_DocumentationValuesPass(t *testing.T) {
	rules := siteRules(t)
	clean := []string{
		"server at 192.0.2.10, fallback 198.51.100.7 and 203.0.113.254",
		"quicbaas.example.com:8443 and gpu-host.internal",
		"a factory runner at load average ~26",
		"version 192.168 of nothing", // not an address
		"/home/agent/go/bin and /var/lib/enclave",
		"buildhost without a number is a word, not a host",
		"see CLAUDE.md in the handbook", // a mention is not a tracked file
	}
	for _, line := range clean {
		if got := scanContent("f.md", []byte(line), rules); len(got) != 0 {
			t.Errorf("false positive on %q: %v", line, got)
		}
	}
}

// A valid site pattern file adds its rules to the built-ins, each with its
// class's guidance; without it, the built-ins do not see a site host.
func TestReleasability_SitePatternsAddRules(t *testing.T) {
	site, err := loadSitePatterns(writePatterns(t, sitePatterns))
	if err != nil {
		t.Fatalf("loadSitePatterns: %v", err)
	}
	wantClasses := []leakClass{classLabHost, classLabHost, classLabHost, classOwnerPath}
	if len(site) != len(wantClasses) {
		t.Fatalf("got %d rule(s), want %d: %v", len(site), len(wantClasses), site)
	}
	for i, r := range site {
		if r.class != wantClasses[i] || r.guidance == "" || r.expr == nil {
			t.Errorf("rule %d = %+v, want class %s with guidance", i, r, wantClasses[i])
		}
	}
	line := []byte("ssh gpuhost")
	if got := scanContent("f", line, leakPatterns); len(got) != 0 {
		t.Errorf("built-in rules alone matched a site host: %v", got)
	}
	if got := scanContent("f", line, siteRules(t)); len(got) != 1 {
		t.Errorf("built-ins plus site rules: got %d finding(s), want 1: %v", len(got), got)
	}
}

func TestReleasability_SitePatternsSkipBlankLinesAndComments(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"blank, comment and indented comment", "\n# a comment\n   \n  # indented\nlab-host\t\\bgpuhost\\b\n\n", 1},
		{"only comments", "# nothing here\n\n", 0},
		{"a hash inside a rule is part of it", "lab-host\t\\bgpuhost#\\d\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadSitePatterns(writePatterns(t, tc.content))
			if err != nil {
				t.Fatalf("loadSitePatterns: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d rule(s), want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

// A malformed rule is an error naming the file and the line, never a rule
// silently dropped: a dropped rule is a site value the gate stops seeing.
func TestReleasability_SitePatternErrorsNameFileAndLine(t *testing.T) {
	cases := []struct {
		name    string
		content string
		line    int
		cause   error // nil: the cause is a regexp syntax error
	}{
		{"unknown class", "# rules\nlab-printer\t\\bx\\b\n", 2, errUnknownClass},
		{"internal-file is not a content class", "internal-file\tx\n", 1, errUnknownClass},
		{"missing tab and regex", "lab-host\n", 1, errMissingField},
		{"empty regex", "\nlab-host\t  \n", 2, errMissingField},
		{"empty class", "\t\\bx\\b\n", 1, errMissingField},
		{"invalid regex", "lab-host\t\\bok\\b\nowner-path\t(unclosed\n", 2, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writePatterns(t, tc.content)
			got, err := loadSitePatterns(p)
			var pe *patternFileError
			if !errors.As(err, &pe) {
				t.Fatalf("loadSitePatterns = %v, %v; want a *patternFileError", got, err)
			}
			if pe.path != p || pe.line != tc.line {
				t.Errorf("error at %s:%d, want %s:%d", pe.path, pe.line, p, tc.line)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Errorf("cause = %v, want %v", pe.err, tc.cause)
			}
			var se *syntax.Error
			if tc.cause == nil && !errors.As(err, &se) {
				t.Errorf("cause = %v, want a *syntax.Error", pe.err)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "absent")
		_, err := loadSitePatterns(p)
		var pe *patternFileError
		if !errors.As(err, &pe) || pe.path != p || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("loadSitePatterns on a missing file = %v; want a *patternFileError wrapping os.ErrNotExist", err)
		}
	})
}

// An unset or empty RELEASABILITY_PATTERNS means the built-in rules only; set,
// it adds the file's rules.
func TestReleasability_UnsetPatternsVariableMeansBuiltinsOnly(t *testing.T) {
	t.Setenv(patternsEnv, "")
	rules, err := contentRules(os.Getenv(patternsEnv))
	if err != nil {
		t.Fatalf("contentRules with %s unset: %v", patternsEnv, err)
	}
	if len(rules) != len(leakPatterns) {
		t.Errorf("%s unset: got %d rule(s), want the %d built-in(s)", patternsEnv, len(rules), len(leakPatterns))
	}
	t.Setenv(patternsEnv, writePatterns(t, sitePatterns))
	rules, err = contentRules(os.Getenv(patternsEnv))
	if err != nil {
		t.Fatalf("contentRules with %s set: %v", patternsEnv, err)
	}
	if len(rules) != len(leakPatterns)+4 {
		t.Errorf("%s set: got %d rule(s), want %d", patternsEnv, len(rules), len(leakPatterns)+4)
	}
}

func TestReleasability_WaiverNeedsAReasonAndAdjacency(t *testing.T) {
	addr := plant("192.168", ".1.7")
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"same line with reason", addr + " // " + waiverPrefix + " benchmark provenance", 0},
		{"line above with reason", "<!-- " + waiverPrefix + " provenance -->\n" + addr, 0},
		{"reason ending at a comment closer", "/* " + waiverPrefix + " provenance */ " + addr, 0},
		{"no reason", addr + " // " + waiverPrefix, 1},
		{"only a comment closer", "<!-- " + waiverPrefix + " -->\n" + addr, 1},
		{"two lines above", "# " + waiverPrefix + " provenance\n\n" + addr, 1},
		{"waiver below does not reach up", addr + "\n# " + waiverPrefix + " provenance", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanContent("f", []byte(tc.content), leakPatterns); len(got) != tc.want {
				t.Errorf("got %d finding(s), want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

func TestReleasability_InternalFilesAreRefused(t *testing.T) {
	refused := []string{
		".serena/memories/notes.md",
		".serena/project.local.yml",
		"sub/.serena/project.yml",
		".serena/project.yml",
		"scheduled_tasks.lock",
		"sub/scheduled_tasks.lock",
		"lane-records/x.env",
		"sub/lane-records/run.json",
		"local.mk",
		".github/workflows/task-worker.yml",
		".gitea/workflows/task-worker.yml",
	}
	for _, p := range refused {
		if _, bad := internalFile(p); !bad {
			t.Errorf("%s is tracked-but-internal and was not refused", p)
		}
	}
	allowed := []string{
		"README.md",
		"docs/claude.md",
		"docs/lane-records.md",
		"scheduled_tasks.lock.md",
		"CLAUDE.md.example",
		".github/workflows/ci.yml",
		"build/ci/buildgates/doc.go",
	}
	for _, p := range allowed {
		if f, bad := internalFile(p); bad {
			t.Errorf("%s refused as internal: %v", p, f)
		}
		if f, strip := stripAtPublish(p); strip {
			t.Errorf("%s reported as strip-at-publish: %v", p, f)
		}
	}
}

// The agent-instruction files are reported for stripping, not refused.
func TestReleasability_AgentInstructionsAreStrippedAtPublish(t *testing.T) {
	for _, p := range []string{"CLAUDE.md", "providertest/CLAUDE.md", "AGENTS.md", ".claude/settings.json", ".claude/agents/x.md"} {
		if _, strip := stripAtPublish(p); !strip {
			t.Errorf("%s is not reported as strip-at-publish", p)
		}
		if f, bad := internalFile(p); bad {
			t.Errorf("%s is refused as internal although the publish step strips it: %v", p, f)
		}
	}
}

// End to end, against a real index: the planted address in a tracked file,
// and a site host the site pattern file names, fail the gate, the same address in an untracked file does not, a tracked
// file deleted from the working tree is skipped rather than erroring, and a
// tracked CLAUDE.md, stripped at publish, is neither refused nor scanned.
func TestReleasability_PlantedTreeFailsTheGate(t *testing.T) {
	root := t.TempDir()
	rules := siteRules(t)
	addr := plant("192.168", ".0.50")
	write := func(name, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init", "-q")
	write("README.md", "clean\n")
	write("docs/deploy.md", "clone from http://"+addr+":3001/x\n")
	write("CLAUDE.md", "notes on "+addr+"\n")
	write("docs/runner.md", "ssh gpuhost, then cd /home/owner/src\n")
	write("local.mk", "X=1\n")
	write("gone.md", "tracked, then deleted from the working tree\n")
	write("bin.dat", "\x00"+addr)
	git("add", ".")
	write("scratch.md", addr+"\n") // untracked
	if err := os.Remove(filepath.Join(root, "gone.md")); err != nil {
		t.Fatal(err)
	}

	files, err := trackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CLAUDE.md", "README.md", "bin.dat", "docs/deploy.md", "docs/runner.md", "gone.md", "local.mk"}; strings.Join(files, ",") != strings.Join(want, ",") {
		t.Fatalf("tracked files = %v, want %v", files, want)
	}
	findings, err := scanTree(root, files, rules)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, fmt.Sprintf("%s:%d:%s:%s", f.path, f.line, f.class, f.match))
	}
	want := []string{
		"docs/deploy.md:1:" + string(classLabAddress) + ":" + addr,
		"docs/runner.md:1:" + string(classLabHost) + ":gpuhost",
		"docs/runner.md:1:" + string(classOwnerPath) + ":/home/owner",
		"local.mk:0:" + string(classInternalFile) + ":local.mk",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A directory that is not a repository must be an error, never an empty and
// therefore clean listing.
func TestReleasability_NoIndexIsAnError(t *testing.T) {
	root := t.TempDir()
	// GIT_CEILING_DIRECTORIES stops git from walking up into whatever
	// repository happens to contain the temp dir.
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
	files, err := trackedFiles(root)
	var le *listError
	if !errors.As(err, &le) {
		t.Fatalf("trackedFiles on a non-repository = %v, %v; want a *listError", files, err)
	}
}

// listError reports that the git index could not be read.
type listError struct {
	root   string
	stderr string
	err    error
}

func (e *listError) Error() string {
	return fmt.Sprintf("git ls-files in %s: %v: %s", e.root, e.err, e.stderr)
}

func (e *listError) Unwrap() error { return e.err }

// trackedFiles lists the files in the git index at root, slash-separated,
// sorted and relative to it.
func trackedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &listError{root: root, stderr: strings.TrimSpace(stderr.String()), err: err}
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// scanTree applies the file rules and the content rules to the named files, read relative to root. A
// tracked file missing from the working tree (a deletion in progress) and a
// binary file are skipped; a symlink is judged by its target text, since that
// text is what git stores and publishes.
func scanTree(root string, files []string, rules []leakPattern) ([]leakFinding, error) {
	var findings []leakFinding
	for _, name := range files {
		if _, stripped := stripAtPublish(name); stripped {
			continue // not published, so neither refused nor scanned
		}
		if f, bad := internalFile(name); bad {
			findings = append(findings, f)
		}
		p := filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var content []byte
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return nil, err
			}
			content = []byte(target)
		case info.Mode().IsRegular():
			content, err = os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			if bytes.IndexByte(content[:min(len(content), binarySniff)], 0) >= 0 {
				continue
			}
		default:
			// A submodule gitlink or anything else with no content here.
			continue
		}
		findings = append(findings, scanContent(name, content, rules)...)
	}
	return findings, nil
}

// internalFile reports whether a tracked path is one that must not be
// published at all.
func internalFile(name string) (leakFinding, bool) {
	if _, stripped := stripAtPublish(name); stripped {
		return leakFinding{}, false
	}
	return matchFileRule(name, internalFileRules)
}

// stripAtPublish reports whether a tracked path is an agent-instruction file
// the publish step strips, so it is neither refused nor scanned.
func stripAtPublish(name string) (leakFinding, bool) {
	return matchFileRule(name, stripAtPublishRules)
}

func matchFileRule(name string, rules []internalFileRule) (leakFinding, bool) {
	segments := strings.Split(name, "/")
	base := path.Base(name)
	for _, r := range rules {
		hit := base == r.name
		switch {
		case r.path != "":
			hit = name == r.path
		case r.dir:
			hit = false
			for _, s := range segments[:len(segments)-1] {
				if s == r.name {
					hit = true
				}
			}
		}
		if hit {
			return leakFinding{path: name, class: classInternalFile, match: r.name + r.path, guidance: r.guidance}, true
		}
	}
	return leakFinding{}, false
}

// scanContent applies every rule in rules to every line not covered by a
// waiver on that line or the one immediately above it.
func scanContent(name string, content []byte, rules []leakPattern) []leakFinding {
	lines := strings.Split(string(content), "\n")
	var findings []leakFinding
	for i, line := range lines {
		if waived(line) || (i > 0 && waived(lines[i-1])) {
			continue
		}
		for _, p := range rules {
			for _, m := range p.expr.FindAllString(line, -1) {
				findings = append(findings, leakFinding{
					path: name, line: i + 1, class: p.class, match: m, guidance: p.guidance,
				})
			}
		}
	}
	return findings
}

// waived reports whether a line carries a waiver with a non-empty reason.
func waived(line string) bool {
	idx := strings.Index(line, waiverPrefix)
	if idx < 0 {
		return false
	}
	reason := strings.TrimSpace(line[idx+len(waiverPrefix):])
	for _, closer := range []string{"-->", "*/"} {
		reason = strings.TrimSpace(strings.TrimSuffix(reason, closer))
	}
	return reason != ""
}
