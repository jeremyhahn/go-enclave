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
// instruction files (CLAUDE.md, AGENTS.md, .claude/, .serena/project.yml), which scaffold §7 has the
// publish step strip from the public tree. They are tracked, reported by this
// gate as strip-at-publish, and their content is not scanned, because it is
// not published.
//
// Classes reported:
//
//   - lab-address: an address anywhere in the 192.168/16 private block. It is
//     unreachable for public readers and publishes the network layout. The
//     whole /16 is matched because the fleet spans many /24s in it and this
//     repository uses no RFC 1918 literal as an opaque test address.
//   - lab-host: a fleet hostname or the fleet's private DNS zones.
//   - owner-path: a path under the owner's home directory or the lab's NFS
//     mount.
//   - internal-file: a tracked file that exists for the fleet's agents and is
//     not stripped at publication: agent tool state, local Makefile overrides,
//     and the retired `task-worker.yml` workflow.
//
// Reported, not refused: strip-at-publish files (CLAUDE.md, AGENTS.md,
// .claude/, .serena/project.yml), logged by the main test so the publish step's input is visible.
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

// leakPatterns is the content rule set, and the one place in this repository
// the fleet's identifiers are written down. A new fleet host or zone is one
// entry here plus one planted sample in TestReleasability_PlantedValuesAreCaught.
// The expressions are written so their own source text does not match them;
// where that cannot be relied on, the line carries a waiver.
var leakPatterns = []leakPattern{
	{
		class:    classLabAddress,
		expr:     regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
		guidance: "use an RFC 5737 documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or a name under example.com",
	},
	{
		class:    classLabHost,
		expr:     regexp.MustCompile(`(?i)\b(?:vstation|dellemc|corertr|coreswt|rack\d?swt|houseswt|officeswt|raritan|eaton)-\d{2}\b`),
		guidance: "name the role, not the machine: \"a factory runner\", \"an 8-core host\", ci-runner-01",
	},
	{
		class:    classLabHost,
		expr:     regexp.MustCompile(`(?i)\bgodlike\b`), // lab-string-ok: the hostname this rule exists to find
		guidance: "name the role, not the machine: gpu-host.internal, \"the GPU host\"",
	},
	{
		class:    classLabHost,
		expr:     regexp.MustCompile(`(?i)\b(?:jeremyhahn|tangerine)\.internal\b`),
		guidance: "the fleet's private DNS zones resolve nowhere else; use a name under example.com",
	},
	{
		class:    classOwnerPath,
		expr:     regexp.MustCompile(`/home/jhahn\b|/mnt/vstation`), // lab-string-ok: the path prefixes this rule exists to find
		guidance: "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
	},
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
	{path: ".serena/project.yml", guidance: "Serena project file (#140): stripped from the public tree at publish, like CLAUDE.md"},
}

var internalFileRules = []internalFileRule{
	{name: ".serena", dir: true, guidance: "local agent tool state: untrack it, it is in .gitignore"},
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

	findings, err := scanTree(root, files)
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

func TestReleasability_PlantedValuesAreCaught(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		class leakClass
		match string
	}{
		{"forge address in a link", "[v0.1.0]: http://" + plant("192.168", ".101.91") + ":3001/x/y", classLabAddress, plant("192.168", ".101.91")},
		{"management subnet", "ipmi at " + plant("192.168", ".50.102"), classLabAddress, plant("192.168", ".50.102")},
		{"cluster subnet", plant("192.168", ".200.20"), classLabAddress, plant("192.168", ".200.20")},
		{"measurement host", "// Measured on " + plant("vstation", "-04") + " at load ~26", classLabHost, plant("vstation", "-04")},
		{"runner host, shouted", "RUNNER=" + plant("DELLEMC", "-01"), classLabHost, plant("DELLEMC", "-01")},
		{"core switch", plant("coreswt", "-01") + " Eth1/35", classLabHost, plant("coreswt", "-01")},
		{"gpu host", "ssh " + plant("god", "like"), classLabHost, plant("god", "like")},
		{"private zone", "mgmt." + plant("jeremyhahn", ".internal"), classLabHost, plant("jeremyhahn", ".internal")},
		{"owner home", "cd " + plant("/home/", "jhahn") + "/sources/x", classOwnerPath, plant("/home/", "jhahn")},
		{"nfs mount", plant("/mnt/", "vstation") + "01/src", classOwnerPath, plant("/mnt/", "vstation")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanContent("f.md", []byte("prose\n"+tc.line+"\nmore prose\n"))
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
	clean := []string{
		"server at 192.0.2.10, fallback 198.51.100.7 and 203.0.113.254",
		"quicbaas.example.com:8443 and gpu-host.internal",
		"a factory runner at load average ~26",
		"version 192.168 of nothing", // not an address
		"/home/agent/go/bin and /var/lib/enclave",
		"vstation without a number is a word, not a host",
		"see CLAUDE.md in the handbook", // a mention is not a tracked file
	}
	for _, line := range clean {
		if got := scanContent("f.md", []byte(line)); len(got) != 0 {
			t.Errorf("false positive on %q: %v", line, got)
		}
	}
}

func TestReleasability_WaiverNeedsAReasonAndAdjacency(t *testing.T) {
	addr := plant("192.168", ".101.7")
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
			if got := scanContent("f", []byte(tc.content)); len(got) != tc.want {
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
	for _, p := range []string{"CLAUDE.md", "providertest/CLAUDE.md", "AGENTS.md", ".claude/settings.json", ".claude/agents/x.md", ".serena/project.yml"} {
		if _, strip := stripAtPublish(p); !strip {
			t.Errorf("%s is not reported as strip-at-publish", p)
		}
		if f, bad := internalFile(p); bad {
			t.Errorf("%s is refused as internal although the publish step strips it: %v", p, f)
		}
	}
}

// End to end, against a real index: the planted address in a tracked file
// fails the gate, the same address in an untracked file does not, a tracked
// file deleted from the working tree is skipped rather than erroring, and a
// tracked CLAUDE.md, stripped at publish, is neither refused nor scanned.
func TestReleasability_PlantedTreeFailsTheGate(t *testing.T) {
	root := t.TempDir()
	addr := plant("192.168", ".101.50")
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
	if want := []string{"CLAUDE.md", "README.md", "bin.dat", "docs/deploy.md", "gone.md", "local.mk"}; strings.Join(files, ",") != strings.Join(want, ",") {
		t.Fatalf("tracked files = %v, want %v", files, want)
	}
	findings, err := scanTree(root, files)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, fmt.Sprintf("%s:%d:%s:%s", f.path, f.line, f.class, f.match))
	}
	want := []string{
		"docs/deploy.md:1:" + string(classLabAddress) + ":" + addr,
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

// scanTree applies every rule to the named files, read relative to root. A
// tracked file missing from the working tree (a deletion in progress) and a
// binary file are skipped; a symlink is judged by its target text, since that
// text is what git stores and publishes.
func scanTree(root string, files []string) ([]leakFinding, error) {
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
		findings = append(findings, scanContent(name, content)...)
	}
	return findings, nil
}

// internalFile reports whether a tracked path is one that must not be
// published at all.
func internalFile(name string) (leakFinding, bool) {
	if _, stripped := stripAtPublish(name); stripped {
		return leakFinding{}, false // .serena/project.yml inside the refused .serena/
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

// scanContent applies every content rule to every line not covered by a
// waiver on that line or the one immediately above it.
func scanContent(name string, content []byte) []leakFinding {
	lines := strings.Split(string(content), "\n")
	var findings []leakFinding
	for i, line := range lines {
		if waived(line) || (i > 0 && waived(lines[i-1])) {
			continue
		}
		for _, p := range leakPatterns {
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
