package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Every `uses:` in every workflow must name a 40-hex commit, with the human
// tag in a trailing comment:
//
//	uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
//
// A tag can be moved by its owner and a branch is re-resolved on every run,
// and these jobs hold write-scoped tokens. A one-line ref change inside a large
// mechanical diff is what review misses, so a gate enforces it.
//
// The gate parses the YAML rather than grepping it. A regex misses spellings
// Actions accepts (flow mapping, quoted key, anchor, alias, block scalar) and
// fires on `uses:` inside block-scalar prose such as `run: |` scripts. After
// parsing, a `uses` mapping key is structurally distinct from that text.
// Every value the parser produces is either resolved to a ref or reported as
// an error; nothing is silently dropped.

// pinnedRef is anything up to the last `@`, then exactly 40 lowercase hex.
// Lowercase is required so one commit has one spelling in a diff.
var pinnedRef = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

// Discovery floors: every other assertion runs in a loop over discovered
// files, and an empty loop passes. They sit below the current counts so that
// deleting a step is not a failure, and catch a broken walk, not a single
// dropped ref (resolveRef failing loudly catches that).
const (
	minWorkflowFiles = 2
	minActionRefs    = 12
)

// workflowDirs covers both forges the repository is mirrored to. A missing
// directory is not an error; the floors notice if both are missing.
var workflowDirs = []string{
	filepath.Join(".github", "workflows"),
	filepath.Join(".gitea", "workflows"),
}

// actionRef is one discovered `uses:` value with its location. err is set when
// the value could not be resolved; it is kept rather than dropped so the gate
// fails on it.
type actionRef struct {
	file    string // repo-relative
	line    int
	value   string // the resolved `uses:` value, e.g. "actions/checkout@<sha>"
	comment string // trailing `#` comment, trimmed; "" when absent
	err     error  // non-nil when the value could not be resolved to a string
}

func TestActionRefsArePinnedToCommitShas(t *testing.T) {
	root := repoRoot(t)
	files := workflowFiles(t, root)

	// Floor 1: discovery found workflow files at all.
	if len(files) < minWorkflowFiles {
		t.Fatalf("discovery floor: found %d workflow file(s) under %v, want at least %d.\n"+
			"Either the workflows were moved and this gate is now checking nothing, or a\n"+
			"file was deleted. Do NOT lower the floor to make this pass — the floor is the\n"+
			"only thing here that fails when the check has no work to do.",
			len(files), workflowDirs, minWorkflowFiles)
	}

	var refs []actionRef
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		got, err := extractRefs(f, src)
		if err != nil {
			t.Fatalf("parse %s: %v\n(a workflow that does not parse is a broken workflow — fix the YAML)", f, err)
		}
		refs = append(refs, got...)
	}

	// Floor 2: those files actually yielded refs.
	if len(refs) < minActionRefs {
		t.Fatalf("discovery floor: found %d action ref(s) across %d workflow file(s), want at least %d.\n"+
			"The files parsed but almost nothing came out, which means the extraction broke,\n"+
			"not that the repo stopped using actions.",
			len(refs), len(files), minActionRefs)
	}

	for _, r := range refs {
		t.Run(fmt.Sprintf("%s:%d", r.file, r.line), func(t *testing.T) {
			if err := validateRef(r); err != nil {
				t.Error(err)
			}
		})
	}

	t.Logf("checked %d action ref(s) across %d workflow file(s)", len(refs), len(files))
}

// validateRef applies the pinning policy to one discovered ref, returning nil
// when it is acceptable and a descriptive error otherwise.
func validateRef(r actionRef) error {
	// An unresolved value might be unpinned; "don't know" must read as "no".
	if r.err != nil {
		return fmt.Errorf("could not resolve the `uses:` value at %s:%d: %w\n\n"+
			"This gate refuses to pass a ref it cannot read. Either write the ref as a\n"+
			"plain scalar (`uses: owner/repo@<40-hex> # v1`) or extend resolveRef to\n"+
			"understand this shape — but do not let it through unchecked.",
			r.file, r.line, r.err)
	}

	// A local action is this repository's own code at this commit.
	if strings.HasPrefix(r.value, "./") {
		return nil
	}

	// Container actions are rejected outright, digests included: none is
	// approved for this repository. If one ever is, the exception belongs
	// here and must accept only an immutable digest, never a tag.
	if strings.HasPrefix(r.value, "docker://") {
		return fmt.Errorf("container action ref %q at %s:%d is not permitted\n\n"+
			"An image tag is mutable in exactly the way this gate exists to prevent:\n"+
			"`docker://alpine:latest` resolves to whatever was pushed last. No container\n"+
			"action is approved for this repository, and adopting one is an owner\n"+
			"decision, not a workflow edit.\n\n"+
			"If one IS approved, extend validateRef to accept an immutable digest\n"+
			"(`docker://<image>@sha256:<64-hex>`) and nothing else — do not reintroduce a\n"+
			"skip, and do not accept a tag.",
			r.value, r.file, r.line)
	}

	if !pinnedRef.MatchString(r.value) {
		return fmt.Errorf("unpinned action ref %q at %s:%d\n\n"+
			"Every `uses:` must name a 40-hex commit. A tag can be moved by its owner\n"+
			"and a branch (`@master`) is re-resolved on every run, so neither records\n"+
			"what this repo actually executed. These jobs hold write-scoped tokens.\n\n"+
			"To fix, resolve the sha yourself — do not copy one from an issue or a\n"+
			"sibling repo:\n\n"+
			"    git ls-remote --tags https://github.com/<owner>/<repo>\n\n"+
			"and take the `^{}` PEELED line when the tag is annotated. An annotated\n"+
			"tag's unpeeled sha is the tag OBJECT, and a run that checks it out fails.\n"+
			"Confirm before committing:\n\n"+
			"    git fetch --depth 1 https://github.com/<owner>/<repo> <sha>\n"+
			"    # then: git cat-file -t <sha>  ->  must print `commit`, never `tag`\n\n"+
			"Then write the version you resolved as a trailing comment:\n\n"+
			"    uses: <owner>/<repo>@<40-hex> # v1.2.3",
			r.value, r.file, r.line)
	}

	if r.comment == "" {
		return fmt.Errorf("action ref %q at %s:%d is pinned but carries no trailing version comment\n\n"+
			"Write it as `uses: %s # v1.2.3`. A bare sha is correct and unmaintainable:\n"+
			"it tells the next maintainer neither what version is in use nor what a\n"+
			"bump would be moving from, so in practice it never gets bumped.",
			r.value, r.file, r.line, r.value)
	}

	return nil
}

// repoRoot walks up from the working directory to the first directory that
// holds a workflow directory, and fails the test if there is none.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		for _, wd := range workflowDirs {
			if fi, err := os.Stat(filepath.Join(dir, wd)); err == nil && fi.IsDir() {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no repository root found above %q: none of %v exists anywhere up the tree.\n"+
				"This gate cannot check what it cannot find; that is a failure, not a skip.",
				dir, workflowDirs)
		}
		dir = parent
	}
}

// workflowFiles lists every workflow in every known workflow directory.
func workflowFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, wd := range workflowDirs {
		abs := filepath.Join(root, wd)
		entries, err := os.ReadDir(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue // the floors catch "neither exists"
			}
			t.Fatalf("read %s: %v", wd, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if ext := filepath.Ext(e.Name()); ext != ".yml" && ext != ".yaml" {
				continue
			}
			out = append(out, filepath.Join(wd, e.Name()))
		}
	}
	return out
}

// extractRefs returns every `uses:` mapping value in one workflow document.
// It matches a `uses` key at any depth rather than following jobs->steps,
// since reusable workflows put it on the job; over-reach fails loudly, while
// under-reach would leave a ref unchecked.
func extractRefs(file string, src []byte) ([]actionRef, error) {
	// ParseComments keeps the `# v6` tokens commentFor needs; without it the
	// parser discards them and every pin would look uncommented.
	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(src), "\n")

	var refs []actionRef
	for _, doc := range f.Docs {
		if doc.Body == nil {
			continue
		}
		// Collect anchors first: an alias's definition may sit anywhere,
		// including under a key that is not `uses`.
		anchors := map[string]ast.Node{}
		ast.Walk(&anchorVisitor{anchors: anchors}, doc.Body)

		v := &usesVisitor{file: file, lines: lines, anchors: anchors}
		ast.Walk(v, doc.Body)
		refs = append(refs, v.refs...)
	}
	return refs, nil
}

type anchorVisitor struct{ anchors map[string]ast.Node }

func (a *anchorVisitor) Visit(n ast.Node) ast.Visitor {
	if an, ok := n.(*ast.AnchorNode); ok && an.Name != nil {
		a.anchors[an.Name.GetToken().Value] = an.Value
	}
	return a
}

type usesVisitor struct {
	file    string
	lines   []string
	anchors map[string]ast.Node
	refs    []actionRef
}

func (v *usesVisitor) Visit(n ast.Node) ast.Visitor {
	mv, ok := n.(*ast.MappingValueNode)
	if !ok {
		return v
	}
	if mv.Key.GetToken().Value != "uses" {
		return v
	}
	value, err := resolveRef(mv.Value, v.anchors, 0)
	v.refs = append(v.refs, actionRef{
		file:    v.file,
		line:    mv.Value.GetToken().Position.Line,
		value:   value,
		comment: v.commentFor(mv),
		err:     err,
	})
	return v
}

// maxAliasDepth bounds alias chasing so a cyclic anchor cannot hang the gate.
const maxAliasDepth = 10

// resolveRef reduces a `uses:` value node to the string Actions would see.
// Every scalar-carrying shape is handled; anything else returns an error, so
// an unrecognized value fails the gate instead of vanishing from its results.
func resolveRef(n ast.Node, anchors map[string]ast.Node, depth int) (string, error) {
	if depth > maxAliasDepth {
		return "", fmt.Errorf("alias chain deeper than %d — cyclic anchor?", maxAliasDepth)
	}
	switch t := n.(type) {
	case *ast.StringNode:
		// Plain, single-quoted and double-quoted all land here; .Value is the
		// unquoted content.
		return t.Value, nil

	case *ast.AnchorNode:
		// `uses: &checkout actions/checkout@v6`: the ref is the anchored value.
		return resolveRef(t.Value, anchors, depth+1)

	case *ast.AliasNode:
		// `uses: *checkout`: resolve against the definition.
		name := t.Value.GetToken().Value
		target, ok := anchors[name]
		if !ok {
			return "", fmt.Errorf("alias *%s has no anchor definition in this document", name)
		}
		return resolveRef(target, anchors, depth+1)

	case *ast.LiteralNode:
		// `uses: |` / `uses: >-`: the content, minus the block's newline.
		if t.Value == nil {
			return "", fmt.Errorf("empty block scalar")
		}
		return strings.TrimSpace(t.Value.Value), nil

	case nil:
		return "", fmt.Errorf("missing value")
	}
	return "", fmt.Errorf("unsupported `uses:` value of type %T (%s)", n, n.Type())
}

// commentFor recovers the trailing `# v6`. The parser attaches it to the value
// or mapping node, except for a flow mapping (`- {uses: x@sha} # v6`), where
// it goes to the enclosing sequence entry; there it falls back to reading the
// value's source line for a `#`.
func (v *usesVisitor) commentFor(mv *ast.MappingValueNode) string {
	if c := mv.Value.GetComment(); c != nil {
		if s := strings.TrimSpace(c.GetToken().Value); s != "" {
			return s
		}
	}
	if c := mv.GetComment(); c != nil {
		if s := strings.TrimSpace(c.GetToken().Value); s != "" {
			return s
		}
	}
	line := mv.Value.GetToken().Position.Line
	if line >= 1 && line <= len(v.lines) {
		if _, after, found := strings.Cut(v.lines[line-1], "#"); found {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// Each spelling Actions accepts must yield exactly one ref, fail when mutable,
// and pass when pinned. The pinned control keeps a gate that rejects the
// spelling outright from satisfying the mutable test; the exactly-one check
// catches a spelling that is silently dropped.

const (
	pinned  = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
	mutable = "actions/checkout@v6"
)

// spelling renders a minimal YAML document containing exactly one `uses:` in
// one of the forms GitHub Actions accepts.
type spelling struct {
	name string
	// render returns YAML holding one `uses:` of ref with a trailing version
	// comment, so only the ref's pinning is under test.
	render func(ref string) string
}

var spellings = []spelling{
	{"plain", func(r string) string {
		return "steps:\n  - uses: " + r + " # v6\n"
	}},
	{"double-quoted", func(r string) string {
		return "steps:\n  - uses: \"" + r + "\" # v6\n"
	}},
	{"single-quoted", func(r string) string {
		return "steps:\n  - uses: '" + r + "' # v6\n"
	}},
	{"flow-mapping", func(r string) string {
		return "steps:\n  - {uses: " + r + "} # v6\n"
	}},
	{"quoted-key", func(r string) string {
		return "steps:\n  - \"uses\": " + r + " # v6\n"
	}},
	{"anchor-on-value", func(r string) string {
		return "steps:\n  - uses: &c " + r + " # v6\n"
	}},
	{"alias-to-anchor-defined-elsewhere", func(r string) string {
		// The anchor sits under a key that is not `uses`.
		return "base: &c " + r + "\nsteps:\n  - uses: *c # v6\n"
	}},
	{"block-scalar-folded", func(r string) string {
		return "steps:\n  - uses: >- # v6\n      " + r + "\n"
	}},
	{"block-scalar-literal", func(r string) string {
		return "steps:\n  - uses: | # v6\n      " + r + "\n"
	}},
}

func TestEverySpellingYieldsExactlyOneRef(t *testing.T) {
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			refs, err := extractRefs("fixture.yml", []byte(sp.render(pinned)))
			if err != nil {
				t.Fatalf("parse: %v\nyaml:\n%s", err, sp.render(pinned))
			}
			if len(refs) != 1 {
				t.Fatalf("got %d ref(s), want exactly 1 — a dropped ref is the round-1 defect.\nyaml:\n%s",
					len(refs), sp.render(pinned))
			}
			if refs[0].err != nil {
				t.Fatalf("ref did not resolve: %v\nyaml:\n%s", refs[0].err, sp.render(pinned))
			}
			if refs[0].value != pinned {
				t.Errorf("resolved %q, want %q", refs[0].value, pinned)
			}
		})
	}
}

func TestMutableRefFailsInEverySpelling(t *testing.T) {
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			src := sp.render(mutable)
			refs, err := extractRefs("fixture.yml", []byte(src))
			if err != nil {
				t.Fatalf("parse: %v\nyaml:\n%s", err, src)
			}
			if len(refs) != 1 {
				t.Fatalf("got %d ref(s), want exactly 1 — a mutable ref that is never "+
					"collected cannot fail, which is how this defect hid.\nyaml:\n%s", len(refs), src)
			}
			err = validateRef(refs[0])
			if err == nil {
				t.Fatalf("validateRef accepted the MUTABLE ref %q — the gate is not gating.\nyaml:\n%s",
					mutable, src)
			}
			if !strings.Contains(err.Error(), "unpinned action ref") {
				t.Errorf("failed for the wrong reason:\n%v", err)
			}
		})
	}
}

// TestPinnedRefPassesInEverySpelling is the control for the mutable test.
func TestPinnedRefPassesInEverySpelling(t *testing.T) {
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			src := sp.render(pinned)
			refs, err := extractRefs("fixture.yml", []byte(src))
			if err != nil {
				t.Fatalf("parse: %v\nyaml:\n%s", err, src)
			}
			if len(refs) != 1 {
				t.Fatalf("got %d ref(s), want exactly 1\nyaml:\n%s", len(refs), src)
			}
			if err := validateRef(refs[0]); err != nil {
				t.Errorf("validateRef rejected a correctly pinned ref:\n%v\nyaml:\n%s", err, src)
			}
		})
	}
}

// TestContainerRefsAreRejected pins that every `docker://` ref fails, digest
// included.
func TestContainerRefsAreRejected(t *testing.T) {
	for _, ref := range []string{
		"docker://alpine:latest",
		"docker://alpine:3.19",
		"docker://ghcr.io/owner/image:v1.2.3",
		"docker://alpine",
		// Even a digest: no container action is approved.
		"docker://alpine@sha256:beefcafe00000000000000000000000000000000000000000000000000000000",
	} {
		t.Run(ref, func(t *testing.T) {
			err := validateRef(actionRef{file: "fixture.yml", line: 1, value: ref, comment: "v1"})
			if err == nil {
				t.Fatalf("validateRef accepted container ref %q — a skip or a pass here "+
					"admits a mutable executable dependency", ref)
			}
			if !strings.Contains(err.Error(), "container action ref") {
				t.Errorf("failed for the wrong reason:\n%v", err)
			}
		})
	}
}

// TestUnresolvableValuesFailExplicitly pins that a value the gate cannot
// reduce to a ref is reported and fails, never dropped.
func TestUnresolvableValuesFailExplicitly(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"alias with no anchor", "steps:\n  - uses: *nosuch # v6\n"},
		{"sequence value", "steps:\n  - uses: [a, b] # v6\n"},
		{"mapping value", "steps:\n  - uses: {a: b} # v6\n"},
		{"null value", "steps:\n  - uses: # v6\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs, err := extractRefs("fixture.yml", []byte(tc.yaml))
			if err != nil {
				// The parser itself may reject an alias with no anchor; that
				// is also a loud failure.
				return
			}
			if len(refs) != 1 {
				t.Fatalf("got %d ref(s), want exactly 1 — an unreadable value must still "+
					"be REPORTED, not dropped\nyaml:\n%s", len(refs), tc.yaml)
			}
			if refs[0].err == nil {
				t.Fatalf("value resolved to %q with no error; this gate must not guess\nyaml:\n%s",
					refs[0].value, tc.yaml)
			}
			if err := validateRef(refs[0]); err == nil {
				t.Fatalf("validateRef passed an unresolvable value\nyaml:\n%s", tc.yaml)
			}
		})
	}
}

// TestProseContainingUsesIsNotARef pins that `uses:` inside a block scalar is
// not collected as a ref.
func TestProseContainingUsesIsNotARef(t *testing.T) {
	const src = `steps:
  - name: a script that merely contains the token
    run: |
      echo "uses: not/a-step@v9"
      echo "uses: another/fake@master"
  - name: an agent prompt, as review workflows in this fleet carry
    with:
      prompt: |
        Check that every ` + "`uses:`" + ` line is pinned, e.g. uses: foo/bar@v1
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
`
	refs, err := extractRefs("fixture.yml", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("got %d ref(s), want exactly 1 — the real step only; prose mentioning "+
			"`uses:` must not be collected", len(refs))
	}
	if err := validateRef(refs[0]); err != nil {
		t.Errorf("the one real ref should pass: %v", err)
	}
}

// TestLocalActionRefsAreAccepted pins that `./` refs pass unpinned.
func TestLocalActionRefsAreAccepted(t *testing.T) {
	refs, err := extractRefs("fixture.yml", []byte("steps:\n  - uses: ./.github/actions/local\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("got %d ref(s), want 1", len(refs))
	}
	if err := validateRef(refs[0]); err != nil {
		t.Errorf("local action ref rejected: %v", err)
	}
}
