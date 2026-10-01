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
// WHY A TEST AND NOT A REVIEW (#70). A tag is a ref its owner can move, and
// `@master` is worse — a BRANCH, re-resolved on every run, so a nightly job
// holding a write-scoped token that uploads SARIF executes whatever upstream
// merged that day. Nobody here reviewed it and no commit here records it.
//
// The pin alone is not the fix, which is the whole reason this file exists. A
// sibling repo re-pinned the identical line FOUR times; every regression came
// in as collateral in a commit whose real payload was something else — a fleet
// rollout of a workflow template that replaced a pinned sha with the tag it was
// cut from. Four human reviewers read those diffs and none caught it, because
// a one-line ref change inside a large mechanical rollout is exactly the shape
// review is worst at. What finally caught it was a gate.
//
// WHY THIS PARSES THE YAML INSTEAD OF GREPPING IT. Both directions bite:
//
//   - A regex over `uses:` MISSES spellings Actions accepts — a flow mapping
//     (`- {uses: foo/bar@sha}`), a quoted key (`"uses": foo/bar@sha`), an
//     anchor on the value (`uses: &c foo/bar@sha`), an alias (`uses: *c`), and
//     a block scalar. Each one is an unpinned ref that a line-oriented check
//     reports as green, which is the worst shape a gate can take.
//   - A regex also CRIES WOLF, because `uses:` is an ordinary word inside a
//     block scalar. A `run: |` script, or the embedded agent prompt that
//     review workflows in this fleet carry, contains the token without any
//     step existing. A gate that fails on prose gets muted, and a muted gate
//     is not a gate.
//
// Going through the parser closes both at once, and not by being cleverer:
// after parsing, a `uses` KEY in a mapping is a structurally different object
// from the characters "uses:" inside a string, so neither case needs handling.
//
// NOTHING IS EVER SILENTLY DROPPED (review round 1). An earlier draft read the
// value only when it was a plain *ast.StringNode and ignored every other node
// type. That is the same defect as the regex, wearing a parser: `uses: &c
// actions/checkout@v6` is an AnchorNode, `uses: *c` is an AliasNode and a
// block scalar is a LiteralNode, so all three vanished from the results and
// the remaining refs passed. Worse, the discovery floor cannot catch it —
// dropping one ref left 14, still above the floor of 12. So resolveRef now
// handles every spelling that carries a scalar and returns an ERROR for
// anything it does not understand, and an unresolvable value FAILS the gate
// instead of disappearing from it.

// A pinned ref: anything up to the last `@`, then exactly 40 lowercase hex.
//
// Lowercase is required rather than merely conventional. Git and every forge
// emit lowercase, so a mixed-case sha is a hand-typed one; more to the point,
// allowing both spellings means the same commit has two representations and a
// human diffing "did this pin change?" can be shown two strings that differ
// and mean the same thing.
var pinnedRef = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

// The trailing comment must name something a human can act on. We do not try
// to validate that it IS the tag the sha came from — nothing offline can know
// that, and a check that cannot fail honestly should not pretend to. We
// require only that the comment is non-empty, because its job is to make the
// pin bumpable: a bare 40-hex ref with nothing beside it tells the next
// maintainer neither what version they are on nor what they would be
// upgrading from.

// Discovery floors. Every other assertion in this file sits inside a loop over
// discovered files, and an empty loop passes. If the workflow directory is
// renamed, the walk breaks, or the extension filter stops matching, all those
// assertions would report success while checking nothing. These two floors are
// the only statements here that fail when the check finds NOTHING to do.
//
// They are floors, not a census: below the current counts (2 files, 15 refs)
// so that legitimately deleting a step or a job is not a gate failure, and far
// enough above zero that a collapsed discovery cannot slip under them.
//
// The floors are a backstop against a BROKEN WALK, and deliberately not the
// mechanism that catches a dropped ref — a floor with slack in it cannot be,
// which is exactly how round 1's silent drop got past. Resolution failing
// loudly is what catches that; see resolveRef.
const (
	minWorkflowFiles = 2
	minActionRefs    = 12
)

// Both forges. This fleet mirrors repositories between Gitea and GitHub, and a
// repo that grows a `.gitea/workflows/` later must not silently acquire an
// unchecked second set of actions. Scanning a directory that does not exist is
// not an error — the floors above are what notice if BOTH are missing.
var workflowDirs = []string{
	filepath.Join(".github", "workflows"),
	filepath.Join(".gitea", "workflows"),
}

// actionRef is one discovered `uses:` value with enough provenance to write a
// failure message someone can act on without opening the file.
//
// err carries a value the parser produced but this gate could not reduce to a
// ref. It is a FIELD rather than a discard because the alternative — returning
// only the refs that happened to be understood — is the round-1 defect.
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

// validateRef applies the pinning policy to one discovered ref. It returns nil
// when the ref is acceptable and a descriptive error otherwise.
//
// Split out of the test loop so the policy can be exercised directly by the
// regression tests below, in every spelling, without a workflow file on disk.
func validateRef(r actionRef) error {
	// A value the parser produced but we could not reduce to a ref. Fail —
	// never skip. An unrecognised shape is the one case where we genuinely do
	// not know whether the ref is pinned, and "don't know" must read as "no".
	if r.err != nil {
		return fmt.Errorf("could not resolve the `uses:` value at %s:%d: %w\n\n"+
			"This gate refuses to pass a ref it cannot read. Either write the ref as a\n"+
			"plain scalar (`uses: owner/repo@<40-hex> # v1`) or extend resolveRef to\n"+
			"understand this shape — but do not let it through unchecked.",
			r.file, r.line, r.err)
	}

	// A local action (`./.github/actions/x`) is this repository's own code at
	// this commit — there is no upstream ref to pin, and no third party who
	// could move it.
	if strings.HasPrefix(r.value, "./") {
		return nil
	}

	// A container action is a DIFFERENT supply chain, and this repo has no
	// approved policy for one.
	//
	// Round 1 had this as a test skip, which was wrong twice over: `docker://`
	// covers `docker://alpine:latest`, a mutable executable dependency with a
	// tag that moves exactly like the action tags this gate exists to reject,
	// and a skip renders green. A gate that reports success on the case it was
	// pointed at is the failure mode the handbook's prohibition on skip guards
	// is about.
	//
	// So: rejected outright, not digest-excepted. Allowing `@sha256:<digest>`
	// would be defensible on the same logic that makes a commit sha
	// acceptable, but no container action is in use here and approving a new
	// class of executable dependency is the owner's call, not this gate's. If
	// one is ever approved, the exception belongs HERE, validating an
	// immutable digest — never a tag.
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

// repoRoot walks up from the test's working directory to the directory that
// holds the workflows. It is derived rather than hardcoded as "../.." so that
// the gate keeps working if this package is moved, and so a failure to find
// the root is a loud error instead of a silent scan of an empty path.
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
				continue // a forge this repo does not mirror to; the floors catch "neither exists"
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
//
// The walk looks for a mapping KEY named `uses` at any depth rather than
// following the jobs->steps path, because the exact shape varies (reusable
// workflows put `uses:` on the job, steps put it on the step) and because a
// ref that this gate fails to reach is a ref that is not checked. Depth-blind
// over-reach is the safe direction: the worst case is insisting that some
// unrelated `uses` key is a pinned ref, which is loud, not silent.
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
		// Anchors first: an alias can only be resolved against a definition,
		// and a definition may sit anywhere in the document — including under
		// a key that is not `uses`, which is precisely the case a
		// definition-site-only check would miss.
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

// maxAliasDepth bounds alias chasing. A YAML document can define an alias that
// resolves to another alias; a malformed or hostile one can make that cyclic,
// and a gate that hangs is a gate that gets disabled.
const maxAliasDepth = 10

// resolveRef reduces a `uses:` value node to the string Actions would see.
//
// Every shape that carries a scalar is handled, and everything else returns an
// error rather than an empty string, so an unrecognised value fails the gate
// loudly instead of vanishing from its results. That asymmetry is the whole
// lesson of review round 1: a parser used carelessly drops refs just as
// silently as a regex misses them.
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
		// `uses: &checkout actions/checkout@v6` — the ref is the anchored
		// value. The anchor is a label, not part of the ref.
		return resolveRef(t.Value, anchors, depth+1)

	case *ast.AliasNode:
		// `uses: *checkout` — resolve against the definition. An alias whose
		// anchor we never saw is an error, not an empty ref.
		name := t.Value.GetToken().Value
		target, ok := anchors[name]
		if !ok {
			return "", fmt.Errorf("alias *%s has no anchor definition in this document", name)
		}
		return resolveRef(target, anchors, depth+1)

	case *ast.LiteralNode:
		// `uses: |` / `uses: >-` block scalars. Actions accepts them; the
		// content is the ref, modulo the newline the block form adds.
		if t.Value == nil {
			return "", fmt.Errorf("empty block scalar")
		}
		return strings.TrimSpace(t.Value.Value), nil

	case nil:
		return "", fmt.Errorf("missing value")
	}
	return "", fmt.Errorf("unsupported `uses:` value of type %T (%s)", n, n.Type())
}

// commentFor recovers the trailing `# v6`.
//
// The parser attaches a comment to the value node for the ordinary block
// spelling, and to the mapping node for some others — but for a step written
// as a flow mapping (`- {uses: x@sha} # v6`) it attaches to the enclosing
// SEQUENCE entry, which is not reachable from here. Rather than fail a
// correctly-pinned ref over where the parser filed its comment, fall back to
// the source line the parser already told us the value is on.
//
// That fallback is not a regex over `uses:` sneaking back in: the structural
// walk has already decided this is a ref and which line it is on, so all that
// remains is reading a known line for a `#`.
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

// Regression fixtures for review round 1.
//
// The defect these exist for: the gate collected only *ast.StringNode values,
// so `uses: &c actions/checkout@v6`, `uses: *c` and block scalars produced NO
// ref at all. They did not fail — they were absent, and absent reads as green.
// The discovery floor could not catch it either, because dropping one ref left
// 14 against a floor of 12.
//
// So each spelling Actions accepts is pinned down twice here, and the pair is
// the point:
//
//   - MUTABLE must FAIL. That is the property the gate exists for.
//   - PINNED must PASS. Without this control, a gate that rejected the
//     spelling outright — or one that failed every ref for some unrelated
//     reason — would satisfy the first half while being useless.
//
// And a third assertion covers the failure mode that motivated all of it:
// every spelling must yield EXACTLY ONE ref. A check that silently returns
// zero passes both of the other two.

const (
	pinned  = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
	mutable = "actions/checkout@v6"
)

// spelling renders a minimal YAML document containing exactly one `uses:` in
// one of the forms GitHub Actions accepts.
type spelling struct {
	name string
	// render returns YAML holding exactly one `uses:` whose value is ref,
	// carrying a trailing version comment so that the ONLY thing under test is
	// whether the ref itself is pinned.
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
		// The anchor sits under a key that is NOT `uses`, so a gate that only
		// inspected definition sites would never see this ref at all.
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

// The control for the test above: the same spellings, pinned, must pass. A
// gate that rejected every spelling would satisfy the mutable test while
// making the repository unmaintainable.
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

// Container actions: a mutable image tag must be rejected, not skipped.
//
// Round 1 returned a PASSING skip for anything `docker://`, so
// `docker://alpine:latest` — a mutable executable dependency, the exact hazard
// this gate exists for — rendered green.
func TestContainerRefsAreRejected(t *testing.T) {
	for _, ref := range []string{
		"docker://alpine:latest",
		"docker://alpine:3.19",
		"docker://ghcr.io/owner/image:v1.2.3",
		"docker://alpine",
		// Even a digest: immutable, but no container action is approved for
		// this repo, and the gate must not be the place that quietly grants
		// one. If the owner approves it, the exception goes in validateRef.
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

// A value the gate cannot reduce to a ref must FAIL, never disappear. This is
// the general form of the round-1 defect: the danger was not the specific node
// types that were missed, it was that missing one was silent.
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
				// An alias with no anchor may be rejected by the parser
				// itself. That is also a loud failure, which is all this test
				// requires.
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

// The other half of parsing rather than grepping: `uses:` is an ordinary word
// inside a block scalar, and a gate that fails on prose gets muted.
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

// Local actions are this repository's own code at this commit: no upstream ref
// exists to pin and no third party can move them.
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
