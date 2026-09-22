package buildgates

import (
	"strings"
	"testing"
)

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
