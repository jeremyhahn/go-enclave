package buildgates

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// FuzzExtractRefs pins that no input, however malformed, makes the gate panic
// or let a ref through unchecked: every ref extractRefs returns is either
// accepted by validateRef for a reason the gate states (a local action, or a
// resolved 40-hex pin with a comment) or rejected with an error.
func FuzzExtractRefs(f *testing.F) {
	for _, sp := range spellings {
		f.Add(sp.render(pinned))
		f.Add(sp.render(mutable))
	}
	for _, seed := range []string{
		"steps:\n  - uses: *nosuch # v6\n",
		"steps:\n  - uses: [a, b] # v6\n",
		"steps:\n  - uses: {a: b} # v6\n",
		"steps:\n  - uses: # v6\n",
		"steps:\n  - run: |\n      echo uses: actions/checkout@v6\n",
		"steps:\n  - uses: ./.github/actions/setup\n",
		"steps:\n  - uses: docker://alpine:latest # v1\n",
		"steps:\n  - uses: \"\" # v6\n",
		"a: &a *a\nsteps:\n  - uses: *a # v6\n",
		"---\nsteps:\n  - uses: " + pinned + " # v6\n---\nsteps:\n  - uses: " + mutable + "\n",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, src string) {
		refs, err := extractRefs("fixture.yml", []byte(src))
		if err != nil {
			return // a parse error fails the gate loudly
		}
		for _, r := range refs {
			verr := validateRef(r)
			if verr != nil {
				if verr.Error() == "" {
					t.Fatalf("validateRef rejected %+v with an empty message", r)
				}
				continue
			}
			if r.err != nil {
				t.Fatalf("validateRef passed a ref that did not resolve: %v\nyaml:\n%q", r.err, src)
			}
			if r.value == "" {
				t.Fatalf("validateRef passed an empty ref\nyaml:\n%q", src)
			}
			local := strings.HasPrefix(r.value, "./")
			if !local && (!pinnedRef.MatchString(r.value) || r.comment == "") {
				t.Fatalf("validateRef passed %q (comment %q), neither local nor a commented pin\nyaml:\n%q",
					r.value, r.comment, src)
			}
		}
	})
}

// aliasTo builds `*name` without a parser, so resolveRef's own depth bound is
// under test rather than whatever the parser does with a cycle.
func aliasTo(name string) *ast.AliasNode {
	return &ast.AliasNode{
		BaseNode: &ast.BaseNode{},
		Value: &ast.StringNode{
			BaseNode: &ast.BaseNode{},
			Token:    &token.Token{Value: name},
			Value:    name,
		},
	}
}

// aliasChain returns the head of n aliases a0 -> a1 -> ... -> a(n-1) -> pinned.
func aliasChain(n int) (ast.Node, map[string]ast.Node) {
	anchors := map[string]ast.Node{}
	for i := 0; i < n-1; i++ {
		anchors[fmt.Sprintf("a%d", i)] = aliasTo(fmt.Sprintf("a%d", i+1))
	}
	anchors[fmt.Sprintf("a%d", n-1)] = &ast.StringNode{
		BaseNode: &ast.BaseNode{},
		Token:    &token.Token{Value: pinned},
		Value:    pinned,
	}
	return aliasTo("a0"), anchors
}

func TestResolveRefAliasDepthBound(t *testing.T) {
	t.Run("at the limit resolves", func(t *testing.T) {
		head, anchors := aliasChain(maxAliasDepth)
		got, err := resolveRef(head, anchors, 0)
		if err != nil {
			t.Fatalf("a chain of %d aliases failed: %v", maxAliasDepth, err)
		}
		if got != pinned {
			t.Fatalf("resolved %q, want %q", got, pinned)
		}
	})
	t.Run("one past the limit fails", func(t *testing.T) {
		head, anchors := aliasChain(maxAliasDepth + 1)
		got, err := resolveRef(head, anchors, 0)
		if err == nil {
			t.Fatalf("a chain of %d aliases resolved to %q; want the depth error", maxAliasDepth+1, got)
		}
		if !strings.Contains(err.Error(), "alias chain deeper than") {
			t.Errorf("failed for the wrong reason: %v", err)
		}
	})
	t.Run("cycle fails", func(t *testing.T) {
		anchors := map[string]ast.Node{"a": aliasTo("b"), "b": aliasTo("a")}
		got, err := resolveRef(aliasTo("a"), anchors, 0)
		if err == nil {
			t.Fatalf("a cyclic alias resolved to %q; want the depth error", got)
		}
		if !strings.Contains(err.Error(), "alias chain deeper than") {
			t.Errorf("failed for the wrong reason: %v", err)
		}
	})
	t.Run("self cycle fails", func(t *testing.T) {
		anchors := map[string]ast.Node{"a": aliasTo("a")}
		if _, err := resolveRef(aliasTo("a"), anchors, 0); err == nil {
			t.Fatal("a self-referencing alias resolved; want the depth error")
		}
	})
}

func TestValidateRefPinEdges(t *testing.T) {
	hex := strings.Repeat("0123456789abcdef", 3)
	for _, tc := range []struct {
		name, value, comment, want string // want "" means the ref passes
	}{
		{"40 hex with comment", "actions/checkout@" + hex[:40], "v6", ""},
		{"39 hex", "actions/checkout@" + hex[:39], "v6", "unpinned action ref"},
		{"41 hex", "actions/checkout@" + hex[:41], "v6", "unpinned action ref"},
		{"uppercase hex", "actions/checkout@" + strings.ToUpper(hex[:40]), "v6", "unpinned action ref"},
		{"no owner before @", "@" + hex[:40], "v6", "unpinned action ref"},
		{"40 hex without comment", "actions/checkout@" + hex[:40], "", "no trailing version comment"},
		{"docker digest", "docker://alpine@sha256:" + hex[:48] + hex[:16], "v1", "container action ref"},
		{"empty ref", "", "v6", "unpinned action ref"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRef(actionRef{file: "fixture.yml", line: 1, value: tc.value, comment: tc.comment})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validateRef rejected %q: %v", tc.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRef accepted %q; want %q", tc.value, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("failed for the wrong reason, want %q:\n%v", tc.want, err)
			}
		})
	}
}
