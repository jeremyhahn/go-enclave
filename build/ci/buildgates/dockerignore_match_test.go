package buildgates

import (
	"errors"
	"path"
	"strings"
	"testing"
)

// dockerignoreMatches reports whether one dockerignore pattern line (without
// its leading !) excludes the slash-separated name: the line is parsed by
// dockerignorePattern, and the pattern matches the name or one of its parent
// directories, as in dockerignoreAdmits.
func dockerignoreMatches(line, name string) (bool, error) {
	_, pattern := dockerignorePattern(line)
	segs := strings.Split(name, "/")
	for n := 1; n <= len(segs); n++ {
		ok, err := matchSegments(pattern, segs[:n])
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// admitsUnder applies dockerignore lines in order, as dockerignoreAdmits does
// with the real file: the last line that matches decides, and ! admits.
func admitsUnder(t *testing.T, lines []string, name string) bool {
	t.Helper()
	admitted := true
	for _, line := range lines {
		negated := strings.HasPrefix(line, "!")
		ok, err := dockerignoreMatches(strings.TrimPrefix(line, "!"), name)
		if err != nil {
			t.Fatalf("pattern %q: %v", line, err)
		}
		if ok {
			admitted = negated
		}
	}
	return admitted
}

// TestMatchSegments_Segments pins the segment matcher on its own: path.Match
// per segment, and ** matches zero or more whole segments.
func TestMatchSegments_Segments(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "foo", true},
		{"*", "foo/bar", false}, // a single * never crosses a slash
		{"*.go", "a.go", true},
		{"*.go", "d/a.go", false},
		{"d/*.go", "d/a.go", true},
		{"d/*.go", "d/e/a.go", false},
		{"**", "a/b/c", true},
		{"**/a.go", "a.go", true}, // ** at the start matches zero segments
		{"**/a.go", "x/y/a.go", true},
		{"**/a.go", "x/y/b.go", false},
		{"a/**/b", "a/b", true}, // ** in the middle matches zero segments
		{"a/**/b", "a/x/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
		{"a/**", "a/x", true}, // ** at the end
		{"a/**", "a/x/y", true},
		{"a/**", "b/x", false},
		{"a/?", "a/b", true},
		{"a/?", "a/bc", false},
		{"a/[bc]", "a/c", true},
		{"a/b", "a", false},
	}
	for _, c := range cases {
		got, err := matchSegments(strings.Split(c.pattern, "/"), strings.Split(c.name, "/"))
		if err != nil {
			t.Errorf("matchSegments(%q, %q): %v", c.pattern, c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("matchSegments(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// TestDockerignoreMatches_DocumentedRules checks pattern lines against the
// rules Docker documents for .dockerignore: patterns are cleaned (a leading
// / or ./ and a trailing / change nothing), are anchored at the context root,
// and a pattern that names a directory excludes everything below it.
func TestDockerignoreMatches_DocumentedRules(t *testing.T) {
	cases := []struct {
		line, name string
		want       bool
	}{
		{"/foo", "foo", true},
		{"/foo", "foo/bar", true},
		{"/foo", "x/foo", false},
		{"./foo", "foo", true},
		{"./foo/*.go", "foo/a.go", true},
		{"foo/", "foo", true},
		{"foo/", "foo/bar/baz", true},
		{"/foo/", "foo/bar", true},
		{"docs", "docs/a/b.md", true}, // a parent directory excludes its children
		{"docs", "docsx/a.md", false},
		{"docs", "x/docs", false}, // anchored at the root
		{"*", "a/b/c", true},      // * excludes the top-level directory a
		{"*.md", "a.md", true},
		{"*.md", "d/a.md", false},
		{"**/*.md", "d/e/a.md", true},
		{"d/**/*.go", "d/a.go", true},
		{"d/**/*.go", "d/e/f/a.go", true},
		{"d/**/*.go", "e/a.go", false},
	}
	for _, c := range cases {
		got, err := dockerignoreMatches(c.line, c.name)
		if err != nil {
			t.Errorf("pattern %q on %q: %v", c.line, c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("pattern %q on %q = %v, want %v", c.line, c.name, got, c.want)
		}
	}
}

// TestMatchSegments_BadPattern pins that a malformed pattern is an error,
// not a silent mismatch, so dockerignoreAdmits fails the gate on it.
func TestMatchSegments_BadPattern(t *testing.T) {
	for _, line := range []string{"[", "a/[", "**/[", "a/[b-"} {
		_, err := dockerignoreMatches(line, "a/b")
		if !errors.Is(err, path.ErrBadPattern) {
			t.Errorf("pattern %q: err = %v, want path.ErrBadPattern", line, err)
		}
	}
}

// TestDockerignore_NegationOrder pins that the last matching line decides: a
// later !pattern re-admits, and a later pattern re-excludes.
func TestDockerignore_NegationOrder(t *testing.T) {
	cases := []struct {
		lines []string
		name  string
		want  bool
	}{
		{nil, "a.go", true},
		{[]string{"*"}, "a.go", false},
		{[]string{"*", "!a.go"}, "a.go", true},
		{[]string{"*", "!a.go"}, "b.go", false},
		{[]string{"*", "!a.go", "a.go"}, "a.go", false},
		{[]string{"!a.go", "*"}, "a.go", false},
		{[]string{"*", "!d/**/*.go"}, "d/e/a.go", true},
		{[]string{"*", "!d/**/*.go", "d/e/*_test.go"}, "d/e/a_test.go", false},
		{[]string{"*", "!d/**/*.go", "d/e/*_test.go", "!d/e/keep_test.go"}, "d/e/keep_test.go", true},
		{[]string{"*", "!d"}, "d/x/y", true},
		{[]string{"*", "!d", "d/x"}, "d/x/y", false},
	}
	for _, c := range cases {
		if got := admitsUnder(t, c.lines, c.name); got != c.want {
			t.Errorf("lines %q admit %q = %v, want %v", c.lines, c.name, got, c.want)
		}
	}
}

// FuzzMatchSegments checks that the matcher never panics and that a path
// with no glob metacharacters, used as its own pattern, always matches.
func FuzzMatchSegments(f *testing.F) {
	for _, s := range [][2]string{
		{"*", "a"}, {"**/a.go", "x/y/a.go"}, {"a/**/b", "a/b"}, {"[", "a"},
		{"a/b", "a/b"}, {"", ""}, {"**/**", "a//b"}, {"\\", "a"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		pat, segs := strings.Split(pattern, "/"), strings.Split(name, "/")
		if len(pat) > 8 || len(segs) > 16 {
			t.Skip() // nested ** backtracks: keep each run bounded
		}
		_, _ = matchSegments(pat, segs)
		if strings.ContainsAny(name, `*?[\`) {
			return
		}
		ok, err := matchSegments(segs, segs)
		if err != nil || !ok {
			t.Fatalf("matchSegments(%q, %q) = %v, %v: a literal path must match itself", name, name, ok, err)
		}
	})
}
