// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package buildgates

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// markdownLinkSkipDirs hold Markdown the gate does not check: copied
// standards (their links point into their own sites) and changelog fragments
// (folded into CHANGELOG.md, which the gate does check).
var markdownLinkSkipDirs = []string{"docs/reference/", "changelog.d/"}

// inlineLinkPattern matches an inline link or image target: ](target) or
// ](<target> "title").
var inlineLinkPattern = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)>?(?:\s+["'(][^)]*)?\)`)

// refDefPattern matches a link reference definition: [label]: target. A
// footnote definition ([^label]: text) is not one.
var refDefPattern = regexp.MustCompile(`^ {0,3}\[[^\]^][^\]]*\]:\s*<?([^\s>]+)>?`)

// schemePattern matches a URL scheme (https:, mailto:).
var schemePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// trackerPathPattern is the part after the climb to the repository root
// that a link leaving the repository may name.
var trackerPathPattern = regexp.MustCompile(`^(issues|pull|milestone)/[0-9]+$`)

// mdLink is one link target and the 1-based line it sits on.
type mdLink struct {
	line   int
	target string
}

// stripCodeSpans removes inline code spans from line: a run of N backticks
// up to the next run of exactly N. An unmatched run stays as text.
func stripCodeSpans(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		closeAt := -1
		for j := i + n; j < len(line); {
			if line[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(line) && line[j+m] == '`' {
				m++
			}
			if m == n {
				closeAt = j + m
				break
			}
			j += m
		}
		if closeAt < 0 {
			b.WriteString(line[i : i+n])
			i += n
			continue
		}
		i = closeAt
	}
	return b.String()
}

// fenceOpen reports the fence marker (a run of ``` or ~~~) that line opens or
// closes, or "" when it is not a fence line.
func fenceOpen(line string) string {
	s := strings.TrimLeft(line, " \t")
	for _, c := range []byte{'`', '~'} {
		n := 0
		for n < len(s) && s[n] == c {
			n++
		}
		if n >= 3 {
			return s[:n]
		}
	}
	return ""
}

// markdownLinks returns the link targets in src outside fenced blocks and
// inline code spans.
func markdownLinks(src string) []mdLink {
	var links []mdLink
	fence := ""
	for i, line := range strings.Split(src, "\n") {
		if marker := fenceOpen(line); marker != "" {
			switch {
			case fence == "":
				fence = marker
			case marker[0] == fence[0] && len(marker) >= len(fence) &&
				strings.TrimSpace(strings.TrimLeft(line, " \t")[len(marker):]) == "":
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		text := stripCodeSpans(line)
		if m := refDefPattern.FindStringSubmatch(text); m != nil {
			links = append(links, mdLink{line: i + 1, target: m[1]})
			continue
		}
		for _, m := range inlineLinkPattern.FindAllStringSubmatch(text, -1) {
			links = append(links, mdLink{line: i + 1, target: m[1]})
		}
	}
	return links
}

// linkProblem returns why target, linked from a Markdown file in the
// repository directory dir ("." for the root), does not resolve, or "" when
// it does or is not a relative link. exists reports whether a
// slash-separated repository path exists.
func linkProblem(dir, target string, exists func(string) bool) string {
	if target == "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "//") ||
		schemePattern.MatchString(target) {
		return ""
	}
	p := target
	if i := strings.IndexAny(p, "#?"); i >= 0 {
		p = p[:i]
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	var joined string
	if strings.HasPrefix(p, "/") {
		joined = path.Clean(strings.TrimPrefix(p, "/"))
	} else {
		joined = path.Join(dir, p)
	}
	if joined == ".." || strings.HasPrefix(joined, "../") {
		depth := 2
		if dir != "." && dir != "" {
			depth += strings.Count(dir, "/") + 1
		}
		climb := strings.Repeat("../", depth)
		if !strings.HasPrefix(p, climb) || !trackerPathPattern.MatchString(strings.TrimPrefix(p, climb)) {
			return "leaves the repository but is not " + climb + "issues/N, pull/N or milestone/N"
		}
		return ""
	}
	if !exists(joined) {
		return "names " + joined + ", which does not exist"
	}
	return ""
}

// TestMarkdownRelativeLinksResolve pins that every relative link in the
// tracked Markdown resolves: a repository path exists, and a link that
// climbs out of the repository names an issue, pull request or milestone at
// the depth that reaches the repository root from blob/main/<dir>/.
func TestMarkdownRelativeLinksResolve(t *testing.T) {
	root := repoRoot(t)
	files, err := trackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return err == nil
	}
	checked := 0
files:
	for _, rel := range files {
		if !strings.HasSuffix(rel, ".md") {
			continue
		}
		for _, skip := range markdownLinkSkipDirs {
			if strings.HasPrefix(rel, skip) {
				continue files
			}
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, l := range markdownLinks(string(src)) {
			if why := linkProblem(path.Dir(rel), l.target, exists); why != "" {
				t.Errorf("%s:%d: link %s %s", rel, l.line, l.target, why)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no tracked Markdown found; the gate checked nothing")
	}
}

// TestMarkdownLinkClassifier pins which link targets the gate accepts.
func TestMarkdownLinkClassifier(t *testing.T) {
	present := map[string]bool{"README.md": true, "docs/a.md": true, "docs/x/b.md": true, "docs/x": true}
	exists := func(rel string) bool { return present[rel] }
	cases := []struct {
		dir, target string
		ok          bool
	}{
		{".", "docs/a.md", true},
		{".", "docs/a.md#section", true},
		{"docs", "x/b.md", true},
		{"docs/x", "../a.md", true},
		{"docs/x", "../../README.md", true},
		{"docs", "x", true},
		{"docs", "missing.md", false},
		{"docs/x", "a.md", false},
		{".", "/docs/a.md", true},
		{".", "#anchor-only", true},
		{".", "https://example.com/x", true},
		{".", "mailto:a@example.com", true},
		{".", "../../issues/12", true},
		{"docs", "../../../pull/3", true},
		{"docs/x", "../../../../milestone/2", true},
		{"docs", "../../issues/12", false},
		{"docs", "../../../../issues/12", false},
		{".", "../../../issues/12", false},
		{"docs", "../../../blob/main/x.md", false},
		{"docs", "../../../issues/abc", false},
	}
	for _, c := range cases {
		why := linkProblem(c.dir, c.target, exists)
		if (why == "") != c.ok {
			t.Errorf("linkProblem(%q, %q) = %q, want ok=%v", c.dir, c.target, why, c.ok)
		}
	}
}

// TestMarkdownLinkExtractor pins which text counts as a link.
func TestMarkdownLinkExtractor(t *testing.T) {
	src := strings.Join([]string{
		"See [a](a.md) and ![img](<b.png> \"title\").",
		"Code `[not](c.md)` and ``[x](`d.md`)`` stay out.",
		"A regex `[a-z](e)` is not a link.",
		"```go",
		"[fenced](f.md)",
		"```",
		"~~~~",
		"[tilde](g.md)",
		"~~~",
		"~~~~",
		"[ref]: h.md \"t\"",
		"Unmatched ` tick [i](i.md).",
		"[^note]: a footnote, not a target",
	}, "\n")
	got := markdownLinks(src)
	want := []mdLink{{1, "a.md"}, {1, "b.png"}, {11, "h.md"}, {12, "i.md"}}
	if len(got) != len(want) {
		t.Fatalf("markdownLinks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %v, want %v", i, got[i], want[i])
		}
	}
}
