package buildgates

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writeSitePatterns writes content to a fresh site pattern file and returns
// its path.
func writeSitePatterns(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "site-patterns.tsv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// FuzzLoadSitePatterns checks that the loader never panics, and that every
// error it returns is a *patternFileError naming the file and a line that
// exists in the input.
func FuzzLoadSitePatterns(f *testing.F) {
	for _, seed := range []string{
		"",
		"\n",
		"# comment\n\nlab-host\texample\\.com\n",
		"lab-address\t192\\.0\\.2\\.\\d+\r\nowner-path\t/home/example\r\n",
		"lab-host\texample\\.com",
		"lab-host\tfoo\tbar\n",
		"lab-host\n",
		"\texample\\.com\n",
		"unknown\texample\\.com\n",
		"lab-host\t(\n",
		"lab-host\t \n",
		"  # indented comment\n\t\n\r\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		path := writeSitePatterns(t, content)
		rules, err := loadSitePatterns(path)
		if err == nil {
			for _, r := range rules {
				if _, known := classGuidance[r.class]; !known {
					t.Fatalf("rule with unknown class %q loaded", r.class)
				}
				if r.expr == nil {
					t.Fatal("rule loaded with a nil expression")
				}
			}
			return
		}
		var pfe *patternFileError
		if !errors.As(err, &pfe) {
			t.Fatalf("error %T is not a *patternFileError: %v", err, err)
		}
		if pfe.path != path {
			t.Fatalf("error names %q, want %q", pfe.path, path)
		}
		lines := strings.Count(content, "\n") + 1
		if pfe.line < 1 || pfe.line > lines {
			t.Fatalf("error line %d outside the input's 1..%d", pfe.line, lines)
		}
		if !strings.Contains(err.Error(), path) {
			t.Fatalf("error %q does not name the file", err)
		}
	})
}

func TestLoadSitePatternsLineEdges(t *testing.T) {
	type rule struct {
		class leakClass
		expr  string
	}
	cases := []struct {
		name    string
		content string
		want    []rule
		errLine int
		errIs   error
	}{
		{
			name:    "comments and blank lines are skipped",
			content: "# header\n\n   \n\t\n  # indented\nlab-host\texample\\.com\n\n",
			want:    []rule{{classLabHost, `example\.com`}},
		},
		{
			name:    "only comments and blanks",
			content: "# one\n\n# two\n",
		},
		{
			name:    "empty file",
			content: "",
		},
		{
			name:    "CRLF line ends",
			content: "# header\r\n\r\nlab-host\texample\\.com\r\nlab-address\t192\\.0\\.2\\.\\d+\r\n",
			want:    []rule{{classLabHost, `example\.com`}, {classLabAddress, `192\.0\.2\.\d+`}},
		},
		{
			name:    "trailing line without a newline",
			content: "lab-host\texample\\.com\nowner-path\t/home/example",
			want:    []rule{{classLabHost, `example\.com`}, {classOwnerPath, `/home/example`}},
		},
		{
			name:    "tab inside the expression is kept",
			content: "lab-host\texample\tcom\n",
			want:    []rule{{classLabHost, "example\tcom"}},
		},
		{
			name:    "spaces around the fields are trimmed",
			content: "  lab-host \t example\\.com  \n",
			want:    []rule{{classLabHost, `example\.com`}},
		},
		{
			name:    "missing tab after CRLF lines",
			content: "# header\r\n\r\nlab-host example\\.com\r\n",
			errLine: 3,
			errIs:   errMissingField,
		},
		{
			name:    "empty expression",
			content: "lab-host\t\r\n",
			errLine: 1,
			errIs:   errMissingField,
		},
		{
			name:    "unknown class on a trailing line without a newline",
			content: "lab-host\texample\\.com\nweb-host\texample\\.com",
			errLine: 2,
			errIs:   errUnknownClass,
		},
		{
			name:    "bad expression",
			content: "\n\nlab-host\texample(\n",
			errLine: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSitePatterns(t, tc.content)
			rules, err := loadSitePatterns(path)
			if tc.errLine != 0 {
				var pfe *patternFileError
				if !errors.As(err, &pfe) {
					t.Fatalf("got %v, want a *patternFileError", err)
				}
				if pfe.path != path || pfe.line != tc.errLine {
					t.Fatalf("error at %s:%d, want %s:%d", pfe.path, pfe.line, path, tc.errLine)
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Fatalf("got %v, want %v", err, tc.errIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != len(tc.want) {
				t.Fatalf("got %d rules, want %d", len(rules), len(tc.want))
			}
			for i, w := range tc.want {
				if rules[i].class != w.class || rules[i].expr.String() != w.expr {
					t.Errorf("rule %d = %s %q, want %s %q", i, rules[i].class, rules[i].expr, w.class, w.expr)
				}
				if rules[i].guidance != classGuidance[w.class] {
					t.Errorf("rule %d guidance %q, want the class guidance", i, rules[i].guidance)
				}
			}
		})
	}
}

func TestScanContentLineEdges(t *testing.T) {
	rules := []leakPattern{
		{class: classLabHost, expr: regexp.MustCompile(`example\.com`), guidance: "host"},
		{class: classLabAddress, expr: regexp.MustCompile(`192\.0\.2\.\d+`), guidance: "address"},
	}
	waiver := "// " + waiverPrefix + " documentation example"
	type hit struct {
		line  int
		match string
	}
	cases := []struct {
		name    string
		content string
		want    []hit
	}{
		{"match on the first line", "example.com\nplain\nplain\n", []hit{{1, "example.com"}}},
		{"match on the last line with a newline", "plain\nplain\n192.0.2.7\n", []hit{{3, "192.0.2.7"}}},
		{"match on the last line without a newline", "plain\nplain\nexample.com", []hit{{3, "example.com"}}},
		{"single line without a newline", "192.0.2.1", []hit{{1, "192.0.2.1"}}},
		{"CRLF line ends", "plain\r\nexample.com\r\n", []hit{{2, "example.com"}}},
		{"two matches on one line", "example.com 192.0.2.9", []hit{{1, "example.com"}, {1, "192.0.2.9"}}},
		{"waiver on the same line", "plain\nexample.com " + waiver + "\n", nil},
		{"waiver on the line before", waiver + "\nexample.com\n", nil},
		{"waiver on the line before, last line without a newline", "plain\n" + waiver + "\n192.0.2.3", nil},
		{"waiver covers one following line only", waiver + "\nexample.com\nexample.com\n", []hit{{3, "example.com"}}},
		{"waiver two lines before does not cover", waiver + "\n\nexample.com", []hit{{3, "example.com"}}},
		{"waiver on the line after does not cover", "example.com\n" + waiver + "\n", []hit{{1, "example.com"}}},
		{"waiver with CRLF on the line before", waiver + "\r\nexample.com\r\n", nil},
		{"waiver without a reason does not cover", "// " + waiverPrefix + "\nexample.com", []hit{{2, "example.com"}}},
		{"empty content", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanContent("docs/example.md", []byte(tc.content), rules)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings %+v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].path != "docs/example.md" || got[i].line != w.line || got[i].match != w.match {
					t.Errorf("finding %d = %s:%d %q, want line %d %q", i, got[i].path, got[i].line, got[i].match, w.line, w.match)
				}
			}
		})
	}
}

func TestWaivedEdges(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"", false},
		{"example.com", false},
		{waiverPrefix, false},
		{waiverPrefix + "   ", false},
		{waiverPrefix + "\r", false},
		{"<!-- " + waiverPrefix + " -->", false},
		{"/* " + waiverPrefix + " */", false},
		{"<!-- " + waiverPrefix + " -->\r", false},
		{waiverPrefix + "documentation", true},
		{"// " + waiverPrefix + " documentation example", true},
		{"// " + waiverPrefix + " documentation example\r", true},
		{"<!-- " + waiverPrefix + " documentation example -->", true},
		{"/* " + waiverPrefix + " documentation example */", true},
		{"example.com # " + waiverPrefix + " documentation", true},
		{strings.TrimSuffix(waiverPrefix, ":") + " documentation", false},
	}
	for _, tc := range cases {
		if got := waived(tc.line); got != tc.want {
			t.Errorf("waived(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
