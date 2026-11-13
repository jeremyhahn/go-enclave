package buildgates

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// scripts/features.map is the one place a feature's source files and integration
// tests are named. The Makefile, scripts/features.sh and these gates all read
// it, so a file or test that the map does not place is found here, not by a
// feature that silently stops running its tests:
//
//   - every non-test .go file of the library belongs to exactly one feature;
//   - every glob matches at least one file;
//   - every integration test carries exactly one feature's name prefix, in that
//     feature's suite directory, and every prefix is used;
//   - every docs/<feature>/ directory has a line, and every line a directory.

// featureLine is one line of scripts/features.map.
type featureLine struct {
	Feature string
	Unit    string
	Suite   string
	Prefix  string
	Globs   []string
	globs   []*regexp.Regexp
}

var (
	featureNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	prefixRE      = regexp.MustCompile(`^Test[A-Za-z0-9]+_$`)
	globRE        = regexp.MustCompile(`^[A-Za-z0-9_./*-]+$`)
)

// globRegexp is scripts/features.sh's translation: `.` is literal and `*`
// matches any run of characters, `/` included. Both read the map the same way.
func globRegexp(glob string) *regexp.Regexp {
	return regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(glob), `\*`, `.*`) + "$")
}

// readFeatureMap parses and validates the map; a malformed line is a failure.
func readFeatureMap(t *testing.T, root string) []featureLine {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, "scripts", "features.map"))
	if err != nil {
		t.Fatalf("read the feature map: %v", err)
	}
	var out []featureLine
	seen := map[string]bool{}
	for i, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		at := func(msg string) { t.Errorf("scripts/features.map:%d: %s", i+1, msg) }
		if len(fields) < 5 {
			at("want <feature> <unit-package> <suite> <test-prefix> <source-glob>...")
			continue
		}
		fl := featureLine{Feature: fields[0], Unit: fields[1], Suite: fields[2], Prefix: fields[3], Globs: fields[4:]}
		if !featureNameRE.MatchString(fl.Feature) {
			at("feature " + fl.Feature + " must be lowercase words joined by -")
		}
		if seen[fl.Feature] {
			at("feature " + fl.Feature + " appears twice")
		}
		seen[fl.Feature] = true
		if !prefixRE.MatchString(fl.Prefix) {
			at("test prefix " + fl.Prefix + " must be Test<Name>_")
		}
		for _, g := range fl.Globs {
			if !globRE.MatchString(g) {
				at("glob " + g + " may hold only letters, digits, _ . / * and -")
				continue
			}
			fl.globs = append(fl.globs, globRegexp(g))
		}
		out = append(out, fl)
	}
	if len(out) == 0 {
		t.Fatal("scripts/features.map holds no feature")
	}
	// No prefix may start with another's, or `-run ^<prefix>` selects two features.
	for _, a := range out {
		for _, b := range out {
			if a.Feature != b.Feature && strings.HasPrefix(a.Prefix, b.Prefix) {
				t.Errorf("test prefix %s (%s) starts with %s (%s): -run ^%s would select both", a.Prefix, a.Feature, b.Prefix, b.Feature, b.Prefix)
			}
		}
	}
	return out
}

// librarySources lists the non-test .go files of the library, repo-relative with
// forward slashes: the root package, internal/ and providertest/ — everything
// but the tooling and test trees, hidden directories and nested modules.
func librarySources(t *testing.T, root string) []string {
	t.Helper()
	skip := map[string]bool{"build": true, "test": true, "docs": true, "scripts": true, "changelog.d": true}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || skip[rel] {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir // a nested module is not this library
			}
			return nil
		}
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

func TestFeatureMap_EverySourceFileBelongsToExactlyOneFeature(t *testing.T) {
	root := repoRoot(t)
	features := readFeatureMap(t, root)
	files := librarySources(t, root)
	// A floor: an empty walk would pass every loop below.
	if len(files) < 20 {
		t.Fatalf("found %d library source file(s) under %s, want at least 20: the walk is broken", len(files), root)
	}
	matched := map[string]int{} // glob -> files it matches
	for _, f := range files {
		var owners []string
		for _, fl := range features {
			for i, re := range fl.globs {
				if re.MatchString(f) {
					matched[fl.Feature+" "+fl.Globs[i]]++
					owners = append(owners, fl.Feature)
					break
				}
			}
		}
		switch len(owners) {
		case 0:
			t.Errorf("%s belongs to no feature: add its glob to a line of scripts/features.map", f)
		case 1:
		default:
			t.Errorf("%s belongs to %d features (%s): a file has one owner in scripts/features.map", f, len(owners), strings.Join(owners, ", "))
		}
	}
	for _, fl := range features {
		for _, g := range fl.Globs {
			if matched[fl.Feature+" "+g] == 0 {
				t.Errorf("glob %q of feature %s matches no file: remove it from scripts/features.map", g, fl.Feature)
			}
		}
	}
}

var integrationTestFunc = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)

func TestFeatureMap_EveryIntegrationTestBelongsToExactlyOneFeature(t *testing.T) {
	root := repoRoot(t)
	features := readFeatureMap(t, root)
	suiteRoot := filepath.Join(root, "test", "integration")
	used := map[string]int{}
	total := 0
	err := filepath.WalkDir(suiteRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(suiteRoot, p)
		suite := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if suite == "internal" {
			// test/integration/internal holds the suites' shared helpers;
			// their unit tests belong to no feature.
			return nil
		}
		for _, m := range integrationTestFunc.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			if name == "TestMain" {
				continue
			}
			total++
			var owners []featureLine
			for _, fl := range features {
				if strings.HasPrefix(name, fl.Prefix) {
					owners = append(owners, fl)
				}
			}
			switch len(owners) {
			case 0:
				t.Errorf("%s: %s carries no feature's prefix; name it <prefix>… from scripts/features.map so `make integration-test-<feature>` runs it", filepath.ToSlash(rel), name)
			case 1:
				used[owners[0].Feature]++
				if owners[0].Suite != suite {
					t.Errorf("%s: %s has feature %s's prefix but sits in suite %q, not %q", filepath.ToSlash(rel), name, owners[0].Feature, suite, owners[0].Suite)
				}
			default:
				t.Errorf("%s: %s carries %d features' prefixes", filepath.ToSlash(rel), name, len(owners))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", suiteRoot, err)
	}
	if total < 20 {
		t.Fatalf("found %d integration test(s), want at least 20: the walk is broken", total)
	}
	for _, fl := range features {
		if used[fl.Feature] == 0 {
			t.Errorf("no integration test carries %s (feature %s): `make integration-test-%s` would run nothing", fl.Prefix, fl.Feature, fl.Feature)
		}
		if fi, err := os.Stat(filepath.Join(suiteRoot, fl.Suite)); err != nil || !fi.IsDir() {
			t.Errorf("feature %s names suite %q, but test/integration/%s is not a directory", fl.Feature, fl.Suite, fl.Suite)
		}
	}
}

func TestFeatureMap_EveryDocsDirectoryIsAFeatureAndBack(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := map[string]bool{}
	for _, e := range entries {
		// docs/reference/ holds the standards the code implements
		// (handbook documentation.md §9), not a feature.
		if e.IsDir() && e.Name() != "reference" {
			dirs[e.Name()] = true
		}
	}
	for _, fl := range readFeatureMap(t, root) {
		if !dirs[fl.Feature] {
			t.Errorf("scripts/features.map names feature %s, which has no docs/%s/", fl.Feature, fl.Feature)
		}
		delete(dirs, fl.Feature)
	}
	for d := range dirs {
		t.Errorf("docs/%s/ is a feature with no line in scripts/features.map", d)
	}
}

// The Go version the toolchain image builds with is the one go.mod requires, so
// a bump of either without the other fails here, not in a build that quietly
// uses an older compiler than the module says.
func TestToolchainImage_GoVersionMatchesGoMod(t *testing.T) {
	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)\s*$`).FindStringSubmatch(string(mod))
	if want == nil {
		t.Fatal("go.mod has no go directive")
	}
	docker, err := os.ReadFile(filepath.Join(root, "build", "docker", "devcontainer", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	got := dockerfileGoVersion(string(docker))
	if got == "" {
		t.Fatal("the Dockerfile's GO_IMAGE does not name a golang version (want golang:<version>…)")
	}
	if got != want[1] {
		t.Errorf("the Dockerfile builds with Go %s but go.mod says go %s: change them together", got, want[1])
	}
}

// dockerfileGoVersion is the version in `ARG GO_IMAGE=golang:<version>[-…][@…]`,
// or "" when there is none.
func dockerfileGoVersion(dockerfile string) string {
	m := regexp.MustCompile(`(?m)^ARG GO_IMAGE=(?:[^\s:@]*/)?golang:(\d+\.\d+(?:\.\d+)?)(?:[-@\s]|$)`).FindStringSubmatch(dockerfile)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestToolchainImage_GoVersionParsing(t *testing.T) {
	for in, want := range map[string]string{
		"ARG GO_IMAGE=golang:1.27.1-alpine3.24@sha256:abc\n": "1.27.1",
		"ARG GO_IMAGE=golang:1.27@sha256:abc\n":              "1.27",
		"ARG GO_IMAGE=docker.io/library/golang:1.27.1\n":     "1.27.1",
		"ARG GO_IMAGE=golang:latest\n":                       "",
		"FROM golang:1.20\n":                                 "",
	} {
		if got := dockerfileGoVersion(in); got != want {
			t.Errorf("dockerfileGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
