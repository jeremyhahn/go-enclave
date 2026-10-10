package buildgates

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/goccy/go-yaml"
)

// Tests for the release and tooling scripts: scripts/release-notes.sh,
// release-check-tag.sh, release-publish.sh, consumer-check.sh and tool.sh.
//
// Most of these run for real only when a tag is pushed, some with a write
// token, and tool.sh decides which binary every lint and security gate trusts.
// Each is driven here offline on scratch inputs: a scratch tree, a local fake
// of the forge API, a local module proxy, fake tool binaries.

// runScript runs scripts/<name> with sh in dir, with env layered over the
// process environment (an empty value unsets in effect: the variable is set to
// ""), and returns its combined output and whether it exited 0.
func runScript(t *testing.T, dir string, env map[string]string, name string, args ...string) (string, bool) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", name)
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		return string(out), false
	}
	return string(out), true
}

func layerEnv(base []string, over map[string]string) []string {
	out := make([]string, 0, len(base)+len(over))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, replaced := over[k]; !replaced {
			out = append(out, kv)
		}
	}
	for k, v := range over {
		out = append(out, k+"="+v)
	}
	return out
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
// release-notes.sh

const notesChangelog = `# Changelog

Preamble.

## [Unreleased]

## [v1.2.30] - 2026-01-04

### Fixed

- thirty

## [v1.2.3-alpha.1] - 2026-01-03

### Fixed

- alpha one

## [v1.2.3-alpha] - 2026-01-02

### Added

- alpha entry,
  wrapped

### Fixed

- alpha fix

## v1.2.3 - 2026-01-01

### Changed

- unbracketed release

[v1.2.3-alpha]: https://example.com/compare/v1.2.3...v1.2.3-alpha
[v1.2.3]: https://example.com/releases/v1.2.3
`

func TestScriptsReleaseNotes_ExtractsExactlyTheVersionsSection(t *testing.T) {
	dir := writeTree(t, map[string]string{"CHANGELOG.md": notesChangelog})
	for _, tc := range []struct{ version, want string }{
		// A version is never matched by a longer one that starts with it.
		{"v1.2.3-alpha", "### Added\n\n- alpha entry,\n  wrapped\n\n### Fixed\n\n- alpha fix\n"},
		{"v1.2.3-alpha.1", "### Fixed\n\n- alpha one\n"},
		{"v1.2.30", "### Fixed\n\n- thirty\n"},
		// Unbracketed heading, and the link-reference footer is the file's,
		// not the last section's.
		{"v1.2.3", "### Changed\n\n- unbracketed release\n"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			out, ok := runScript(t, dir, nil, "release-notes.sh", tc.version)
			if !ok {
				t.Fatalf("extraction failed:\n%s", out)
			}
			if out != tc.want {
				t.Fatalf("notes for %s:\n--- got ---\n%s\n--- want ---\n%s", tc.version, out, tc.want)
			}
		})
	}
}

func TestScriptsReleaseNotes_RefusesWhatItCannotPublish(t *testing.T) {
	for _, tc := range []struct {
		name, changelog, version, wantMsg string
	}{
		{"no section", notesChangelog, "v9.9.9", "no section heading"},
		{"prefix of a real version", notesChangelog, "v1.2", "not vX.Y.Z"},
		{"not a version", notesChangelog, "latest", "not vX.Y.Z"},
		{"multi-line version", notesChangelog, "x\nv1.2.3", "not vX.Y.Z"},
		{"duplicate section", "## [v1.0.0] - 2026-01-01\n\n- a\n\n## [v1.0.0] - 2026-01-02\n\n- b\n", "v1.0.0", "2 section headings"},
		{"empty section", "## [v1.0.0] - 2026-01-02\n\n\n## [v0.9.0] - 2026-01-01\n\n- old\n", "v1.0.0", "is empty"},
		{"only a footer", "## [v1.0.0] - 2026-01-02\n\n[v1.0.0]: https://example.com\n", "v1.0.0", "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"CHANGELOG.md": tc.changelog})
			out, ok := runScript(t, dir, nil, "release-notes.sh", tc.version)
			if ok {
				t.Fatalf("extraction succeeded, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// TestScriptsReleaseNotes_RealChangelog extracts every released section of
// this repository's CHANGELOG.md and requires each to be exactly the text
// between its heading and the next heading: verbatim, contiguous, complete.
// It is the property release.yml relies on to publish a release body.
func TestScriptsReleaseNotes_RealChangelog(t *testing.T) {
	root := repoRoot(t)
	changelog := readFile(t, filepath.Join(root, "CHANGELOG.md"))
	headings := regexp.MustCompile(`(?m)^## \[(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)\][^\n]*\n`).FindAllStringSubmatchIndex(changelog, -1)
	if len(headings) < 5 {
		t.Fatalf("found %d released sections in CHANGELOG.md; the discovery is broken, not the file", len(headings))
	}
	for i, h := range headings {
		version := changelog[h[2]:h[3]]
		end := len(changelog)
		if i+1 < len(headings) {
			end = headings[i+1][0]
		}
		want := strings.Trim(changelog[h[1]:end], "\n") + "\n"
		out, ok := runScript(t, root, nil, "release-notes.sh", version)
		if !ok {
			t.Fatalf("%s: extraction failed:\n%s", version, out)
		}
		if out != want {
			t.Fatalf("%s: notes differ from the section's text.\n--- got ---\n%s\n--- want ---\n%s", version, out, want)
		}
	}
}

// ---------------------------------------------------------------------------
// release-check-tag.sh

const checkTagChangelog = `# Changelog

## [Unreleased]

## [v1.4.0-rc.12] - 2026-02-03

### Added

- a twelfth candidate

## [v1.4.0-rc.1] - 2026-02-02

### Added

- a first candidate

## [v1.4.0-alpha] - 2026-02-01

### Added

- a thing

## [v1.3.0] - 2026-01-01

### Added

- an older thing
`

func checkTagTree(t *testing.T, version, changelog string, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"VERSION":              version,
		"CHANGELOG.md":         changelog,
		"changelog.d/.gitkeep": "",
	}
	for k, v := range extra {
		files[k] = v
	}
	return writeTree(t, files)
}

func TestScriptsReleaseCheckTag_AcceptsAConsistentTree(t *testing.T) {
	for _, tc := range []struct{ tag, version string }{
		{"v1.4.0-alpha", "1.4.0-alpha\n"},
		{"v1.4.0-rc.1", "1.4.0-rc.1\n"},
		{"v1.4.0-rc.12", "1.4.0-rc.12\n"},
		{"v1.3.0", "1.3.0\n"},
		{"v1.3.0", "1.3.0"}, // no trailing newline is still one line
	} {
		dir := checkTagTree(t, tc.version, checkTagChangelog, nil)
		if out, ok := runScript(t, dir, nil, "release-check-tag.sh", tc.tag); !ok {
			t.Fatalf("%s with VERSION %q refused:\n%s", tc.tag, tc.version, out)
		}
	}
}

func TestScriptsReleaseCheckTag_RefusesEveryDisagreement(t *testing.T) {
	for _, tc := range []struct {
		name, tag, version, changelog string
		extra                         map[string]string
		wantMsg                       string
	}{
		{"VERSION behind the tag", "v1.4.0-alpha", "1.3.0\n", checkTagChangelog, nil, "VERSION reads '1.3.0'"},
		{"VERSION carries the prefix", "v1.4.0-alpha", "v1.4.0-alpha\n", checkTagChangelog, nil, "unprefixed"},
		{"VERSION has a second line", "v1.4.0-alpha", "1.4.0-alpha\n1.4.0-alpha\n", checkTagChangelog, nil, "2 lines"},
		{"VERSION has a stray space", "v1.4.0-alpha", "1.4.0-alpha \n", checkTagChangelog, nil, "VERSION reads"},
		{"unsanctioned pre-release", "v1.4.0-beta", "1.4.0-beta\n", strings.ReplaceAll(checkTagChangelog, "-alpha", "-beta"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"candidate number zero", "v1.4.0-rc.0", "1.4.0-rc.0\n", strings.ReplaceAll(checkTagChangelog, "-alpha", "-rc.0"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"candidate number with a leading zero", "v1.4.0-rc.01", "1.4.0-rc.01\n", strings.ReplaceAll(checkTagChangelog, "-alpha", "-rc.01"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"candidate without a number", "v1.4.0-rc", "1.4.0-rc\n", strings.ReplaceAll(checkTagChangelog, "-alpha", "-rc"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"candidate and alpha at once", "v1.4.0-rc.1-alpha", "1.4.0-rc.1-alpha\n", strings.ReplaceAll(checkTagChangelog, "-alpha", "-rc.1-alpha"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"leading zero in the core", "v01.4.0", "01.4.0\n", strings.ReplaceAll(checkTagChangelog, "v1.4.0-alpha", "v01.4.0"), nil, "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"VERSION on the wrong candidate", "v1.4.0-rc.12", "1.4.0-rc.1\n", checkTagChangelog, nil, "VERSION reads '1.4.0-rc.1'"},
		{"no CHANGELOG section", "v1.5.0-alpha", "1.5.0-alpha\n", checkTagChangelog, nil, "no usable section"},
		{"fragment never folded", "v1.4.0-alpha", "1.4.0-alpha\n", checkTagChangelog, map[string]string{"changelog.d/77-thing.md": "### Fixed\n\n- x\n"}, "77-thing.md was never folded"},
		{"multi-line tag", "v1.3.0\nv1.4.0-alpha", "1.4.0-alpha\n", checkTagChangelog, nil, "is not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"},
		{"entry left in Unreleased", "v1.4.0-alpha", "1.4.0-alpha\n", strings.Replace(checkTagChangelog, "## [Unreleased]\n", "## [Unreleased]\n\n### Fixed\n\n- stranded\n", 1), nil, "stranded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := checkTagTree(t, tc.version, tc.changelog, tc.extra)
			out, ok := runScript(t, dir, nil, "release-check-tag.sh", tc.tag)
			if ok {
				t.Fatalf("accepted, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// release-publish.sh, against a fake of the Gitea API.

const (
	fakeToken = "0123456789abcdef0123456789abcdef01234567"
	fakeSHA   = "1111111111111111111111111111111111111111"
	otherSHA  = "2222222222222222222222222222222222222222"
)

type fakeRelease struct {
	ID         int    `json:"id"`
	TagName    string `json:"tag_name"`
	Target     string `json:"target_commitish"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// fakeForge is the slice of the Gitea API release-publish.sh uses.
type fakeForge struct {
	mu        sync.Mutex
	tagSHA    map[string]string // tag -> commit; absent = 404
	releases  map[string]*fakeRelease
	writes    []string // "POST <path>" / "PATCH <path>"
	requests  int
	badAuth   int
	failWrite bool                // answer 500 to POST/PATCH
	mangle    func(string) string // what the forge "stores" instead of the sent body
	// commitState is the combined commit status per commit; a commit absent
	// from it reads defaultState, and "" there answers 404.
	commitState  map[string]string
	defaultState string
}

func newFakeForge() *fakeForge {
	return &fakeForge{tagSHA: map[string]string{}, releases: map[string]*fakeRelease{}}
}

func (f *fakeForge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if r.Header.Get("Authorization") != "token "+fakeToken {
		f.badAuth++
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	const prefix = "/api/v1/repos/owner/repo"
	path, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/commits/") && strings.HasSuffix(path, "/status"):
		sha := strings.TrimSuffix(strings.TrimPrefix(path, "/commits/"), "/status")
		state, ok := f.commitState[sha]
		if !ok {
			state = f.defaultState
		}
		if state == "" {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		reply(http.StatusOK, map[string]any{"sha": sha, "state": state, "total_count": 1})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/tags/"):
		tag := strings.TrimPrefix(path, "/tags/")
		sha, ok := f.tagSHA[tag]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		reply(http.StatusOK, map[string]any{"name": tag, "commit": map[string]string{"sha": sha}})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/releases/tags/"):
		rel, ok := f.releases[strings.TrimPrefix(path, "/releases/tags/")]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}
		reply(http.StatusOK, rel)
	case r.Method == http.MethodPost && path == "/releases", r.Method == http.MethodPatch && strings.HasPrefix(path, "/releases/"):
		f.writes = append(f.writes, r.Method+" "+path)
		if f.failWrite {
			reply(http.StatusInternalServerError, map[string]string{"message": "boom"})
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			reply(http.StatusUnsupportedMediaType, map[string]string{"message": "json only"})
			return
		}
		var in fakeRelease
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			reply(http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		if f.mangle != nil {
			in.Body = f.mangle(in.Body)
		}
		status := http.StatusOK
		if r.Method == http.MethodPost {
			status = http.StatusCreated
			in.ID = 100 + len(f.releases)
		} else {
			in.ID = f.releases[in.TagName].ID
		}
		f.releases[in.TagName] = &in
		reply(status, in)
	default:
		reply(http.StatusNotFound, map[string]string{"message": "no route " + r.Method + " " + path})
	}
}

func publishEnv(api string) map[string]string {
	return map[string]string{
		"FORGE_API_URL":    api,
		"FORGE_REPOSITORY": "owner/repo",
		"FORGE_TOKEN":      fakeToken,
	}
}

func startForge(t *testing.T, f *fakeForge) string {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv.URL + "/api/v1"
}

func TestScriptsReleasePublish_CreatesTheReleaseFromTheChangelog(t *testing.T) {
	for _, tc := range []struct {
		tag        string
		prerelease bool
	}{
		{"v1.4.0-alpha", true},
		{"v1.4.0-rc.1", true},
		{"v1.4.0-rc.12", true},
		{"v1.3.0", false},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			f := newFakeForge()
			f.tagSHA[tc.tag] = fakeSHA
			dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
			out, ok := runScript(t, dir, publishEnv(startForge(t, f)), "release-publish.sh", tc.tag, fakeSHA)
			if !ok {
				t.Fatalf("publish failed:\n%s", out)
			}
			if strings.Contains(out, fakeToken) {
				t.Fatalf("the token reached the output:\n%s", out)
			}
			notes, ok := runScript(t, dir, nil, "release-notes.sh", tc.tag)
			if !ok {
				t.Fatalf("notes: %s", notes)
			}
			rel := f.releases[tc.tag]
			if rel == nil {
				t.Fatalf("no release was created; writes: %v", f.writes)
			}
			if rel.Body+"\n" != notes || rel.Name != tc.tag || rel.Prerelease != tc.prerelease || rel.Draft {
				t.Fatalf("release = %+v, want body %q, name %s, prerelease %v, not a draft", rel, notes, tc.tag, tc.prerelease)
			}
			if rel.Target != fakeSHA {
				t.Fatalf("release target_commitish = %q, want the gated commit %s", rel.Target, fakeSHA)
			}
			if len(f.writes) != 1 || f.writes[0] != "POST /releases" {
				t.Fatalf("writes = %v, want exactly one POST /releases", f.writes)
			}
		})
	}
}

func TestScriptsReleasePublish_ConvergesAnExistingRelease(t *testing.T) {
	f := newFakeForge()
	f.tagSHA["v1.4.0-alpha"] = fakeSHA
	f.releases["v1.4.0-alpha"] = &fakeRelease{ID: 7, TagName: "v1.4.0-alpha", Name: "old", Body: "stale", Prerelease: false}
	dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
	out, ok := runScript(t, dir, publishEnv(startForge(t, f)), "release-publish.sh", "v1.4.0-alpha", fakeSHA)
	if !ok {
		t.Fatalf("re-publishing failed:\n%s", out)
	}
	if len(f.writes) != 1 || f.writes[0] != "PATCH /releases/7" {
		t.Fatalf("writes = %v, want exactly one PATCH of the existing release", f.writes)
	}
	if rel := f.releases["v1.4.0-alpha"]; rel.Body != "### Added\n\n- a thing" || !rel.Prerelease || rel.Name != "v1.4.0-alpha" || rel.Target != fakeSHA {
		t.Fatalf("release not converged: %+v", rel)
	}
}

func TestScriptsReleasePublish_RefusesWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(f *fakeForge)
		env     func(api string) map[string]string
		sha     string
		tag     string
		wantMsg string
		noCalls bool // refused before any request
	}{
		{
			name: "tag missing on the forge", setup: func(*fakeForge) {},
			wantMsg: "does not exist on the forge",
		},
		{
			name: "tag names a different commit", setup: func(f *fakeForge) { f.tagSHA["v1.4.0-alpha"] = otherSHA },
			wantMsg: "but the gate ran on",
		},
		{
			name: "GitHub endpoint", env: func(string) map[string]string { return publishEnv("https://api.github.com") },
			wantMsg: "refusing to publish on GitHub", noCalls: true,
		},
		{
			name: "token that could inject curl directives",
			env: func(api string) map[string]string {
				e := publishEnv(api)
				e["FORGE_TOKEN"] = "abc\"\nurl = \"http://example.invalid"
				return e
			},
			wantMsg: "refusing to use it", noCalls: true,
		},
		// Curl-config injection: a token whose second line is a valid token
		// on its own would otherwise become a curl directive.
		{
			name: "multi-line token, a later line valid on its own",
			env: func(api string) map[string]string {
				e := publishEnv(api)
				e["FORGE_TOKEN"] = "x\"\nurl = \"file:///dev/null\"\n" + fakeToken
				return e
			},
			wantMsg: "refusing to use it", noCalls: true,
		},
		{
			name: "multi-line token, the first line valid on its own",
			env: func(api string) map[string]string {
				e := publishEnv(api)
				e["FORGE_TOKEN"] = fakeToken + "\nurl = \"file:///dev/null\""
				return e
			},
			wantMsg: "refusing to use it", noCalls: true,
		},
		{
			name: "token with a trailing newline",
			env: func(api string) map[string]string {
				e := publishEnv(api)
				e["FORGE_TOKEN"] = fakeToken + "\n"
				return e
			},
			wantMsg: "refusing to use it", noCalls: true,
		},
		{name: "multi-line tag", tag: "v1.4.0-alpha\nv1.3.0", wantMsg: "is not vX.Y.Z", noCalls: true},
		{name: "multi-line sha", sha: "zz\n" + fakeSHA, wantMsg: "not a 40-hex", noCalls: true},
		{
			name: "missing token",
			env: func(api string) map[string]string {
				e := publishEnv(api)
				e["FORGE_TOKEN"] = ""
				return e
			},
			wantMsg: "FORGE_TOKEN is unset", noCalls: true,
		},
		{name: "short sha", sha: "abc123", wantMsg: "not a 40-hex", noCalls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeForge()
			if tc.setup != nil {
				tc.setup(f)
			} else {
				f.tagSHA["v1.4.0-alpha"] = fakeSHA
			}
			api := startForge(t, f)
			env := publishEnv(api)
			if tc.env != nil {
				env = tc.env(api)
			}
			sha := fakeSHA
			if tc.sha != "" {
				sha = tc.sha
			}
			tag := "v1.4.0-alpha"
			if tc.tag != "" {
				tag = tc.tag
			}
			dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
			out, ok := runScript(t, dir, env, "release-publish.sh", tag, sha)
			if ok {
				t.Fatalf("published, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
			if len(f.writes) != 0 {
				t.Fatalf("refused, but wrote anyway: %v", f.writes)
			}
			if tc.noCalls && f.requests != 0 {
				t.Fatalf("refused, but made %d request(s) first", f.requests)
			}
		})
	}
}

// TestScriptsReleasePublish_RefusesEverySpellingOfGitHub pins that the refusal
// tests the host, so no spelling of a github.com endpoint (case, port, scheme,
// userinfo, trailing dot, bare domain, another subdomain) gets through, nor a
// URL whose host cannot be verified. All are refused before any request.
func TestScriptsReleasePublish_RefusesEverySpellingOfGitHub(t *testing.T) {
	for _, api := range []string{
		"https://api.github.com",
		"https://api.github.com/",
		"https://api.github.com:443",
		"https://api.github.com:443/repos",
		"HTTPS://API.GITHUB.COM/",
		"https://Api.GitHub.Com",
		"http://api.github.com",
		"https://token@api.github.com",
		"https://user:pass@api.github.com:8443/x",
		"https://api.github.com./",
		"https://api.github.com..",
		"https://github.com/api/v3",
		"https://uploads.github.com",
		"https://api.github.com?x=1",
		"https://api.github.com#frag",
	} {
		t.Run(api, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
			out, ok := runScript(t, dir, publishEnv(api), "release-publish.sh", "v1.4.0-alpha", fakeSHA)
			if ok || !strings.Contains(out, "refusing to publish on GitHub") {
				t.Fatalf("not refused as GitHub (ok=%v):\n%s", ok, out)
			}
		})
	}
	for api, wantMsg := range map[string]string{
		"https://api.github.com\\@evil.example": "characters a URL does not",
		"https://api.github.com\n":              "characters a URL does not",
		"https://[::1]/api/v1":                  "characters a URL does not",
		"https://":                              "no host this script can verify",
		"ftp://git.example.com/api/v1":          "not an http(s) URL",
	} {
		dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
		out, ok := runScript(t, dir, publishEnv(api), "release-publish.sh", "v1.4.0-alpha", fakeSHA)
		if ok || !strings.Contains(out, wantMsg) {
			t.Fatalf("%q: not refused with %q (ok=%v):\n%s", api, wantMsg, ok, out)
		}
	}
}

// TestScriptsReleasePublish_AHostMerelyNamingGitHubIsAForge pins that the
// refusal is exact, not a substring match. curl resolves any *.localhost name
// to loopback, so these hosts reach the local fake forge and publish.
func TestScriptsReleasePublish_AHostMerelyNamingGitHubIsAForge(t *testing.T) {
	for _, host := range []string{"github.com.localhost", "notgithub.localhost"} {
		t.Run(host, func(t *testing.T) {
			f := newFakeForge()
			f.tagSHA["v1.4.0-alpha"] = fakeSHA
			api := startForge(t, f)
			api = strings.Replace(api, "127.0.0.1", host, 1)
			dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
			out, ok := runScript(t, dir, publishEnv(api), "release-publish.sh", "v1.4.0-alpha", fakeSHA)
			if !ok || f.releases["v1.4.0-alpha"] == nil {
				t.Fatalf("%s did not publish (ok=%v):\n%s", api, ok, out)
			}
		})
	}
}

func TestScriptsReleasePublish_FailsWhenTheForgeDoesNotKeepWhatWasSent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(f *fakeForge)
		wantMsg string
	}{
		{"write refused", func(f *fakeForge) { f.failWrite = true }, "HTTP 500"},
		{"body altered on store", func(f *fakeForge) { f.mangle = func(s string) string { return s + "\nextra" } }, "does not match what was sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeForge()
			f.tagSHA["v1.4.0-alpha"] = fakeSHA
			tc.setup(f)
			dir := writeTree(t, map[string]string{"CHANGELOG.md": checkTagChangelog})
			out, ok := runScript(t, dir, publishEnv(startForge(t, f)), "release-publish.sh", "v1.4.0-alpha", fakeSHA)
			if ok {
				t.Fatalf("reported success:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("failure does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// consumer-check.sh, against this working tree served as a published module.

const (
	modulePath    = "github.com/jeremyhahn/go-enclave"
	fakeModuleVer = "v0.999.0-buildgate"
)

// writeModuleProxy lays out a GOPROXY=file:// directory serving the working
// tree as modulePath@version: the files git would publish (tracked, plus
// untracked-but-not-ignored, so a change is judged before it is committed),
// minus nested modules, as a module zip.
func writeModuleProxy(t *testing.T, root, version string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var nested []string
	var files []string
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if f == "" {
			continue
		}
		if strings.HasSuffix(f, "/go.mod") {
			nested = append(nested, strings.TrimSuffix(f, "go.mod"))
		}
		files = append(files, f)
	}
	proxy := t.TempDir()
	vdir := filepath.Join(proxy, filepath.FromSlash(modulePath), "@v")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	zf, err := os.Create(filepath.Join(vdir, version+".zip"))
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(zf)
	added := 0
files:
	for _, f := range files {
		for _, n := range nested {
			if strings.HasPrefix(f, n) {
				continue files
			}
		}
		fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(f)))
		if errors.Is(err, os.ErrNotExist) {
			continue // deleted in the working tree, not yet in the index
		}
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s: not a regular file (%v)", f, err)
		}
		w, err := zw.Create(modulePath + "@" + version + "/" + f)
		if err != nil {
			t.Fatalf("zip: %v", err)
		}
		src, err := os.Open(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := io.Copy(w, src); err != nil {
			t.Fatalf("zip %s: %v", f, err)
		}
		_ = src.Close()
		added++
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := zf.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if added < 20 {
		t.Fatalf("only %d files went into the module zip; the listing is broken", added)
	}
	gomod := readFile(t, filepath.Join(root, "go.mod"))
	if err := os.WriteFile(filepath.Join(vdir, version+".mod"), []byte(gomod), 0o644); err != nil {
		t.Fatalf("write mod: %v", err)
	}
	info := fmt.Sprintf(`{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
	if err := os.WriteFile(filepath.Join(vdir, version+".info"), []byte(info), 0o644); err != nil {
		t.Fatalf("write info: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vdir, "list"), []byte(version+"\n"), 0o644); err != nil {
		t.Fatalf("write list: %v", err)
	}
	return proxy
}

// consumerEnv points the script at the local proxy, falling back to the
// already-verified module cache for go-enclave's own dependencies, so the run
// needs no network. GOSUMDB is off only in this subprocess: the module is the
// working tree under a version no checksum database has seen, and the cache
// verified the dependencies when it fetched them. release.yml exercises the
// network path on every tag.
func consumerEnv(t *testing.T, proxy string) map[string]string {
	t.Helper()
	root := repoRoot(t)
	// The fallback must hold the root module's dependencies; fetching them is
	// a no-op on any machine that has built the module.
	dl := exec.Command("go", "mod", "download")
	dl.Dir = root
	dl.Env = layerEnv(os.Environ(), map[string]string{"GOWORK": "off", "GOFLAGS": ""})
	if out, err := dl.CombinedOutput(); err != nil {
		t.Fatalf("go mod download in the repository: %v\n%s", err, out)
	}
	modcache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	// GOENV=off: the go command reads an empty variable as unset and falls
	// back to the user's go env file, whose GOPRIVATE could send the fetch
	// past this proxy.
	return map[string]string{
		"GOENV":       "off",
		"GOPROXY":     "file://" + proxy + ",file://" + filepath.Join(strings.TrimSpace(string(modcache)), "cache", "download"),
		"GOSUMDB":     "off",
		"GOPRIVATE":   "",
		"GONOPROXY":   "",
		"GONOSUMDB":   "",
		"GOFLAGS":     "",
		"GOTOOLCHAIN": "local",
		"TMPDIR":      t.TempDir(),
	}
}

func TestScriptsConsumerCheck_TheWorkingTreeServesAWorkingConsumer(t *testing.T) {
	root := repoRoot(t)
	env := consumerEnv(t, writeModuleProxy(t, root, fakeModuleVer))
	out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", modulePath, fakeModuleVer)
	if !ok {
		t.Fatalf("the consumer of this tree failed. If the public API changed, update scripts/testdata/consumer/main.go in the same change.\n%s", out)
	}
	if !strings.Contains(out, modulePath+"@"+fakeModuleVer+" builds and runs") {
		t.Fatalf("no success line:\n%s", out)
	}
	left, err := os.ReadDir(env["TMPDIR"])
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("the scratch consumer was not removed: %v", left)
	}
}

func TestScriptsConsumerCheck_RefusesWhatItCannotResolve(t *testing.T) {
	root := repoRoot(t)
	env := consumerEnv(t, writeModuleProxy(t, root, fakeModuleVer))
	for _, tc := range []struct {
		name, module, version, wantMsg string
	}{
		{"version not published", modulePath, "v0.999.1-missing", "go get " + modulePath + "@v0.999.1-missing failed"},
		{"not a version", modulePath, "latest", "not vX.Y.Z"},
		{"not a module path", "../go-enclave", fakeModuleVer, "not a module path"},
		{"multi-line module path", "../x\n" + modulePath, fakeModuleVer, "not a module path"},
		{"multi-line version", modulePath, "x\n" + fakeModuleVer, "not vX.Y.Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", tc.module, tc.version)
			if ok {
				t.Fatalf("succeeded, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// tool.sh

// fakeTool writes an executable shell script named name into dir that prints
// output.
func fakeTool(t *testing.T, dir, name, output string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(dir, name)
	body := "#!/bin/sh\ncat <<'EOF'\n" + output + "\nEOF\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// toolUtilities are the external commands scripts/tool.sh and the fixtures
// run, and nothing else. Resolver tests put only these (plus fixtures) on
// PATH, so a real copy of a tool on the runner, such as an image's shellcheck,
// cannot answer for an "absent" fixture.
var toolUtilities = []string{
	"sh", "cat", "chmod", "cut", "grep", "mkdir", "mktemp", "mv", "printenv",
	"rm", "sed", "sha256sum", "tar", "uname",
}

// toolUtilitiesOptional are needed only by paths a test may not reach (tar's
// decompressors); linked when present.
var toolUtilitiesOptional = []string{"gzip", "xz"}

// isolatedPath returns a directory holding a symlink to each tool utility and
// nothing else.
func isolatedPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	link := func(name string, required bool) {
		p, err := exec.LookPath(name)
		if err != nil {
			if required {
				t.Fatalf("%s is required to run the resolver tests: %v", name, err)
			}
			return
		}
		if err := os.Symlink(p, filepath.Join(dir, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	for _, u := range toolUtilities {
		link(u, true)
	}
	for _, u := range toolUtilitiesOptional {
		link(u, false)
	}
	return dir
}

// requireAbsent fails the test unless name is undiscoverable on the PATH in
// env, the precondition every "absent" case depends on.
func requireAbsent(t *testing.T, env map[string]string, name string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `command -v "$1"`, "sh", name)
	cmd.Env = layerEnv(os.Environ(), env)
	if out, err := cmd.Output(); err == nil {
		t.Fatalf("the fixture PATH still resolves %s to %s; the absent case would test the machine, not the resolver", name, strings.TrimSpace(string(out)))
	}
}

// toolEnv runs tool.sh with only bin (the test's fixtures) and an isolated
// utility directory on PATH, so no real copy of a tool can answer for the
// fake.
func toolEnv(t *testing.T, bin string, over map[string]string) map[string]string {
	t.Helper()
	// A go that only reports the toolchain TOOLCHAIN names as the builder of
	// any binary; every other invocation (an install attempt) fails loudly.
	goCmd := filepath.Join(t.TempDir(), "go")
	goScript := "#!/bin/sh\n" +
		"if [ \"$1\" = version ] && [ $# -eq 2 ]; then echo \"$2: go1.27.1\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(goCmd, []byte(goScript), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}
	env := map[string]string{
		"PATH":         bin + ":" + isolatedPath(t),
		"TOOL_INSTALL": "0",
		"TOOLS_DIR":    "",
		"TOOLCHAIN":    "go1.27.1",
		"GO":           goCmd,
	}
	for _, k := range []string{"TRIVY", "SHELLCHECK"} {
		for _, kind := range []string{"SHA256", "BIN_SHA256"} {
			for _, arch := range []string{"AMD64", "ARM64"} {
				env[k+"_"+kind+"_LINUX_"+arch] = strings.Repeat("a", 64)
			}
		}
	}
	for k, v := range over {
		env[k] = v
	}
	return env
}

// The version each tool really prints, including shapes that carry a second
// version (the Go toolchain's) that a careless parse would read instead.
// actionlint is not here: it is never taken from PATH
// (TestScriptsToolResolve_ActionlintIgnoresToolInstallZero).
var toolOutputs = []struct {
	tool, version, output string
}{
	{"golangci-lint", "v2.14.0", "golangci-lint has version 2.14.0 built with go1.26.7 from (unknown, modified: ?, mod sum: \"h1:x\") on (unknown)"},
	{"golangci-lint", "v2.14.0", "golangci-lint has version v2.14.0 built with go1.27.1 from 1234abcd on 2026-09-01T00:00:00Z"},
	{"staticcheck", "v0.8.1", "staticcheck 2026.2.1 (0.8.1)"},
	{"gosec", "v2.29.0", "Version: v2.29.0\nGit tag: \nBuild date: "},
	{"govulncheck", "v1.8.0", "Scanner: govulncheck@v1.8.0\nGo: go1.27.1\nDB: https://vuln.go.dev"},
	{"govulncheck", "v1.8.0", "Go: go1.27.1\nScanner: govulncheck@v1.8.0\nDB: https://vuln.go.dev"},
	{"trivy", "v0.75.0", "Version: 0.75.0\nVulnerability DB:\n  Version: 2"},
	{"shellcheck", "v0.11.0", "ShellCheck - shell script analysis tool\nversion: 0.11.0\nlicense: GNU General Public License, version 3\nwebsite: https://www.shellcheck.net"},
}

// pinBinary pins the SHA-256 of the file at p as the binary hash of tool on
// both architectures, when tool is installed from a release archive (TOOL_INSTALL=0
// then requires the binary to hash to it). Other tools are left alone.
func pinBinary(t *testing.T, env map[string]string, tool, p string) map[string]string {
	t.Helper()
	prefix := strings.ToUpper(tool)
	if tool != "trivy" && tool != "shellcheck" {
		return env
	}
	sum := sha256Hex(t, p)
	return mergeEnv(env, map[string]string{
		prefix + "_BIN_SHA256_LINUX_AMD64": sum,
		prefix + "_BIN_SHA256_LINUX_ARM64": sum,
	})
}

func TestScriptsToolResolve_AcceptsThePinnedVersionInEveryOutputShape(t *testing.T) {
	for _, tc := range toolOutputs {
		t.Run(tc.tool+"/"+tc.version, func(t *testing.T) {
			bin := t.TempDir()
			want := fakeTool(t, bin, tc.tool, tc.output)
			out, ok := runScript(t, t.TempDir(), pinBinary(t, toolEnv(t, bin, nil), tc.tool, want), "tool.sh", tc.tool, tc.version)
			if !ok {
				t.Fatalf("refused the pinned version:\n%s", out)
			}
			if strings.TrimSpace(out) != want {
				t.Fatalf("printed %q, want the path %q", out, want)
			}
		})
	}
}

func TestScriptsToolResolve_FailsClosedOnAnythingElse(t *testing.T) {
	for _, tc := range []struct {
		name, tool, version, output, wantMsg string
		env                                  map[string]string
		absent                               bool
	}{
		{name: "another version", tool: "golangci-lint", version: "v2.15.0", output: toolOutputs[0].output, wantMsg: "is v2.14.0, but the Makefile pins v2.15.0"},
		{name: "the Go version is not the tool's", tool: "golangci-lint", version: "v1.26.7", output: toolOutputs[0].output, wantMsg: "is v2.14.0"},
		{name: "unversioned gosec", tool: "gosec", version: "v2.29.0", output: "Version: dev\nGit tag: ", wantMsg: "does not report a version"},
		{name: "unversioned trivy", tool: "trivy", version: "v0.75.0", output: "Version: dev", wantMsg: "does not report a version"},
		{name: "unparseable", tool: "staticcheck", version: "v0.8.1", output: "staticcheck (devel)", wantMsg: "does not report a version"},
		{name: "shellcheck from another distro", tool: "shellcheck", version: "v0.11.0", output: "ShellCheck - shell script analysis tool\nversion: 0.10.0", wantMsg: "is v0.10.0, but the Makefile pins v0.11.0"},
		{name: "built by another Go", tool: "gosec", version: "v2.29.0", output: "Version: v2.29.0", env: map[string]string{"TOOLCHAIN": "go1.28.0"}, wantMsg: "was built with 'go1.27.1', but this module's toolchain is go1.28.0"},
		{name: "absent", tool: "govulncheck", version: "v1.8.0", absent: true, wantMsg: "not on PATH and TOOL_INSTALL=0 forbids installing it"},
		{name: "absent shellcheck", tool: "shellcheck", version: "v0.11.0", absent: true, wantMsg: "not on PATH and TOOL_INSTALL=0 forbids installing it"},
		{name: "TOOL_INSTALL unset", tool: "gosec", version: "v2.29.0", output: "Version: v2.29.0", env: map[string]string{"TOOL_INSTALL": ""}, wantMsg: "TOOL_INSTALL must be 0"},
		{name: "TOOL_INSTALL yes", tool: "gosec", version: "v2.29.0", output: "Version: v2.29.0", env: map[string]string{"TOOL_INSTALL": "yes"}, wantMsg: "TOOL_INSTALL must be 0"},
		{name: "unknown tool", tool: "sh", version: "v1.0.0", output: "", wantMsg: "unknown tool"},
		{name: "floating version", tool: "gosec", version: "latest", output: "Version: v2.29.0", wantMsg: "not a pinned vX.Y.Z"},
		// A second line that is itself a valid pin must not carry the value.
		{name: "multi-line version", tool: "gosec", version: "../../x\nv2.29.0", output: "Version: v2.29.0", wantMsg: "not a pinned vX.Y.Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			env := toolEnv(t, bin, tc.env)
			if !tc.absent {
				env = pinBinary(t, env, tc.tool, fakeTool(t, bin, tc.tool, tc.output))
			}
			if tc.absent {
				requireAbsent(t, env, tc.tool)
			}
			out, ok := runScript(t, t.TempDir(), env, "tool.sh", tc.tool, tc.version)
			if ok {
				t.Fatalf("accepted, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// TestScriptsToolResolve_ArchiveToolOnPathMustHashToThePin pins that
// TOOL_INSTALL=0 does not take an archive tool's word for its version: a
// binary that prints the pinned version but hashes to something else is
// refused, and is not executed to find out.
func TestScriptsToolResolve_ArchiveToolOnPathMustHashToThePin(t *testing.T) {
	for _, tc := range []struct{ tool, version, output string }{
		{"trivy", "v0.75.0", "Version: 0.75.0"},
		{"shellcheck", "v0.11.0", "ShellCheck - shell script analysis tool\nversion: 0.11.0"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			bin := t.TempDir()
			marker := filepath.Join(t.TempDir(), "ran")
			planted := filepath.Join(bin, tc.tool)
			body := "#!/bin/sh\n: > " + marker + "\ncat <<'EOF'\n" + tc.output + "\nEOF\n"
			if err := os.WriteFile(planted, []byte(body), 0o755); err != nil {
				t.Fatalf("write %s: %v", planted, err)
			}

			// The pins (all "a"s) are not this binary's hash.
			env := toolEnv(t, bin, nil)
			out, ok := runScript(t, t.TempDir(), env, "tool.sh", tc.tool, tc.version)
			if ok || !strings.Contains(out, "does not hash to the pinned binary SHA-256") {
				t.Fatalf("accepted a %s that reports the pin but hashes to something else (ok=%v):\n%s", tc.tool, ok, out)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("executed the unverified %s (stat: %v)", tc.tool, err)
			}

			// A missing pin is no pin.
			prefix := strings.ToUpper(tc.tool)
			missing := mergeEnv(env, map[string]string{prefix + "_BIN_SHA256_LINUX_AMD64": "", prefix + "_BIN_SHA256_LINUX_ARM64": ""})
			out, ok = runScript(t, t.TempDir(), missing, "tool.sh", tc.tool, tc.version)
			if ok || !strings.Contains(out, "missing or malformed") {
				t.Fatalf("accepted a %s with no pinned binary SHA-256 (ok=%v):\n%s", tc.tool, ok, out)
			}

			// The pinned hash is accepted.
			out, ok = runScript(t, t.TempDir(), pinBinary(t, env, tc.tool, planted), "tool.sh", tc.tool, tc.version)
			if !ok || strings.TrimSpace(out) != planted {
				t.Fatalf("refused a %s that hashes to its pin (ok=%v):\n%s", tc.tool, ok, out)
			}
		})
	}
}

// buildFakeGoTool compiles a real Go binary that prints output, so `go
// version <binary>` reads genuine build metadata from it, and returns the
// binary and the toolchain that built it.
func buildFakeGoTool(t *testing.T, output string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	src := fmt.Sprintf("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(%q) }\n", output)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/faketool\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	env := layerEnv(os.Environ(), map[string]string{"GOWORK": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local"})
	build := exec.Command("go", "build", "-o", "faketool", ".")
	build.Dir = dir
	build.Env = env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the fake tool: %v\n%s", err, out)
	}
	ver := exec.Command("go", "env", "GOVERSION")
	ver.Dir = dir
	ver.Env = env
	tc, err := ver.Output()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v", err)
	}
	return filepath.Join(dir, "faketool"), strings.TrimSpace(string(tc))
}

// fakeGo writes a go command that answers `go version <file>` with the real
// go and logs and fails every other invocation, so a test can tell a reuse
// from a reinstall attempt without the network.
func fakeGo(t *testing.T, log string) string {
	t.Helper()
	real, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required: %v", err)
	}
	p := filepath.Join(t.TempDir(), "go")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = version ] && [ $# -eq 2 ]; then exec " + real + " version \"$2\"; fi\n" +
		"echo \"GOTOOLCHAIN=$GOTOOLCHAIN $*\" >> " + log + "\n" +
		"exit 1\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}
	return p
}

func copyExec(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestScriptsToolResolve_ActionlintIgnoresToolInstallZero pins #145/#146:
// actionlint ignores TOOL_INSTALL=0 and is resolved as under TOOL_INSTALL=1. A
// copy on PATH that reports exactly the pin (and was built by the module's Go)
// is used; the CI image's copy, built from an untagged commit, reports a
// pseudo-version and is not, so the pinned tag is built into TOOLS_DIR instead.
// The version check still refuses an unversioned binary.
func TestScriptsToolResolve_ActionlintIgnoresToolInstallZero(t *testing.T) {
	requireLinuxInstallPath(t)
	const pin = "v1.7.12"
	pseudo := "v1.7.13-0.20260419144658-011a6d15e749\ninstalled by building from source\nbuilt with go1.27.1 compiler for linux/amd64"
	genuine := pin + "\ninstalled by building from source\nbuilt with go1.27.1 compiler for linux/amd64"

	for _, mode := range []string{"0", "1"} {
		t.Run("TOOL_INSTALL="+mode, func(t *testing.T) {
			image, toolchain := buildFakeGoTool(t, pseudo)
			real, _ := buildFakeGoTool(t, genuine)
			bin := t.TempDir()
			onPath := filepath.Join(bin, "actionlint")
			tools := t.TempDir()
			cached := filepath.Join(tools, "actionlint-"+pin+"-"+toolchain, "actionlint")
			log := filepath.Join(t.TempDir(), "go.log")
			run := func() (string, bool, string) {
				t.Helper()
				_ = os.Remove(log)
				env := toolEnv(t, bin, map[string]string{
					"TOOL_INSTALL": mode, "TOOLS_DIR": tools, "TOOLCHAIN": toolchain, "GO": fakeGo(t, log),
				})
				out, ok := runScript(t, t.TempDir(), env, "tool.sh", "actionlint", pin)
				calls, _ := os.ReadFile(log)
				return out, ok, string(calls)
			}

			// A PATH copy reporting a pseudo-version is not used: the pinned
			// tag is installed instead (the fake go fails it, so the run fails).
			copyExec(t, image, onPath)
			out, ok, calls := run()
			if ok || !strings.Contains(calls, "GOTOOLCHAIN="+toolchain+" install github.com/rhysd/actionlint/cmd/actionlint@"+pin) {
				t.Fatalf("did not build actionlint %s from source (ok=%v, go calls %q):\n%s", pin, ok, calls, out)
			}
			if !strings.Contains(out, "is not the pinned build") {
				t.Fatalf("the PATH copy's refusal is not reported:\n%s", out)
			}

			// A PATH copy reporting exactly the pin is used, with no install.
			copyExec(t, real, onPath)
			if out, ok, calls = run(); !ok || strings.TrimSpace(out) != onPath || calls != "" {
				t.Fatalf("did not use the PATH copy at the pin (ok=%v, go calls %q):\n%s", ok, calls, out)
			}

			// An unversioned binary in the project's own directory is refused
			// as well, and reinstalled over.
			copyExec(t, image, onPath)
			copyExec(t, image, cached)
			if out, ok, calls = run(); ok || !strings.Contains(calls, " install") {
				t.Fatalf("trusted a project-built actionlint that reports a pseudo-version (ok=%v, go calls %q):\n%s", ok, calls, out)
			}

			// The genuine pinned build in the project's directory is used with
			// no install, though PATH still carries the image's copy.
			copyExec(t, real, cached)
			// (out carries stderr too; the path is its last line.)
			if out, ok, calls = run(); !ok || !strings.HasSuffix(strings.TrimSpace(out), "\n"+cached) || calls != "" {
				t.Fatalf("did not use the project-built actionlint (ok=%v, go calls %q):\n%s", ok, calls, out)
			}
		})
	}

	// A value that is neither 0 nor 1 is still refused.
	env := toolEnv(t, t.TempDir(), map[string]string{"TOOL_INSTALL": "yes", "TOOLS_DIR": t.TempDir()})
	if out, ok := runScript(t, t.TempDir(), env, "tool.sh", "actionlint", pin); ok || !strings.Contains(out, "TOOL_INSTALL must be 0") {
		t.Fatalf("accepted TOOL_INSTALL=yes for actionlint (ok=%v):\n%s", ok, out)
	}
}

// TestScriptsToolResolve_GoToolCacheIsKeyedByToolchain pins that a cached Go
// tool is reused only for the toolchain that built it.
func TestScriptsToolResolve_GoToolCacheIsKeyedByToolchain(t *testing.T) {
	built, toolchain := buildFakeGoTool(t, "Version: v2.29.0")
	const other = "go1.26.7"
	if toolchain == other {
		t.Fatalf("the test toolchain is %s, the one it uses as 'other'", other)
	}
	tools := t.TempDir()
	log := filepath.Join(t.TempDir(), "go.log")
	run := func(tc string) (string, bool, string) {
		t.Helper()
		_ = os.Remove(log)
		env := toolEnv(t, t.TempDir(), map[string]string{
			"TOOL_INSTALL": "1", "TOOLS_DIR": tools, "TOOLCHAIN": tc, "GO": fakeGo(t, log),
		})
		out, ok := runScript(t, t.TempDir(), env, "tool.sh", "gosec", "v2.29.0")
		calls, _ := os.ReadFile(log)
		return out, ok, string(calls)
	}

	cached := filepath.Join(tools, "gosec-v2.29.0-"+toolchain, "gosec")
	copyExec(t, built, cached)

	// The toolchain that built it: reused, nothing installed.
	out, ok, calls := run(toolchain)
	if !ok || strings.TrimSpace(out) != cached || calls != "" {
		t.Fatalf("did not reuse the cache built by %s (ok=%v, go calls %q):\n%s", toolchain, ok, calls, out)
	}

	// Another toolchain: a different cache entry, so an install under that
	// toolchain.
	out, ok, calls = run(other)
	if ok || !strings.Contains(calls, "GOTOOLCHAIN="+other+" install") {
		t.Fatalf("toolchain %s did not force a reinstall under it (ok=%v, go calls %q):\n%s", other, ok, calls, out)
	}

	// The same binary copied into the other toolchain's directory: its build
	// metadata says otherwise, so it is not trusted on its path.
	copyExec(t, built, filepath.Join(tools, "gosec-v2.29.0-"+other, "gosec"))
	if out, ok, calls = run(other); ok || !strings.Contains(calls, " install") {
		t.Fatalf("trusted a binary whose build metadata names %s under %s (ok=%v, go calls %q):\n%s", toolchain, other, ok, calls, out)
	}

	// A script with the right name and output but no build metadata at all.
	fakeTool(t, filepath.Join(tools, "gosec-v2.29.0-"+toolchain), "gosec", "Version: v2.29.0")
	if out, ok, calls = run(toolchain); ok || !strings.Contains(calls, " install") {
		t.Fatalf("trusted a cached binary with no Go build metadata (ok=%v, go calls %q):\n%s", ok, calls, out)
	}

	// The right toolchain but the wrong version.
	wrong, _ := buildFakeGoTool(t, "Version: v2.28.0")
	copyExec(t, wrong, cached)
	if out, ok, calls = run(toolchain); ok || !strings.Contains(calls, " install") {
		t.Fatalf("trusted a cached binary reporting another version (ok=%v, go calls %q):\n%s", ok, calls, out)
	}

	for name, over := range map[string]map[string]string{
		"relative TOOLS_DIR":     {"TOOLS_DIR": "bin/tools"},
		"no TOOLCHAIN":           {"TOOLCHAIN": ""},
		"multi-line TOOLCHAIN":   {"TOOLCHAIN": "../../x\ngo1.27.1"},
		"TOOLCHAIN not a Go one": {"TOOLCHAIN": "local"},
	} {
		env := toolEnv(t, t.TempDir(), mergeEnv(map[string]string{"TOOL_INSTALL": "1", "TOOLS_DIR": tools}, over))
		if out, ok := runScript(t, t.TempDir(), env, "tool.sh", "staticcheck", "v0.8.1"); ok {
			t.Fatalf("%s: accepted:\n%s", name, out)
		}
	}
}

func requireLinuxInstallPath(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("uname", "-sm").Output(); err != nil || !regexp.MustCompile(`^Linux (x86_64|aarch64|arm64)\s*$`).Match(out) {
		t.Fatalf("this test drives the Linux install path; uname -sm = %q (%v)", out, err)
	}
}

// fakeCurlDir holds a curl that writes body to its -o file and logs each call.
func fakeCurlDir(t *testing.T, body, log string) string {
	t.Helper()
	bin := t.TempDir()
	curl := "#!/bin/sh\n" +
		"echo \"$*\" >> " + log + "\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then out=$2; shift; fi; shift; done\n" +
		"printf '%s' '" + body + "' > \"$out\"\n"
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o755); err != nil {
		t.Fatalf("write curl: %v", err)
	}
	return bin
}

func sha256Hex(t *testing.T, p string) string {
	t.Helper()
	out, err := exec.Command("sha256sum", p).Output()
	if err != nil {
		t.Fatalf("sha256sum: %v", err)
	}
	return strings.Fields(string(out))[0]
}

// TestScriptsToolResolve_ArchiveToolsAreTrustedOnlyThroughPinnedHashes serves
// a tampered archive through a fake curl: the install must refuse it and leave
// nothing where the next run would look. A cached archive tool is reused only
// when its bytes hash to the pinned binary SHA-256.
func TestScriptsToolResolve_ArchiveToolsAreTrustedOnlyThroughPinnedHashes(t *testing.T) {
	requireLinuxInstallPath(t)
	for _, tc := range []struct{ tool, version, output, prefix string }{
		{"trivy", "v0.75.0", "Version: 0.75.0", "TRIVY"},
		{"shellcheck", "v0.11.0", "ShellCheck - shell script analysis tool\nversion: 0.11.0", "SHELLCHECK"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "curl.log")
			tools := t.TempDir()
			env := toolEnv(t, fakeCurlDir(t, "not the release", log), map[string]string{"TOOL_INSTALL": "1", "TOOLS_DIR": tools})

			out, ok := runScript(t, t.TempDir(), env, "tool.sh", tc.tool, tc.version)
			if ok || !strings.Contains(out, "CHECKSUM MISMATCH") {
				t.Fatalf("accepted an archive that does not match the pin (ok=%v):\n%s", ok, out)
			}
			cached := filepath.Join(tools, tc.tool+"-"+tc.version, tc.tool)
			if _, err := os.Stat(cached); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused install left a binary behind (stat: %v)", err)
			}

			// A cached binary whose bytes match the pinned binary hash is
			// reused without a download.
			fakeTool(t, filepath.Dir(cached), tc.tool, tc.output)
			pinned := mergeEnv(env, nil)
			for _, arch := range []string{"AMD64", "ARM64"} {
				pinned[tc.prefix+"_BIN_SHA256_LINUX_"+arch] = sha256Hex(t, cached)
			}
			_ = os.Remove(log)
			out, ok = runScript(t, t.TempDir(), pinned, "tool.sh", tc.tool, tc.version)
			if _, err := os.Stat(log); !ok || strings.TrimSpace(out) != cached || !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("did not reuse a cached binary matching the pinned hash (ok=%v, curl log stat %v):\n%s", ok, err, out)
			}

			// The same self-reported version with other bytes is not trusted:
			// it is re-downloaded (and the tampered download refused).
			_ = os.Remove(log)
			out, ok = runScript(t, t.TempDir(), env, "tool.sh", tc.tool, tc.version)
			if _, err := os.Stat(log); ok || err != nil {
				t.Fatalf("trusted a cached binary on its self-reported version (ok=%v, curl log stat %v):\n%s", ok, err, out)
			}

			for _, kind := range []string{"SHA256", "BIN_SHA256"} {
				missing := mergeEnv(env, map[string]string{tc.prefix + "_" + kind + "_LINUX_AMD64": "", tc.prefix + "_" + kind + "_LINUX_ARM64": ""})
				out, ok = runScript(t, t.TempDir(), missing, "tool.sh", tc.tool, tc.version)
				if ok || !strings.Contains(out, "missing or malformed") {
					t.Fatalf("installed with no pinned %s (ok=%v):\n%s", kind, ok, out)
				}
			}
		})
	}
}

// TestScriptsToolResolve_UsesAVerifiedCopyOnPath pins that TOOL_INSTALL=1 uses
// a tool already on PATH (the devcontainer bakes every pin into
// /usr/local/bin) when it proves what a cached install must, and installs
// rather than trust one that does not.
func TestScriptsToolResolve_UsesAVerifiedCopyOnPath(t *testing.T) {
	requireLinuxInstallPath(t)

	t.Run("go tool", func(t *testing.T) {
		built, toolchain := buildFakeGoTool(t, "Version: v2.29.0")
		bin := t.TempDir()
		onPath := filepath.Join(bin, "gosec")
		copyExec(t, built, onPath)
		tools := t.TempDir()
		log := filepath.Join(t.TempDir(), "go.log")
		run := func(tc string) (string, bool, string) {
			t.Helper()
			_ = os.Remove(log)
			env := toolEnv(t, bin, map[string]string{
				"TOOL_INSTALL": "1", "TOOLS_DIR": tools, "TOOLCHAIN": tc, "GO": fakeGo(t, log),
			})
			out, ok := runScript(t, t.TempDir(), env, "tool.sh", "gosec", "v2.29.0")
			calls, _ := os.ReadFile(log)
			return out, ok, string(calls)
		}

		if out, ok, calls := run(toolchain); !ok || strings.TrimSpace(out) != onPath || calls != "" {
			t.Fatalf("did not use the verified copy on PATH (ok=%v, go calls %q):\n%s", ok, calls, out)
		}
		// Built by another toolchain: not the pinned build, so an install.
		if out, ok, calls := run("go1.26.7"); ok || !strings.Contains(calls, " install") || !strings.Contains(out, "is not the pinned build") {
			t.Fatalf("trusted a copy on PATH built by another toolchain (ok=%v, go calls %q):\n%s", ok, calls, out)
		}
		// The right toolchain but another version.
		wrong, _ := buildFakeGoTool(t, "Version: v2.28.0")
		copyExec(t, wrong, onPath)
		if out, ok, calls := run(toolchain); ok || !strings.Contains(calls, " install") {
			t.Fatalf("trusted a copy on PATH reporting another version (ok=%v, go calls %q):\n%s", ok, calls, out)
		}
	})

	t.Run("archive tool", func(t *testing.T) {
		log := filepath.Join(t.TempDir(), "curl.log")
		bin := fakeCurlDir(t, "not the release", log)
		onPath := fakeTool(t, bin, "trivy", "Version: 0.75.0")
		tools := t.TempDir()
		env := toolEnv(t, bin, map[string]string{"TOOL_INSTALL": "1", "TOOLS_DIR": tools})
		pinned := mergeEnv(env, map[string]string{
			"TRIVY_BIN_SHA256_LINUX_AMD64": sha256Hex(t, onPath),
			"TRIVY_BIN_SHA256_LINUX_ARM64": sha256Hex(t, onPath),
		})

		out, ok := runScript(t, t.TempDir(), pinned, "tool.sh", "trivy", "v0.75.0")
		if _, err := os.Stat(log); !ok || strings.TrimSpace(out) != onPath || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("did not use the copy on PATH matching the pinned hash (ok=%v, curl log stat %v):\n%s", ok, err, out)
		}
		// The same self-reported version with other bytes is downloaded
		// instead, and the tampered download refused.
		out, ok = runScript(t, t.TempDir(), env, "tool.sh", "trivy", "v0.75.0")
		if _, err := os.Stat(log); ok || err != nil || !strings.Contains(out, "CHECKSUM MISMATCH") {
			t.Fatalf("trusted a copy on PATH on its self-reported version (ok=%v, curl log stat %v):\n%s", ok, err, out)
		}
	})
}

// ---------------------------------------------------------------------------
// release-version-check.sh

// versionCheckTree makes a scratch git repository holding VERSION and the
// given tags, isolated from the user's and system git configuration.
func versionCheckTree(t *testing.T, version string, tags ...string) (string, map[string]string) {
	t.Helper()
	dir := writeTree(t, map[string]string{"VERSION": version})
	env := map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = layerEnv(os.Environ(), env)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "root")
	for _, tag := range tags {
		git("tag", tag)
	}
	return dir, env
}

func TestScriptsReleaseVersionCheck_RequiresStrictlyGreaterThanVersionAndEveryTag(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		tags          []string
		next          string
		ok            bool
		wantMsg       string
	}{
		{"next alpha patch", "0.2.0", []string{"v0.1.0-alpha", "v0.2.0-alpha", "v0.2.0"}, "v0.2.1-alpha", true, ""},
		{"next minor", "0.2.0", []string{"v0.2.0"}, "v0.3.0-alpha", true, ""},
		{"candidate above the alpha", "0.3.0-alpha", []string{"v0.3.0-alpha"}, "v0.3.0-rc.1", true, ""},
		{"candidate numbers numerically", "0.3.0-rc.2", []string{"v0.3.0-rc.2"}, "v0.3.0-rc.10", true, ""},
		{"lower candidate", "0.3.0-rc.10", []string{"v0.3.0-rc.10"}, "v0.3.0-rc.2", false, "VERSION (v0.3.0-rc.10)"},
		{"alpha below the candidate", "0.3.0-rc.1", []string{"v0.3.0-rc.1"}, "v0.3.0-alpha", false, "VERSION (v0.3.0-rc.1)"},
		{"release above its candidates", "0.3.0-rc.12", []string{"v0.3.0-rc.12"}, "v0.3.0", true, ""},
		{"no tags yet", "0.1.0-alpha", nil, "v0.1.0", true, ""},
		{"equal to VERSION and the tag", "0.2.0", []string{"v0.2.0"}, "v0.2.0", false, "VERSION (v0.2.0)"},
		{"pre-release of the current release", "0.2.0", []string{"v0.2.0"}, "v0.2.0-alpha", false, "v0.2.0 (v0.2.0)"},
		{"lower patch", "0.2.0", []string{"v0.2.0"}, "v0.1.9", false, "VERSION"},
		{"below a tag VERSION trails", "0.2.0", []string{"v0.2.0", "v0.4.0-alpha"}, "v0.3.0-alpha", false, "v0.4.0-alpha (v0.4.0-alpha)"},
		{"below a VERSION that leads the tags", "0.5.0-alpha", []string{"v0.2.0"}, "v0.4.0-alpha", false, "VERSION (v0.5.0-alpha)"},
		// SemVer 2.0.0 §11 pre-release precedence.
		{"numeric identifiers numerically", "1.0.0-alpha.2", []string{"v1.0.0-alpha.2"}, "v1.0.0-alpha.10", true, ""},
		{"numeric below alphanumeric", "1.0.0-alpha.2", []string{"v1.0.0-alpha.2"}, "v1.0.0-alpha.beta", true, ""},
		{"shorter identifier list is lower", "1.0.0-alpha.2", []string{"v1.0.0-alpha.2"}, "v1.0.0-alpha", false, "VERSION"},
		{"lower numeric identifier", "1.0.0-alpha.2", []string{"v1.0.0-alpha.2"}, "v1.0.0-alpha.1", false, "VERSION"},
		{"release above its pre-releases", "1.0.0-alpha.2", []string{"v1.0.0-alpha.2"}, "v1.0.0", true, ""},
		{"multi-digit components numerically", "0.9.0", []string{"v0.9.0"}, "v0.10.0", true, ""},
		// Identifiers are compared as strings, never as AWK numbers: "1e10"
		// is alphanumeric and sorts below "1e2" in ASCII, and numerics past
		// 2^53 must not collapse to the same double.
		{"exponent-shaped alphanumerics in ASCII order", "1.0.0-1e2", nil, "v1.0.0-1e10", false, "VERSION (v1.0.0-1e2)"},
		{"exponent-shaped alphanumerics, upward", "1.0.0-1e10", nil, "v1.0.0-1e2", true, ""},
		{"numerically equal alphanumerics differ", "1.0.0-10e1", nil, "v1.0.0-1e2", true, ""},
		{"pre-release numerics beyond 2^53", "1.0.0-alpha.9007199254740992", nil, "v1.0.0-alpha.9007199254740993", true, ""},
		{"pre-release numerics beyond 2^53, downward", "1.0.0-alpha.9007199254740993", nil, "v1.0.0-alpha.9007199254740992", false, "VERSION"},
		{"core numerics beyond 2^53", "9007199254740992.0.0", nil, "v9007199254740993.0.0", true, ""},
		{"numeric below an exponent-shaped alphanumeric", "1.0.0-rc.100", nil, "v1.0.0-rc.1e2", true, ""},
		{"exponent-shaped alphanumeric above a numeric", "1.0.0-rc.1e2", nil, "v1.0.0-rc.100", false, "VERSION"},
		{"mixed alphanumeric above a larger numeric", "1.0.0-alpha.10", nil, "v1.0.0-alpha.9a", true, ""},
		{"build metadata is ignored", "0.2.0", []string{"v0.2.0"}, "v0.2.0+build.5", false, "VERSION"},
		// Refusals of what cannot be ordered.
		{"a tag that is not SemVer", "0.2.0", []string{"v0.2.0", "vnext"}, "v0.3.0", false, "tag 'vnext' is not SemVer"},
		{"leading zero", "0.2.0", nil, "v0.02.1", false, "not a v-prefixed SemVer"},
		{"unprefixed", "0.2.0", nil, "0.3.0", false, "not a v-prefixed SemVer"},
		{"multi-line version", "0.2.0", nil, "v0.1.0\nv0.3.0", false, "not a v-prefixed SemVer"},
		{"VERSION carries the prefix", "v0.2.0", nil, "v0.3.0", false, "not an unprefixed SemVer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, env := versionCheckTree(t, tc.version+"\n", tc.tags...)
			out, ok := runScript(t, dir, env, "release-version-check.sh", tc.next)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v:\n%s", ok, tc.ok, out)
			}
			if !tc.ok && !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not name %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// TestScriptsRelease_ChecksTheVersionBeforeWritingAnything reads the recipes
// the three release targets would run, each the one scripts/release.sh with
// its kind, and requires the
// monotonicity check to come before the first command that writes the tree.
func TestScriptsRelease_ChecksTheVersionBeforeWritingAnything(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct{ target, version, want string }{
		{"release", "v9.9.9", "scripts/release.sh release"},
		{"release-candidate", "v9.9.9-rc.1", "scripts/release.sh candidate"},
		{"release-alpha", "v9.9.9-alpha", "scripts/release.sh alpha"},
	} {
		cmd := exec.Command("make", "-n", "--no-print-directory", tc.target, "VERSION="+tc.version, "AGENT_GIT=/bin/false")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make -n %s: %v\n%s", tc.target, err, out)
		}
		if !strings.Contains(string(out), tc.want) {
			t.Fatalf("%s does not run %q:\n%s", tc.target, tc.want, out)
		}
	}
	body, err := os.ReadFile(filepath.Join(root, "scripts", "release.sh"))
	if err != nil {
		t.Fatalf("read release.sh: %v", err)
	}
	script := string(body)
	check := strings.Index(script, `"$here/release-version-check.sh"`)
	if check < 0 {
		t.Fatalf("release.sh does not run release-version-check.sh:\n%s", script)
	}
	// Every git write goes through the AGENT_GIT wrapper, read as a quoted
	// variable.
	for _, write := range []string{`"$here/changelog-assemble.sh"`, "> VERSION", `"$agent_git" "$repo_name" add `, `"$agent_git" "$repo_name" commit `, `"$agent_git" "$repo_name" tag -a `, `"$agent_git" "$repo_name" push `} {
		at := strings.Index(script, write)
		if at < 0 {
			t.Fatalf("release.sh no longer contains %q; update this test with the script:\n%s", write, script)
		}
		if at < check {
			t.Fatalf("release.sh runs %q before the version check:\n%s", write, script)
		}
	}
}

// releaseRepo is a scratch repository on main for scripts/release.sh: a dev
// remote (a bare repository), one fragment to fold, and a wrapper standing in
// for AGENT_GIT that signs nothing and logs the repo name it was given. It is
// isolated from the user's and system git configuration.
type releaseRepo struct {
	t         *testing.T
	dir, bare string
	env       map[string]string
	forge     *fakeForge // answers the combined commit status; green by default
}

func newReleaseRepo(t *testing.T) *releaseRepo {
	t.Helper()
	dir := writeTree(t, map[string]string{
		"VERSION":              "1.4.0-alpha\n",
		"CHANGELOG.md":         "# Changelog\n\n## [Unreleased]\n\n## [v1.4.0-alpha] - 2026-02-01\n\n### Added\n\n- a thing\n",
		"changelog.d/.gitkeep": "",
		"changelog.d/134-x.md": "### Added\n\n- a candidate\n",
	})
	wrapper := filepath.Join(t.TempDir(), "agent-git")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$0.log\"\nshift\nexec git -c commit.gpgsign=false -c tag.gpgsign=false \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	forge := newFakeForge()
	forge.defaultState = "success"
	r := &releaseRepo{t: t, dir: dir, bare: t.TempDir(), forge: forge, env: map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
		"AGENT_GIT": wrapper, "REPO_NAME": "go-enclave-test", "VERSION": "",
		"FORGE_API_URL": startForge(t, forge), "FORGE_REPOSITORY": "owner/repo", "FORGE_TOKEN": fakeToken,
	}}
	r.git(r.bare, "init", "-q", "--bare")
	r.git(dir, "init", "-q", "-b", "main")
	r.git(dir, "remote", "add", "dev", r.bare)
	r.git(dir, "add", "-A")
	r.git(dir, "commit", "-q", "-m", "root")
	r.git(dir, "push", "-q", "dev", "main")
	return r
}

func (r *releaseRepo) git(dir string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), r.env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// state is everything a refused release must leave alone.
func (r *releaseRepo) state() string {
	return strings.Join([]string{
		r.git(r.dir, "rev-parse", "HEAD"),
		r.git(r.dir, "tag", "-l"),
		r.git(r.bare, "tag", "-l"),
		readFile(r.t, filepath.Join(r.dir, "VERSION")),
		readFile(r.t, filepath.Join(r.dir, "CHANGELOG.md")),
	}, "\x00")
}

// advanceDev lands a commit on dev's main from a second clone, leaving the
// release repository's local main stale.
func (r *releaseRepo) advanceDev(msg string) {
	r.t.Helper()
	other := filepath.Join(r.t.TempDir(), "other")
	r.git(r.t.TempDir(), "clone", "-q", "-b", "main", r.bare, other)
	r.git(other, "commit", "-q", "--allow-empty", "-m", msg)
	r.git(other, "push", "-q", "origin", "HEAD:main")
}

func (r *releaseRepo) run(kind, version string) (string, bool) {
	r.t.Helper()
	return runScript(r.t, r.dir, mergeEnv(r.env, map[string]string{"VERSION": version}), "release.sh", kind)
}

func TestScriptsRelease_RefusesWhatItMustNotPublish(t *testing.T) {
	const forms = "not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"
	for _, tc := range []struct {
		name, kind, version string
		setup               func(r *releaseRepo)
		wantMsg             string
	}{
		{"no version, production", "release", "", nil, "state the version explicitly"},
		{"no version, candidate", "candidate", "", nil, "state the version explicitly"},
		{"no version, alpha", "alpha", "", nil, "state the version explicitly"},
		{"candidate number zero", "candidate", "v1.5.0-rc.0", nil, forms},
		{"candidate number with a leading zero", "candidate", "v1.5.0-rc.01", nil, forms},
		{"candidate without a number", "candidate", "v1.5.0-rc", nil, forms},
		{"unsanctioned pre-release", "candidate", "v1.5.0-beta", nil, forms},
		{"unsanctioned pre-release, production", "release", "v1.5.0-beta", nil, forms},
		{"candidate and alpha at once", "candidate", "v1.5.0-rc.1-alpha", nil, forms},
		{"unprefixed", "candidate", "1.5.0-rc.1", nil, forms},
		{"two components", "release", "v1.5", nil, forms},
		{"leading zero in the core", "release", "v1.05.0", nil, forms},
		{"build metadata", "candidate", "v1.5.0+build", nil, "characters no release version does"},
		{"multi-line", "candidate", "v1.5.0-rc.1\nv1.5.0-rc.2", nil, "characters no release version does"},
		{"no signing wrapper", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["AGENT_GIT"] = "" }, "AGENT_GIT is unset"},
		{"another branch", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.git(r.dir, "checkout", "-q", "-b", "topic") }, "releases are cut from main; you are on topic"},
		{"tag exists locally", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.git(r.dir, "tag", "v1.5.0-rc.1") }, "already exists locally"},
		{"tag exists on the remote", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.git(r.dir, "tag", "v1.5.0-rc.1")
			r.git(r.dir, "push", "-q", "dev", "refs/tags/v1.5.0-rc.1")
			r.git(r.dir, "tag", "-d", "v1.5.0-rc.1")
		}, "already exists on dev"},
		{"remote unreachable", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.git(r.dir, "remote", "set-url", "dev", filepath.Join(r.bare, "missing"))
		}, "could not query dev"},
		{"no dev remote", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.git(r.dir, "remote", "remove", "dev") }, "no 'dev' remote"},
		{"dirty tree", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			if err := os.WriteFile(filepath.Join(r.dir, "stray.txt"), []byte("x"), 0o600); err != nil {
				t.Fatalf("write stray: %v", err)
			}
		}, "working tree not clean"},
		{"version does not move forward", "alpha", "v1.4.0-alpha", nil, "is not greater than"},
		{"below an existing candidate tag", "alpha", "v1.4.0-alpha", func(r *releaseRepo) {
			r.git(r.dir, "tag", "v1.4.0-rc.1")
		}, "v1.4.0-rc.1 (v1.4.0-rc.1)"},
		{"nothing to release", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.git(r.dir, "rm", "-q", "changelog.d/134-x.md")
			r.git(r.dir, "commit", "-q", "-m", "drop the fragment")
			r.git(r.dir, "push", "-q", "dev", "main")
		}, "nothing to release"},
		{"local main behind dev", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.advanceDev("someone else's commit") }, "is not dev/main"},
		{"local main ahead of dev", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.git(r.dir, "commit", "-q", "--allow-empty", "-m", "unpushed")
		}, "is not dev/main"},
		{"dev has no main", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.git(r.bare, "update-ref", "-d", "refs/heads/main")
		}, "could not fetch main from dev"},
		{"CI red on main", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.forge.defaultState = "failure" }, "CI is not green"},
		{"CI pending on main", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.forge.defaultState = "pending" }, "CI is not green"},
		{"forge has no status", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.forge.defaultState = "" }, "could not read the forge's commit status"},
		{"forge unreachable", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["FORGE_API_URL"] = "http://127.0.0.1:1/api/v1" }, "could not read the forge's commit status"},
		{"forge rejects the token", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["FORGE_TOKEN"] = "wrong" }, "could not read the forge's commit status"},
		{"no forge URL", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["FORGE_API_URL"] = "" }, "FORGE_API_URL is unset"},
		{"no forge repository", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["FORGE_REPOSITORY"] = "" }, "FORGE_REPOSITORY is unset"},
		{"no forge token", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) { r.env["FORGE_TOKEN"] = "" }, "FORGE_TOKEN is unset"},
		{"token that could inject curl directives", "candidate", "v1.5.0-rc.1", func(r *releaseRepo) {
			r.env["FORGE_TOKEN"] = "abc\"\nurl = \"http://example.invalid"
		}, "refusing to use it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReleaseRepo(t)
			if tc.setup != nil {
				tc.setup(r)
			}
			before := r.state()
			out, ok := r.run(tc.kind, tc.version)
			if ok {
				t.Fatalf("accepted %q, want a refusal:\n%s", tc.version, out)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
			if after := r.state(); after != before {
				t.Fatalf("a refused release changed the repository:\nbefore %q\nafter  %q", before, after)
			}
		})
	}
}

// releaseKinds pairs each release target's kind with a version of that kind.
var releaseKinds = []struct{ kind, target, forms, version string }{
	{"release", "make release", "vX.Y.Z;", "v1.5.0"},
	{"candidate", "make release-candidate", "vX.Y.Z-rc.N;", "v1.5.0-rc.1"},
	{"alpha", "make release-alpha", "vX.Y.Z-alpha;", "v1.5.0-alpha"},
}

// TestScriptsRelease_EachTargetRefusesTheOtherKinds drives every kind with
// every version of the other two kinds: each is refused before anything is
// written.
func TestScriptsRelease_EachTargetRefusesTheOtherKinds(t *testing.T) {
	for _, k := range releaseKinds {
		for _, other := range releaseKinds {
			if other.kind == k.kind {
				continue
			}
			t.Run(k.kind+" given "+other.version, func(t *testing.T) {
				r := newReleaseRepo(t)
				before := r.state()
				out, ok := r.run(k.kind, other.version)
				if ok {
					t.Fatalf("%s accepted %s:\n%s", k.target, other.version, out)
				}
				if want := "is not " + k.forms; !strings.Contains(out, want) {
					t.Fatalf("refusal does not say %q:\n%s", want, out)
				}
				if after := r.state(); after != before {
					t.Fatalf("a refused release changed the repository:\nbefore %q\nafter  %q", before, after)
				}
			})
		}
	}
}

func TestScriptsRelease_RefusesAnUnknownKind(t *testing.T) {
	r := newReleaseRepo(t)
	for _, kind := range []string{"", "any", "rc", "Release"} {
		if out, ok := r.run(kind, "v1.5.0"); ok || !strings.Contains(out, "usage") {
			t.Fatalf("kind %q was not refused with a usage line (ok=%v):\n%s", kind, ok, out)
		}
	}
	out, ok := runScript(t, r.dir, mergeEnv(r.env, map[string]string{"VERSION": "v1.5.0"}), "release.sh")
	if ok || !strings.Contains(out, "usage") {
		t.Fatalf("no kind was not refused with a usage line (ok=%v):\n%s", ok, out)
	}
}

// TestScriptsRelease_MakeTargetsRefuseTheOtherKinds drives each real target
// with a version of each of the other two kinds. The refusal comes before
// anything else is looked at, so nothing in this checkout is touched; a
// target's own kind is covered above, on a scratch repository.
func TestScriptsRelease_MakeTargetsRefuseTheOtherKinds(t *testing.T) {
	for _, k := range releaseKinds {
		for _, other := range releaseKinds {
			if other.kind == k.kind {
				continue
			}
			t.Run(strings.TrimPrefix(k.target, "make ")+" given "+other.version, func(t *testing.T) {
				out, ok := runMake(t, map[string]string{"VERSION": "", "AGENT_GIT": "/bin/false"}, strings.TrimPrefix(k.target, "make "), "VERSION="+other.version)
				if ok {
					t.Fatalf("%s accepted VERSION=%s:\n%s", k.target, other.version, out)
				}
				if want := "is not " + k.forms; !strings.Contains(out, want) {
					t.Fatalf("refusal does not say %q:\n%s", want, out)
				}
			})
		}
	}
}

func TestScriptsRelease_TagsAndPushesEveryKind(t *testing.T) {
	for _, tc := range []struct{ kind, version string }{
		{"candidate", "v1.5.0-rc.1"},
		{"candidate", "v1.5.0-rc.12"},
		{"alpha", "v1.5.0-alpha"},
		{"release", "v1.5.0"},
	} {
		t.Run(tc.kind+" "+tc.version, func(t *testing.T) {
			r := newReleaseRepo(t)
			out, ok := r.run(tc.kind, tc.version)
			if !ok {
				t.Fatalf("refused:\n%s", out)
			}
			if got, want := readFile(t, filepath.Join(r.dir, "VERSION")), strings.TrimPrefix(tc.version, "v")+"\n"; got != want {
				t.Fatalf("VERSION = %q, want %q", got, want)
			}
			if changelog := readFile(t, filepath.Join(r.dir, "CHANGELOG.md")); !strings.Contains(changelog, "\n## ["+tc.version+"] - ") || !strings.Contains(changelog, "- a candidate") {
				t.Fatalf("CHANGELOG.md has no assembled section for %s:\n%s", tc.version, changelog)
			}
			if _, err := os.Stat(filepath.Join(r.dir, "changelog.d", "134-x.md")); !os.IsNotExist(err) {
				t.Fatalf("the fragment was not folded in (stat err %v)", err)
			}
			if got := r.git(r.dir, "cat-file", "-t", "refs/tags/"+tc.version); got != "tag" {
				t.Fatalf("%s is a %q object, want an annotated tag", tc.version, got)
			}
			if got, want := r.git(r.bare, "rev-parse", tc.version+"^{commit}"), r.git(r.dir, "rev-parse", "HEAD"); got != want {
				t.Fatalf("dev's %s names %s, want HEAD %s", tc.version, got, want)
			}
			if got := r.git(r.bare, "tag", "-l"); got != tc.version {
				t.Fatalf("dev holds tags %q, want only %s", got, tc.version)
			}
			if got, want := r.git(r.bare, "rev-parse", "refs/heads/main"), r.git(r.dir, "rev-parse", "HEAD"); got != want {
				t.Fatalf("dev's main names %s, want the release commit %s", got, want)
			}
			if got := r.git(r.dir, "log", "-1", "--format=%s"); got != "chore(release): "+tc.version {
				t.Fatalf("release commit = %q", got)
			}
			if got := r.git(r.dir, "status", "--porcelain"); got != "" {
				t.Fatalf("the release left the tree dirty:\n%s", got)
			}
			if log := readFile(t, r.env["AGENT_GIT"]+".log"); strings.Trim(strings.ReplaceAll(log, "go-enclave-test\n", ""), "\n") != "" {
				t.Fatalf("a git write ran under another repo name:\n%s", log)
			}
		})
	}
}

// TestScriptsRelease_CandidatesFollowOneAnother cuts rc.1, then refuses the
// same candidate again and an alpha below it, and then cuts rc.2.
func TestScriptsRelease_CandidatesFollowOneAnother(t *testing.T) {
	r := newReleaseRepo(t)
	if out, ok := r.run("candidate", "v1.5.0-rc.1"); !ok {
		t.Fatalf("rc.1 refused:\n%s", out)
	}
	if out, ok := r.run("candidate", "v1.5.0-rc.1"); ok || !strings.Contains(out, "already exists locally") {
		t.Fatalf("a second rc.1 was not refused as an existing tag (ok=%v):\n%s", ok, out)
	}
	if out, ok := r.run("alpha", "v1.5.0-alpha"); ok || !strings.Contains(out, "is not greater than") {
		t.Fatalf("an alpha below rc.1 was not refused (ok=%v):\n%s", ok, out)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "changelog.d", "134-y.md"), []byte("### Fixed\n\n- a second candidate\n"), 0o600); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	r.git(r.dir, "add", "-A")
	r.git(r.dir, "commit", "-q", "-m", "fix")
	r.git(r.dir, "push", "-q", "dev", "main")
	if out, ok := r.run("candidate", "v1.5.0-rc.2"); !ok {
		t.Fatalf("rc.2 refused:\n%s", out)
	}
	if got := r.git(r.bare, "tag", "-l"); got != "v1.5.0-rc.1\nv1.5.0-rc.2" {
		t.Fatalf("dev holds tags %q", got)
	}
}

// TestScriptsRelease_ARejectedMainNeverLeavesTheTag stands in for main moving
// between the check and the push: dev refuses the main update (a per-ref hook,
// so only an atomic push stops the tag with it). The immutable tag must not
// land.
func TestScriptsRelease_ARejectedMainNeverLeavesTheTag(t *testing.T) {
	r := newReleaseRepo(t)
	hook := "#!/bin/sh\n[ \"$1\" = refs/heads/main ] && exit 1\nexit 0\n"
	if err := os.WriteFile(filepath.Join(r.bare, "hooks", "update"), []byte(hook), 0o755); err != nil {
		t.Fatalf("write hook: %v", err)
	}
	out, ok := r.run("candidate", "v1.5.0-rc.1")
	if ok {
		t.Fatalf("released although dev refused main:\n%s", out)
	}
	if got := r.git(r.bare, "tag", "-l"); got != "" {
		t.Fatalf("dev holds tags %q after its main was refused; the push was not atomic", got)
	}
}

// TestScriptsMakefile_AnalysersCoverTheBuildGatesModule requires the Go
// analysers to also run inside build/ci/buildgates, which `./...` from the root
// never reaches (it is its own module), and `vuln` to be govulncheck.
func TestScriptsMakefile_AnalysersCoverTheBuildGatesModule(t *testing.T) {
	root := repoRoot(t)
	dryRun := func(target string) string {
		t.Helper()
		cmd := exec.Command("make", "-n", "--no-print-directory", target)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make -n %s: %v\n%s", target, err, out)
		}
		return string(out)
	}
	for _, target := range []string{"lint-go", "staticcheck", "govulncheck", "vuln"} {
		if recipe := dryRun(target); !strings.Contains(recipe, "build/ci/buildgates") {
			t.Errorf("make %s does not analyze the build/ci/buildgates module:\n%s", target, recipe)
		}
	}
	if vuln, gov := dryRun("vuln"), dryRun("govulncheck"); vuln != gov {
		t.Errorf("make vuln is not govulncheck:\nvuln:\n%s\ngovulncheck:\n%s", vuln, gov)
	}
	cmd := exec.Command("make", "--no-print-directory", "help")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make help: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "vuln:") {
		t.Errorf("make help does not list vuln:\n%s", out)
	}
}

func mergeEnv(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Make entry points with hostile values.

// hostileValues are values a pushed tag, a workflow or a user can hand to the
// release targets. Git accepts tag names with backticks, $(...), `;`, quotes
// and `&`, and the `v*` trigger matches them. Each payload would create
// <marker>/<n> if it were ever parsed as shell or make source.
func hostileValues(marker string) []string {
	m := func(n string) string { return filepath.Join(marker, n) }
	return []string{
		"v`touch " + m("backtick") + "`",
		"v$(touch " + m("dollar-paren") + ")",
		"v1.0.0;touch " + m("semicolon"),
		"v1.0.0\ntouch " + m("newline"),
		"v1.0.0' ; touch '" + m("single-quote"),
		"v1.0.0\" ; touch \"" + m("double-quote"),
		"v1.0.0 && touch " + m("and"),
		"v1.0.0|touch " + m("pipe"),
		"$(shell touch " + m("make-shell") + ")",
		"v$$(touch " + m("make-escaped") + ")",
		"${shell touch " + m("make-brace") + "}",
	}
}

// runMake runs `make <target>` in the repository with the given command-line
// assignments and environment, and returns its output and whether it exited 0.
func runMake(t *testing.T, env map[string]string, target string, assignments ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("make", append([]string{"--no-print-directory", "-s", target}, assignments...)...)
	cmd.Dir = repoRoot(t)
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running make %s: %v", target, err)
		}
		return string(out), false
	}
	return string(out), true
}

func requireNoMarkers(t *testing.T, marker, context, out string) {
	t.Helper()
	left, err := os.ReadDir(marker)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(left) != 0 {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("%s EXECUTED a payload (created %v):\n%s", context, names, out)
	}
}

// TestScriptsMakeEntryPoints_TreatHostileValuesAsData drives every make target
// that takes an externally controlled value, with each hostile value, both as
// a make command-line assignment and through the environment. Nothing may
// execute, and every call must be refused.
func TestScriptsMakeEntryPoints_TreatHostileValuesAsData(t *testing.T) {
	const okSHA = "1111111111111111111111111111111111111111"
	for _, tc := range []struct {
		name, target, variable string
		fixed                  map[string]string // other values the target needs
		// envIgnored: the Makefile assigns the variable itself, so an
		// environment value is not used (the coverage floor cannot be lowered
		// by an exported variable). envTarget is run instead, to show the
		// value is ignored and never executed.
		envIgnored bool
		envTarget  string
	}{
		{"release-verify TAG", "release-verify", "TAG", nil, false, ""},
		{"release-verify MAIN_REF", "release-verify", "MAIN_REF", map[string]string{"TAG": "v0.0.1"}, false, ""},
		{"consumer-check TAG", "consumer-check", "TAG", nil, false, ""},
		{"release-publish TAG", "release-publish", "TAG", map[string]string{"SHA": okSHA}, false, ""},
		{"release-publish SHA", "release-publish", "SHA", map[string]string{"TAG": "v0.0.1"}, false, ""},
		{"release VERSION", "release", "VERSION", map[string]string{"AGENT_GIT": "/bin/false"}, false, ""},
		{"release-candidate VERSION", "release-candidate", "VERSION", map[string]string{"AGENT_GIT": "/bin/false"}, false, ""},
		{"release-alpha VERSION", "release-alpha", "VERSION", map[string]string{"AGENT_GIT": "/bin/false"}, false, ""},
		{"lint-scripts TOOL_INSTALL", "lint-scripts", "TOOL_INSTALL", nil, false, ""},
		// `coverage` checks the floor before the suite runs, so a refused value
		// costs nothing.
		{"coverage COVERAGE_THRESHOLD", "coverage", "COVERAGE_THRESHOLD", nil, true, "coverage-threshold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := t.TempDir()
			for i, value := range hostileValues(marker) {
				// Publishing must never get as far as a request, whatever
				// happens: point it at nothing.
				env := map[string]string{
					"FORGE_API_URL": "http://127.0.0.1:9/api/v1", "FORGE_REPOSITORY": "owner/repo", "FORGE_TOKEN": "x",
					"TAG": "", "SHA": "", "MAIN_REF": "", "VERSION": "",
				}
				var assignments []string
				for k, v := range tc.fixed {
					assignments = append(assignments, k+"="+v)
				}

				// As a make command-line assignment.
				out, ok := runMake(t, env, tc.target, append(assignments, tc.variable+"="+value)...)
				requireNoMarkers(t, marker, fmt.Sprintf("make %s %s=<payload %d>", tc.target, tc.variable, i), out)
				if ok {
					t.Fatalf("make %s accepted %s=%q:\n%s", tc.target, tc.variable, value, out)
				}

				// Through the environment, as release.yml passes it.
				envHostile := mergeEnv(env, map[string]string{tc.variable: value})
				if tc.envIgnored {
					out, ok = runMake(t, envHostile, tc.envTarget, assignments...)
					requireNoMarkers(t, marker, fmt.Sprintf("%s=<payload %d> make %s", tc.variable, i, tc.envTarget), out)
					if !ok {
						t.Fatalf("make %s did not ignore %s from the environment:\n%s", tc.envTarget, tc.variable, out)
					}
					continue
				}
				out, ok = runMake(t, envHostile, tc.target, assignments...)
				requireNoMarkers(t, marker, fmt.Sprintf("%s=<payload %d> make %s", tc.variable, i, tc.target), out)
				if ok {
					t.Fatalf("make %s accepted %s=%q from the environment:\n%s", tc.target, tc.variable, value, out)
				}
			}
		})
	}
}

// TestScriptsMakeEntryPoints_ValidatorsSeeTheRawValue pins that the value a
// script validates is the text that was passed, not what a shell or make made
// of it (for TAG=v`id`, not the output of id).
func TestScriptsMakeEntryPoints_ValidatorsSeeTheRawValue(t *testing.T) {
	for _, assign := range []bool{true, false} {
		env := map[string]string{"TAG": ""}
		var args []string
		if assign {
			args = []string{"TAG=v`id`"}
		} else {
			env["TAG"] = "v`id`"
		}
		out, ok := runMake(t, env, "release-verify", args...)
		if ok || !strings.Contains(out, "tag 'v`id`' is not vX.Y.Z") || strings.Contains(out, "uid=") {
			t.Fatalf("command-line=%v: the validator did not receive the raw tag (ok=%v):\n%s", assign, ok, out)
		}
	}
}

// ---------------------------------------------------------------------------
// The Makefile from a checkout at a hostile path.

// hostileDirName is a directory name a checkout can really have: a space, a
// command substitution, backticks, `;`, `&&` and both quote characters. Each
// payload creates a pwned-* file wherever a shell runs it. The quotes are
// balanced on purpose: an unbalanced one turns a spliced command line into a
// syntax error, so the payload would never run and the test would not see it.
const hostileDirName = "go enclave $(touch pwned-dollar) `touch pwned-tick` ;touch pwned-semi && touch pwned-and 'q' \"d\""

// copyCheckout copies the files git would publish (tracked, plus untracked
// but not ignored) from the repository into dst.
func copyCheckout(t *testing.T, dst string) {
	t.Helper()
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if f == "" {
			continue
		}
		src := filepath.Join(root, filepath.FromSlash(f))
		fi, err := os.Lstat(src)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		p := filepath.Join(dst, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, b, fi.Mode().Perm()); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
}

// operandLogger writes an executable that records each of its arguments as
// one <…> line in log (one operand with spaces is one line, a path split by
// the shell is two) and does nothing else.
func operandLogger(t *testing.T, dir, name, log, extra string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	script := "#!/bin/sh\n{ printf '%s\\n' '--- " + name + "'; for a in \"$@\"; do printf '<%s>\\n' \"$a\"; done; } >> '" + log + "'\n" + extra
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// requireNoPwned fails if any payload in hostileDirName ran anywhere under dir.
func requireNoPwned(t *testing.T, dir, context string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), "pwned-") {
			t.Fatalf("%s EXECUTED a payload from the checkout path: %s", context, p)
		}
		return nil
	})
}

func readLog(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read %s: %v", log, err)
	}
	return string(b)
}

func TestScriptsMakefile_AHostileCheckoutPathIsOneLiteralOperand(t *testing.T) {
	parent := t.TempDir()
	// The sibling an unquoted `rm -rf <parent>/go enclave…/bin/tools`
	// deletes first.
	sibling := filepath.Join(parent, "go")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "keep"), nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	checkout := filepath.Join(parent, hostileDirName)
	copyCheckout(t, checkout)
	tools := filepath.Join(checkout, "bin", "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	fakes := filepath.Join(t.TempDir(), "fakes")
	log := filepath.Join(t.TempDir(), "operands.log")
	operandLogger(t, fakes, "rm", log, "")
	operandLogger(t, fakes, "rmdir", log, "")
	operandLogger(t, fakes, "shellcheck", log, "")
	// A go command at a hostile path, too: GOCMD is a path like any other.
	fakeGoDir := filepath.Join(checkout, "my go $(touch pwned-gocmd) `touch pwned-gotick`")
	operandLogger(t, fakeGoDir, "go", log, "[ \"$1 $2\" = 'env GOVERSION' ] && echo go1.27.1\nexit 0\n")
	fakeGo := filepath.Join(fakeGoDir, "go")

	makeIn := func(env map[string]string, args ...string) (string, bool) {
		t.Helper()
		_ = os.Remove(log)
		cmd := exec.Command("make", append([]string{"--no-print-directory", "-s"}, args...)...)
		cmd.Dir = checkout
		cmd.Env = layerEnv(os.Environ(), mergeEnv(map[string]string{"TOOL_INSTALL": "0"}, env))
		out, err := cmd.CombinedOutput()
		return string(out), err == nil
	}
	withFakes := map[string]string{"PATH": fakes + ":" + os.Getenv("PATH")}

	// clean-tools: exactly one operand, the literal tools directory.
	out, ok := makeIn(withFakes, "clean-tools")
	if want := "--- rm\n<-rf>\n<-->\n<" + tools + ">\n"; !ok || readLog(t, log) != want {
		t.Fatalf("clean-tools (ok=%v) passed rm:\n%s\nwant:\n%s\noutput:\n%s", ok, readLog(t, log), want, out)
	}

	// clean: each artifact one operand; the report directory only via rmdir.
	out, ok = makeIn(withFakes, "clean")
	if want := "--- rm\n<-f>\n<-->\n<coverage.out>\n<coverage/coverage.html>\n<coverage-*.out>\n<gosec.sarif>\n<trivy-results.sarif>\n--- rmdir\n<-->\n<coverage>\n"; !ok || readLog(t, log) != want {
		t.Fatalf("clean (ok=%v) passed:\n%s\nwant:\n%s\noutput:\n%s", ok, readLog(t, log), want, out)
	}

	// Overridden artifact paths are data too.
	hostileProfile := "cov $(touch pwned-profile) `touch pwned-ptick`;x.out"
	out, ok = makeIn(withFakes, "clean", "COVERAGE_PROFILE="+hostileProfile, "COVERAGE_HTML=report dir/r.html")
	if want := "--- rm\n<-f>\n<-->\n<" + hostileProfile + ">\n<report dir/r.html>\n<coverage-*.out>\n<gosec.sarif>\n<trivy-results.sarif>\n--- rmdir\n<-->\n<report dir>\n"; !ok || readLog(t, log) != want {
		t.Fatalf("clean with overridden paths (ok=%v) passed:\n%s\nwant:\n%s\noutput:\n%s", ok, readLog(t, log), want, out)
	}

	// lint-scripts resolves shellcheck on PATH; its operands are literal.
	operandLogger(t, fakes, "shellcheck", log, "[ \"$1\" = --version ] && printf 'version: 0.11.0\\n'\nexit 0\n")
	// TOOL_INSTALL=0 requires it to hash to the pin, so the fake's hash is the pin.
	sum := sha256Hex(t, filepath.Join(fakes, "shellcheck"))
	out, ok = makeIn(withFakes, "lint-scripts", "SHELLCHECK_BIN_SHA256_LINUX_AMD64="+sum, "SHELLCHECK_BIN_SHA256_LINUX_ARM64="+sum)
	if logged := readLog(t, log); !ok || !strings.Contains(logged, "<--shell=sh>\n<scripts/changelog-assemble.sh>\n") || !strings.Contains(logged, "<scripts/tool.sh>\n") {
		t.Fatalf("lint-scripts (ok=%v) passed shellcheck:\n%s\noutput:\n%s", ok, logged, out)
	}

	// GOCMD at a hostile path: one word in recipes (TOOLCHAIN is lazy, so no $(shell) runs it).
	out, ok = makeIn(nil, "build", "GOCMD="+fakeGo)
	if logged := readLog(t, log); !ok || !strings.Contains(logged, "--- go\n<build>\n<./...>\n") {
		t.Fatalf("make build GOCMD=<hostile path> (ok=%v) logged:\n%s\noutput:\n%s", ok, logged, out)
	}

	// help reads the Makefile at the hostile path.
	if out, ok = makeIn(nil, "help"); !ok || !strings.Contains(out, "clean-tools:") {
		t.Fatalf("help (ok=%v):\n%s", ok, out)
	}

	// make -f <hostile path>/Makefile from elsewhere: MAKEFILE_LIST carries
	// the path, which make cannot represent with spaces, so help cannot find
	// its file; it must say so, and run nothing.
	cmd := exec.Command("make", "--no-print-directory", "-s", "-f", filepath.Join(checkout, "Makefile"), "help")
	cmd.Dir = parent
	if b, err := cmd.CombinedOutput(); err == nil && !strings.Contains(string(b), "clean-tools:") {
		t.Fatalf("help from -f reported success without listing targets:\n%s", b)
	}
	requireNoPwned(t, parent, "make -f <hostile path> help")

	// The real rm: the tools directory goes, the sibling stays.
	if out, ok = makeIn(nil, "clean-tools"); !ok {
		t.Fatalf("clean-tools with the real rm failed:\n%s", out)
	}
	if _, err := os.Stat(tools); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean-tools left %s (stat: %v)", tools, err)
	}
	if _, err := os.Stat(filepath.Join(sibling, "keep")); err != nil {
		t.Fatalf("clean-tools deleted the sibling directory %s: %v", sibling, err)
	}
	if _, err := os.Stat(filepath.Join(checkout, "Makefile")); err != nil {
		t.Fatalf("clean-tools damaged the checkout: %v", err)
	}

	requireNoPwned(t, parent, "make at a hostile checkout path")
}

// TestScriptsMakefile_CleanToolsRefusesWhatItMustNotDelete pins that an
// overridden TOOLS_DIR that is relative, or resolves to /, the checkout or
// $HOME, is refused before anything is removed.
func TestScriptsMakefile_CleanToolsRefusesWhatItMustNotDelete(t *testing.T) {
	checkout := filepath.Join(t.TempDir(), "repo")
	copyCheckout(t, checkout)
	home := t.TempDir()
	fakes := t.TempDir()
	log := filepath.Join(t.TempDir(), "rm.log")
	operandLogger(t, fakes, "rm", log, "")
	for name, dir := range map[string]string{
		"empty":         "",
		"relative":      "bin/tools",
		"root":          "/",
		"root, spelled": "/./",
		"the checkout":  checkout,
		"via ..":        filepath.Join(checkout, "scripts", ".."),
		"HOME":          home,
	} {
		cmd := exec.Command("make", "--no-print-directory", "-s", "clean-tools", "TOOLS_DIR="+dir)
		cmd.Dir = checkout
		cmd.Env = layerEnv(os.Environ(), map[string]string{"PATH": fakes + ":" + os.Getenv("PATH"), "HOME": home})
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%s: clean-tools accepted TOOLS_DIR=%q:\n%s", name, dir, out)
		}
		if b, _ := os.ReadFile(log); len(b) != 0 {
			t.Fatalf("%s: clean-tools ran rm before refusing:\n%s", name, b)
		}
	}
}

// TestScriptsReleaseWorkflow_PublishWaitsForTheErasingBuild requires release.yml
// to run `make test-runtimesecret` on the tag, directly or through the ci-test
// aggregate that includes it, in a job that publish needs and checks by name,
// so a regression confined to that build cannot ship.
func TestScriptsReleaseWorkflow_EveryJobRunsOnTheVerifiedCommit(t *testing.T) {
	type step struct {
		Uses string            `yaml:"uses"`
		With map[string]string `yaml:"with"`
	}
	type job struct {
		Steps []step `yaml:"steps"`
	}
	var wf struct {
		Jobs map[string]job `yaml:"jobs"`
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	if len(wf.Jobs) < 7 {
		t.Fatalf("release.yml has %d jobs; the discovery is broken", len(wf.Jobs))
	}
	const verified = "${{ needs.verify.outputs.sha }}"
	for name, j := range wf.Jobs {
		if name == "verify" {
			continue // resolves the tag to the commit the others use
		}
		checkouts := 0
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "actions/checkout@") {
				continue
			}
			checkouts++
			if got := s.With["ref"]; got != verified {
				t.Errorf("job %s checks out ref %q, want %q: a tag moved after Verify must not change what the gates run on", name, got, verified)
			}
		}
		if checkouts == 0 {
			t.Errorf("job %s has no checkout step; the discovery is broken", name)
		}
	}
}

func TestScriptsReleaseWorkflow_PublishWaitsForTheErasingBuild(t *testing.T) {
	type step struct {
		Run string `yaml:"run"`
	}
	type job struct {
		Needs []string `yaml:"needs"`
		Steps []step   `yaml:"steps"`
	}
	var wf struct {
		Jobs map[string]job `yaml:"jobs"`
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	publish, ok := wf.Jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	var gate string
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			fields := strings.Fields(s.Run)
			if len(fields) > 1 && fields[0] == "make" && (slices.Contains(fields, "test-runtimesecret") || slices.Contains(fields, "ci-test")) {
				gate = name
			}
		}
	}
	if gate == "" {
		t.Fatal("no release.yml job runs `make test-runtimesecret`")
	}
	needed := false
	for _, n := range publish.Needs {
		needed = needed || n == gate
	}
	if !needed {
		t.Fatalf("publish does not need %q, the job that runs make test-runtimesecret (needs: %v)", gate, publish.Needs)
	}
	var checks string
	for _, s := range publish.Steps {
		checks += s.Run
	}
	if !strings.Contains(checks, "needs."+gate+".result") {
		t.Fatalf("publish does not check needs.%s.result before publishing", gate)
	}
}
