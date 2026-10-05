package buildgates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/goccy/go-yaml"
)

// Tests for .github/workflows/automerge.yml. The merge step's shell is run
// against a fake Gitea API, so the merge decision itself is under test, and
// the workflow's triggers are checked to be ones Gitea defines from the base
// branch.

// baseDefinedEvents are the triggers whose workflow definition Gitea takes
// from the base or default branch, never from a PR head.
var baseDefinedEvents = map[string]bool{"pull_request_target": true, "workflow_run": true, "schedule": true}

type automergeWorkflow struct {
	On   map[string]any `yaml:"on"`
	Jobs map[string]struct {
		Steps []struct {
			Uses string            `yaml:"uses"`
			Env  map[string]string `yaml:"env"`
			Run  string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readAutomerge(t *testing.T) automergeWorkflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "automerge.yml"))
	if err != nil {
		t.Fatalf("read automerge.yml: %v", err)
	}
	var wf automergeWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse automerge.yml: %v", err)
	}
	return wf
}

func TestScriptsAutomerge_TokenOnlyReachesBaseDefinedRuns(t *testing.T) {
	wf := readAutomerge(t)
	if len(wf.On) == 0 {
		t.Fatal("automerge.yml declares no triggers")
	}
	for ev := range wf.On {
		if !baseDefinedEvents[ev] {
			t.Errorf("automerge.yml triggers on %q, whose definition Gitea may take from the PR head", ev)
		}
	}
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if strings.Contains(s.Uses, "checkout") {
				t.Errorf("job %s checks out code (%s); the token-bearing run must never run PR code", name, s.Uses)
			}
		}
	}
}

// fakeGitea serves the Gitea endpoints the merge step calls for PR 7. Issue
// labels are served unpaged, as Gitea does; a page parameter there would loop.
type fakeGitea struct {
	mu          sync.Mutex
	author      string
	labels      []string
	reviews     []map[string]any
	reviewsCode int
	merged      []map[string]any
}

const (
	fakeHead = "0123456789abcdef0123456789abcdef01234567"
	fakeMain = "89abcdef0123456789abcdef0123456789abcdef"
)

func (f *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/repos/o/r")
	page := r.URL.Query().Get("page")
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	paged := func(code int, v any) {
		switch {
		case code != 0:
			reply(code, map[string]string{"message": "boom"})
		case page == "1":
			reply(200, v)
		default:
			reply(200, []any{})
		}
	}
	names := func(ls []string) []map[string]string {
		out := []map[string]string{}
		for _, l := range ls {
			out = append(out, map[string]string{"name": l})
		}
		return out
	}
	switch {
	case r.Method == http.MethodGet && path == "/pulls/7":
		reply(200, map[string]any{"state": "open", "draft": false,
			"head": map[string]any{"sha": fakeHead}, "base": map[string]any{"ref": "main"},
			"merge_base": fakeMain, "user": map[string]any{"login": f.author}})
	case r.Method == http.MethodGet && path == "/branches/main":
		reply(200, map[string]any{"name": "main", "commit": map[string]any{"id": fakeMain}})
	case r.Method == http.MethodGet && path == "/branches":
		paged(0, []map[string]any{{"name": "main", "commit": map[string]any{"id": fakeMain}}})
	case r.Method == http.MethodGet && path == "/issues/7/comments":
		reply(200, []any{})
	case r.Method == http.MethodGet && path == "/pulls":
		paged(0, []map[string]any{{"number": 7, "head": map[string]any{"sha": fakeHead}}})
	case r.Method == http.MethodGet && path == "/branch_protections/main":
		reply(200, map[string]any{"enable_status_check": true, "status_check_contexts": []string{"CI / CI Gate"}})
	case r.Method == http.MethodGet && path == "/issues/7/labels":
		if page != "" {
			reply(599, map[string]string{"message": "issue labels are not paged"})
			return
		}
		reply(200, names(f.labels))
	case r.Method == http.MethodDelete && path == "/pulls/7/merge":
		reply(404, map[string]string{})
	case r.Method == http.MethodGet && path == "/commits/"+fakeHead+"/status":
		if page == "1" {
			reply(200, map[string]any{"total_count": 1,
				"statuses": []map[string]string{{"context": "CI / CI Gate", "status": "success"}}})
		} else {
			reply(200, map[string]any{"total_count": 1, "statuses": []any{}})
		}
	case r.Method == http.MethodGet && path == "/pulls/7/reviews":
		paged(f.reviewsCode, f.reviews)
	case r.Method == http.MethodPost && path == "/pulls/7/merge":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.merged = append(f.merged, body)
		reply(200, map[string]any{})
	default:
		reply(599, map[string]string{"message": "unexpected " + r.Method + " " + r.URL.String()})
	}
}

func review(id int, login, state string) map[string]any {
	return map[string]any{"id": id, "commit_id": fakeHead, "stale": false, "dismissed": false,
		"state": state, "user": map[string]any{"login": login}}
}

// runAutomerge runs the merge step for event against f and reports its output
// and whether it exited zero.
func runAutomerge(t *testing.T, f *fakeGitea, event string) (string, bool) {
	t.Helper()
	return runAutomergeWith(t, f, event, nil)
}

// runAutomergeWith runs the merge step against api, with extra layered over
// the step's environment.
func runAutomergeWith(t *testing.T, api http.Handler, event string, extra map[string]string) (string, bool) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("the merge step needs jq: %v", err)
	}
	wf := readAutomerge(t)
	step := wf.Jobs["merge"].Steps[0]
	srv := httptest.NewServer(api)
	defer srv.Close()
	// The step keeps its scratch files in /tmp; give each run its own.
	tmp := t.TempDir()
	script := strings.ReplaceAll(step.Run, "/tmp/", tmp+"/")
	env := map[string]string{}
	for k, v := range step.Env {
		if !strings.Contains(v, "${{") {
			env[k] = v
		}
	}
	env["BOT"] = "token"
	env["REPO_API"] = srv.URL + "/api/v1/repos/o/r"
	env["REPOSITORY"] = "o/r"
	env["EVENT"] = event
	env["PR_FROM_EVENT"] = "7"
	env["RUN_SHA"] = fakeHead
	env["no_proxy"], env["NO_PROXY"] = "*", "*"
	for k, v := range extra {
		env[k] = v
	}
	cmd := exec.Command("bash", "-e", "-c", script)
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running the merge step: %v", err)
		}
		return string(out), false
	}
	return string(out), true
}

func TestScriptsAutomerge_Decisions(t *testing.T) {
	label := []string{"code-review"}
	for _, tc := range []struct {
		name        string
		event       string
		labels      []string
		reviews     []map[string]any
		reviewsCode int
		wantOK      bool
		wantMerge   bool
		wantMsg     string
	}{
		{"no label merges on green CI", "pull_request_target", nil, nil, 0, true, true, "merged PR 7"},
		{"no label merges from a CI completion", "workflow_run", []string{"effort:high"}, nil, 0, true, true, "merged PR 7"},
		{"code-review waits for an approval", "pull_request_target", label, nil, 0, true, false, "waiting for an approval"},
		{"code-review merges on another approver's approval", "pull_request_target", label, []map[string]any{review(1, "codex", "APPROVED")}, 0, true, true, "approved on"},
		{"the author's own approval does not count", "pull_request_target", label, []map[string]any{review(1, "claude", "APPROVED")}, 0, true, false, "waiting for an approval"},
		{"an approval from outside APPROVERS does not count", "pull_request_target", label, []map[string]any{review(1, "mallory", "APPROVED")}, 0, true, false, "waiting for an approval"},
		{"request changes blocks an approval", "workflow_run", label, []map[string]any{review(1, "codex", "APPROVED"), review(2, "opencode", "REQUEST_CHANGES")}, 0, true, false, "changes requested"},
		{"an unreadable review list fails the run", "pull_request_target", label, nil, 500, false, false, "cannot read /pulls/7/reviews"},
		{"the schedule sweep merges an approved PR", "schedule", label, []map[string]any{review(1, "jeremyhahn", "APPROVED")}, 0, true, true, "merged PR 7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGitea{author: "claude", labels: tc.labels, reviews: tc.reviews, reviewsCode: tc.reviewsCode}
			if f.reviews == nil {
				f.reviews = []map[string]any{}
			}
			out, ok := runAutomerge(t, f, tc.event)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v:\n%s", ok, tc.wantOK, out)
			}
			if merged := len(f.merged) > 0; merged != tc.wantMerge {
				t.Fatalf("merged = %v, want %v:\n%s", merged, tc.wantMerge, out)
			}
			if tc.wantMerge && fmt.Sprint(f.merged[0]["head_commit_id"]) != fakeHead {
				t.Fatalf("merge not pinned to the head whose checks were read: %v", f.merged[0])
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("output does not say %q:\n%s", tc.wantMsg, out)
			}
		})
	}
}

// trainGitea serves the merge-train endpoints from a real bare repository:
// PR heads are refs/pull/N/head, branches are refs/heads/*, and a squash merge
// writes a commit onto main. The workflow fetches and pushes that repository.
type trainGitea struct {
	t             *testing.T
	mu            sync.Mutex
	bare          string
	open          map[int]bool
	block         bool   // block_on_outdated_branch as branch protection reports it
	enforceBehind bool   // the merge call refuses a PR that is behind main
	trainCI       string // the push status on any merge-train/* tip; "" is none yet
	checking      map[int]bool
	racer         bool // main gains a commit right after the first merge
	merged        []int
	pins          []string
	updated       []int
	deleted       []string
	comments      map[int][]string
}

const (
	trainAgent  = "agent-r"
	pushContext = "CI / CI Gate (push)"
)

// gitIn runs git in dir with no user or system configuration.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
		"-c", "commit.gpgSign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = layerEnv(os.Environ(), map[string]string{"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newTrainGitea(t *testing.T) *trainGitea {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("the merge train needs git: %v", err)
	}
	f := &trainGitea{t: t, bare: t.TempDir(), open: map[int]bool{}, checking: map[int]bool{}, comments: map[int][]string{}}
	gitIn(t, f.bare, "init", "-q", "--bare")
	f.commitOn("main", "README", "line one\nline two\n")
	return f
}

// commitOn commits file=body onto ref's tip (a fresh root when ref is unset)
// and points ref at it.
func (f *trainGitea) commitOn(ref, file, body string) string {
	f.t.Helper()
	return f.commitFrom(f.revOr("refs/heads/"+ref), "refs/heads/"+ref, file, body)
}

func (f *trainGitea) revOr(ref string) string {
	cmd := exec.Command("git", "-C", f.bare, "rev-parse", "--verify", "-q", ref)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func (f *trainGitea) commitFrom(parent, ref, file, body string) string {
	f.t.Helper()
	blob := strings.TrimSpace(f.gitStdin(body, "hash-object", "-w", "--stdin"))
	idx := filepath.Join(f.t.TempDir(), "index")
	env := []string{"GIT_INDEX_FILE=" + idx}
	if parent != "" {
		f.gitEnv(env, "read-tree", parent)
	}
	f.gitEnv(env, "update-index", "--add", "--cacheinfo", "100644,"+blob+","+file)
	tree := f.gitEnv(env, "write-tree")
	args := []string{"commit-tree", tree, "-m", "change " + file}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	sha := gitIn(f.t, f.bare, args...)
	gitIn(f.t, f.bare, "update-ref", ref, sha)
	return sha
}

func (f *trainGitea) gitEnv(env []string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.bare}, args...)...)
	cmd.Env = append(layerEnv(os.Environ(), map[string]string{"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *trainGitea) gitStdin(in string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.bare}, args...)...)
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.Output()
	if err != nil {
		f.t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// openPR opens PR n with file=body committed onto from (a main commit).
func (f *trainGitea) openPR(n int, from, file, body string) string {
	f.t.Helper()
	f.open[n] = true
	return f.commitFrom(from, fmt.Sprintf("refs/pull/%d/head", n), file, body)
}

func (f *trainGitea) head(n int) string { return f.revOr(fmt.Sprintf("refs/pull/%d/head", n)) }
func (f *trainGitea) main() string      { return f.revOr("refs/heads/main") }

// trainBranches lists merge-train/* branches as name -> tip.
func (f *trainGitea) trainBranches() map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(gitIn(f.t, f.bare, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads/merge-train/"), "\n") {
		if name, sha, ok := strings.Cut(l, " "); ok {
			out[name] = sha
		}
	}
	return out
}

// onlyTrain returns the single train branch's name and head message.
func (f *trainGitea) onlyTrain() (string, string) {
	f.t.Helper()
	tb := f.trainBranches()
	if len(tb) != 1 {
		f.t.Fatalf("want exactly one train branch, have %v", tb)
	}
	for name, sha := range tb {
		return name, gitIn(f.t, f.bare, "log", "-1", "--format=%B", sha)
	}
	return "", ""
}

func (f *trainGitea) branchJSON(name string) map[string]any {
	sha := f.revOr("refs/heads/" + name)
	return map[string]any{"name": name, "commit": map[string]any{"id": sha,
		"message": gitIn(f.t, f.bare, "log", "-1", "--format=%B", sha)}}
}

func (f *trainGitea) mergeBase(n int) string {
	return gitIn(f.t, f.bare, "merge-base", "refs/heads/main", f.head(n))
}

func (f *trainGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/repos/o/r")
	page := r.URL.Query().Get("page")
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	firstPage := func(v any) {
		if page == "1" {
			reply(200, v)
		} else {
			reply(200, []any{})
		}
	}
	var n int
	pr := func(format string) bool {
		_, err := fmt.Sscanf(path, format, &n)
		return err == nil && fmt.Sprintf(format, n) == path
	}
	switch {
	case r.Method == http.MethodGet && path == "/pulls":
		list := []map[string]any{}
		for num, open := range f.open {
			if open {
				list = append(list, map[string]any{"number": num, "head": map[string]any{"sha": f.head(num)}})
			}
		}
		firstPage(list)
	case r.Method == http.MethodGet && pr("/pulls/%d"):
		state := "closed"
		if f.open[n] {
			state = "open"
		}
		reply(200, map[string]any{"state": state, "draft": false, "head": map[string]any{"sha": f.head(n)},
			"base": map[string]any{"ref": "main"}, "merge_base": f.mergeBase(n), "user": map[string]any{"login": "claude"}})
	case r.Method == http.MethodGet && path == "/branch_protections/main":
		reply(200, map[string]any{"enable_status_check": true, "block_on_outdated_branch": f.block,
			"status_check_contexts": []string{"CI / CI Gate (pull_request)"}})
	case r.Method == http.MethodDelete && pr("/pulls/%d/merge"):
		reply(404, map[string]string{})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/commits/") && strings.HasSuffix(path, "/status"):
		sha := strings.TrimSuffix(strings.TrimPrefix(path, "/commits/"), "/status")
		statuses := []map[string]string{}
		for num := range f.open {
			if f.head(num) == sha {
				statuses = append(statuses, map[string]string{"context": "CI / CI Gate (pull_request)", "status": "success"})
			}
		}
		for _, tip := range f.trainBranches() {
			if tip == sha && f.trainCI != "" {
				statuses = append(statuses, map[string]string{"context": pushContext, "status": f.trainCI})
			}
		}
		if page != "1" {
			statuses = nil
		}
		reply(200, map[string]any{"total_count": len(statuses), "statuses": statuses})
	case r.Method == http.MethodGet && pr("/issues/%d/labels"):
		reply(200, []any{})
	case r.Method == http.MethodGet && pr("/issues/%d/comments"):
		if page != "" {
			reply(599, map[string]string{"message": "issue comments are not paged"})
			return
		}
		list := []map[string]any{}
		for _, b := range f.comments[n] {
			login := trainAgent
			if by, rest, ok := strings.Cut(b, "\x00"); ok { // a comment someone else left
				login, b = by, rest
			}
			list = append(list, map[string]any{"body": b, "user": map[string]any{"login": login}})
		}
		reply(200, list)
	case r.Method == http.MethodPost && pr("/issues/%d/comments"):
		var body struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.comments[n] = append(f.comments[n], body.Body)
		reply(201, map[string]any{"body": body.Body, "user": map[string]any{"login": trainAgent}})
	case r.Method == http.MethodGet && path == "/branches":
		list := []map[string]any{}
		for _, name := range strings.Split(gitIn(f.t, f.bare, "for-each-ref", "--format=%(refname:short)", "refs/heads/"), "\n") {
			list = append(list, f.branchJSON(name))
		}
		firstPage(list)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/branches/"):
		name := strings.TrimPrefix(path, "/branches/")
		if f.revOr("refs/heads/"+name) == "" {
			reply(404, map[string]string{})
			return
		}
		reply(200, f.branchJSON(name))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/branches/"):
		name := strings.TrimPrefix(path, "/branches/")
		f.deleted = append(f.deleted, name)
		gitIn(f.t, f.bare, "update-ref", "-d", "refs/heads/"+name)
		reply(204, nil)
	case r.Method == http.MethodPost && pr("/pulls/%d/merge"):
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		head := f.head(n)
		switch {
		case fmt.Sprint(body["head_commit_id"]) != head || body["Do"] != "squash":
			reply(409, map[string]string{"message": "head moved"})
		case f.checking[n]:
			delete(f.checking, n)
			reply(405, map[string]string{"message": "Please try again later"})
		case f.enforceBehind && f.mergeBase(n) != f.main():
			reply(405, map[string]string{"message": "head branch is behind the base branch"})
		default:
			tree := strings.Split(gitIn(f.t, f.bare, "merge-tree", "--write-tree", "refs/heads/main", head), "\n")[0]
			sha := gitIn(f.t, f.bare, "commit-tree", tree, "-p", f.main(), "-m", fmt.Sprintf("squash #%d", n))
			gitIn(f.t, f.bare, "update-ref", "refs/heads/main", sha)
			f.open[n] = false
			f.merged = append(f.merged, n)
			f.pins = append(f.pins, head)
			if f.racer {
				f.racer = false
				f.commitOn("main", "racer", "landed meanwhile\n")
			}
			reply(200, map[string]any{})
		}
	case r.Method == http.MethodPost && pr("/pulls/%d/update"):
		f.updated = append(f.updated, n)
		reply(200, map[string]any{})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/git/commits/"):
		sha := strings.TrimPrefix(path, "/git/commits/")
		reply(200, map[string]any{"sha": sha, "commit": map[string]any{"tree": map[string]any{
			"sha": gitIn(f.t, f.bare, "rev-parse", sha+"^{tree}")}}})
	default:
		reply(599, map[string]string{"message": "unexpected " + r.Method + " " + r.URL.String()})
	}
}

var trainRuns int

// sweep runs the merge step as a schedule sweep against f and fails the test
// unless it exits as wantOK says.
func (f *trainGitea) sweep(wantOK bool) string {
	f.t.Helper()
	trainRuns++
	out, ok := runAutomergeWith(f.t, f, "schedule", map[string]string{
		"GIT_URL": f.bare, "RUN_ID": fmt.Sprint(trainRuns), "RETRY_SLEEP": "0",
		"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
	if ok != wantOK {
		f.t.Fatalf("sweep ok = %v, want %v:\n%s", ok, wantOK, out)
	}
	return out
}

// twoBehind opens PRs 7 and 8 off a main that has since moved on.
func twoBehind(t *testing.T) *trainGitea {
	t.Helper()
	f := newTrainGitea(t)
	old := f.main()
	f.commitOn("main", "later", "main moved\n")
	f.openPR(7, old, "seven", "7\n")
	f.openPR(8, old, "eight", "8\n")
	return f
}

func mustContain(t *testing.T, s, want string) {
	t.Helper()
	if !strings.Contains(s, want) {
		t.Fatalf("missing %q in:\n%s", want, s)
	}
}

func TestScriptsAutomergeTrain_UpToDatePRMergesDirectly(t *testing.T) {
	f := newTrainGitea(t)
	f.openPR(7, f.main(), "seven", "7\n")
	out := f.sweep(true)
	if fmt.Sprint(f.merged) != "[7]" || len(f.trainBranches()) != 0 {
		t.Fatalf("merged %v, trains %v; want PR 7 merged directly, no train:\n%s", f.merged, f.trainBranches(), out)
	}
}

func TestScriptsAutomergeTrain_BuildsOneTrainAndWaitsForItsCI(t *testing.T) {
	f := twoBehind(t)
	base := f.main()
	out := f.sweep(true)
	name, msg := f.onlyTrain()
	mustContain(t, msg, "base "+base)
	mustContain(t, msg, fmt.Sprintf("pr 7 %s\npr 8 %s", f.head(7), f.head(8)))
	files := gitIn(t, f.bare, "ls-tree", "--name-only", name)
	for _, want := range []string{"README", "later", "seven", "eight"} {
		mustContain(t, files, want)
	}
	if len(f.merged) != 0 || len(f.updated) != 0 {
		t.Fatalf("merged %v, updated %v before the train's CI:\n%s", f.merged, f.updated, out)
	}

	out = f.sweep(true)
	mustContain(t, out, "is waiting for CI")
	if again, _ := f.onlyTrain(); again != name || len(f.merged) != 0 || len(f.deleted) != 0 {
		t.Fatalf("a pending train was replaced (%s -> %s, deleted %v) or merged %v:\n%s", name, again, f.deleted, f.merged, out)
	}
}

func TestScriptsAutomergeTrain_GreenTrainLandsInOrderAndIsDeleted(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	name, _ := f.onlyTrain()
	trainTree := gitIn(t, f.bare, "rev-parse", name+"^{tree}")
	heads := []string{f.head(7), f.head(8)}
	f.trainCI = "success"
	f.checking[8] = true // Gitea re-tests PR 8 once PR 7 lands
	out := f.sweep(true)
	if fmt.Sprint(f.merged) != "[7 8]" || fmt.Sprint(f.pins) != fmt.Sprint(heads) {
		t.Fatalf("merged %v pinned to %v, want [7 8] pinned to %v:\n%s", f.merged, f.pins, heads, out)
	}
	if len(f.trainBranches()) != 0 || !strings.Contains(strings.Join(f.deleted, " "), name) {
		t.Fatalf("train %s not deleted (deleted %v):\n%s", name, f.deleted, out)
	}
	if got := gitIn(t, f.bare, "rev-parse", "main^{tree}"); got != trainTree || strings.Contains(out, "does not have the tree") {
		t.Fatalf("main's tree %s is not the train's %s:\n%s", got, trainTree, out)
	}
}

func TestScriptsAutomergeTrain_AnUntestedTreeOnMainFailsTheRun(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	f.trainCI, f.racer = "success", true
	out := f.sweep(false)
	mustContain(t, out, "does not have the tree")
	if len(f.trainBranches()) != 0 {
		t.Fatalf("train left behind: %v", f.trainBranches())
	}
}

func TestScriptsAutomergeTrain_RedTrainDropsTheNewest(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	old, _ := f.onlyTrain()
	f.trainCI = "failure"
	out := f.sweep(true)
	name, msg := f.onlyTrain()
	if name == old || !strings.Contains(msg, "pr 7 ") || strings.Contains(msg, "pr 8 ") {
		t.Fatalf("want a new train with PR 7 only, have %s:\n%s\n%s", name, msg, out)
	}
	if len(f.comments[7]) != 1 || len(f.comments[8]) != 1 || len(f.merged) != 0 {
		t.Fatalf("comments %v, merged %v; want one comment on each train PR and no merge", f.comments, f.merged)
	}
	mustContain(t, f.comments[8][0], "without the newest, #8")

	// That one-PR train fails too: PR 7 is left to its author, and PR 8 rides alone.
	out = f.sweep(true)
	mustContain(t, f.comments[7][1], "<!-- merge-train:failed "+f.head(7)+" -->")
	if _, msg = f.onlyTrain(); strings.Contains(msg, "pr 7 ") || !strings.Contains(msg, "pr 8 ") {
		t.Fatalf("want a train with PR 8 only:\n%s\n%s", msg, out)
	}
	f.trainCI = ""
	out = f.sweep(true)
	mustContain(t, out, "PR 7 failed a train on its own")
}

func TestScriptsAutomergeTrain_OnlyTheAgentsMarkersCount(t *testing.T) {
	f := twoBehind(t)
	f.comments[8] = []string{"mallory\x00<!-- merge-train:failed " + f.head(8) + " -->"}
	out := f.sweep(true)
	if _, msg := f.onlyTrain(); !strings.Contains(msg, "pr 8 ") {
		t.Fatalf("a marker left by someone else kept PR 8 off the train:\n%s\n%s", msg, out)
	}
}

func TestScriptsAutomergeTrain_ConflictIsSkippedWithAComment(t *testing.T) {
	f := newTrainGitea(t)
	old := f.main()
	f.commitOn("main", "later", "main moved\n")
	f.openPR(7, old, "README", "seven\n")
	f.openPR(8, old, "README", "eight\n")
	out := f.sweep(true)
	_, msg := f.onlyTrain()
	if !strings.Contains(msg, "pr 7 ") || strings.Contains(msg, "pr 8 ") {
		t.Fatalf("want a train with PR 7 only:\n%s\n%s", msg, out)
	}
	if len(f.comments[8]) != 1 || len(f.comments[7]) != 0 {
		t.Fatalf("comments %v; want one on PR 8 only", f.comments)
	}
	mustContain(t, f.comments[8][0], "does not merge cleanly")
}

func TestScriptsAutomergeTrain_MainMovedAbandonsAndRebuilds(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	old, _ := f.onlyTrain()
	f.trainCI = "success"
	moved := f.commitOn("main", "hotfix", "moved again\n")
	out := f.sweep(true)
	mustContain(t, out, "abandoning "+old)
	name, msg := f.onlyTrain()
	if name == old || !strings.Contains(msg, "base "+moved) || len(f.merged) != 0 {
		t.Fatalf("want a new train on %s and nothing merged (merged %v), have %s:\n%s\n%s", moved, f.merged, name, msg, out)
	}
}

func TestScriptsAutomergeTrain_OutdatedBranchRuleFallsBackToUpdateBranch(t *testing.T) {
	t.Run("protection still blocks outdated branches", func(t *testing.T) {
		f := twoBehind(t)
		f.block, f.enforceBehind = true, true
		out := f.sweep(true)
		if fmt.Sprint(f.updated) != "[7 8]" || len(f.trainBranches()) != 0 || len(f.merged) != 0 {
			t.Fatalf("updated %v, trains %v, merged %v; want v5 update-branch, no train:\n%s", f.updated, f.trainBranches(), f.merged, out)
		}
	})
	t.Run("the merge call refuses a behind PR", func(t *testing.T) {
		f := twoBehind(t)
		f.sweep(true)
		f.trainCI, f.enforceBehind = "success", true
		out := f.sweep(true)
		if fmt.Sprint(f.updated) != "[7 8]" || len(f.trainBranches()) != 0 || len(f.merged) != 0 {
			t.Fatalf("updated %v, trains %v, merged %v; want update-branch for both and the train deleted:\n%s", f.updated, f.trainBranches(), f.merged, out)
		}
		mustContain(t, out, "fall back to update-branch")
	})
}

func TestScriptsCI_StagesRunInParallelAndTrainsRunCI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf struct {
		On struct {
			Push struct {
				Branches []string `yaml:"branches"`
			} `yaml:"push"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Needs []string `yaml:"needs"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	if !strings.Contains(strings.Join(wf.On.Push.Branches, " "), "merge-train/**") {
		t.Errorf("ci.yml does not run on pushes to merge-train/**: %v", wf.On.Push.Branches)
	}
	gate, ok := wf.Jobs["ci-gate"]
	if !ok {
		t.Fatal("ci.yml has no ci-gate job")
	}
	needs := strings.Join(gate.Needs, " ")
	var checks strings.Builder
	for _, s := range gate.Steps {
		checks.WriteString(s.Run)
	}
	for name, job := range wf.Jobs {
		if name == "ci-gate" {
			continue
		}
		if len(job.Needs) != 0 {
			t.Errorf("job %s waits on %v; every stage starts at once", name, job.Needs)
		}
		if !strings.Contains(" "+needs+" ", " "+name+" ") || !strings.Contains(checks.String(), "needs."+name+".result") {
			t.Errorf("ci-gate does not both need and check job %s", name)
		}
	}
}
