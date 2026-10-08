package buildgates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
			With map[string]string `yaml:"with"`
			Env  map[string]string `yaml:"env"`
			Run  string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// automergeScript is the merge step's script, which the workflow runs from the
// base branch.
const automergeScript = "build/ci/automerge.sh"

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
	// The merge script is read from the repository, so the job checks out the
	// base branch: anything else could hand the token to the PR's own code.
	const baseRef = "${{ github.event.repository.default_branch }}"
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if !strings.Contains(s.Uses, "checkout") {
				continue
			}
			if s.With["ref"] != baseRef {
				t.Errorf("job %s checks out %q; the token-bearing run must check out only the base branch (%s)", name, s.With["ref"], baseRef)
			}
			if s.With["persist-credentials"] != "false" {
				t.Errorf("job %s leaves credentials in its checkout", name)
			}
		}
	}
}

func TestScriptsAutomerge_StepRunsTheScript(t *testing.T) {
	wf := readAutomerge(t)
	var runs []string
	for _, s := range wf.Jobs["merge"].Steps {
		if s.Run != "" {
			runs = append(runs, s.Run)
		}
	}
	if len(runs) != 1 || strings.Count(runs[0], "\n") > 1 || !strings.Contains(runs[0], automergeScript) {
		t.Errorf("the merge job must run %s as its one inline command, got %q", automergeScript, runs)
	}
	if _, err := os.Stat(filepath.Join(repoRoot(t), automergeScript)); err != nil {
		t.Errorf("the merge script: %v", err)
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
	var step struct {
		Env map[string]string
	}
	for _, s := range wf.Jobs["merge"].Steps {
		if strings.Contains(s.Run, automergeScript) {
			step.Env = s.Env
		}
	}
	srv := httptest.NewServer(api)
	defer srv.Close()
	// The script keeps its scratch files in a mktemp directory of its own;
	// point TMPDIR at the test's so a run leaves nothing behind.
	tmp := t.TempDir()
	env := map[string]string{"TMPDIR": tmp}
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
	cmd := exec.Command("bash", filepath.Join(repoRoot(t), automergeScript))
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
// constituent PR heads are refs/pull/N/head, a train PR's head is its
// merge-train/* branch, and a squash merge writes a commit onto main. The
// workflow fetches and pushes that repository.
type trainGitea struct {
	t            *testing.T
	mu           sync.Mutex
	bare         string
	prs          map[int]*fakePR
	nextPR       int
	issues       map[int]bool // issue number -> open
	block        bool         // block_on_outdated_branch: a merge must contain main's tip
	trainCI      string       // the PR status on any merge-train/* tip; "" is none yet
	checking     map[int]bool
	racer        bool   // main gains a commit just before the next merge is applied
	racerPR      func() // runs once, right after the next merge is applied
	keywordClose bool   // a merge closes what its PR body's "Closes #n" lines name, as Gitea does
	merged       []int
	pins         []string
	messages     []string // each squash: title, blank line, message
	updated      []int
	deleted      []string
	closed       []int
	reopened     []int
	closedIssues []int
	comments     map[int][]string
}

type fakePR struct {
	ref      string // the git ref holding its head
	branch   string // head.ref as Gitea reports it
	title    string
	body     string
	user     string
	open     bool
	mergeSHA string
}

const (
	trainAgent = "agent-r"
	prContext  = "CI / CI Gate (pull_request)"
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
	f := &trainGitea{t: t, bare: t.TempDir(), prs: map[int]*fakePR{}, nextPR: 100, issues: map[int]bool{},
		block: true, checking: map[int]bool{}, comments: map[int][]string{}}
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
	return f.commitTree(parent, ref, file, body, "change "+file)
}

// commitTree commits parent's tree plus file=body as msg and points ref at it.
func (f *trainGitea) commitTree(parent, ref, file, body, msg string) string {
	f.t.Helper()
	blob := strings.TrimSpace(f.gitStdin(body, "hash-object", "-w", "--stdin"))
	idx := filepath.Join(f.t.TempDir(), "index")
	env := []string{"GIT_INDEX_FILE=" + idx}
	if parent != "" {
		f.gitEnv(env, "read-tree", parent)
	}
	f.gitEnv(env, "update-index", "--add", "--cacheinfo", "100644,"+blob+","+file)
	tree := f.gitEnv(env, "write-tree")
	args := []string{"commit-tree", tree, "-m", msg}
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

// openPR opens PR n, by claude from branch issue/<n>, with file=body
// committed onto from (a main commit).
func (f *trainGitea) openPR(n int, from, file, body string) string {
	f.t.Helper()
	ref := fmt.Sprintf("refs/pull/%d/head", n)
	f.prs[n] = &fakePR{ref: ref, branch: fmt.Sprintf("issue/%d", n), title: fmt.Sprintf("feat: change %d", n), user: "claude", open: true}
	sha := f.commitFrom(from, ref, file, body)
	gitIn(f.t, f.bare, "update-ref", "refs/heads/"+f.prs[n].branch, sha)
	return sha
}

func (f *trainGitea) head(n int) string {
	if p := f.prs[n]; p != nil {
		return f.revOr(p.ref)
	}
	return ""
}
func (f *trainGitea) main() string { return f.revOr("refs/heads/main") }

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

// openTrainPRs returns the open PRs whose head is a merge-train/* branch.
func (f *trainGitea) openTrainPRs() map[int]*fakePR {
	out := map[int]*fakePR{}
	for n, p := range f.prs {
		if p.open && strings.HasPrefix(p.branch, "merge-train/") {
			out[n] = p
		}
	}
	return out
}

// onlyTrainPR returns the single open train PR, which must be the agent's and
// be headed by the single train branch.
func (f *trainGitea) onlyTrainPR() (int, *fakePR) {
	f.t.Helper()
	name, _ := f.onlyTrain()
	prs := f.openTrainPRs()
	if len(prs) != 1 {
		f.t.Fatalf("want exactly one open train PR, have %d", len(prs))
	}
	for n, p := range prs {
		if p.branch != name || p.user != trainAgent {
			f.t.Fatalf("train PR #%d is %s by %s, want %s by %s", n, p.branch, p.user, name, trainAgent)
		}
		return n, p
	}
	return 0, nil
}

func (f *trainGitea) branchJSON(name string) map[string]any {
	sha := f.revOr("refs/heads/" + name)
	return map[string]any{"name": name, "commit": map[string]any{"id": sha,
		"message": gitIn(f.t, f.bare, "log", "-1", "--format=%B", sha)}}
}

func (f *trainGitea) mergeBase(n int) string {
	h := f.head(n)
	if h == "" {
		return ""
	}
	return gitIn(f.t, f.bare, "merge-base", "refs/heads/main", h)
}

func (f *trainGitea) prJSON(n int) map[string]any {
	p := f.prs[n]
	state := "closed"
	if p.open {
		state = "open"
	}
	return map[string]any{"number": n, "state": state, "draft": false, "title": p.title, "body": p.body,
		"head":       map[string]any{"sha": f.head(n), "ref": p.branch, "repo": map[string]any{"full_name": "o/r"}},
		"base":       map[string]any{"ref": "main", "repo": map[string]any{"full_name": "o/r"}},
		"merge_base": f.mergeBase(n), "user": map[string]any{"login": p.user}, "merge_commit_sha": p.mergeSHA}
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
		return err == nil && fmt.Sprintf(format, n) == path && f.prs[n] != nil
	}
	switch {
	case r.Method == http.MethodGet && path == "/pulls":
		list := []map[string]any{}
		for num, p := range f.prs {
			if p.open {
				list = append(list, f.prJSON(num))
			}
		}
		firstPage(list)
	case r.Method == http.MethodPost && path == "/pulls":
		var body struct{ Title, Body, Head, Base string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, p := range f.prs {
			if p.open && p.branch == body.Head {
				reply(409, map[string]string{"message": "pull request already exists"})
				return
			}
		}
		if body.Base != "main" || f.revOr("refs/heads/"+body.Head) == "" {
			reply(422, map[string]string{"message": "bad head or base"})
			return
		}
		f.nextPR++
		f.prs[f.nextPR] = &fakePR{ref: "refs/heads/" + body.Head, branch: body.Head, title: body.Title, body: body.Body, user: trainAgent, open: true}
		reply(201, f.prJSON(f.nextPR))
	case r.Method == http.MethodGet && pr("/pulls/%d"):
		reply(200, f.prJSON(n))
	case r.Method == http.MethodPatch && pr("/pulls/%d"):
		var body struct{ State string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body.State {
		case "closed":
			f.prs[n].open = false
			f.closed = append(f.closed, n)
		case "open":
			f.prs[n].open = true
			f.reopened = append(f.reopened, n)
		default:
			reply(422, map[string]string{"message": "bad state"})
			return
		}
		reply(201, f.prJSON(n))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/issues/") && !strings.Contains(strings.TrimPrefix(path, "/issues/"), "/"):
		num, _ := strconv.Atoi(strings.TrimPrefix(path, "/issues/"))
		switch open, ok := f.issues[num]; {
		case f.prs[num] != nil:
			reply(200, map[string]any{"number": num, "state": "open", "pull_request": map[string]any{"merged": false}})
		case ok:
			state := "closed"
			if open {
				state = "open"
			}
			reply(200, map[string]any{"number": num, "state": state, "pull_request": nil})
		default:
			reply(404, map[string]string{"message": "no such issue"})
		}
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/issues/"):
		num, _ := strconv.Atoi(strings.TrimPrefix(path, "/issues/"))
		if _, ok := f.issues[num]; !ok {
			reply(404, map[string]string{"message": "no such issue"})
			return
		}
		f.issues[num] = false
		f.closedIssues = append(f.closedIssues, num)
		reply(201, map[string]any{"number": num, "state": "closed"})
	case r.Method == http.MethodGet && path == "/branch_protections/main":
		reply(200, map[string]any{"enable_status_check": true, "block_on_outdated_branch": f.block,
			"status_check_contexts": []string{prContext}})
	case r.Method == http.MethodDelete && pr("/pulls/%d/merge"):
		reply(404, map[string]string{})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/commits/") && strings.HasSuffix(path, "/status"):
		sha := strings.TrimSuffix(strings.TrimPrefix(path, "/commits/"), "/status")
		statuses := []map[string]string{}
		for num, p := range f.prs {
			if p.open && !strings.HasPrefix(p.branch, "merge-train/") && f.head(num) == sha {
				statuses = append(statuses, map[string]string{"context": prContext, "status": "success"})
			}
		}
		for _, tip := range f.trainBranches() {
			if tip == sha && f.trainCI != "" {
				statuses = append(statuses, map[string]string{"context": prContext, "status": f.trainCI})
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
		if f.revOr("refs/heads/"+name) == "" {
			reply(404, map[string]string{})
			return
		}
		f.deleted = append(f.deleted, name)
		gitIn(f.t, f.bare, "update-ref", "-d", "refs/heads/"+name)
		reply(204, nil)
	case r.Method == http.MethodPost && pr("/pulls/%d/merge"):
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p, head := f.prs[n], f.head(n)
		if f.racer {
			f.racer = false
			f.commitOn("main", "racer", "landed meanwhile\n")
		}
		switch {
		case !p.open || fmt.Sprint(body["head_commit_id"]) != head || body["Do"] != "squash":
			reply(409, map[string]string{"message": "head moved"})
		case f.checking[n]:
			delete(f.checking, n)
			reply(405, map[string]string{"message": "Please try again later"})
		case f.block && f.mergeBase(n) != f.main():
			reply(405, map[string]string{"message": "head branch is behind the base branch"})
		default:
			msg := fmt.Sprintf("squash #%d", n)
			if title, ok := body["MergeTitleField"].(string); ok && title != "" {
				msg = title + "\n\n" + fmt.Sprint(body["MergeMessageField"])
			}
			tree := strings.Split(gitIn(f.t, f.bare, "merge-tree", "--write-tree", "refs/heads/main", head), "\n")[0]
			sha := gitIn(f.t, f.bare, "commit-tree", tree, "-p", f.main(), "-m", msg)
			gitIn(f.t, f.bare, "update-ref", "refs/heads/main", sha)
			p.open, p.mergeSHA = false, sha
			f.merged = append(f.merged, n)
			f.pins = append(f.pins, head)
			f.messages = append(f.messages, msg)
			if f.racerPR != nil {
				f.racerPR()
				f.racerPR = nil
			}
			if f.keywordClose {
				for _, l := range strings.Split(p.body, "\n") {
					var ref int
					if _, err := fmt.Sscanf(l, "Closes #%d", &ref); err == nil {
						if q := f.prs[ref]; q != nil {
							q.open = false
						} else if _, ok := f.issues[ref]; ok {
							f.issues[ref] = false
						}
					}
				}
			}
			if body["delete_branch_after_merge"] == true && strings.HasPrefix(p.ref, "refs/heads/") {
				f.deleted = append(f.deleted, p.branch)
				gitIn(f.t, f.bare, "update-ref", "-d", p.ref)
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

// run runs the merge step for event against f and fails the test unless it
// exits as wantOK says.
func (f *trainGitea) run(event string, pr int, wantOK bool) string {
	f.t.Helper()
	trainRuns++
	out, ok := runAutomergeWith(f.t, f, event, map[string]string{
		"GIT_URL": f.bare, "RUN_ID": fmt.Sprint(trainRuns), "RETRY_SLEEP": "0", "PR_FROM_EVENT": fmt.Sprint(pr),
		"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
	if ok != wantOK {
		f.t.Fatalf("%s run ok = %v, want %v:\n%s", event, ok, wantOK, out)
	}
	return out
}

// sweep runs the merge step as a schedule sweep.
func (f *trainGitea) sweep(wantOK bool) string {
	f.t.Helper()
	return f.run("schedule", 0, wantOK)
}

// twoBehind opens PRs 7 and 8 off a main that has since moved on. PR 7
// closes issue 3; PR 8 fixes issue 4 and mentions PR 7.
func twoBehind(t *testing.T) *trainGitea {
	t.Helper()
	f := newTrainGitea(t)
	old := f.main()
	f.commitOn("main", "later", "main moved\n")
	f.openPR(7, old, "seven", "7\n")
	f.openPR(8, old, "eight", "8\n")
	f.prs[7].body = "Closes #3\n\nSee the design notes."
	f.prs[8].body = "Fixes #4. Resolves #7, and close #8 is ignored."
	f.issues[3], f.issues[4] = true, true
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
	if fmt.Sprint(f.merged) != "[7]" || len(f.trainBranches()) != 0 || len(f.openTrainPRs()) != 0 {
		t.Fatalf("merged %v, trains %v; want PR 7 merged directly, no train:\n%s", f.merged, f.trainBranches(), out)
	}
	if f.pins[0] != f.head(7) {
		t.Fatalf("merge pinned to %s, want PR 7's head %s", f.pins[0], f.head(7))
	}
}

func TestScriptsAutomergeTrain_OpensOneTrainPRAndWaitsForItsCI(t *testing.T) {
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
	trainPR, p := f.onlyTrainPR()
	if p.title != "merge train: #7, #8" {
		t.Fatalf("train PR title %q, want %q", p.title, "merge train: #7, #8")
	}
	for _, want := range []string{"#7 feat: change 7 (" + f.head(7) + ")", "#8 feat: change 8 (" + f.head(8) + ")",
		"Closes #3\n", "Closes #4\n", "Closes #7\n", "Closes #8\n"} {
		mustContain(t, p.body, want)
	}
	if strings.Count(p.body, "Closes #7\n") != 1 {
		t.Fatalf("PR 7 is closed twice in the train body:\n%s", p.body)
	}
	if len(f.merged) != 0 || len(f.updated) != 0 || len(f.closed) != 0 {
		t.Fatalf("merged %v, updated %v, closed %v before the train's CI:\n%s", f.merged, f.updated, f.closed, out)
	}

	out = f.sweep(true)
	mustContain(t, out, "is waiting for CI")
	if again, _ := f.onlyTrainPR(); again != trainPR || len(f.merged) != 0 || len(f.deleted) != 0 {
		t.Fatalf("a pending train was replaced (#%d -> #%d, deleted %v) or merged %v:\n%s", trainPR, again, f.deleted, f.merged, out)
	}
}

func TestScriptsAutomergeTrain_GreenTrainSquashesTheTrainPRAndClosesItsPRs(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	name, _ := f.onlyTrain()
	trainPR, _ := f.onlyTrainPR()
	trainTip := f.trainBranches()[name]
	trainTree := gitIn(t, f.bare, "rev-parse", name+"^{tree}")
	f.trainCI = "success"
	f.checking[trainPR] = true // Gitea answers "try again later" once
	out := f.sweep(true)

	if fmt.Sprint(f.merged) != fmt.Sprint([]int{trainPR}) || fmt.Sprint(f.pins) != fmt.Sprint([]string{trainTip}) {
		t.Fatalf("merged %v pinned to %v, want only train PR #%d pinned to %s:\n%s", f.merged, f.pins, trainPR, trainTip, out)
	}
	squash := f.prs[trainPR].mergeSHA
	if got := gitIn(t, f.bare, "rev-parse", "main^{tree}"); got != trainTree || f.main() != squash {
		t.Fatalf("main (%s, tree %s) is not the squash %s of the train tree %s:\n%s", f.main(), got, squash, trainTree, out)
	}
	title, body, _ := strings.Cut(f.messages[0], "\n\n")
	if want := fmt.Sprintf("merge train: feat: change 7; feat: change 8 (#%d)", trainPR); title != want {
		t.Fatalf("squash title %q, want %q", title, want)
	}
	mustContain(t, body, "- #7 feat: change 7")
	mustContain(t, body, "- #8 feat: change 8")
	if len(f.trainBranches()) != 0 || !strings.Contains(strings.Join(f.deleted, " "), name) {
		t.Fatalf("train %s not deleted (deleted %v):\n%s", name, f.deleted, out)
	}
	for _, n := range []int{7, 8} {
		if !strings.Contains(" "+strings.Join(f.deleted, " ")+" ", fmt.Sprintf(" issue/%d ", n)) {
			t.Fatalf("PR %d's branch was not deleted (deleted %v):\n%s", n, f.deleted, out)
		}
		if f.prs[n].open || len(f.comments[n]) != 1 {
			t.Fatalf("PR %d open=%v comments %q; want it closed with one comment:\n%s", n, f.prs[n].open, f.comments[n], out)
		}
		mustContain(t, f.comments[n][0], fmt.Sprintf("Landed in %s via merge train #%d", squash, trainPR))
	}
	if fmt.Sprint(f.closedIssues) != "[3 4]" {
		t.Fatalf("closed issues %v, want [3 4] (PR 7 is not an issue):\n%s", f.closedIssues, out)
	}
	if strings.Contains(out, "does not have the tree") {
		t.Fatalf("a clean landing reported a tree mismatch:\n%s", out)
	}
}

func TestScriptsAutomergeTrain_APRThatMovedWhileLandingStaysOpen(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	f.trainCI = "success"
	landed := f.head(8)
	f.racerPR = func() { f.commitFrom(landed, "refs/pull/8/head", "eight", "8 again\n") }
	f.keywordClose = true
	out := f.sweep(true)
	if !f.prs[8].open || f.prs[7].open {
		t.Fatalf("PR 7 open=%v, PR 8 open=%v; want only PR 8, which moved, left open:\n%s", f.prs[7].open, f.prs[8].open, out)
	}
	mustContain(t, strings.Join(f.comments[8], "\n"), "pushed since")
}

func TestScriptsAutomergeTrain_AnUntestedTreeOnMainFailsTheRun(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	f.block = false // nothing stops Gitea squashing onto a main that moved
	f.trainCI, f.racer = "success", true
	out := f.sweep(false)
	mustContain(t, out, "does not have the tree")
	if len(f.trainBranches()) != 0 {
		t.Fatalf("train left behind: %v", f.trainBranches())
	}
}

func TestScriptsAutomergeTrain_MainMovingDuringTheMergeAbandonsTheTrain(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	old, _ := f.onlyTrainPR()
	f.trainCI, f.racer = "success", true
	out := f.sweep(true)
	if len(f.merged) != 0 || f.prs[old].open {
		t.Fatalf("merged %v, train PR #%d open=%v; want nothing merged and the train PR closed:\n%s", f.merged, old, f.prs[old].open, out)
	}
	if again, _ := f.onlyTrainPR(); again == old {
		t.Fatalf("no new train after main moved:\n%s", out)
	}
}

func TestScriptsAutomergeTrain_ATamperedTrainIsNeverLanded(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	name, msg := f.onlyTrain()
	trainPR, _ := f.onlyTrainPR()
	tip := f.trainBranches()[name]
	// Same recorded base and heads, one extra file: only the tree tells.
	f.commitTree(tip+"^", "refs/heads/"+name, "evil", "x\n", msg)
	f.trainCI = "success"
	out := f.sweep(true)
	mustContain(t, out, "abandoning "+name)
	if len(f.merged) != 0 || f.prs[trainPR].open {
		t.Fatalf("merged %v, train PR open=%v; a train whose tree is not main plus its PRs must not land:\n%s", f.merged, f.prs[trainPR].open, out)
	}
	if again, _ := f.onlyTrain(); strings.Contains(gitIn(t, f.bare, "ls-tree", "--name-only", again), "evil") {
		t.Fatalf("the rebuilt train kept the tampered file:\n%s", out)
	}
}

func TestScriptsAutomergeTrain_RedTrainDropsTheNewest(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	old, _ := f.onlyTrain()
	oldPR, _ := f.onlyTrainPR()
	f.trainCI = "failure"
	out := f.sweep(true)
	name, msg := f.onlyTrain()
	if name == old || !strings.Contains(msg, "pr 7 ") || strings.Contains(msg, "pr 8 ") {
		t.Fatalf("want a new train with PR 7 only, have %s:\n%s\n%s", name, msg, out)
	}
	if f.prs[oldPR].open {
		t.Fatalf("the red train PR #%d was left open:\n%s", oldPR, out)
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

func TestScriptsAutomergeTrain_ALandedPRLeftOpenIsClosed(t *testing.T) {
	f := twoBehind(t)
	f.comments[8] = []string{"Landed in x via merge train #1.\n\n<!-- merge-train:landed " + f.head(8) + " -->"}
	out := f.sweep(true)
	if f.prs[8].open || !strings.Contains(strings.Join(f.deleted, " "), "issue/8") {
		t.Fatalf("PR 8, already landed at its head, was left open or its branch kept (deleted %v):\n%s", f.deleted, out)
	}
	if _, msg := f.onlyTrain(); strings.Contains(msg, "pr 8 ") {
		t.Fatalf("a landed PR boarded another train:\n%s\n%s", msg, out)
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

func TestScriptsAutomergeTrain_MainMovedClosesTheTrainPRAndRebuilds(t *testing.T) {
	for _, ci := range []string{"", "success"} {
		t.Run("train CI "+ci, func(t *testing.T) { mainMovedRebuilds(t, ci) })
	}
}

func mainMovedRebuilds(t *testing.T, ci string) {
	f := twoBehind(t)
	f.sweep(true)
	old, _ := f.onlyTrain()
	oldPR, _ := f.onlyTrainPR()
	f.trainCI = ci
	moved := f.commitOn("main", "hotfix", "moved again\n")
	out := f.sweep(true)
	mustContain(t, out, "abandoning "+old)
	name, msg := f.onlyTrain()
	newPR, _ := f.onlyTrainPR()
	if name == old || newPR == oldPR || !strings.Contains(msg, "base "+moved) || len(f.merged) != 0 {
		t.Fatalf("want a new train PR on %s and nothing merged (merged %v), have %s (#%d):\n%s\n%s", moved, f.merged, name, newPR, msg, out)
	}
	if f.prs[oldPR].open || !strings.Contains(strings.Join(f.deleted, " "), old) {
		t.Fatalf("old train PR #%d open=%v, deleted %v; want it closed and %s deleted", oldPR, f.prs[oldPR].open, f.deleted, old)
	}
}

func TestScriptsAutomergeTrain_ATrainBranchWithoutItsPRGetsOne(t *testing.T) {
	f := twoBehind(t)
	f.sweep(true)
	trainPR, _ := f.onlyTrainPR()
	f.prs[trainPR].open = false // as if the run died between push and PR
	delete(f.prs, trainPR)
	out := f.sweep(true)
	if again, _ := f.onlyTrainPR(); again == trainPR || len(f.merged) != 0 {
		t.Fatalf("want a new PR for the existing train and nothing merged:\n%s", out)
	}
}

func TestScriptsAutomergeTrain_TrainPRsNeverBoardATrain(t *testing.T) {
	t.Run("the agent's own train PR", func(t *testing.T) {
		f := twoBehind(t)
		f.sweep(true)
		trainPR, _ := f.onlyTrainPR()
		out := f.run("pull_request_target", trainPR, true)
		mustContain(t, out, "is a merge train")
		out = f.sweep(true)
		if strings.Contains(out, fmt.Sprintf("PR %d is ready", trainPR)) || len(f.merged) != 0 {
			t.Fatalf("the sweep treated train PR #%d as a candidate:\n%s", trainPR, out)
		}
	})
	t.Run("someone else's PR from the train's own branch", func(t *testing.T) {
		f := twoBehind(t)
		f.sweep(true)
		name, _ := f.onlyTrain()
		trainPR, _ := f.onlyTrainPR()
		delete(f.prs, trainPR)
		f.prs[50] = &fakePR{ref: "refs/heads/" + name, branch: name, title: "merge train: #7, #8", user: "mallory", open: true}
		f.trainCI = "success"
		out := f.sweep(true)
		if len(f.merged) != 0 || len(f.closed) != 0 {
			t.Fatalf("merged %v, closed %v; only a train PR the agent opened may land:\n%s", f.merged, f.closed, out)
		}
		if _, ok := f.trainBranches()[name]; ok {
			t.Fatalf("a train held by someone else's PR was kept, so it can never land:\n%s", out)
		}
		f.sweep(true)
		ours := 0
		for _, p := range f.openTrainPRs() {
			if p.user == trainAgent {
				ours++
			}
		}
		if ours != 1 || len(f.merged) != 0 {
			t.Fatalf("want one new train PR by the agent after the rebuild, have %d (merged %v)", ours, f.merged)
		}
	})
	t.Run("a merge-train branch PR by someone else", func(t *testing.T) {
		f := newTrainGitea(t)
		f.commitFrom(f.main(), "refs/heads/merge-train/1-1", "evil", "x\n")
		f.prs[50] = &fakePR{ref: "refs/heads/merge-train/1-1", branch: "merge-train/1-1", title: "merge train: #1", user: "mallory", open: true}
		f.trainCI = "success"
		out := f.sweep(true)
		if len(f.merged) != 0 {
			t.Fatalf("merged %v; a merge-train PR not opened by the agent must never land:\n%s", f.merged, out)
		}
		out = f.run("pull_request_target", 50, true)
		if len(f.merged) != 0 {
			t.Fatalf("merged %v from its own event:\n%s", f.merged, out)
		}
	})
}

func TestScriptsAutomergeTrain_RunsWithTheOutdatedBranchRuleOn(t *testing.T) {
	f := twoBehind(t)
	if !f.block {
		t.Fatal("train tests must run with block_on_outdated_branch on, as main has it")
	}
	f.sweep(true)
	if len(f.updated) != 0 {
		t.Fatalf("updated %v: with the flag on, behind PRs board a train instead of update-branch", f.updated)
	}
	f.onlyTrainPR()
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
			PullRequest struct {
				Branches []string `yaml:"branches"`
			} `yaml:"pull_request"`
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
	// A train is a PR into main, so it runs CI through pull_request.
	if fmt.Sprint(wf.On.PullRequest.Branches) != "[main]" {
		t.Errorf("ci.yml pull_request branches = %v, want [main]", wf.On.PullRequest.Branches)
	}
	if fmt.Sprint(wf.On.Push.Branches) != "[main]" {
		t.Errorf("ci.yml push branches = %v, want [main]", wf.On.Push.Branches)
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
