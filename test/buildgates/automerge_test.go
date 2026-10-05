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

const fakeHead = "0123456789abcdef0123456789abcdef01234567"

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
			"user": map[string]any{"login": f.author}})
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
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("the merge step needs jq: %v", err)
	}
	wf := readAutomerge(t)
	step := wf.Jobs["merge"].Steps[0]
	srv := httptest.NewServer(f)
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
	env["EVENT"] = event
	env["PR_FROM_EVENT"] = "7"
	env["RUN_SHA"] = fakeHead
	env["no_proxy"], env["NO_PROXY"] = "*", "*"
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
