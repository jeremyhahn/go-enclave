package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/goccy/go-yaml"
)

// codeReviewWorkflowFile is the review workflow, relative to the repository
// root.
const codeReviewWorkflowFile = ".github/workflows/code-review.yml"

// readyForReviewViolations returns what is wrong with the `types` of event in
// a workflow's `on:`, or nil. A draft PR marked ready fires the event with
// action ready_for_review; a `types` list without it starts no run on the mark.
func readyForReviewViolations(src []byte, event string) ([]string, error) {
	var wf tieredWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	events, err := workflowEvents(wf.On)
	if err != nil {
		return nil, err
	}
	ev, ok := events[event]
	if !ok {
		return []string{fmt.Sprintf("has no %s trigger", event)}, nil
	}
	cfg, _ := ev.(map[string]any)
	types, ok := cfg["types"].([]any)
	if !ok {
		// No types list: GitHub's default (opened, synchronize, reopened)
		// leaves ready_for_review out.
		return []string{fmt.Sprintf("%s lists no types, so ready_for_review starts no run", event)}, nil
	}
	if !slices.ContainsFunc(types, func(t any) bool { return t == "ready_for_review" }) {
		return []string{fmt.Sprintf("%s types %v lack ready_for_review: marking a draft ready starts no run", event, types)}, nil
	}
	return nil, nil
}

func TestWorkflowsRunWhenADraftIsMarkedReady(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct{ file, event string }{
		{ciWorkflowFile, "pull_request"},
		{codeReviewWorkflowFile, "pull_request_target"},
	} {
		src, err := os.ReadFile(filepath.Join(root, tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		bad, err := readyForReviewViolations(src, tc.event)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", tc.file, b)
		}
	}
}

func TestReadyForReviewViolations_RefusesWhatItMustRefuse(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		wantBad   bool
	}{
		{"listed", "on:\n  pull_request:\n    types: [opened, ready_for_review]\n", false},
		{"missing", "on:\n  pull_request:\n    types: [opened, synchronize, reopened]\n", true},
		{"no types", "on:\n  pull_request:\n    branches: [main]\n", true},
		{"no event", "on: push\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := readyForReviewViolations([]byte(tc.src), "pull_request")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if (len(bad) > 0) != tc.wantBad {
				t.Errorf("violations %v, want bad=%v", bad, tc.wantBad)
			}
		})
	}
}
