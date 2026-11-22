package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/goccy/go-yaml"
)

var (
	// ciScriptRef is a scripts/*.sh path anywhere in a step's run script.
	ciScriptRef = regexp.MustCompile(`(?:^|[\s"'=(])(scripts/[A-Za-z0-9._/-]+\.sh)\b`)
	// ciScriptExec is a scripts/*.sh path run as a command of its own (first
	// word of a line, or after a shell list operator), which needs the
	// executable bit.
	ciScriptExec = regexp.MustCompile(`(?m)(?:^|&&|\|\||;|\|)\s*(scripts/[A-Za-z0-9._/-]+\.sh)\b`)
)

// TestCIHelperScriptsShip checks that every scripts/*.sh a ci.yml step runs
// is in the tree, and is executable where the step runs it as a command. A
// missing helper fails its job with exit 127, on every runner.
func TestCIHelperScriptsShip(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	refs := map[string]bool{} // path -> run as a command
	for _, job := range wf.Jobs {
		for _, st := range job.Steps {
			for _, m := range ciScriptRef.FindAllStringSubmatch(st.Run, -1) {
				if _, seen := refs[m[1]]; !seen {
					refs[m[1]] = false
				}
			}
			for _, m := range ciScriptExec.FindAllStringSubmatch(st.Run, -1) {
				refs[m[1]] = true
			}
		}
	}
	for _, want := range []string{"scripts/ci-mask-lan.sh", "scripts/ci-image-history.sh"} {
		if !refs[want] {
			t.Errorf("ci.yml runs no %s as a command; the template's steps do", want)
		}
	}
	paths := make([]string, 0, len(refs))
	for p := range refs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Errorf("ci.yml calls %s, which is not in the tree: %v", p, err)
			continue
		}
		if refs[p] && fi.Mode().Perm()&0o111 != 0o111 {
			t.Errorf("ci.yml runs %s as a command, but its mode is %v, want 755", p, fi.Mode().Perm())
		}
	}
}
