package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
)

// Every workflow declares a top-level `permissions:` block, and that block
// grants no write scope. Without one, the workflow token takes the repository's
// default, which on a forge or mirror configured permissively is write on
// everything; a job that needs more says so in its own `permissions:`, where a
// reviewer sees the grant next to the job that uses it.

// workflowPermissionScopes are the scopes of a workflow token (GitHub Actions
// "Controlling permissions for GITHUB_TOKEN"). A scope not listed is refused, so
// a mistyped one cannot look like a grant that is not there.
var workflowPermissionScopes = map[string]bool{
	"actions": true, "attestations": true, "checks": true,
	"contents": true, "deployments": true, "discussions": true, "id-token": true,
	"issues": true, "models": true, "packages": true, "pages": true,
	"pull-requests": true, "security-events": true, "statuses": true,
}

// permissionsViolations returns what is wrong with one workflow's source,
// or nil when it is acceptable.
func permissionsViolations(src []byte) ([]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	var bad []string
	perms, ok := doc["permissions"]
	switch {
	case !ok:
		bad = append(bad, "no top-level `permissions:` block")
	case perms == nil:
		bad = append(bad, "top-level `permissions:` is empty (null); write `permissions: {}` or the scopes needed")
	default:
		// Fail closed: only these shapes and values pass, so an expression,
		// a typo or a future write-capable value is refused, not waved through.
		switch p := perms.(type) {
		case string:
			if p != "read-all" {
				bad = append(bad, fmt.Sprintf("top-level `permissions: %s`; want read-all, {} or a mapping of scopes at read or none", p))
			}
		case map[string]any:
			for scope, level := range p {
				if !workflowPermissionScopes[scope] {
					bad = append(bad, fmt.Sprintf("top-level `permissions:` names %q, which is not a workflow token scope", scope))
					continue
				}
				if l, isString := level.(string); !isString || (l != "read" && l != "none") {
					bad = append(bad, fmt.Sprintf("top-level `permissions: %s: %v`; want read or none, and grant write in the one job that needs it", scope, level))
				}
			}
		default:
			bad = append(bad, fmt.Sprintf("top-level `permissions:` is a %T, want read-all, {} or a mapping of scopes", perms))
		}
	}
	return bad, nil
}

func TestWorkflowsDeclareLeastPrivilegePermissions(t *testing.T) {
	root := repoRoot(t)
	files := workflowFiles(t, root)
	if len(files) < minWorkflowFiles {
		t.Fatalf("discovery floor: found %d workflow file(s), want at least %d; the gate would check nothing", len(files), minWorkflowFiles)
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			bad, err := permissionsViolations(src)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, b := range bad {
				t.Errorf("%s: %s", f, b)
			}
		})
	}
}

// TestWorkflowPermissionsGate_RefusesWhatItMustRefuse pins the check against
// hand-written workflows, so a rewrite that stops looking cannot pass.
func TestWorkflowPermissionsGate_RefusesWhatItMustRefuse(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		wantBad   bool
	}{
		{"none", "name: x\non: push\njobs: {}\n", true},
		{"null", "name: x\npermissions:\njobs: {}\n", true},
		{"write-all", "name: x\npermissions: write-all\njobs: {}\n", true},
		{"scope write", "name: x\npermissions:\n  contents: write\njobs: {}\n", true},
		{"a list", "name: x\npermissions: [contents]\njobs: {}\n", true},
		{"unknown scalar", "name: x\npermissions: read\njobs: {}\n", true},
		{"empty string", "name: x\npermissions: ''\njobs: {}\n", true},
		{"expression scalar", "name: x\npermissions: ${{ vars.PERMS }}\njobs: {}\n", true},
		{"expression level", "name: x\npermissions:\n  contents: ${{ vars.LEVEL }}\njobs: {}\n", true},
		{"unknown level", "name: x\npermissions:\n  contents: admin\njobs: {}\n", true},
		{"boolean level", "name: x\npermissions:\n  contents: true\njobs: {}\n", true},
		{"mapping level", "name: x\npermissions:\n  contents: {level: read}\njobs: {}\n", true},
		{"null level", "name: x\npermissions:\n  contents:\njobs: {}\n", true},
		{"unknown scope", "name: x\npermissions:\n  content: read\njobs: {}\n", true},
		{"one scope write among reads", "name: x\npermissions:\n  contents: read\n  id-token: write\njobs: {}\n", true},
		{"scope none", "name: x\npermissions:\n  contents: none\njobs: {}\n", false},
		{"several scopes", "name: x\npermissions:\n  contents: read\n  pull-requests: read\n  id-token: none\njobs: {}\n", false},
		{"read", "name: x\npermissions:\n  contents: read\njobs: {}\n", false},
		{"read-all", "name: x\npermissions: read-all\njobs: {}\n", false},
		{"empty mapping", "name: x\npermissions: {}\njobs: {}\n", false},
		{"write only in a job", "name: x\npermissions:\n  contents: read\njobs:\n  a:\n    permissions:\n      contents: write\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := permissionsViolations([]byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if (len(bad) > 0) != tc.wantBad {
				t.Fatalf("violations = %v, want a refusal: %v", bad, tc.wantBad)
			}
		})
	}
}
