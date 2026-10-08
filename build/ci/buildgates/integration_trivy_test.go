package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The integration job scans the image it builds with the pinned trivy, taken
// from the toolchain image rather than downloaded on every run, and scans it
// once: the userns, default and FIPS runs share the one image that was scanned.

func TestIntegrationJobsTakeTrivyFromTheToolchainImage(t *testing.T) {
	type step struct {
		Run string `yaml:"run"`
	}
	type job struct {
		Env   map[string]string `yaml:"env"`
		Steps []step            `yaml:"steps"`
	}
	for _, f := range []string{"ci.yml", "release.yml"} {
		t.Run(f, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", f))
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			var wf struct {
				Jobs map[string]job `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(raw, &wf); err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			j, ok := wf.Jobs["integration"]
			if !ok {
				t.Fatalf("%s has no integration job", f)
			}
			if v, set := j.Env["TOOL_INSTALL"]; set {
				t.Errorf("%s: the integration job sets TOOL_INSTALL=%q; the pinned trivy comes from the toolchain image, not a download", f, v)
			}
			fetch, run := -1, -1
			for i, s := range j.Steps {
				if strings.Contains(s.Run, "build/ci/toolchain-trivy.sh") {
					fetch = i
				}
				if strings.Contains(s.Run, "make ci-integration") {
					run = i
				}
			}
			if fetch < 0 || run < 0 || fetch > run {
				t.Errorf("%s: want a toolchain-trivy.sh step (at %d) before `make ci-integration` (at %d)", f, fetch, run)
			}
		})
	}
}

// ci-integration hands both suite targets to the one script that builds and
// scans the image, so nothing in the recipe builds, scans or skips a scan itself.
func TestMakeCIIntegrationRunsEverySuiteOnOneScannedImage(t *testing.T) {
	cmd := exec.Command("make", "-n", "--no-print-directory", "ci-integration")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n ci-integration: %v\n%s", err, out)
	}
	recipe := string(out)
	if got := strings.Count(recipe, "scripts/integration-image.sh"); got != 1 {
		t.Fatalf("ci-integration builds the image %d times, want once:\n%s", got, recipe)
	}
	if !strings.Contains(recipe, "integration-test integration-test-fips") {
		t.Errorf("ci-integration does not run the default and FIPS targets under the image script:\n%s", recipe)
	}
	for _, banned := range []string{"INTEGRATION_SCAN", "scripts/integration-test.sh"} {
		if strings.Contains(recipe, banned) {
			t.Errorf("ci-integration's recipe mentions %q; a suite outside the image script can build or skip the scan on its own:\n%s", banned, recipe)
		}
	}
}
