package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// opteeSelected runs scripts/optee-selected.sh with files (one changed path
// per line) on stdin and pins (the diff of scripts/tool-pins.sh) in a file,
// and returns its output and whether it exited zero.
func opteeSelected(t *testing.T, files []string, pins string) (string, bool) {
	t.Helper()
	diff := filepath.Join(t.TempDir(), "pins.diff")
	if err := os.WriteFile(diff, []byte(pins), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(repoRoot(t), "scripts", "optee-selected.sh"), diff)
	cmd.Dir = t.TempDir()
	if len(files) > 0 {
		cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// pinsDiff is a diff of scripts/tool-pins.sh that replaces old with new.
func pinsDiff(old, new string) string {
	return "diff --git a/scripts/tool-pins.sh b/scripts/tool-pins.sh\n" +
		"--- a/scripts/tool-pins.sh\n" +
		"+++ b/scripts/tool-pins.sh\n" +
		"@@ -1,3 +1,3 @@\n" +
		" # pins\n" +
		"-" + old + "\n" +
		"+" + new + "\n"
}

// The OP-TEE job runs when a change reaches what it builds or runs: the
// backend, its harness and fixture script, the Makefile recipe that wires
// them, the scripts and image that recipe calls, and the pins it reads.
func TestScriptsOPTEESelect_SelectsWhatTheHarnessRuns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		pins  string
		want  string
	}{
		{"a Makefile-only change", []string{"Makefile"}, "", "true"},
		{"an in-toolchain-image.sh-only change", []string{"scripts/in-toolchain-image.sh"}, "", "true"},
		{"the image script", []string{"scripts/devcontainer.sh"}, "", "true"},
		{"the scripts' shared library", []string{"scripts/lib.sh"}, "", "true"},
		{"a toolchain image input script", []string{"scripts/install-tools.sh"}, "", "true"},
		{"the devcontainer", []string{"build/docker/devcontainer/Dockerfile"}, "", "true"},
		{"the backend", []string{"backends/armtrustzone/optee_test.go"}, "", "true"},
		{"the fixture script", []string{"scripts/optee-fixture.sh"}, "", "true"},
		{"the root harness", []string{"test/integration/enclave/main_optee_test.go"}, "", "true"},
		{"the selector itself", []string{"scripts/optee-selected.sh"}, "", "true"},
		{"a workflow-only change", []string{".github/workflows/ci.yml"}, "", "true"},
		{"another workflow", []string{".github/workflows/code-review.yml"}, "", "false"},
		{"one selected path among others", []string{"README.md", "Makefile", "docs/x.md"}, "", "true"},
		{"a docs-only change", []string{"docs/README.md", "changelog.d/1-x.md"}, "", "false"},
		{"a Makefile elsewhere", []string{"docs/Makefile"}, "", "false"},
		{"a TRUSTED_FIRMWARE_TAG pin change", []string{"scripts/tool-pins.sh"},
			pinsDiff("TRUSTED_FIRMWARE_TAG=v0.4.1-alpha", "TRUSTED_FIRMWARE_TAG=v0.4.2-alpha"), "true"},
		{"a fixture image pin change", []string{"scripts/tool-pins.sh"},
			pinsDiff("OPTEE_FIXTURE_IMAGE=", "OPTEE_FIXTURE_IMAGE=x@sha256:00"), "true"},
		{"an unrelated pin change", []string{"scripts/tool-pins.sh"},
			pinsDiff("GOLANGCI_LINT_VERSION=v2.1.0", "GOLANGCI_LINT_VERSION=v2.2.0"), "false"},
		{"an empty diff", nil, "", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := opteeSelected(t, tc.files, tc.pins)
			if !ok || got != tc.want {
				t.Fatalf("optee-selected.sh = %q (ok=%v), want %q", got, ok, tc.want)
			}
		})
	}
}

// Without the pins diff the script cannot decide, and fails: the workflow
// selects the job when the script fails.
func TestScriptsOPTEESelect_FailsWithoutThePinsDiff(t *testing.T) {
	cmd := exec.Command("sh", filepath.Join(repoRoot(t), "scripts", "optee-selected.sh"))
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader("Makefile\n")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("optee-selected.sh without a pins diff exited zero:\n%s", out)
	}
}
