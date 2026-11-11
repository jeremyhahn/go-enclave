package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// swtpmJob and swtpmInstallStep name the tpm-swtpm job's apt step. A
// transient mirror or DNS error in it failed main (#326), so the step
// retries: apt's own Acquire::Retries, and a bounded loop around both apt
// calls.
const (
	swtpmJob         = "tpm-swtpm"
	swtpmInstallStep = "Install swtpm"
)

// aptRetriesRe matches apt-get's per-download retry option and its count.
var aptRetriesRe = regexp.MustCompile(`-o\s+Acquire::Retries=(\d+)`)

// swtpmInstallScript returns the run script of the tpm-swtpm job's
// "Install swtpm" step in ci.yml.
func swtpmInstallScript(t *testing.T) string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, filepath.Join(repoRoot(t), ciWorkflowFile))), &wf); err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	job, ok := wf.Jobs[swtpmJob]
	if !ok {
		t.Fatalf("%s: no job %s", ciWorkflowFile, swtpmJob)
	}
	for _, st := range job.Steps {
		if st.Name == swtpmInstallStep {
			return st.Run
		}
	}
	t.Fatalf("%s: job %s has no step %q", ciWorkflowFile, swtpmJob, swtpmInstallStep)
	return ""
}

// TestSwtpmInstallAptCallsRetry pins that both apt-get calls ask apt to
// retry each download at least three times.
func TestSwtpmInstallAptCallsRetry(t *testing.T) {
	script := swtpmInstallScript(t)
	for _, verb := range []string{"update", "install"} {
		found := false
		for line := range strings.SplitSeq(script, "\n") {
			if !strings.Contains(line, "apt-get") || !regexp.MustCompile(`\b`+verb+`\b`).MatchString(line) {
				continue
			}
			found = true
			m := aptRetriesRe.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("apt-get %s line %q has no -o Acquire::Retries=N", verb, strings.TrimSpace(line))
				continue
			}
			if n, _ := strconv.Atoi(m[1]); n < 3 {
				t.Errorf("apt-get %s line %q retries %d times; want 3 or more", verb, strings.TrimSpace(line), n)
			}
		}
		if !found {
			t.Errorf("step %q runs no apt-get %s", swtpmInstallStep, verb)
		}
	}
}

// runSwtpmInstall runs the step's script as GitHub runs a bash step, with
// sudo, sleep and swtpm stubbed: sudo fails its first fails calls and
// succeeds after. It returns the script's error and how many times it
// called sudo.
func runSwtpmInstall(t *testing.T, script string, fails int) (int, error) {
	t.Helper()
	bin := t.TempDir()
	count := filepath.Join(t.TempDir(), "count")
	stubs := map[string]string{
		"sudo":  "#!/bin/sh\nn=$(cat \"$SUDO_COUNT\" 2>/dev/null || echo 0)\nn=$((n+1))\necho \"$n\" > \"$SUDO_COUNT\"\n[ \"$n\" -gt \"$SUDO_FAILS\" ]\n",
		"sleep": "#!/bin/sh\nexit 0\n",
		"swtpm": "#!/bin/sh\necho swtpm stub\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SUDO_COUNT="+count,
		"SUDO_FAILS="+strconv.Itoa(fails),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("fails=%d output:\n%s", fails, out)
	raw, rerr := os.ReadFile(count)
	if rerr != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return n, err
}

// TestSwtpmInstallRetriesBounded pins the step's retry loop: one transient
// failure does not fail the step, and a failure that lasts stops the step,
// non-zero, after at most five attempts.
func TestSwtpmInstallRetriesBounded(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script := swtpmInstallScript(t)

	if _, err := runSwtpmInstall(t, script, 1); err != nil {
		t.Errorf("one failed apt-get call failed the step (%v); want a retry that succeeds", err)
	}

	calls, err := runSwtpmInstall(t, script, 1000)
	if err == nil {
		t.Errorf("step exited zero although apt-get never succeeded")
	}
	// Every attempt stops at its failed apt-get update, so calls counts the
	// attempts.
	if calls < 2 || calls > 5 {
		t.Errorf("step made %d attempts while apt-get kept failing; want 2 to 5", calls)
	}
}
