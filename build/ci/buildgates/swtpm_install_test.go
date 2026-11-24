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

// swtpmStubSudo stands in for sudo: it finds the apt-get subcommand in its
// arguments, counts the calls per subcommand in $STUB_DIR, and fails the
// first $UPDATE_FAILS update calls and the first $INSTALL_FAILS install
// calls.
const swtpmStubSudo = `#!/bin/sh
v=other
for a in "$@"; do
  case "$a" in update|install) v=$a; break ;; esac
done
f="$STUB_DIR/$v.count"
n=$(cat "$f" 2>/dev/null || echo 0)
n=$((n+1))
echo "$n" > "$f"
case "$v" in
  update) max=$UPDATE_FAILS ;;
  install) max=$INSTALL_FAILS ;;
  *) max=0 ;;
esac
[ "$n" -gt "$max" ]
`

// swtpmRun is what one run of the step's script did.
type swtpmRun struct {
	updates, installs int  // apt-get update and install calls
	swtpmRan          bool // the script reached swtpm --version
}

// runSwtpmInstall runs the step's script as GitHub runs a bash step, with
// sudo, sleep and swtpm stubbed: apt-get update fails its first updateFails
// calls and apt-get install its first installFails calls, and each succeeds
// after.
func runSwtpmInstall(t *testing.T, script string, updateFails, installFails int) (swtpmRun, error) {
	t.Helper()
	bin := t.TempDir()
	state := t.TempDir()
	stubs := map[string]string{
		"sudo":  swtpmStubSudo,
		"sleep": "#!/bin/sh\nexit 0\n",
		"swtpm": "#!/bin/sh\n: > \"$STUB_DIR/swtpm.ran\"\necho swtpm stub\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+state,
		"UPDATE_FAILS="+strconv.Itoa(updateFails),
		"INSTALL_FAILS="+strconv.Itoa(installFails),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("update fails=%d install fails=%d output:\n%s", updateFails, installFails, out)
	count := func(verb string) int {
		raw, rerr := os.ReadFile(filepath.Join(state, verb+".count"))
		if rerr != nil {
			return 0
		}
		n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		return n
	}
	_, serr := os.Stat(filepath.Join(state, "swtpm.ran"))
	return swtpmRun{updates: count("update"), installs: count("install"), swtpmRan: serr == nil}, err
}

// TestSwtpmInstallRetriesBounded pins the step's retry loop around both apt
// calls: one transient failure of update or of install does not fail the
// step, and a failure that lasts stops the step, non-zero, before swtpm
// --version: after two to five attempts when update keeps failing, and after
// exactly three install attempts when install keeps failing, which fails if
// install leaves the loop.
func TestSwtpmInstallRetriesBounded(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script := swtpmInstallScript(t)
	const always = 1000
	cases := []struct {
		name                      string
		updateFails, installFails int
		wantOK                    bool
		minUpdates, maxUpdates    int
		minInstalls, maxInstalls  int
	}{
		{"update fails once", 1, 0, true, 2, 2, 1, 1},
		{"update keeps failing", always, 0, false, 2, 5, 0, 0},
		{"install fails once", 0, 1, true, 2, 2, 2, 2},
		{"install keeps failing", 0, always, false, 3, 3, 3, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run, err := runSwtpmInstall(t, script, c.updateFails, c.installFails)
			if c.wantOK && err != nil {
				t.Errorf("step failed (%v); want a retry that succeeds", err)
			}
			if !c.wantOK && err == nil {
				t.Errorf("step exited zero although apt-get never succeeded")
			}
			if run.swtpmRan != c.wantOK {
				t.Errorf("swtpm --version reached = %v; want %v", run.swtpmRan, c.wantOK)
			}
			if run.updates < c.minUpdates || run.updates > c.maxUpdates {
				t.Errorf("apt-get update ran %d times; want %d to %d", run.updates, c.minUpdates, c.maxUpdates)
			}
			if run.installs < c.minInstalls || run.installs > c.maxInstalls {
				t.Errorf("apt-get install ran %d times; want %d to %d", run.installs, c.minInstalls, c.maxInstalls)
			}
		})
	}
}
