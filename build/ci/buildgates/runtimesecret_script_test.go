package buildgates

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scripts/test-runtimesecret.sh

const runtimesecretProof = "^TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret$"

// runtimesecretTargets is the erasure file each target must build, as the
// script checks it.
var runtimesecretTargets = map[string]string{
	"linux/amd64":   "secret_erase.go",
	"linux/arm64":   "secret_erase.go",
	"linux/386":     "secret_noerase.go",
	"android/amd64": "secret_noerase.go",
	"android/arm64": "secret_noerase.go",
	"darwin/arm64":  "secret_noerase.go",
}

func runtimesecretWrong(file string) string {
	if file == "secret_erase.go" {
		return "secret_noerase.go"
	}
	return "secret_erase.go"
}

// runtimesecretFixture is a fake toolchain: GOCMD (a fakeTool) prints a
// GOROOT whose bin/go answers list from selection, keyed by GOOS/GOARCH, and
// logs every call to the returned log file. FAKE_GO_LIST_FAIL (a target) makes
// that list fail; FAKE_GO_TEST_FAIL (-skip or -run) makes that test call fail.
func runtimesecretFixture(t *testing.T, selection map[string]string, extra map[string]string) (map[string]string, string) {
	t.Helper()
	root := t.TempDir()
	goroot := filepath.Join(root, "goroot")
	logPath := filepath.Join(root, "go.log")

	targets := make([]string, 0, len(selection))
	for target := range selection {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	var arms strings.Builder
	for _, target := range targets {
		arms.WriteString("  " + target + ") echo 'aead.go " + selection[target] + " doc.go' ;;\n")
	}
	body := "#!/bin/sh\n" +
		"case $1 in\n" +
		"list)\n" +
		"  echo \"list GOEXPERIMENT=$GOEXPERIMENT CGO_ENABLED=$CGO_ENABLED $GOOS/$GOARCH $*\" >>\"$FAKE_GO_LOG\"\n" +
		"  if [ \"$GOOS/$GOARCH\" = \"$FAKE_GO_LIST_FAIL\" ]; then echo 'fake go: list failed' >&2; exit 1; fi\n" +
		"  case $GOOS/$GOARCH in\n" +
		arms.String() +
		"  *) echo \"fake go: unexpected target $GOOS/$GOARCH\" >&2; exit 2 ;;\n" +
		"  esac ;;\n" +
		"test)\n" +
		"  echo \"test GOEXPERIMENT=$GOEXPERIMENT $*\" >>\"$FAKE_GO_LOG\"\n" +
		"  case \" $* \" in *\" $FAKE_GO_TEST_FAIL \"*) echo 'fake go: test failed' >&2; exit 1 ;; esac ;;\n" +
		"*) echo \"fake go: unexpected call $*\" >&2; exit 2 ;;\n" +
		"esac\n"
	if err := os.MkdirAll(filepath.Join(goroot, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeExecutable(t, filepath.Join(goroot, "bin", "go"), []byte(body))
	gocmd := fakeTool(t, filepath.Join(root, "gocmd"), "go", goroot)

	env := map[string]string{
		"PATH":              isolatedPath(t),
		"GOCMD":             gocmd,
		"GOEXPERIMENT":      "",
		"FAKE_GO_LOG":       logPath,
		"FAKE_GO_LIST_FAIL": "",
		"FAKE_GO_TEST_FAIL": "none",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env, logPath
}

// runtimesecretCalls returns the fake go's logged calls of kind (list or test).
func runtimesecretCalls(t *testing.T, logPath, kind string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var calls []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(line, kind+" ") {
			calls = append(calls, line)
		}
	}
	return calls
}

func TestRuntimesecretScript_AllTargetsSelectedRunsBothTestCalls(t *testing.T) {
	env, logPath := runtimesecretFixture(t, runtimesecretTargets, nil)
	out, ok := runScript(t, t.TempDir(), env, "test-runtimesecret.sh", "-race", "-timeout=10m")
	if !ok {
		t.Fatalf("want success, got failure:\n%s", out)
	}
	for target, want := range runtimesecretTargets {
		if !strings.Contains(out, "erasure selection "+target+": "+want) {
			t.Errorf("output does not report %s selecting %s:\n%s", target, want, out)
		}
	}
	lists := runtimesecretCalls(t, logPath, "list")
	if len(lists) != len(runtimesecretTargets) {
		t.Fatalf("want %d list calls, got %d: %q", len(runtimesecretTargets), len(lists), lists)
	}
	for _, l := range lists {
		if !strings.HasPrefix(l, "list GOEXPERIMENT=runtimesecret CGO_ENABLED=0 ") {
			t.Errorf("list call without the experiment and CGO_ENABLED=0: %q", l)
		}
	}
	tests := runtimesecretCalls(t, logPath, "test")
	want := []string{
		"test GOEXPERIMENT=runtimesecret test -race -timeout=10m -skip " + runtimesecretProof + " ./...",
		"test GOEXPERIMENT=runtimesecret test -count=5 -cpu=1,2,8 -run " + runtimesecretProof + " .",
	}
	if strings.Join(tests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("test calls:\n got %q\nwant %q", tests, want)
	}
}

func TestRuntimesecretScript_WrongSelectionFailsNamingTheTarget(t *testing.T) {
	for target, file := range runtimesecretTargets {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			selection := make(map[string]string, len(runtimesecretTargets))
			for k, v := range runtimesecretTargets {
				selection[k] = v
			}
			selection[target] = runtimesecretWrong(file)
			env, logPath := runtimesecretFixture(t, selection, nil)
			out, ok := runScript(t, t.TempDir(), env, "test-runtimesecret.sh")
			if ok {
				t.Fatalf("want failure, got success:\n%s", out)
			}
			msg := "test-runtimesecret: GOEXPERIMENT=runtimesecret on " + target + " does not build " + file
			if !strings.Contains(out, msg) {
				t.Errorf("output does not name %s:\n%s", target, out)
			}
			if calls := runtimesecretCalls(t, logPath, "test"); len(calls) != 0 {
				t.Errorf("want no test call, got %q", calls)
			}
		})
	}
}

func TestRuntimesecretScript_ListFailureFails(t *testing.T) {
	env, logPath := runtimesecretFixture(t, runtimesecretTargets, map[string]string{"FAKE_GO_LIST_FAIL": "linux/386"})
	out, ok := runScript(t, t.TempDir(), env, "test-runtimesecret.sh")
	if ok {
		t.Fatalf("want failure, got success:\n%s", out)
	}
	if !strings.Contains(out, "fake go: list failed") {
		t.Errorf("output does not carry the list error:\n%s", out)
	}
	if calls := runtimesecretCalls(t, logPath, "test"); len(calls) != 0 {
		t.Errorf("want no test call, got %q", calls)
	}
}

func TestRuntimesecretScript_GOCMDFailureFails(t *testing.T) {
	env, logPath := runtimesecretFixture(t, runtimesecretTargets, nil)
	bad := filepath.Join(t.TempDir(), "go")
	writeExecutable(t, bad, []byte("#!/bin/sh\necho 'fake go: env failed' >&2\nexit 1\n"))
	env["GOCMD"] = bad
	out, ok := runScript(t, t.TempDir(), env, "test-runtimesecret.sh")
	if ok {
		t.Fatalf("want failure, got success:\n%s", out)
	}
	if !strings.Contains(out, "fake go: env failed") {
		t.Errorf("output does not carry the env error:\n%s", out)
	}
	if b, err := os.ReadFile(logPath); err == nil {
		t.Errorf("want no toolchain call, got %q", b)
	}
}

func TestRuntimesecretScript_TestFailureFails(t *testing.T) {
	cases := map[string]int{"-skip": 1, "-run": 2}
	for flag, wantCalls := range cases {
		t.Run(flag, func(t *testing.T) {
			env, logPath := runtimesecretFixture(t, runtimesecretTargets, map[string]string{"FAKE_GO_TEST_FAIL": flag})
			out, ok := runScript(t, t.TempDir(), env, "test-runtimesecret.sh")
			if ok {
				t.Fatalf("want failure, got success:\n%s", out)
			}
			if calls := runtimesecretCalls(t, logPath, "test"); len(calls) != wantCalls {
				t.Errorf("want %d test calls, got %q", wantCalls, calls)
			}
		})
	}
}
