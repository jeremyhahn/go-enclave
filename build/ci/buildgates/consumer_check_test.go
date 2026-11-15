package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// consumer-check.sh against a fake go: every refusal after the argument
// checks, without a network or a module proxy. The fake is driven by
// environment variables:
//
//	FAKE_GO_LOG       a file each invocation appends "<args> GOFLAGS=[..] GOWORK=.." to
//	FAKE_GO_FAIL      the step that fails: "mod init", "get", "mod verify" or "build"
//	FAKE_GO_VERSION   the version `go list -m` reports (default: the one asked for)
//	FAKE_GO_REPLACE   `go list -m`'s replacement field ("replaced" or empty)
//	FAKE_GO_DIR       `go list -m`'s module directory (default: under GOMODCACHE)
//	FAKE_CONSUMER_OUT what the built consumer prints (default: the success marker)
//	FAKE_CONSUMER_RC  the built consumer's exit status (default 0)
const consumerFakeGo = `#!/bin/sh
[ -z "${FAKE_GO_LOG-}" ] || echo "$* GOFLAGS=[${GOFLAGS-unset}] GOWORK=${GOWORK-unset}" >> "$FAKE_GO_LOG"
fail() { echo "fake go: $1 failed" >&2; exit 1; }
case "$1 ${2-}" in
"clean -modcache") exit 0 ;;
"mod init")
  [ "${FAKE_GO_FAIL-}" != "mod init" ] || fail "mod init"
  echo "module $3" > go.mod ;;
"get "*)
  [ "${FAKE_GO_FAIL-}" != get ] || fail get
  echo "$2" > .fake-get ;;
"list -m")
  asked=$(cat .fake-get); asked=${asked#*@}
  printf '%s|%s|%s\n' "${FAKE_GO_VERSION-$asked}" "${FAKE_GO_REPLACE-}" "${FAKE_GO_DIR-$GOMODCACHE/$4@$asked}" ;;
"mod verify")
  [ "${FAKE_GO_FAIL-}" != "mod verify" ] || fail "mod verify"
  echo "all modules verified" ;;
"build -o")
  [ "${FAKE_GO_FAIL-}" != build ] || fail build
  [ -f main.go ] || fail "build (no main.go)"
  printf '#!/bin/sh\nprintf "%%s\\n" "${FAKE_CONSUMER_OUT-consumer-check: ok}"\nexit "${FAKE_CONSUMER_RC-0}"\n' > "$3"
  chmod +x "$3" ;;
*) fail "unexpected go $*" ;;
esac
`

const (
	fakeConsumerModule  = "example.com/fake/consumed"
	fakeConsumerVersion = "v1.2.3"
)

// consumerFakeEnv returns an environment with only the fake go and the shell
// utilities on PATH, a private TMPDIR, a caller GOFLAGS the script must clear,
// and the fake's log file.
func consumerFakeEnv(t *testing.T, over map[string]string) (env map[string]string, tmp, log string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bin")
	writeExecutableDir(t, bin)
	writeExecutable(t, filepath.Join(bin, "go"), []byte(consumerFakeGo))
	iso := isolatedPath(t)
	cp, err := exec.LookPath("cp")
	if err != nil {
		t.Fatalf("cp is required: %v", err)
	}
	if err := os.Symlink(cp, filepath.Join(iso, "cp")); err != nil {
		t.Fatalf("symlink cp: %v", err)
	}
	tmp = t.TempDir()
	log = filepath.Join(t.TempDir(), "go.log")
	env = map[string]string{
		"PATH":        bin + string(os.PathListSeparator) + iso,
		"TMPDIR":      tmp,
		"GOFLAGS":     "-mod=vendor -tags=caller",
		"GOWORK":      "/caller/go.work",
		"FAKE_GO_LOG": log,
	}
	for k, v := range over {
		env[k] = v
	}
	return env, tmp, log
}

func writeExecutableDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

// requireWorkRemoved fails unless the scratch work directory under TMPDIR is gone.
func requireWorkRemoved(t *testing.T, tmp string) {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(tmp, "consumer-check.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("the scratch work directory was not removed: %v", left)
	}
}

func TestScriptsConsumerCheck_FakeGoRefusals(t *testing.T) {
	mv := fakeConsumerModule + "@" + fakeConsumerVersion
	for _, tc := range []struct {
		name    string
		over    map[string]string
		wantMsg string
	}{
		{"go mod init fails", map[string]string{"FAKE_GO_FAIL": "mod init"}, "go mod init failed"},
		{"go get fails", map[string]string{"FAKE_GO_FAIL": "get"}, "go get " + mv + " failed"},
		{"replaced module", map[string]string{"FAKE_GO_REPLACE": "replaced"}, "the build list does not hold " + mv + " from the module cache"},
		{"other version selected", map[string]string{"FAKE_GO_VERSION": "v1.2.4"}, "the build list does not hold " + mv + " from the module cache"},
		{"module outside the cache", map[string]string{"FAKE_GO_DIR": "/elsewhere/consumed"}, "the build list does not hold " + mv + " from the module cache"},
		{"go mod verify fails", map[string]string{"FAKE_GO_FAIL": "mod verify"}, "go mod verify failed for the consumer's dependencies"},
		{"go build fails", map[string]string{"FAKE_GO_FAIL": "build"}, "the consumer program does not build against " + mv},
		{"consumer exits non-zero", map[string]string{"FAKE_CONSUMER_RC": "3"}, "the consumer program failed against " + mv},
		{"consumer prints something else", map[string]string{"FAKE_CONSUMER_OUT": "consumer-check: ok, mostly"}, "unexpected consumer output: consumer-check: ok, mostly"},
		{"consumer prints nothing", map[string]string{"FAKE_CONSUMER_OUT": ""}, "unexpected consumer output:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, tmp, log := consumerFakeEnv(t, tc.over)
			out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", fakeConsumerModule, fakeConsumerVersion)
			if ok {
				t.Fatalf("succeeded, want a refusal:\n%s", out)
			}
			if !strings.Contains(out, "consumer-check: "+tc.wantMsg) {
				t.Fatalf("refusal does not say %q:\n%s", tc.wantMsg, out)
			}
			if strings.Contains(out, "builds and runs in a fresh consumer") {
				t.Fatalf("a refusal printed the success line:\n%s", out)
			}
			requireWorkRemoved(t, tmp)
			requireCallerEnvCleared(t, log)
		})
	}
}

func TestScriptsConsumerCheck_FakeGoSucceeds(t *testing.T) {
	env, tmp, log := consumerFakeEnv(t, nil)
	out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", fakeConsumerModule, fakeConsumerVersion)
	if !ok {
		t.Fatalf("failed against a fake go that does everything right:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	want := "consumer-check: " + fakeConsumerModule + "@" + fakeConsumerVersion + " builds and runs in a fresh consumer"
	if last := lines[len(lines)-1]; last != want {
		t.Fatalf("last line = %q, want %q:\n%s", last, want, out)
	}
	requireWorkRemoved(t, tmp)
	logged := requireCallerEnvCleared(t, log)
	for _, step := range []string{"mod init ", "get " + fakeConsumerModule + "@" + fakeConsumerVersion, "list -m ", "mod verify", "build -o consumer .", "clean -modcache"} {
		if !strings.Contains(logged, step) {
			t.Fatalf("the fake go never ran %q:\n%s", step, logged)
		}
	}
}

// requireCallerEnvCleared fails unless every go invocation ran with GOFLAGS
// empty and GOWORK=off, and returns the log.
func requireCallerEnvCleared(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the fake go was never run: %v", err)
	}
	logged := string(b)
	for _, line := range strings.Split(strings.TrimRight(logged, "\n"), "\n") {
		if !strings.HasSuffix(line, " GOFLAGS=[] GOWORK=off") {
			t.Fatalf("go ran with the caller's GOFLAGS or GOWORK: %q", line)
		}
	}
	return logged
}

func TestScriptsConsumerCheck_RefusesBeforeWork(t *testing.T) {
	t.Run("wrong argument count", func(t *testing.T) {
		env, tmp, _ := consumerFakeEnv(t, nil)
		out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", fakeConsumerModule)
		if ok || !strings.Contains(out, "usage: ") {
			t.Fatalf("ok=%v, want a usage refusal:\n%s", ok, out)
		}
		requireWorkRemoved(t, tmp)
	})
	t.Run("go not on PATH", func(t *testing.T) {
		env, tmp, _ := consumerFakeEnv(t, nil)
		env["PATH"] = isolatedPath(t)
		out, ok := runScript(t, t.TempDir(), env, "consumer-check.sh", fakeConsumerModule, fakeConsumerVersion)
		if ok || !strings.Contains(out, "consumer-check: go is not on PATH") {
			t.Fatalf("ok=%v, want the no-go refusal:\n%s", ok, out)
		}
		requireWorkRemoved(t, tmp)
	})
	t.Run("consumer program missing", func(t *testing.T) {
		// A copy of the script without testdata/consumer beside it.
		scripts := filepath.Join(t.TempDir(), "scripts")
		writeExecutableDir(t, scripts)
		for _, name := range []string{"consumer-check.sh", "lib.sh"} {
			b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			writeExecutable(t, filepath.Join(scripts, name), b)
		}
		env, tmp, _ := consumerFakeEnv(t, nil)
		cmd := exec.Command("sh", filepath.Join(scripts, "consumer-check.sh"), fakeConsumerModule, fakeConsumerVersion)
		cmd.Dir = t.TempDir()
		cmd.Env = layerEnv(os.Environ(), env)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "consumer program "+filepath.Join(scripts, "testdata", "consumer", "main.go")+" not found") {
			t.Fatalf("err=%v, want the missing-program refusal:\n%s", err, out)
		}
		requireWorkRemoved(t, tmp)
	})
}
