package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runCIScript runs build/ci/<name> under sh in dir. Unlike runScript it does
// not inherit the caller's environment: the job's GOPRIVATE, GIT_CONFIG_*,
// SHA and GITHUB_* must come from env alone, so an "unset" case is unset.
// It returns the combined output and the exit status.
func runCIScript(t *testing.T, dir string, env map[string]string, name string) (string, int) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "build", "ci", name)
	cmd := exec.Command("sh", script)
	cmd.Dir = dir
	cmd.Env = layerEnv([]string{"HOME=" + dir, "LC_ALL=C"}, env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		return string(out), exitErr.ExitCode()
	}
	return string(out), 0
}

// ciFakes is an isolated PATH holding fake go, git and make. Each fake logs
// its argv to <name>.log in logDir; make also logs the FORGE_* values it was
// given. go answers `go env GOPRIVATE` with $FAKE_GOPRIVATE; git answers
// `git rev-parse HEAD` with $FAKE_HEAD (or fails when $FAKE_GIT_RC is set);
// make exits with $FAKE_MAKE_RC (default 0).
type ciFakes struct {
	path   string
	logDir string
}

func newCIFakes(t *testing.T) ciFakes {
	t.Helper()
	path := isolatedPath(t)
	logDir := t.TempDir()
	logTo := func(name string) string {
		return "printf '%s\\n' \"$*\" >> '" + filepath.Join(logDir, name+".log") + "'\n"
	}
	writeExecutable(t, filepath.Join(path, "go"), []byte("#!/bin/sh\n"+logTo("go")+
		"if [ \"$*\" = 'env GOPRIVATE' ]; then printf '%s\\n' \"${FAKE_GOPRIVATE-}\"; exit 0; fi\n"+
		"exit 3\n"))
	writeExecutable(t, filepath.Join(path, "git"), []byte("#!/bin/sh\n"+logTo("git")+
		"if [ -n \"${FAKE_GIT_RC-}\" ]; then echo 'fatal: not a git repository' >&2; exit \"$FAKE_GIT_RC\"; fi\n"+
		"if [ \"$*\" = 'rev-parse HEAD' ]; then printf '%s\\n' \"${FAKE_HEAD-}\"; exit 0; fi\n"+
		"exit 3\n"))
	writeExecutable(t, filepath.Join(path, "make"), []byte("#!/bin/sh\n"+logTo("make")+
		"printf 'FORGE_API_URL=%s\\nFORGE_REPOSITORY=%s\\n' \"${FORGE_API_URL-<unset>}\" \"${FORGE_REPOSITORY-<unset>}\" >> '"+
		filepath.Join(logDir, "make.env")+"'\n"+
		"exit \"${FAKE_MAKE_RC:-0}\"\n"))
	return ciFakes{path: path, logDir: logDir}
}

// log returns what the named fake logged, or "" when it never ran.
func (f ciFakes) log(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.logDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

const plantedToken = "PLANTEDtoken0123456789abcdef"

func rewriteKey(suffix string) string {
	return "url.https://x-access-token:" + plantedToken + "@forge.example/." + suffix
}

func TestForgeResolution(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		pass bool
		want string
	}{
		{
			name: "GOPRIVATE empty",
			env: map[string]string{
				"FAKE_GOPRIVATE": "", "GIT_CONFIG_COUNT": "1",
				"GIT_CONFIG_KEY_0": rewriteKey("insteadOf"), "GIT_CONFIG_VALUE_0": "https://forge.example/",
			},
			want: "GOPRIVATE is not set",
		},
		{
			name: "count unset",
			env:  map[string]string{"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_KEY_0": rewriteKey("insteadOf")},
			want: "no git insteadOf rewrite",
		},
		{
			name: "count empty",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "",
				"GIT_CONFIG_KEY_0": rewriteKey("insteadOf"),
			},
			want: "no git insteadOf rewrite",
		},
		{
			name: "count not numeric",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "x2",
				"GIT_CONFIG_KEY_0": rewriteKey("insteadOf"), "GIT_CONFIG_KEY_1": rewriteKey("insteadOf"),
			},
			want: "no git insteadOf rewrite",
		},
		{
			name: "count zero",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "0",
				"GIT_CONFIG_KEY_0": rewriteKey("insteadOf"),
			},
			want: "no git insteadOf rewrite",
		},
		{
			name: "match at index 1 of 2",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "2",
				"GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
				"GIT_CONFIG_KEY_1": rewriteKey("insteadOf"), "GIT_CONFIG_VALUE_1": "https://forge.example/",
			},
			pass: true,
			want: "GOPRIVATE and a git insteadOf rewrite are present",
		},
		{
			name: "match only at index 2 of count 2",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "2",
				"GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_KEY_1": "core.autocrlf",
				"GIT_CONFIG_KEY_2": rewriteKey("insteadOf"),
			},
			want: "no git insteadOf rewrite",
		},
		{
			name: "lower-case insteadof",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "1",
				"GIT_CONFIG_KEY_0": rewriteKey("insteadof"),
			},
			pass: true,
			want: "GOPRIVATE and a git insteadOf rewrite are present",
		},
		{
			name: "pushInsteadOf only",
			env: map[string]string{
				"FAKE_GOPRIVATE": "forge.example", "GIT_CONFIG_COUNT": "1",
				"GIT_CONFIG_KEY_0": rewriteKey("pushInsteadOf"),
			},
			want: "no git insteadOf rewrite",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCIFakes(t)
			env := map[string]string{"PATH": f.path}
			for k, v := range tc.env {
				env[k] = v
			}
			out, rc := runCIScript(t, t.TempDir(), env, "forge-resolution.sh")
			if pass := rc == 0; pass != tc.pass {
				t.Fatalf("exit %d, want pass=%v; output:\n%s", rc, tc.pass, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output does not name %q:\n%s", tc.want, out)
			}
			if strings.Contains(out, plantedToken) || strings.Contains(out, "x-access-token") {
				t.Errorf("output carries the rewrite key:\n%s", out)
			}
			if got := f.log(t, "go.log"); got != "env GOPRIVATE\n" {
				t.Errorf("go called with %q, want exactly `env GOPRIVATE`", got)
			}
		})
	}
}
