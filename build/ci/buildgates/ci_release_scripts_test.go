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

func TestPublishRelease(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	base := func(f ciFakes) map[string]string {
		return map[string]string{
			"PATH":              f.path,
			"FAKE_HEAD":         sha,
			"SHA":               sha,
			"TAG":               "v1.2.3",
			"GITHUB_API_URL":    "https://api.forge.example",
			"GITHUB_REPOSITORY": "owner/repo",
		}
	}
	cases := []struct {
		name  string
		edit  func(env map[string]string)
		rc    int // -1: any non-zero
		want  []string
		makes bool
	}{
		{
			name: "HEAD is not SHA",
			edit: func(env map[string]string) { env["FAKE_HEAD"] = "fedcba9876543210fedcba9876543210fedcba98" },
			rc:   1,
			want: []string{"fedcba9876543210fedcba9876543210fedcba98", sha},
		},
		{
			name: "git rev-parse fails",
			edit: func(env map[string]string) { env["FAKE_GIT_RC"] = "128" },
			rc:   -1,
		},
		{
			name: "SHA unset",
			edit: func(env map[string]string) { delete(env, "SHA") },
			rc:   -1,
			want: []string{"SHA is required"},
		},
		{
			name: "GITHUB_API_URL unset",
			edit: func(env map[string]string) { delete(env, "GITHUB_API_URL") },
			rc:   -1,
			want: []string{"GITHUB_API_URL is required"},
		},
		{
			name: "GITHUB_REPOSITORY unset",
			edit: func(env map[string]string) { delete(env, "GITHUB_REPOSITORY") },
			rc:   -1,
			want: []string{"GITHUB_REPOSITORY is required"},
		},
		{
			name:  "publishes",
			edit:  func(map[string]string) {},
			rc:    0,
			makes: true,
		},
		{
			name:  "make fails",
			edit:  func(env map[string]string) { env["FAKE_MAKE_RC"] = "7" },
			rc:    7,
			makes: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCIFakes(t)
			env := base(f)
			tc.edit(env)
			out, rc := runCIScript(t, t.TempDir(), env, "publish-release.sh")
			if (tc.rc == -1 && rc == 0) || (tc.rc != -1 && rc != tc.rc) {
				t.Fatalf("exit %d, want %d; output:\n%s", rc, tc.rc, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output does not name %q:\n%s", w, out)
				}
			}
			makeLog := f.log(t, "make.log")
			if !tc.makes {
				if makeLog != "" {
					t.Errorf("make ran on a refused publish: %q", makeLog)
				}
				return
			}
			if makeLog != "release-publish\n" {
				t.Errorf("make argv %q, want exactly one `release-publish`", makeLog)
			}
			wantEnv := "FORGE_API_URL=https://api.forge.example\nFORGE_REPOSITORY=owner/repo\n"
			if got := f.log(t, "make.env"); got != wantEnv {
				t.Errorf("make env:\n%s\nwant:\n%s", got, wantEnv)
			}
		})
	}
}
