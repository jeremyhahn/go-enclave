package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/userns-test.sh, driven offline: a copy of the script and lib.sh
// beside a stub integration-image.sh, a scratch compose directory, and a fake
// docker whose answers come from FAKE_* environment variables. Every call the
// fake receives is appended to DOCKER_LOG.

const usernsTestName = "TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace"

// usernsFakeDocker answers the calls userns-test.sh and require_scanned_image
// make:
//
//	FAKE_NO_COMPOSE   non-empty: `docker compose version` fails
//	FAKE_DAEMON_RC    exit status of `docker version`
//	FAKE_IMAGE_ID     what `docker image inspect` prints (empty: it fails)
//	FAKE_RUN_OUT      what `docker compose ... run` prints
//	FAKE_RUN_RC       exit status of `docker compose ... run`
//	FAKE_DOWN_RC      exit status of `docker compose ... down`
const usernsFakeDocker = `#!/bin/sh
echo "docker $*" >>"$DOCKER_LOG"
case "$1 ${2-}" in
"compose version") [ -z "${FAKE_NO_COMPOSE-}" ]; exit ;;
"version --format") exit "${FAKE_DAEMON_RC:-0}" ;;
"image inspect")
  [ -n "${FAKE_IMAGE_ID-}" ] || exit 1
  echo "$FAKE_IMAGE_ID"; exit 0 ;;
esac
if [ "$1" = compose ]; then
  for a; do
    case $a in
    run) printf '%s\n' "${FAKE_RUN_OUT-}"; exit "${FAKE_RUN_RC:-0}" ;;
    down) exit "${FAKE_DOWN_RC:-0}" ;;
    esac
  done
fi
exit 0
`

type usernsRig struct {
	dir     string // the working directory
	script  string // the copy of userns-test.sh
	compose string // the scratch compose file
	log     string // DOCKER_LOG
	env     map[string]string
}

// newUsernsRig lays out the copy, the compose directory and the fake docker,
// and returns an environment under which the script reaches the compose run
// and passes.
func newUsernsRig(t *testing.T) *usernsRig {
	t.Helper()
	root := t.TempDir()
	scripts := filepath.Join(root, "scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"userns-test.sh", "lib.sh"} {
		body, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		writeExecutable(t, filepath.Join(scripts, name), body)
	}
	fakeTool(t, scripts, "integration-image.sh", "integration-image.sh stub ran")

	composeDir := filepath.Join(root, "devcontainer")
	if err := os.MkdirAll(composeDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	compose := filepath.Join(composeDir, "compose.yaml")
	for _, p := range []string{compose, filepath.Join(composeDir, "seccomp-userns.json")} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	bin := isolatedPath(t)
	for _, u := range []string{"date", "od", "tr"} {
		p, err := exec.LookPath(u)
		if err != nil {
			t.Fatalf("%s is required: %v", u, err)
		}
		if err := os.Symlink(p, filepath.Join(bin, u)); err != nil {
			t.Fatalf("symlink %s: %v", u, err)
		}
	}
	writeExecutable(t, filepath.Join(bin, "docker"), []byte(usernsFakeDocker))

	r := &usernsRig{
		dir:     root,
		script:  filepath.Join(scripts, "userns-test.sh"),
		compose: compose,
		log:     filepath.Join(root, "docker.log"),
	}
	r.env = map[string]string{
		"PATH":                   bin,
		"DEVCONTAINER_COMPOSE":   compose,
		"DOCKER_LOG":             r.log,
		"GO_ENCLAVE_IT_IMAGE":    "go-enclave-it:test",
		"GO_ENCLAVE_IT_IMAGE_ID": "sha256:scanned",
		"FAKE_IMAGE_ID":          "sha256:scanned",
		"FAKE_NO_COMPOSE":        "",
		"FAKE_DAEMON_RC":         "0",
		"FAKE_RUN_OUT":           "=== RUN   " + usernsTestName + "\n--- PASS: " + usernsTestName + " (0.01s)\nPASS",
		"FAKE_RUN_RC":            "0",
		"FAKE_DOWN_RC":           "0",
	}
	return r
}

// run runs the copy with sh in the rig's directory, with over layered on the
// rig's environment, and returns its combined output and whether it exited 0.
func (r *usernsRig) run(t *testing.T, over map[string]string, args ...string) (string, bool) {
	t.Helper()
	env := map[string]string{}
	for k, v := range r.env {
		env[k] = v
	}
	for k, v := range over {
		env[k] = v
	}
	cmd := exec.Command("sh", append([]string{r.script}, args...)...)
	cmd.Dir = r.dir
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", r.script, err)
		}
		return string(out), false
	}
	return string(out), true
}

// dockerCalls returns the calls the fake docker received.
func (r *usernsRig) dockerCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read docker log: %v", err)
	}
	return string(b)
}

func wantOutput(t *testing.T, out string, ok, wantOK bool, wants ...string) {
	t.Helper()
	if ok != wantOK {
		t.Fatalf("exit ok = %v, want %v; output:\n%s", ok, wantOK, out)
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Fatalf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestUsernsScript_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *usernsRig) map[string]string
		args  []string
		want  string
	}{
		{
			name:  "an argument",
			setup: func(*usernsRig) map[string]string { return nil },
			args:  []string{"extra"},
			want:  "userns-test: usage: ",
		},
		{
			name: "no compose file",
			setup: func(r *usernsRig) map[string]string {
				return map[string]string{"DEVCONTAINER_COMPOSE": filepath.Join(r.dir, "devcontainer", "absent.yaml")}
			},
			want: "absent.yaml not found. The user-namespace test runs in the project devcontainer",
		},
		{
			name: "no seccomp profile beside it",
			setup: func(r *usernsRig) map[string]string {
				if err := os.Remove(filepath.Join(filepath.Dir(r.compose), "seccomp-userns.json")); err != nil {
					panic(err)
				}
				return nil
			},
			want: "seccomp-userns.json not found: without its profile the test cannot create a user namespace.",
		},
		{
			name: "no docker",
			setup: func(r *usernsRig) map[string]string {
				if err := os.Remove(filepath.Join(r.env["PATH"], "docker")); err != nil {
					panic(err)
				}
				return nil
			},
			want: "'docker compose' (Compose v2) is required",
		},
		{
			name:  "no docker compose",
			setup: func(*usernsRig) map[string]string { return map[string]string{"FAKE_NO_COMPOSE": "1"} },
			want:  "'docker compose' (Compose v2) is required",
		},
		{
			name:  "no daemon",
			setup: func(*usernsRig) map[string]string { return map[string]string{"FAKE_DAEMON_RC": "1"} },
			want:  "the Docker daemon is not reachable",
		},
		{
			name:  "no scanned image ID",
			setup: func(*usernsRig) map[string]string { return map[string]string{"GO_ENCLAVE_IT_IMAGE_ID": ""} },
			want:  "GO_ENCLAVE_IT_IMAGE and GO_ENCLAVE_IT_IMAGE_ID are required",
		},
		{
			name:  "no image",
			setup: func(*usernsRig) map[string]string { return map[string]string{"FAKE_IMAGE_ID": ""} },
			want:  "the integration image go-enclave-it:test does not exist",
		},
		{
			name:  "an image other than the scanned one",
			setup: func(*usernsRig) map[string]string { return map[string]string{"FAKE_IMAGE_ID": "sha256:other"} },
			want:  "the integration image go-enclave-it:test is sha256:other, not the sha256:scanned that was scanned",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newUsernsRig(t)
			out, ok := r.run(t, tc.setup(r), tc.args...)
			wantOutput(t, out, ok, false, tc.want)
			if calls := r.dockerCalls(t); strings.Contains(calls, " run ") || strings.Contains(calls, " down ") {
				t.Fatalf("a refusal reached compose:\n%s", calls)
			}
		})
	}
}

func TestUsernsScript_ReexecsThroughIntegrationImageWithoutAnImage(t *testing.T) {
	r := newUsernsRig(t)
	out, ok := r.run(t, map[string]string{"GO_ENCLAVE_IT_IMAGE": ""})
	wantOutput(t, out, ok, true, "integration-image.sh stub ran")
	if calls := r.dockerCalls(t); strings.Contains(calls, "image inspect") || strings.Contains(calls, " run ") {
		t.Fatalf("the script went on past the re-exec:\n%s", calls)
	}
}

func TestUsernsScript_Runs(t *testing.T) {
	cases := []struct {
		name   string
		over   map[string]string
		wantOK bool
		want   []string
	}{
		{
			name:   "the test passes",
			wantOK: true,
			want:   []string{"compose project: go-enclave-userns-", "--- PASS: " + usernsTestName + " "},
		},
		{
			name:   "nothing ran",
			over:   map[string]string{"FAKE_RUN_OUT": "testing: warning: no tests to run\nPASS"},
			wantOK: false,
			want:   []string{"userns-test: " + usernsTestName + " did not pass: nothing ran"},
		},
		{
			name:   "the test fails",
			over:   map[string]string{"FAKE_RUN_OUT": "--- FAIL: " + usernsTestName + " (0.01s)\nFAIL", "FAKE_RUN_RC": "1"},
			wantOK: false,
			want:   []string{"--- FAIL: " + usernsTestName, "userns-test: " + usernsTestName + " failed"},
		},
		{
			name:   "the teardown fails after a pass",
			over:   map[string]string{"FAKE_DOWN_RC": "1"},
			wantOK: false,
			want:   []string{"ERROR: teardown of compose project go-enclave-userns-", "remove it with: docker compose -f '", "down --volumes --remove-orphans"},
		},
		{
			name:   "the teardown fails after a failure",
			over:   map[string]string{"FAKE_RUN_RC": "1", "FAKE_DOWN_RC": "1"},
			wantOK: false,
			want:   []string{" failed", "ERROR: teardown of compose project"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newUsernsRig(t)
			out, ok := r.run(t, tc.over)
			wantOutput(t, out, ok, tc.wantOK, tc.want...)
			calls := r.dockerCalls(t)
			for _, w := range []string{
				"compose -f " + r.compose + " -p go-enclave-userns-",
				"run --rm --pull never userns go test -tags=userns -race -count=1 -v -timeout=300s -run ^" + usernsTestName + "$ .",
				"down --volumes --remove-orphans",
			} {
				if !strings.Contains(calls, w) {
					t.Fatalf("docker calls lack %q:\n%s", w, calls)
				}
			}
		})
	}
}
