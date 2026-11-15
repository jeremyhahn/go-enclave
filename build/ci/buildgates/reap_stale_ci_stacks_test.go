package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDocker answers the reaper's read calls from fixture files in
// $FAKE_FIX and logs every call to $FAKE_LOG. Any call that is not a read
// is logged as "WRITE ..." and fails, so a dry run that tried to change
// the daemon shows in the log.
const fakeDocker = `#!/usr/bin/env bash
f=$FAKE_FIX
printf '%s\n' "$*" >>"$FAKE_LOG"
out() { if [ -f "$f/$1" ]; then cat "$f/$1"; fi; return 0; }
filter='' format=''
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case ${args[i]} in
    --filter) filter=${args[i+1]} ;;
    --format | -f) format=${args[i+1]} ;;
  esac
done
last=${!#}
case "$1 $2" in
  "ps "*)
    case $filter in
      label=com.docker.compose.project) out projects ;;
      label=com.docker.compose.project=*) out "project-${filter##*=}" ;;
      name=*) out loose ;;
      ancestor=*) out "users-${filter#ancestor=}" ;;
      *) echo "WRITE $*" >>"$FAKE_LOG"; exit 1 ;;
    esac ;;
  "inspect "*) [ -f "$f/inspect-$last" ] || exit 1; cat "$f/inspect-$last" ;;
  "network ls") out "net-${filter##*=}" ;;
  "volume ls") out "vol-${filter##*=}" ;;
  "images "*) out images ;;
  "image inspect")
    case $format in
      *LastTagTime*) out "tag-$last" ;;
      *) out "image-$last" ;;
    esac ;;
  *) echo "WRITE $*" >>"$FAKE_LOG"; exit 1 ;;
esac
`

// reapRun runs scripts/reap-stale-ci-stacks.sh with bash, always under
// REAP_DRY_RUN=1, with the fake docker first on PATH. It returns the
// combined output, the exit code and the fake's call log.
func reapRun(t *testing.T, fix map[string]string, env map[string]string, args ...string) (string, int, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	fixDir := filepath.Join(dir, "fix")
	for _, d := range []string{bin, fixDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range fix {
		if err := os.WriteFile(filepath.Join(fixDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "docker.log")
	over := map[string]string{
		"PATH":         bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_FIX":     fixDir,
		"FAKE_LOG":     logPath,
		"REAP_DRY_RUN": "1",
	}
	for k, v := range env {
		over[k] = v
	}
	over["REAP_DRY_RUN"] = "1"
	script := filepath.Join(repoRoot(t), "scripts", "reap-stale-ci-stacks.sh")
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), over)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		code = exitErr.ExitCode()
	}
	log, err := os.ReadFile(logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(out), code, string(log)
}

func TestReapStaleCIStacksRefusesBadArguments(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"empty prefix", nil, []string{""}},
		{"prefix with a space", nil, []string{"ci x"}},
		{"min-age with a unit", nil, []string{"ci-", "1h"}},
		{"image min age not a number", map[string]string{"REAP_IMAGE_MIN_AGE": "x"}, []string{"ci-"}},
		{"negative lock wait", map[string]string{"REAP_LOCK_WAIT": "-1"}, []string{"ci-"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, log := reapRun(t, nil, tc.env, tc.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; output:\n%s", code, out)
			}
			if log != "" {
				t.Fatalf("docker was called on a refused argument:\n%s", log)
			}
		})
	}
}

func TestReapStaleCIStacksDryRun(t *testing.T) {
	now := time.Now().UTC()
	ts := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	tag := func(ago time.Duration) string {
		return now.Add(-ago).Format("2006-01-02 15:04:05.00 -0700") + " UTC"
	}
	const zero = "0001-01-01T00:00:00Z"
	const zeroTag = "0001-01-01 00:00:00 +0000 UTC"
	old, recent := 2*time.Hour, time.Minute
	inspect := func(state string, finished, created string) string {
		return state + " " + finished + " " + created + "\n"
	}

	fix := map[string]string{
		"projects": "ci-a\nci-b\nci-c\nci-d\nother-p\n",
		// ci-a: every container stale, one exited, one created and never
		// started, aged by Created.
		"project-ci-a": "a1\na2\n",
		"inspect-a1":   inspect("exited", ts(old), ts(old+time.Hour)),
		"inspect-a2":   inspect("created", zero, ts(old)),
		"net-ci-a":     "net-a\n",
		"vol-ci-a":     "vol-a\n",
		// ci-b: one running container keeps the project.
		"project-ci-b": "b1\nb2\n",
		"inspect-b1":   inspect("exited", ts(old), ts(old)),
		"inspect-b2":   inspect("running", zero, ts(old)),
		"net-ci-b":     "net-b\n",
		// ci-c: a created container made recently is not stale, although
		// its FinishedAt is the zero time.
		"project-ci-c": "c1\n",
		"inspect-c1":   inspect("created", zero, ts(recent)),
		// ci-d: a container exited within min-age keeps the project.
		"project-ci-d": "d1\n",
		"inspect-d1":   inspect("exited", ts(recent), ts(old)),
		// other-p does not start with the prefix: never listed or touched.
		"project-other-p": "o1\n",
		"inspect-o1":      inspect("exited", ts(old), ts(old)),

		// Loose containers: a compose one (skipped), a stale and a fresh
		// prefixed one, and one whose name lacks the prefix.
		"loose":      "a1 ci-a-web-1 ci-a\nl1 ci-loose-old\nl2 ci-loose-new\nx1 other-x\n",
		"inspect-l1": inspect("exited", ts(old), ts(old)),
		"inspect-l2": inspect("exited", ts(recent), ts(old)),
		"inspect-x1": inspect("exited", ts(old), ts(old)),

		// Images.
		"images":               "ci-it:old\nci-it:oldtag\nci-it:retagged\nci-it:fresh\nci-it:used\nci-it:leased\nci-it:noid\nother:tag\n",
		"image-ci-it:old":      "sha256:old " + ts(old) + "\n",
		"tag-ci-it:old":        zeroTag + "\n",
		"image-ci-it:oldtag":   "sha256:oldtag " + ts(old+time.Hour) + "\n",
		"tag-ci-it:oldtag":     tag(old) + "\n",
		"image-ci-it:retagged": "sha256:retagged " + ts(old) + "\n",
		"tag-ci-it:retagged":   tag(recent) + "\n",
		"image-ci-it:fresh":    "sha256:fresh " + ts(recent) + "\n",
		"tag-ci-it:fresh":      zeroTag + "\n",
		"image-ci-it:used":     "sha256:used " + ts(old) + "\n",
		"tag-ci-it:used":       zeroTag + "\n",
		"users-sha256:used":    "b2\n",
		"image-ci-it:leased":   "sha256:leased " + ts(old) + "\n",
		"tag-ci-it:leased":     zeroTag + "\n",
		"users-sha256:leased":  "lease1\n",
		"inspect-lease1":       inspect("created", zero, ts(recent)),
		"image-other:tag":      "sha256:other " + ts(old) + "\n",
	}
	out, code, log := reapRun(t, fix, map[string]string{"REAP_IMAGE_MIN_AGE": "3600"}, "ci-", "3600")
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	has := func(want string) bool {
		for _, l := range lines {
			if l == want || strings.HasPrefix(l, want) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{
		"reap  ci-a: 2 container(s)",
		"dry   docker rm -v a1 a2",
		"dry   docker network rm net-a",
		"dry   docker volume rm vol-a",
		"keep  ci-b (a container is live or stopped within 3600s)",
		"keep  ci-c (a container is live or stopped within 3600s)",
		"keep  ci-d (a container is live or stopped within 3600s)",
		"reap  container ci-loose-old",
		"dry   docker rm -v l1",
		"reap  image ci-it:old",
		"dry   docker image rm ci-it:old",
		"reap  image ci-it:oldtag",
		"dry   docker image rm ci-it:oldtag",
		"keep  image ci-it:retagged (created or tagged within 3600s)",
		"keep  image ci-it:fresh (created or tagged within 3600s)",
		"keep  image ci-it:used (in use: 1 container(s) on sha256:used)",
		"keep  image ci-it:leased (in use: 1 container(s) on sha256:leased)",
		"keep  image ci-it:noid (docker image inspect gave no id)",
		"reaper: 1 compose project(s) and 2 image(s) would be removed for prefix 'ci-'",
	} {
		if !has(want) {
			t.Errorf("output lacks %q; output:\n%s", want, out)
		}
	}
	if lines[len(lines)-1] != "reaper: 1 compose project(s) and 2 image(s) would be removed for prefix 'ci-'" {
		t.Errorf("last line %q is not the dry-run summary", lines[len(lines)-1])
	}
	for _, unwanted := range []string{
		"other-p", "o1", "ci-loose-new", "l2", "other-x", "x1", "other:tag",
		"net-b", "rm -v b1", "rm -v c1", "rm -v d1",
		"image rm ci-it:retagged", "image rm ci-it:fresh", "image rm ci-it:used",
		"image rm ci-it:leased", "image rm ci-it:noid",
	} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output names %q; output:\n%s", unwanted, out)
		}
	}

	// Only reads reach the fake: no write, and never a project or an
	// image outside the prefix.
	for _, call := range strings.Split(strings.TrimRight(log, "\n"), "\n") {
		read := false
		for _, p := range []string{"ps ", "inspect ", "network ls ", "volume ls ", "images ", "image inspect "} {
			if strings.HasPrefix(call, p) {
				read = true
			}
		}
		if !read || strings.HasPrefix(call, "WRITE") {
			t.Errorf("fake docker got a non-read call %q", call)
		}
		for _, bad := range []string{"other-p", "other:tag", "o1", "x1"} {
			if strings.Contains(call, bad) {
				t.Errorf("fake docker call %q touches %q outside the prefix", call, bad)
			}
		}
	}
}
