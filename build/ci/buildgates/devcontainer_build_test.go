package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `devcontainer.sh build` (make docker-build) builds content-tagged images,
// and two jobs on one daemon race to the same tag: the loser's BuildKit export
// fails with "already exists" (main run 59297). These tests drive the real
// script against a fake docker that holds the tags listed in FAKE_HELD.

// fakeBuildDocker logs every call to FAKE_LOG. `image inspect <ref>` succeeds
// when FAKE_HELD lists ref. `build` and `compose ... build` succeed, unless
// FAKE_FAIL is set; then, with FAKE_RACE set, the tag they build is added to
// FAKE_HELD first, as another job on the daemon would.
const fakeBuildDocker = `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
held() {
  while IFS= read -r l; do [ "$l" = "$1" ] && return 0; done < "$FAKE_HELD"
  return 1
}
case $1 in
  image) [ "$2" = inspect ] && held "$3"; exit ;;
  build|compose)
    [ -n "${FAKE_FAIL-}" ] || exit 0
    if [ -n "${FAKE_RACE-}" ]; then
      if [ "$1" = compose ]; then
        echo "$GO_ENCLAVE_IT_IMAGE" >> "$FAKE_HELD"
      else
        while [ $# -gt 0 ]; do
          if [ "$1" = -t ]; then echo "$2" >> "$FAKE_HELD"; break; fi
          shift
        done
      fi
    fi
    echo 'ERROR: failed to build: image already exists' >&2
    exit 1 ;;
esac
exit 0
`

const fakeBuildITImage = "go-enclave-ci-it:0123456789ab"

// runDevcontainerBuild runs `devcontainer.sh build` with the fake docker,
// holding the tags in held, and returns the output, the docker calls and
// whether it succeeded.
func runDevcontainerBuild(t *testing.T, held []string, over map[string]string) (string, []string, bool) {
	t.Helper()
	root := repoRoot(t)
	bin := t.TempDir()
	scratch := t.TempDir()
	log := filepath.Join(scratch, "calls.log")
	heldFile := filepath.Join(scratch, "held")
	writeExecutable(t, filepath.Join(bin, "docker"), []byte(fakeBuildDocker))
	body := ""
	for _, h := range held {
		body += h + "\n"
	}
	if err := os.WriteFile(heldFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PATH":                bin + ":" + os.Getenv("PATH"),
		"FAKE_LOG":            log,
		"FAKE_HELD":           heldFile,
		"FAKE_FAIL":           "",
		"FAKE_RACE":           "",
		"GO_ENCLAVE_IT_IMAGE": fakeBuildITImage,
	}
	for k, v := range over {
		env[k] = v
	}
	cmd := exec.Command("sh", filepath.Join(root, "scripts", "devcontainer.sh"), "build")
	cmd.Dir = root
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	return string(out), readCallLog(t, log), err == nil
}

func toolchainRef(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("sh", "scripts/devcontainer.sh", "tag")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("devcontainer.sh tag: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// builds counts the toolchain and integration builds in the docker calls and
// reports whether the toolchain's :latest alias was set by `docker tag`.
func builds(calls []string, ref string) (toolchain, integration int, latest bool) {
	for _, c := range calls {
		switch {
		case strings.HasPrefix(c, "docker build "):
			toolchain++
		case strings.HasPrefix(c, "docker compose ") && strings.HasSuffix(c, " build integration"):
			integration++
		case c == "docker tag "+ref+" go-enclave-toolchain:latest":
			latest = true
		}
	}
	return toolchain, integration, latest
}

// A stage whose content tag the daemon holds is not built; the toolchain's
// :latest alias is still set.
func TestScriptsDevcontainer_BuildSkipsAHeldTag(t *testing.T) {
	ref := toolchainRef(t)
	out, calls, ok := runDevcontainerBuild(t, []string{ref, fakeBuildITImage}, nil)
	if !ok {
		t.Fatalf("build failed with both tags held:\n%s", out)
	}
	tc, it, latest := builds(calls, ref)
	if tc != 0 || it != 0 {
		t.Fatalf("built a held tag (toolchain=%d integration=%d):\n%s", tc, it, strings.Join(calls, "\n"))
	}
	if !latest {
		t.Fatalf("did not tag %s as go-enclave-toolchain:latest:\n%s", ref, strings.Join(calls, "\n"))
	}
}

// A build that fails while another job tags the same content counts as built.
func TestScriptsDevcontainer_BuildLostToARaceCountsAsBuilt(t *testing.T) {
	ref := toolchainRef(t)
	out, calls, ok := runDevcontainerBuild(t, nil, map[string]string{"FAKE_FAIL": "1", "FAKE_RACE": "1"})
	if !ok {
		t.Fatalf("a build lost to a race on its content tag failed:\n%s", out)
	}
	tc, it, latest := builds(calls, ref)
	if tc != 1 || it != 1 || !latest {
		t.Fatalf("toolchain=%d integration=%d latest=%v, want 1, 1, true:\n%s", tc, it, latest, strings.Join(calls, "\n"))
	}
}

// A build that fails with its tag not held fails, at either stage.
func TestScriptsDevcontainer_BuildFailsWhenTheTagIsNotHeld(t *testing.T) {
	ref := toolchainRef(t)
	out, calls, ok := runDevcontainerBuild(t, nil, map[string]string{"FAKE_FAIL": "1"})
	if ok || !strings.Contains(out, "building "+ref+" failed") {
		t.Fatalf("a failed toolchain build with no held tag passed (ok=%v):\n%s", ok, out)
	}
	if _, it, _ := builds(calls, ref); it != 0 {
		t.Fatalf("built the integration image after the toolchain failed:\n%s", strings.Join(calls, "\n"))
	}

	out, _, ok = runDevcontainerBuild(t, []string{ref}, map[string]string{"FAKE_FAIL": "1"})
	if ok || !strings.Contains(out, "building "+fakeBuildITImage+" failed") {
		t.Fatalf("a failed integration build with no held tag passed (ok=%v):\n%s", ok, out)
	}
}
