package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The userns, default and FIPS integration suites run on the one image that
// scripts/integration-image.sh built and scanned. These tests drive the real
// scripts against a fake docker and trivy that log what they are asked.

// fakeImageWorld puts a fake docker and trivy first on PATH. docker logs every
// call with the GO_ENCLAVE_IT_IMAGE it saw, reports the image ID in idFile, and
// makes a `go test` run print the userns test's PASS line. It returns the
// environment for scripts/integration-image.sh and the log.
func fakeImageWorld(t *testing.T) (env map[string]string, log, idFile string) {
	t.Helper()
	requireLinuxInstallPath(t)
	bin := t.TempDir()
	scratch := t.TempDir()
	log = filepath.Join(scratch, "calls.log")
	idFile = filepath.Join(scratch, "id")
	if err := os.WriteFile(idFile, []byte("sha256:"+strings.Repeat("a", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	docker := `#!/bin/sh
echo "docker image=${GO_ENCLAVE_IT_IMAGE-} $*" >> "$FAKE_LOG"
# Like the real CLI, refuse a flag the subcommand does not have: ` + "`compose run`" + `
# has no --no-build (only up and create do), and CI failed on exactly that.
case " $* " in
  *" compose "*" run "*)
    for a in "$@"; do
      case $a in --no-build|--build) echo "unknown flag: $a" >&2; exit 1 ;; esac
    done ;;
esac
case $1 in
  version) echo 28.0.0; exit 0 ;;
  compose) ;;
  image)
    if [ "$2" = inspect ] && [ "$3" = --format ]; then cat "$FAKE_ID_FILE"; fi
    exit 0 ;;
  *) exit 0 ;;
esac
case " $* " in
  *" run "*) case " $* " in *" go "*) echo "--- PASS: TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace (0.00s)" ;; esac ;;
esac
`
	for name, body := range map[string]string{"docker": docker, "trivy": fakeTrivy(0)} {
		writeExecutable(t, filepath.Join(bin, name), []byte(body))
	}
	return pinFakeTrivy(t, map[string]string{
		"PATH":                   bin + ":" + os.Getenv("PATH"),
		"FAKE_LOG":               log,
		"FAKE_ID_FILE":           idFile,
		"TOOL_INSTALL":           "0",
		"TRIVY_VERSION":          "v0.75.0",
		"DEVCONTAINER_COMPOSE":   "build/docker/devcontainer/compose.yaml",
		"DEVCONTAINER_SERVICE":   "integration",
		"INTEGRATION_TESTFLAGS":  "-tags=integration",
		"COVERAGE_THRESHOLD":     "0",
		"GO_ENCLAVE_IT_IMAGE":    "",
		"GO_ENCLAVE_IT_IMAGE_ID": "",
	}, filepath.Join(bin, "trivy")), log, idFile
}

// fakeTrivy is a trivy that reports the pinned version, logs a scan and exits
// with scanRC.
func fakeTrivy(scanRC int) string {
	rc := "0"
	if scanRC != 0 {
		rc = "1"
	}
	return "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Version: 0.75.0'; exit 0; fi\n" +
		"echo \"trivy $*\" >> \"$FAKE_LOG\"\nexit " + rc + "\n"
}

// pinFakeTrivy pins the hash of the fake at p, which tool.sh requires of a
// trivy under TOOL_INSTALL=0.
func pinFakeTrivy(t *testing.T, env map[string]string, p string) map[string]string {
	t.Helper()
	sum := sha256Hex(t, p)
	env["TRIVY_BIN_SHA256_LINUX_AMD64"] = sum
	env["TRIVY_BIN_SHA256_LINUX_ARM64"] = sum
	return env
}

func runImageScript(t *testing.T, env map[string]string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(repoRoot(t), "scripts", "integration-image.sh")}, args...)...)
	cmd.Dir = repoRoot(t)
	cmd.Env = layerEnv(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func readCallLog(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", log, err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func isComposeCall(l, sub string) bool {
	return strings.Contains(l, " compose ") && strings.Contains(l, " "+sub+" ")
}

// TestIntegrationImage_BuildsOnceScansThatImageAndRunsEverySuiteOnIt pins the
// scan identity: the userns, default and FIPS suites run on the image that was
// built once and scanned, nothing rebuilds between them, and it is removed after
// the last.
func TestIntegrationImage_BuildsOnceScansThatImageAndRunsEverySuiteOnIt(t *testing.T) {
	env, log, _ := fakeImageWorld(t)
	suites := `sh scripts/userns-test.sh &&
sh scripts/integration-test.sh enclave github.com/jeremyhahn/go-enclave &&
sh scripts/integration-test.sh enclave github.com/jeremyhahn/go-enclave -e GOFIPS140=latest`
	out, ok := runImageScript(t, env, "sh", "-c", suites)
	if !ok {
		t.Fatalf("the suites failed under the image script:\n%s", out)
	}

	var builds, scans, runs, removes []int
	var image string
	lines := readCallLog(t, log)
	for i, l := range lines {
		switch {
		case isComposeCall(l, "build"):
			builds = append(builds, i)
			image = strings.Fields(strings.TrimPrefix(l, "docker image="))[0]
		case strings.HasPrefix(l, "trivy image "):
			scans = append(scans, i)
		case isComposeCall(l, "run"):
			runs = append(runs, i)
		case strings.Contains(l, " image rm "):
			removes = append(removes, i)
		}
	}
	dump := strings.Join(lines, "\n")
	if len(builds) != 1 || len(scans) != 1 || len(runs) != 3 || len(removes) != 1 {
		t.Fatalf("builds=%d scans=%d runs=%d removals=%d, want 1, 1, 3, 1:\n%s", len(builds), len(scans), len(runs), len(removes), dump)
	}
	if !strings.HasPrefix(image, "go-enclave-it:") {
		t.Fatalf("the image is tagged %q, want a unique go-enclave-it:<run> tag", image)
	}
	if !(builds[0] < scans[0] && scans[0] < runs[0] && runs[2] < removes[0] && removes[0] == len(lines)-1) {
		t.Fatalf("want build, scan, the three suites, then removal last:\n%s", dump)
	}
	if !strings.HasSuffix(lines[scans[0]], " "+image) {
		t.Errorf("trivy scanned %q, not the image the suites run on (%s)", lines[scans[0]], image)
	}
	for _, r := range runs {
		if !strings.HasPrefix(lines[r], "docker image="+image+" ") || !strings.Contains(lines[r], " --pull never ") {
			t.Errorf("a suite does not run on the scanned image without a build: %s", lines[r])
		}
	}
	if !strings.HasSuffix(lines[removes[0]], " "+image) {
		t.Errorf("removed %q, want the image %s", lines[removes[0]], image)
	}
}

// A suite refuses an image that is no longer the one that was scanned, and the
// script builds the image itself rather than being handed one.
func TestIntegrationImage_SuiteRefusesAnImageThatWasNotScanned(t *testing.T) {
	env, log, idFile := fakeImageWorld(t)
	swap := "echo sha256:" + strings.Repeat("b", 64) + " > " + idFile + " && sh scripts/integration-test.sh enclave github.com/jeremyhahn/go-enclave"
	out, ok := runImageScript(t, env, "sh", "-c", swap)
	if ok || !strings.Contains(out, "that was scanned") {
		t.Fatalf("ran a suite on an image whose ID changed after the scan (ok=%v):\n%s", ok, out)
	}
	for _, l := range readCallLog(t, log) {
		if isComposeCall(l, "run") {
			t.Fatalf("a suite ran on the swapped image: %s", l)
		}
	}

	env["GO_ENCLAVE_IT_IMAGE"] = "go-enclave-it:planted"
	if out, ok := runImageScript(t, env, "true"); ok || !strings.Contains(out, "already set") {
		t.Fatalf("accepted a supplied image instead of building and scanning one (ok=%v):\n%s", ok, out)
	}
}

// A scan that fails stops the run: no suite starts, and the image is removed.
func TestIntegrationImage_AFailedScanRunsNoSuite(t *testing.T) {
	env, log, _ := fakeImageWorld(t)
	trivy := filepath.Join(strings.SplitN(env["PATH"], ":", 2)[0], "trivy")
	writeExecutable(t, trivy, []byte(fakeTrivy(1)))
	pinFakeTrivy(t, env, trivy)
	out, ok := runImageScript(t, env, "sh", "-c", "sh scripts/integration-test.sh enclave github.com/jeremyhahn/go-enclave")
	if ok {
		t.Fatalf("ran the suite after a failed scan:\n%s", out)
	}
	var removed bool
	for _, l := range readCallLog(t, log) {
		if isComposeCall(l, "run") {
			t.Fatalf("a suite ran after a failed scan: %s", l)
		}
		removed = removed || strings.Contains(l, " image rm ")
	}
	if !removed {
		t.Error("the image was left behind after a failed scan")
	}
}
