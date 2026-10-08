package buildgates

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// toolchainTrivyTree copies build/ci/toolchain-trivy.sh into a scratch tree
// next to a scripts/tool-pins.sh pinning the SHA-256 of good for both
// architectures, and puts a fake docker and make first on PATH: docker cp
// writes served as the trivy binary. It returns the script and the PATH.
func toolchainTrivyTree(t *testing.T, good, served string) (script, path string) {
	t.Helper()
	root := t.TempDir()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "build", "ci", "toolchain-trivy.sh"))
	if err != nil {
		t.Fatalf("read toolchain-trivy.sh: %v", err)
	}
	script = filepath.Join(root, "build", "ci", "toolchain-trivy.sh")
	sum := sha256.Sum256([]byte(good))
	pins := "TRIVY_BIN_SHA256_LINUX_AMD64=" + hex.EncodeToString(sum[:]) + "\n" +
		"TRIVY_BIN_SHA256_LINUX_ARM64=" + hex.EncodeToString(sum[:]) + "\n"
	for p, body := range map[string]string{
		script: string(src),
		filepath.Join(root, "scripts", "tool-pins.sh"): pins,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	bin := t.TempDir()
	servedFile := filepath.Join(t.TempDir(), "served")
	if err := os.WriteFile(servedFile, []byte(served), 0o644); err != nil {
		t.Fatalf("write served: %v", err)
	}
	docker := "#!/bin/sh\n" +
		"case $1 in\n" +
		"  image) exit 0 ;;\n" +
		"  create) echo cid ;;\n" +
		"  cp) cp " + servedFile + " \"$3\" ;;\n" +
		"  rm) exit 0 ;;\n" +
		"esac\n"
	fakeMake := "#!/bin/sh\necho go-enclave-toolchain:planted\n"
	for name, body := range map[string]string{"docker": docker, "make": fakeMake} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return script, bin + ":" + os.Getenv("PATH")
}

// An image already carrying the toolchain tag may have been planted on a shared
// daemon, so the trivy copied out of it must hash to the pin before it reaches
// the directory the job puts on PATH.
func TestToolchainTrivyVerifiesTheCopyAgainstThePinnedHash(t *testing.T) {
	const genuine = "the reviewed trivy"
	for _, tc := range []struct {
		name, served string
		wantOK       bool
	}{
		{"pinned binary", genuine, true},
		{"planted binary", "#!/bin/sh\necho 'Version: 0.75.0'\n", false},
		{"empty copy", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, path := toolchainTrivyTree(t, genuine, tc.served)
			dest := filepath.Join(t.TempDir(), "bin")
			cmd := exec.Command("sh", script, dest)
			cmd.Env = layerEnv(os.Environ(), map[string]string{"PATH": path})
			out, err := cmd.CombinedOutput()
			_, statErr := os.Stat(filepath.Join(dest, "trivy"))
			if tc.wantOK {
				if err != nil || statErr != nil {
					t.Fatalf("refused the pinned binary (run: %v, stat: %v):\n%s", err, statErr, out)
				}
				return
			}
			if err == nil || !strings.Contains(string(out), "CHECKSUM MISMATCH") {
				t.Fatalf("accepted a copy that does not hash to the pin (run: %v):\n%s", err, out)
			}
			if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("left an unverified trivy in the PATH directory (stat: %v)", statErr)
			}
		})
	}
}
