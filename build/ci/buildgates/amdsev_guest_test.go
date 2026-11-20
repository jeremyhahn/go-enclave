package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// amdsevGuest runs scripts/amdsev-guest.sh with args and an empty OVMF,
// kernel and initrd in a temporary directory, and returns its combined output
// and whether it exited zero.
func amdsevGuest(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"OVMF.fd", "bzImage", "initrd.img"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	argv := append([]string{filepath.Join(repoRoot(t), "scripts", "amdsev-guest.sh"),
		"--ovmf", filepath.Join(dir, "OVMF.fd"),
		"--kernel", filepath.Join(dir, "bzImage"),
		"--initrd", filepath.Join(dir, "initrd.img"),
		"--serial", filepath.Join(dir, "serial.log"),
		"--qemu", filepath.Join(dir, "no-such-qemu")}, args...)
	cmd := exec.Command("sh", argv...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "AMDSEV_APPEND=")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// Each mode's dry run prints one QEMU command line: KVM on the real CPU, the
// pinned OVMF and the direct-boot kernel, initrd and command line, the serial
// console in a file, no network device, and the mode's SEV object or none.
func TestAMDSEVGuest_DryRunPrintsTheModesQEMUObjects(t *testing.T) {
	common := []string{"-accel kvm", "-bios ", "-kernel ", "-initrd ", "-append ", "-serial file:", "-nic none", "-nodefaults", "-no-reboot"}
	for _, tc := range []struct {
		mode    string
		want    []string
		without []string
	}{
		{"snp", []string{
			"confidential-guest-support=sev0",
			"-object sev-snp-guest,id=sev0,",
			"policy=0x30000", // bit 19 (debug) and bit 18 (migration agent) clear
			"kernel-hashes=on",
			"memory-backend-memfd",
		}, []string{"sev-guest,", "debug=on"}},
		{"sev-es", []string{
			"confidential-guest-support=sev0",
			"-object sev-guest,id=sev0,",
			"policy=0x5", // NODBG and ES
			"kernel-hashes=on",
		}, []string{"sev-snp-guest"}},
		{"plain", nil, []string{"sev-snp-guest", "sev-guest", "confidential-guest-support"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			out, ok := amdsevGuest(t, "--dry-run", tc.mode)
			if !ok {
				t.Fatalf("amdsev-guest.sh --dry-run %s failed:\n%s", tc.mode, out)
			}
			if n := strings.Count(out, "\n"); n != 0 {
				t.Fatalf("dry run printed %d lines, want one command line:\n%s", n+1, out)
			}
			for _, w := range append(common, tc.want...) {
				if !strings.Contains(out, w) {
					t.Errorf("dry run %s lacks %q:\n%s", tc.mode, w, out)
				}
			}
			for _, w := range append([]string{"-netdev", "-net ", "user,", "tap,", "http"}, tc.without...) {
				if strings.Contains(out, w) {
					t.Errorf("dry run %s carries %q:\n%s", tc.mode, w, out)
				}
			}
		})
	}
}

func TestAMDSEVGuest_RefusesWhatItMustRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		msg  string
	}{
		{"no mode", []string{"--dry-run"}, "usage"},
		{"an unknown mode", []string{"--dry-run", "tdx"}, "unknown mode"},
		{"an unknown flag", []string{"--dry-run", "--net", "user", "snp"}, "unknown flag"},
		{"a missing kernel", []string{"--dry-run", "--kernel", "/nonexistent/bzImage", "snp"}, "/nonexistent/bzImage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := amdsevGuest(t, tc.args...)
			if ok || !strings.Contains(out, tc.msg) {
				t.Fatalf("amdsev-guest.sh %v = ok=%v, want a refusal naming %q:\n%s", tc.args, ok, tc.msg, out)
			}
		})
	}
}

// A real run needs /dev/kvm, and SNP and SEV-ES also /dev/sev; without them
// the script refuses before it starts QEMU.
func TestAMDSEVGuest_RefusesWithoutTheDevices(t *testing.T) {
	for _, tc := range []struct {
		mode, dev string
	}{
		{"plain", "/dev/kvm"},
		{"sev-es", "/dev/sev"},
		{"snp", "/dev/sev"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			if _, err := os.Stat(tc.dev); err == nil {
				t.Skipf("%s exists here", tc.dev)
			}
			out, ok := amdsevGuest(t, tc.mode)
			if ok || !strings.Contains(out, "/dev/") || strings.Contains(out, "no-such-qemu: not found") {
				t.Fatalf("amdsev-guest.sh %s without %s = ok=%v, want a refusal naming the device:\n%s", tc.mode, tc.dev, ok, out)
			}
		})
	}
}

// Neither script reaches the network: no download tool, no URL, and the host
// scan helper builds with the module proxy off.
func TestAMDSEVGuest_ScriptsDownloadNothing(t *testing.T) {
	for _, s := range []string{"amdsev-guest.sh", "amdsev-host-scan.sh"} {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", s))
		if err != nil {
			t.Fatalf("read scripts/%s: %v", s, err)
		}
		for _, w := range []string{"curl", "wget", "http://", "https://", "git clone", "go get", "go install"} {
			if strings.Contains(string(src), w) {
				t.Errorf("scripts/%s contains %q", s, w)
			}
		}
		if s == "amdsev-host-scan.sh" && !strings.Contains(string(src), "GOPROXY=off") {
			t.Errorf("scripts/%s does not build its helper with GOPROXY=off", s)
		}
	}
}
