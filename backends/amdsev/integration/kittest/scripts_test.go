// Package kittest drives the SEV-SNP kit's scripts (scripts/amd-sev-snp) on
// their paths that need no SNP host: argument checks, the host record on fake
// /proc, /sys and /dev trees, dry runs and pin checks. The hardware paths run
// under make integration-test-amd-sev.
package kittest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// scripts is scripts/amd-sev-snp of this checkout.
func scripts(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	d := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "scripts", "amd-sev-snp")
	if _, err := os.Stat(filepath.Join(d, "run.sh")); err != nil {
		t.Fatalf("scripts/amd-sev-snp: %v", err)
	}
	return d
}

type result struct {
	code           int
	stdout, stderr string
}

// sh runs script with args under env (added to a minimal environment).
func sh(t *testing.T, script string, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(scripts(t), script)}, args...)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "LC_ALL=C"}, env...)
	cmd.Dir = t.TempDir()
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("%s: %v", script, err)
		}
		code = ee.ExitCode()
	}
	return result{code, out.String(), errOut.String()}
}

func (r result) want(t *testing.T, code int, needles ...string) {
	t.Helper()
	all := r.stdout + r.stderr
	for _, n := range needles {
		if !strings.Contains(all, n) {
			t.Errorf("output lacks %q", n)
		}
	}
	if r.code != code || t.Failed() {
		t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, code, r.stdout, r.stderr)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// snpRoot is a fake root of an SNP-ready host.
func snpRoot(t *testing.T) (root, klog string) {
	t.Helper()
	root = t.TempDir()
	write(t, filepath.Join(root, "proc", "cpuinfo"), "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 25\nmodel\t\t: 17\nmodel name\t: AMD EPYC 9124 16-Core Processor\nflags\t\t: fpu sme sev sev_es sev_snp\n\n")
	write(t, filepath.Join(root, "sys", "module", "kvm_amd", "parameters", "sev_snp"), "Y\n")
	write(t, filepath.Join(root, "dev", "kvm"), "")
	write(t, filepath.Join(root, "dev", "sev"), "")
	klog = filepath.Join(t.TempDir(), "klog")
	write(t, klog, "[    5.1] ccp 0000:01:00.5: sev enabled\n[    5.2] ccp 0000:01:00.5: SEV-SNP API:1.55 build:21\n")
	return root, klog
}

func TestAmdSev_HostRecordReadyHost(t *testing.T) {
	root, klog := snpRoot(t)
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog}).
		want(t, 0, "AuthenticAMD", "AMD EPYC 9124", "1.55", "sev-snp: ready")
}

func TestAmdSev_HostRecordNamesWhatIsMissing(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "proc", "cpuinfo"), "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vmx\n\n")
	klog := filepath.Join(t.TempDir(), "klog")
	write(t, klog, "")
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog}).
		want(t, 2, "cannot run an SEV-SNP guest", "sev_snp", "/dev/kvm", "kvm_amd", "/dev/sev")
}

func TestAmdSev_HostRecordRefusesArguments(t *testing.T) {
	sh(t, "host-record.sh", nil, "extra").want(t, 2)
}

func TestAmdSev_GuestImageDryRun(t *testing.T) {
	cache := t.TempDir()
	sh(t, "guest-image.sh", []string{"AMDSEV_CACHE=" + cache}, "--dry-run", "all").
		want(t, 0, filepath.Join(cache, "kit"), "ovmf", "kernel", "qemu")
}

func TestAmdSev_GuestImageRefusesAnUnknownStep(t *testing.T) {
	sh(t, "guest-image.sh", []string{"AMDSEV_CACHE=" + t.TempDir()}, "bogus").want(t, 2, "bogus")
}

// TestAmdSev_GuestImageRefusesAMismatchedInput serves a file of the wrong
// content where the pinned OVMF package should be.
func TestAmdSev_GuestImageRefusesAMismatchedInput(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("curl: %v (the kit fetches with it)", err)
	}
	snap := t.TempDir()
	for _, p := range []string{"e/edk2", "l/linux"} {
		if err := os.MkdirAll(filepath.Join(snap, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Every pinned .deb path gets the same wrong bytes; the first fetch fails.
	bogus := []byte("not the pinned package\n")
	sum := sha256.Sum256(bogus)
	r := sh(t, "guest-image.sh", []string{"AMDSEV_CACHE=" + t.TempDir(), "AMDSEV_SNAPSHOT=file://" + snap}, "--dry-run", "inputs")
	r.want(t, 0)
	for _, line := range strings.Split(r.stdout, "\n") {
		f := strings.Fields(line)
		for _, w := range f {
			if strings.HasSuffix(w, ".deb") && strings.HasPrefix(w, "file://") {
				write(t, strings.TrimPrefix(w, "file://"), string(bogus))
			}
		}
	}
	sh(t, "guest-image.sh", []string{"AMDSEV_CACHE=" + t.TempDir(), "AMDSEV_SNAPSHOT=file://" + snap}, "inputs").
		want(t, 2, hex.EncodeToString(sum[:]), "refusing it")
}

// kit is a fake kit directory with the files guest.sh wants.
func kit(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, f := range []string{"OVMF.amdsev.fd", "vmlinuz", "initrd.img", "qemu-system-x86_64"} {
		write(t, filepath.Join(d, f), "")
	}
	return d
}

func TestAmdSev_GuestDryRunSNP(t *testing.T) {
	r := sh(t, "guest.sh", nil, "--kit", kit(t), "--pidfile", "/run/q.pid", "--dry-run", "snp")
	r.want(t, 0, "-accel kvm", "-pidfile /run/q.pid", "sev-snp-guest", "policy=0x30000", "confidential-guest-support=sev0", "memory-backend-memfd", "amdsev.mode=snp")
}

func TestAmdSev_GuestDryRunPlain(t *testing.T) {
	r := sh(t, "guest.sh", nil, "--kit", kit(t), "--dry-run", "plain")
	r.want(t, 0, "amdsev.mode=plain", "-accel kvm")
	if strings.Contains(r.stdout, "sev-snp-guest") || strings.Contains(r.stdout, "confidential-guest-support") {
		t.Fatalf("the plain control names SEV:\n%s", r.stdout)
	}
}

func TestAmdSev_GuestRefusals(t *testing.T) {
	k := kit(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no mode", []string{"--kit", k}, "usage"},
		{"an unknown mode", []string{"--kit", k, "tdx"}, "tdx"},
		{"a flag without its value", []string{"--kit", k, "snp", "--smp"}, "--smp"},
		{"a count that is not a number", []string{"--kit", k, "--smp", "two", "--dry-run", "snp"}, "two"},
		{"a missing kit file", []string{"--kit", t.TempDir(), "--dry-run", "snp"}, "guest-image.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sh(t, "guest.sh", nil, tc.args...).want(t, 2, tc.want)
		})
	}
}

func TestAmdSev_HostScanRefusesBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"none", nil},
		{"a pid that is not a number", []string{"qemu", "00"}},
		{"a needle that is not hex", []string{"1", "zz"}},
		{"an odd needle", []string{"1", "abc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sh(t, "host-scan.sh", []string{"AMDSEV_HOSTSCAN=/bin/false"}, tc.args...).want(t, 2)
		})
	}
}

// TestAmdSev_HostScanPassesTheHelpersStatus runs host-scan.sh on this test's
// own process with a fake helper that exits with a chosen status.
func TestAmdSev_HostScanPassesTheHelpersStatus(t *testing.T) {
	for _, code := range []int{0, 1, 2} {
		helper := filepath.Join(t.TempDir(), "scan")
		if err := os.WriteFile(helper, []byte("#!/bin/sh\necho \"helper $*\"\nexit "+strconv.Itoa(code)+"\n"), 0o700); err != nil { //nolint:gosec // an executable helper
			t.Fatal(err)
		}
		pid := os.Getpid()
		r := sh(t, "host-scan.sh", []string{"AMDSEV_HOSTSCAN=" + helper}, itoa(pid), "00ff")
		r.want(t, code, "helper "+itoa(pid)+" 00ff")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestAmdSev_RunRefusesArguments(t *testing.T) {
	sh(t, "run.sh", nil, "extra").want(t, 2)
}

// TestAmdSev_RunStopsAtTheHostRecord is what make integration-test-amd-sev
// does on a host without SNP: step 1 fails and names what is missing.
func TestAmdSev_RunStopsAtTheHostRecord(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "proc", "cpuinfo"), "processor\t: 0\nvendor_id\t: AuthenticAMD\nflags\t\t: fpu sev\n\n")
	klog := filepath.Join(t.TempDir(), "klog")
	write(t, klog, "")
	cache := t.TempDir()
	sh(t, "run.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog, "AMDSEV_CACHE=" + cache}).
		want(t, 2, "step 1", "cannot run the SEV-SNP tests", "sev_snp", "/dev/sev")
}
