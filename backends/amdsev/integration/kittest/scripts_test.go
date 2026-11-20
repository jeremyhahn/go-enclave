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
	for _, p := range []string{"sev", "sev_es", "sev_snp"} {
		write(t, filepath.Join(root, "sys", "module", "kvm_amd", "parameters", p), "Y\n")
	}
	write(t, filepath.Join(root, "dev", "kvm"), "")
	write(t, filepath.Join(root, "dev", "sev"), "")
	klog = filepath.Join(t.TempDir(), "klog")
	write(t, klog, "[    5.1] ccp 0000:01:00.5: sev enabled\n[    5.2] ccp 0000:01:00.5: SEV-SNP API:1.55 build:21\n")
	return root, klog
}

// sevRoot is a host with SEV and SEV-ES but no SEV-SNP: the CPU flag and the
// kvm_amd parameter for SNP are absent or off, as where the firmware has no
// SNP setting.
func sevRoot(t *testing.T) (root, klog string) {
	t.Helper()
	root = t.TempDir()
	write(t, filepath.Join(root, "proc", "cpuinfo"), "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 23\nmodel\t\t: 49\nmodel name\t: AMD EPYC 7302 16-Core Processor\nflags\t\t: fpu sme sev sev_es\n\n")
	write(t, filepath.Join(root, "sys", "module", "kvm_amd", "parameters", "sev"), "Y\n")
	write(t, filepath.Join(root, "sys", "module", "kvm_amd", "parameters", "sev_es"), "Y\n")
	write(t, filepath.Join(root, "sys", "module", "kvm_amd", "parameters", "sev_snp"), "N\n")
	write(t, filepath.Join(root, "dev", "kvm"), "")
	write(t, filepath.Join(root, "dev", "sev"), "")
	klog = filepath.Join(t.TempDir(), "klog")
	write(t, klog, "[    5.1] ccp 0000:01:00.5: sev enabled\n[    5.2] ccp 0000:01:00.5: SEV API:0.24 build:18\n")
	return root, klog
}

func TestAmdSev_HostRecordReadyHost(t *testing.T) {
	root, klog := snpRoot(t)
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog}).
		want(t, 0, "AuthenticAMD", "AMD EPYC 9124", "1.55", "guests: sev sev-es", "amd-sev: ready")
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog, "AMDSEV_GUESTS=sev sev-es snp"}).
		want(t, 0, "guests: sev sev-es snp", "amd-sev: ready")
}

// A host whose firmware offers SEV and SEV-ES but not SNP runs the default
// guests, and refuses an SNP guest naming what SNP lacks.
func TestAmdSev_HostRecordSEVOnlyHost(t *testing.T) {
	root, klog := sevRoot(t)
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog}).
		want(t, 0, "AMD EPYC 7302", "amd-sev: ready")
	r := sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog, "AMDSEV_GUESTS=snp"})
	r.want(t, 2, "cannot run", "sev_snp", "kvm_amd sev_snp=Y")
	if strings.Contains(r.stderr, "sev_es CPU flag") {
		t.Errorf("an SNP-only request named SEV-ES as missing: %s", r.stderr)
	}
}

func TestAmdSev_HostRecordRefusesAnUnknownGuest(t *testing.T) {
	root, klog := snpRoot(t)
	for _, g := range []string{"tdx", "plain", "sev snp-x", " "} {
		sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog, "AMDSEV_GUESTS=" + g}).
			want(t, 2, "AMDSEV_GUESTS")
	}
}

func TestAmdSev_HostRecordNamesWhatIsMissing(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "proc", "cpuinfo"), "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vmx\n\n")
	klog := filepath.Join(t.TempDir(), "klog")
	write(t, klog, "")
	sh(t, "host-record.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog}).
		want(t, 2, "cannot run", "the sev CPU flag", "the sev_es CPU flag", "/dev/kvm", "kvm_amd sev=Y", "kvm_amd sev_es=Y", "/dev/sev")
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

// SEV and SEV-ES guests boot with the sev-guest object: policy 0x1 forbids
// debugging, and SEV-ES adds bit 2 for the encrypted register state. Neither
// takes the SNP memfd backend.
func TestAmdSev_GuestDryRunSEV(t *testing.T) {
	for mode, policy := range map[string]string{"sev": "policy=0x1", "sev-es": "policy=0x5"} {
		r := sh(t, "guest.sh", nil, "--kit", kit(t), "--pidfile", "/run/q.pid", "--dry-run", mode)
		r.want(t, 0, "-accel kvm", "-pidfile /run/q.pid", "sev-guest,id=sev0", policy, "confidential-guest-support=sev0", "amdsev.mode="+mode)
		for _, absent := range []string{"sev-snp-guest", "memory-backend-memfd"} {
			if strings.Contains(r.stdout, absent) {
				t.Errorf("%s: the dry run names %q:\n%s", mode, absent, r.stdout)
			}
		}
	}
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
		if err := os.WriteFile(helper, []byte("#!/bin/sh\necho \"helper $*\"\nexit "+strconv.Itoa(code)+"\n"), 0o700); err != nil {
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
		want(t, 2, "step 1", "cannot run", "the sev_es CPU flag", "/dev/sev")
	sh(t, "run.sh", []string{"AMDSEV_ROOT=" + root, "AMDSEV_KLOG=" + klog, "AMDSEV_CACHE=" + cache, "AMDSEV_GUESTS=tdx"}).
		want(t, 2, "AMDSEV_GUESTS")
}

// Step 4 runs under sudo when the caller is not root, and sudo's secure_path
// need not hold go: run.sh must build amdsev-hostscan before that step and
// hand host-scan.sh its absolute path in AMDSEV_HOSTSCAN, so nothing under
// sudo builds. Reaching step 4 needs the hardware, so this reads the script.
func TestAmdSev_RunBuildsTheScannerBeforeSudo(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(scripts(t), "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	build := strings.Index(src, "go build -o \"$scanner\" ./cmd/amdsev-hostscan")
	sudo := strings.Index(src, "sudo -n --")
	if build < 0 || sudo < 0 || build > sudo {
		t.Fatalf("run.sh must build ./cmd/amdsev-hostscan into $scanner before its sudo step (build at %d, sudo at %d)", build, sudo)
	}
	if !strings.Contains(src, "scanner=$cache/amdsev-hostscan") {
		t.Error("run.sh must build the scanner to an absolute path under the cache")
	}
	pass := strings.Index(src, "AMDSEV_HOSTSCAN=\"$scanner\"")
	if pass < 0 || pass > sudo {
		t.Error("run.sh must pass the scanner to the step-4 environment as AMDSEV_HOSTSCAN=\"$scanner\"")
	}
}
