//go:build amdsev

// Package amdsev_test is the AMD SEV hardware suite: SEV, SEV-ES and SEV-SNP
// guests, and the plain KVM control. Its TestAmdSev_Guest
// tests run inside a guest the kit boots (scripts/amd-sev-snp/guest.sh, with
// guestinit as /init); its TestAmdSev_Host tests run on the host, as root,
// under scripts/amd-sev-snp/run.sh. A test run in the wrong place fails. The
// amdsev build tag selects it, so make test-backends never runs it.
package amdsev_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backends/amdsev"
	"github.com/jeremyhahn/go-enclave/backendtest"

	"github.com/jeremyhahn/go-enclave/backends/amdsev/integration/guestcfg"
)

// inGuest returns the kit guest's configuration, failing the test outside one.
func inGuest(t *testing.T, mode string) guestcfg.Config {
	t.Helper()
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := guestcfg.Parse(string(b))
	if err != nil {
		t.Fatalf("%v: run this test in the kit's guest (make integration-test-amd-sev)", err)
	}
	if mode != "" && cfg.Mode != mode {
		t.Fatalf("guest mode %s, this test runs in mode %s", cfg.Mode, mode)
	}
	return cfg
}

// onHost fails the test inside a kit guest.
func onHost(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guestcfg.Parse(string(b)); !errors.Is(err, guestcfg.ErrNotKitGuest) {
		t.Fatalf("this is a host test, but /proc/cmdline is a kit guest's (%v)", err)
	}
}

// TestAmdSev_GuestConformance runs the backend conformance suite on the
// amd-sev backend inside the SEV-SNP guest.
func TestAmdSev_GuestConformance(t *testing.T) {
	inGuest(t, guestcfg.ModeSNP)
	b, err := newBackend()
	if err != nil {
		t.Fatalf("the amd-sev backend inside an SEV-SNP guest: %v", err)
	}
	c, ok := b.(enclave.Confiner)
	if !ok || !c.ConfinesProcess() {
		t.Fatalf("the amd-sev backend inside an SEV-SNP guest does not confine the process (Confiner %v)", ok)
	}
	if err := backendtest.TestBackend(context.Background(), conformance(t.Logf)); err != nil {
		t.Fatal(err)
	}
}

// refused fails unless newBackend refuses with the typed error.
func refused(t *testing.T, where string) {
	t.Helper()
	b, err := newBackend()
	if b != nil || !errors.Is(err, amdsev.ErrSNPGuestUnavailable) {
		t.Fatalf("%s: newBackend = %v, %v; want no backend and an error that is amdsev.ErrSNPGuestUnavailable", where, b, err)
	}
}

// TestAmdSev_GuestRefusal: in an SEV, SEV-ES or plain KVM guest the backend
// refuses, since only SEV-SNP gives it what it needs.
func TestAmdSev_GuestRefusal(t *testing.T) {
	cfg := inGuest(t, "")
	if cfg.Mode == guestcfg.ModeSNP {
		t.Fatalf("the refusal runs in an SEV, SEV-ES or plain KVM guest, not in mode %s", cfg.Mode)
	}
	refused(t, "a "+cfg.Mode+" guest")
}

// TestAmdSev_HostRefusal: on the host the backend refuses.
func TestAmdSev_HostRefusal(t *testing.T) {
	onHost(t)
	refused(t, "the host")
}

// TestAmdSev_GuestHoldNeedle holds a random needle in a memory enclave,
// prints it for the host scan, holds it for the configured time, then
// destroys the enclave.
func TestAmdSev_GuestHoldNeedle(t *testing.T) {
	cfg := inGuest(t, "")
	mem, err := enclave.NewMemorySized(32)
	if err != nil {
		t.Fatal(err)
	}
	var needle string
	if err := mem.WithBytes(func(b []byte) error {
		if _, err := rand.Read(b); err != nil {
			return err
		}
		needle = hex.EncodeToString(b)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s%s\n", guestcfg.NeedleMarker, needle)
	time.Sleep(cfg.Hold)
	if err := mem.Destroy(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(guestcfg.ReleasedLine)
}

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is empty; scripts/amd-sev-snp/run.sh sets it (make integration-test-amd-sev)", name)
	}
	return v
}

// TestAmdSev_HostScan boots a fresh guest per mode, waits for the guest's
// needle, and scans the guest's QEMU process for it as root: for each guest
// AMDSEV_GUESTS lists (sev, sev-es, snp) the encrypted memory must not yield it, the plain KVM control's must. Each guest
// also runs its in-guest tests, and the guest's status must be 0.
func TestAmdSev_HostScan(t *testing.T) {
	onHost(t)
	kit, results, scripts := env(t, "AMDSEV_KIT"), env(t, "AMDSEV_RESULTS"), env(t, "AMDSEV_SCRIPTS")
	if os.Geteuid() != 0 {
		t.Fatal("the host scan reads another process's memory: run it as root")
	}
	type guestRun struct {
		mode      string
		wantFound bool
	}
	var runs []guestRun
	for _, m := range strings.Fields(env(t, "AMDSEV_GUESTS")) {
		if !slices.Contains(guestcfg.SEVModes(), m) {
			t.Fatalf("AMDSEV_GUESTS names %q; want words from %v", m, guestcfg.SEVModes())
		}
		// The host must not find the needle in an encrypted guest's memory.
		runs = append(runs, guestRun{m, false})
	}
	if len(runs) == 0 {
		t.Fatalf("AMDSEV_GUESTS lists no guest; want words from %v", guestcfg.SEVModes())
	}
	// The plain KVM control: here the scan must find the needle, or it proves
	// nothing about the encrypted guests.
	runs = append(runs, guestRun{guestcfg.ModePlain, true})
	for _, tc := range runs {
		t.Run(tc.mode, func(t *testing.T) {
			serial := filepath.Join(results, "guest-"+tc.mode+".log")
			pidfile := filepath.Join(t.TempDir(), "qemu.pid")
			guest := exec.Command("sh", filepath.Join(scripts, "guest.sh"), "--kit", kit, "--serial", serial, "--pidfile", pidfile, tc.mode) //nolint:gosec // the kit's own script
			guest.Stdout, guest.Stderr = os.Stdout, os.Stderr
			// The launcher starts timeout and QEMU as descendants: its own
			// process group lets the cleanup end all of them, on every path.
			guest.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := guest.Start(); err != nil {
				t.Fatal(err)
			}
			pgid := guest.Process.Pid
			t.Cleanup(func() {
				if err := terminateGroup(pgid, 30*time.Second); err != nil {
					t.Error(err)
				}
			})
			done := make(chan error, 1)
			go func() { done <- guest.Wait() }()
			needle, err := awaitNeedle(serial, done, 20*time.Minute)
			if err != nil {
				t.Fatalf("%s guest: %v", tc.mode, err)
			}
			pid, err := readPid(pidfile)
			if err != nil {
				t.Fatal(err)
			}
			scan := exec.Command("sh", filepath.Join(scripts, "host-scan.sh"), strconv.Itoa(pid), needle) //nolint:gosec // the kit's own script
			out, err := scan.CombinedOutput()
			t.Logf("host scan of the %s guest's QEMU (pid %d):\n%s", tc.mode, pid, out)
			// The verdict counts only if the needle was live for the
			// whole scan: a release before completion fails the run.
			if err := heldThroughScan(serial, needle); err != nil {
				t.Fatalf("%s guest: %v", tc.mode, err)
			}
			code := 0
			var ee *exec.ExitError
			switch {
			case errors.As(err, &ee):
				code = ee.ExitCode()
			case err != nil:
				t.Errorf("host scan: %v", err)
			}
			switch {
			case code == 2:
				t.Errorf("the host scan failed (status 2)")
			case tc.wantFound && code != 1:
				t.Errorf("the control failed: the plain KVM guest's needle was not found in its QEMU process, so the scan proves nothing")
			case !tc.wantFound && code != 0:
				t.Errorf("the %s guest's needle was found in its QEMU process: guest memory is readable from the host", tc.mode)
			}
			if err := <-done; err != nil {
				t.Errorf("%s guest exited: %v (its console: %s)", tc.mode, err, serial)
			}
		})
	}
}

// awaitNeedle polls the guest's console for the needle line until the guest
// exits or the timeout passes.
func awaitNeedle(serial string, done <-chan error, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n, ok := needleIn(serial); ok {
			return n, nil
		}
		select {
		case err := <-done:
			return "", fmt.Errorf("exited (%v) before printing its needle; console in %s", err, serial)
		case <-time.After(time.Second):
		}
	}
	return "", fmt.Errorf("no needle within %s; console in %s", timeout, serial)
}

func readPid(pidfile string) (int, error) {
	b, err := os.ReadFile(pidfile) //nolint:gosec // QEMU's pidfile
	if err != nil {
		return 0, fmt.Errorf("QEMU's pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("QEMU's pidfile holds %q", b)
	}
	return pid, nil
}
