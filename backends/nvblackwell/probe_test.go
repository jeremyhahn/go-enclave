package nvblackwell

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// The buffers are laid out as the driver writes /proc/driver/nvidia/version
// (nv-procfs.c): an "NVRM version:" line naming the module and its version,
// then a "GCC version:" line. They test the parser, not a device.
const (
	openModuleVersion = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  570.86.15  Release Build  (builder@host)  Thu Jan 16 21:36:37 UTC 2025\n" +
		"GCC version:  gcc version 12.2.0 (Debian 12.2.0-14) \n"
	openModuleARMVersion = "NVRM version: NVIDIA UNIX Open Kernel Module for aarch64  575.51.03  Release Build  (builder@host)  Tue Apr 29 2025\n"
	proprietaryVersion   = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  570.86.15  Thu Jan 16 21:36:37 UTC 2025\n" +
		"GCC version:  gcc version 12.2.0 (Debian 12.2.0-14) \n"
)

func TestParseDriverVersion(t *testing.T) {
	cases := []struct {
		name    string
		buf     string
		open    bool
		version string
	}{
		{"open-x86_64", openModuleVersion, true, "570.86.15"},
		{"open-aarch64", openModuleARMVersion, true, "575.51.03"},
		{"proprietary", proprietaryVersion, false, "570.86.15"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDriverVersion([]byte(tc.buf))
			if err != nil {
				t.Fatalf("parseDriverVersion: %v", err)
			}
			if got.open != tc.open || got.version != tc.version {
				t.Errorf("parseDriverVersion = %+v, want open %v version %q", got, tc.open, tc.version)
			}
		})
	}
}

func TestParseDriverVersionRefusesMalformed(t *testing.T) {
	for name, buf := range map[string]string{
		"empty":      "",
		"no-nvrm":    "GCC version:  gcc version 12.2.0\n",
		"no-version": "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  Release Build\n",
		"truncated":  "NVRM version: ",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseDriverVersion([]byte(buf)); err == nil {
				t.Errorf("parseDriverVersion(%q) = %+v, want an error", buf, got)
			}
		})
	}
}

// checkDriverVersion turns the procfs entry's content into the probe's
// verdict: nil for the open kernel module, a DriverError naming the step
// otherwise.
func TestCheckDriverVersion(t *testing.T) {
	if err := checkDriverVersion([]byte(openModuleVersion)); err != nil {
		t.Errorf("checkDriverVersion(open module) = %v, want nil", err)
	}
	for buf, op := range map[string]string{
		proprietaryVersion: "open-kernel-module",
		"garbage\n":        "parse",
	} {
		err := checkDriverVersion([]byte(buf))
		var de *DriverError
		if !errors.As(err, &de) || de.Op != op || de.Path != driverVersionPath {
			t.Errorf("checkDriverVersion(%q) = %v, want a *DriverError at %s, step %q", buf, err, driverVersionPath, op)
		}
		if !errors.Is(err, ErrNVMLUnavailable) {
			t.Errorf("checkDriverVersion(%q) = %v, want it to match ErrNVMLUnavailable", buf, err)
		}
	}
}

// requireNoDriver skips on a host where the NVIDIA driver is loaded: the run
// on the hardware is the conformance slice's, not this refusal test's.
func requireNoDriver(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	if _, err := os.Stat(driverVersionPath); err == nil {
		t.Skipf("%s exists: the NVIDIA driver is loaded on this host", driverVersionPath)
	}
}

// On a host without the hardware Probe refuses for real: on linux the
// driver's procfs entry is missing, a DriverError at step "open" wrapping
// ENOENT; elsewhere a PlatformError.
func TestProbeRefusesWithoutTheDriver(t *testing.T) {
	requireNoDriver(t)
	for _, ctx := range []context.Context{context.Background(), nil} {
		err := Probe(ctx)
		if runtime.GOOS != "linux" {
			var pe *PlatformError
			if !errors.As(err, &pe) || pe.GOOS != runtime.GOOS || !errors.Is(err, ErrUnsupportedPlatform) {
				t.Fatalf("Probe = %v, want a *PlatformError for %s", err, runtime.GOOS)
			}
			continue
		}
		var de *DriverError
		if !errors.As(err, &de) || de.Op != "open" || de.Path != driverVersionPath {
			t.Fatalf("Probe = %v, want a *DriverError at %s, step \"open\"", err, driverVersionPath)
		}
		if !errors.Is(err, syscall.ENOENT) || !errors.Is(err, ErrNVMLUnavailable) {
			t.Errorf("Probe = %v, want it to match ENOENT and ErrNVMLUnavailable", err)
		}
	}
}

func TestProbeHonoursAnEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Probe(canceled ctx) = %v, want context.Canceled", err)
	}
}
