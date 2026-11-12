package nvblackwell

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Every typed error matches its own sentinel and no other, carries the
// sentinel's text and its fields, and unwraps to its cause where it has one.
func TestErrorsMatchTheirSentinel(t *testing.T) {
	enoent := os.NewSyscallError("open", syscall.ENOENT)
	cases := []struct {
		name     string
		err      error
		sentinel error
		want     []string
		cause    error
	}{
		{"platform", &PlatformError{GOOS: "darwin"}, ErrUnsupportedPlatform, []string{`"darwin"`}, nil},
		{"driver", &DriverError{Path: driverVersionPath, Op: "open", Cause: enoent}, ErrNVMLUnavailable,
			[]string{`"` + driverVersionPath + `"`, ": open: ", "no such file"}, enoent},
		{"driver-no-cause", &DriverError{Path: driverVersionPath, Op: "open-kernel-module"}, ErrNVMLUnavailable,
			[]string{": open-kernel-module"}, nil},
		{"nvml", &NVMLError{Call: "nvmlInit_v2", Return: 9}, ErrNVMLUnavailable, []string{"nvmlInit_v2", "returned 9"}, nil},
		{"nvml-cause", &NVMLError{Call: "load libnvidia-ml.so.1", Cause: enoent}, ErrNVMLUnavailable,
			[]string{"load libnvidia-ml.so.1", "no such file"}, enoent},
		{"cc", &ConfComputeError{Device: 0, Setting: "cc-mode", Value: "off"}, ErrConfComputeUnavailable,
			[]string{"gpu 0", "cc-mode", `"off"`}, nil},
		{"cc-system", &ConfComputeError{Device: SystemWide, Setting: "device-count", Value: "0"}, ErrConfComputeUnavailable,
			[]string{"system", "device-count", `"0"`}, nil},
		{"arch", &GPUArchitectureError{Device: 1, Architecture: 9}, ErrUnsupportedGPU, []string{"gpu 1", "architecture 9"}, nil},
		{"attest", &GPUAttestationError{Device: 2, Cause: enoent}, ErrGPUAttestation, []string{"gpu 2", "no such file"}, enoent},
	}
	sentinels := []error{ErrUnsupportedPlatform, ErrNVMLUnavailable, ErrConfComputeUnavailable, ErrUnsupportedGPU, ErrGPUAttestation}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, tc.sentinel.Error()) {
				t.Errorf("Error() = %q, want the prefix %q", msg, tc.sentinel.Error())
			}
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("Error() = %q, want it to contain %q", msg, w)
				}
			}
			for _, s := range sentinels {
				if got, want := errors.Is(tc.err, s), s == tc.sentinel; got != want {
					t.Errorf("errors.Is(%T, %v) = %v, want %v", tc.err, s, got, want)
				}
			}
			if got := errors.Unwrap(tc.err); got != tc.cause {
				t.Errorf("Unwrap() = %v, want %v", got, tc.cause)
			}
			if tc.cause != nil && !errors.Is(tc.err, syscall.ENOENT) {
				t.Errorf("errors.Is(%T, ENOENT) = false, want the errno to match through the cause", tc.err)
			}
		})
	}
}
