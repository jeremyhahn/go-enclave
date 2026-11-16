package backendtest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// TestBackendConformance_ResidueReportsSkippedGuardPages pins that the
// residue note carries the kernel guard pages each sweep skipped, so a run
// shows how much of the process the sweep could not read and why that was
// excused.
func TestBackendConformance_ResidueReportsSkippedGuardPages(t *testing.T) {
	if !memscan.Supported {
		t.Fatalf("the residue sweep needs Linux: %s", memscan.UnsupportedReason)
	}
	defer func(orig func([]byte, uintptr) (memscan.Result, error)) { sweepProcess = orig }(sweepProcess)
	sweepProcess = func(needle []byte, home uintptr) (memscan.Result, error) {
		r, err := memscan.Sweep(needle, home)
		r.GuardPages = 3
		return r, err
	}

	var notes []string
	cfg := residueConfig(faults{})
	cfg.Logf = func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }
	if err := runFake(context.Background(), cfg); err != nil {
		t.Fatalf("TestBackend = %v", err)
	}
	const want = "skipped 3 kernel guard page(s) while the handle was alive and 3 after"
	for _, n := range notes {
		if strings.Contains(n, "residue sweep ran") && strings.Contains(n, want) {
			return
		}
	}
	t.Fatalf("no residue note reports the skipped guard pages (%q): %q", want, notes)
}
