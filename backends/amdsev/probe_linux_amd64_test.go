package amdsev

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// TestProbeRefusesOutsideAnSNPGuest runs the probe against this host's real
// configfs-tsm path. On a host that is not an SNP guest (a bare-metal EPYC
// host, or an SEV or SEV-ES guest) it must refuse with an [*SNPGuestError]
// naming the step that failed. The in-guest pass, where the probe returns nil
// and Attest returns a report, belongs to the later slice that runs inside
// an SNP guest; here a nil verdict skips rather than fails.
func TestProbeRefusesOutsideAnSNPGuest(t *testing.T) {
	err := probe(context.Background(), tsmReportRoot)
	if err == nil {
		t.Skip("this host is an SNP guest: the in-guest conformance run covers it")
	}
	var ge *SNPGuestError
	if !errors.As(err, &ge) || !errors.Is(err, ErrSNPGuestUnavailable) {
		t.Fatalf("probe = %v, want an *SNPGuestError matching ErrSNPGuestUnavailable", err)
	}
	switch ge.Op {
	case "mkdir":
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			t.Errorf("probe failed at mkdir with %v, want ENOENT, EACCES or EPERM", ge.Cause)
		}
	case "provider":
	default:
		t.Errorf("probe failed at %q, want mkdir or provider outside an SNP guest: %v", ge.Op, err)
	}
	if errors.Is(err, ErrSNPReport) {
		t.Errorf("probe = %v: \"not here\" must not match ErrSNPReport", err)
	}
	// The verdict is the same while the host is unchanged.
	if again := probe(context.Background(), tsmReportRoot); again == nil || again.Error() != err.Error() {
		t.Errorf("second probe = %v, want %v", again, err)
	}
}

// TestProbeMissingRoot names mkdir and wraps ENOENT when configfs-tsm is
// absent, as it is when configfs is not mounted.
func TestProbeMissingRoot(t *testing.T) {
	err := probe(context.Background(), filepath.Join(t.TempDir(), "missing", "tsm", "report"))
	var ge *SNPGuestError
	if !errors.As(err, &ge) || ge.Op != "mkdir" || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("probe = %v, want *SNPGuestError{Op: mkdir} wrapping ENOENT", err)
	}
}

func TestProbeEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx, tsmReportRoot); !errors.Is(err, context.Canceled) {
		t.Errorf("probe(canceled) = %v, want context.Canceled", err)
	}
}
