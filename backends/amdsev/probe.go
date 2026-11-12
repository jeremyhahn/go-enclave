package amdsev

import (
	"context"
	"crypto/rand"
	"errors"
)

// tsmReportRoot is where configfs-tsm reports live (CONFIG_TSM_REPORTS,
// Linux 6.7), with configfs mounted at /sys/kernel/config.
const tsmReportRoot = "/sys/kernel/config/tsm/report"

// providerSEVGuest is configfs-tsm's provider in an SEV-SNP guest.
const providerSEVGuest = "sev_guest"

// ctxErr is ctx.Err(), with a nil ctx that never ends.
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// guestError fails a step as "not here".
func guestError(op string, err error) error { return &SNPGuestError{Op: op, Cause: err} }

// reportError fails a step as "here, and this request failed".
func reportError(op string, err error) error { return &SNPReportError{Op: op, Cause: err} }

// probe requests one report under root over a fresh random nonce and checks
// that the report is [ReportSize] bytes with that nonce in REPORT_DATA. It
// verifies nothing else, and removes its configfs-tsm entry. Every failure
// is an [*SNPGuestError] naming the step, ctx.Err() when ctx ended first, or
// [ErrSNPGuestUnavailable] off Linux on amd64.
func probe(ctx context.Context, root string) error {
	_, err := probeReport(ctx, root)
	return err
}

// probeReport is probe returning the report it checked, so New can read
// the guest's policy from it.
func probeReport(ctx context.Context, root string) (Report, error) {
	if err := ctxErr(ctx); err != nil {
		return Report{}, err
	}
	nonce := make([]byte, ReportDataSize)
	_, _ = rand.Read(nonce) // crypto/rand.Read never fails
	out, err := requestReport(ctx, root, nonce, guestError)
	if err != nil {
		return Report{}, err
	}
	r, err := ParseReport(out)
	if err != nil {
		var re *SNPReportError
		if errors.As(err, &re) {
			return Report{}, guestError(re.Op, re.Cause)
		}
		return Report{}, guestError("outblob", err)
	}
	if !r.HasReportData(nonce) {
		return Report{}, guestError("report-data", ErrReportDataMismatch)
	}
	return r, nil
}
