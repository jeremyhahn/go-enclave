package intelsgx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeProbeDir is fakeAttestation with a report whose ATTRIBUTES.FLAGS are
// flags, so probe reads every pseudo-file from the stand-in directory.
func fakeProbeDir(t *testing.T, flags uint64) string {
	t.Helper()
	dir := fakeAttestation(t)
	if err := os.WriteFile(filepath.Join(dir, "report"), report(flags), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func wantEnclaveOp(t *testing.T, err error, op string) {
	t.Helper()
	var ee *SGXEnclaveError
	if !errors.As(err, &ee) || ee.Op != op {
		t.Fatalf("err = %v, want an SGXEnclaveError with Op %q", err, op)
	}
	if !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("err = %v, want it to match ErrSGXUnavailable", err)
	}
}

func TestNewAndProbeInStandInEnclave(t *testing.T) {
	fakeProbeDir(t, 0)
	//nolint:staticcheck // New and Probe take a nil context as Background.
	b, err := New(nil)
	if err != nil {
		t.Fatalf("New = %v, want a Backend", err)
	}
	//nolint:staticcheck // as above.
	if err := b.Probe(nil); err != nil {
		t.Fatalf("Probe = %v, want nil", err)
	}
}

func TestProbeRefusesEachStandInFault(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		op    string
		is    error
	}{
		{"no attestation_type", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "attestation_type")); err != nil {
				t.Fatal(err)
			}
		}, "attestation_type", nil},
		{"epid attestation_type", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "attestation_type"), []byte("epid\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "attestation_type", nil},
		{"no report", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "report")); err != nil {
				t.Fatal(err)
			}
		}, opReport, nil},
		{"short report", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "report"), []byte{1}, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "report", nil},
		{"debug enclave", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "report"), report(flagDebug), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "debug", ErrDebugEnclave},
		{"malformed quote", func(*testing.T, string) {
			readQuote = func(string) ([]byte, error) { return []byte{3, 0, 2, 0}, nil }
		}, opQuote, nil},
		{"quote over other report data", func(*testing.T, string) {
			readQuote = func(string) ([]byte, error) {
				return quote(quoteVersion, keyTypeECDSAP256, make([]byte, reportDataSize)), nil
			}
		}, opQuote, ErrReportDataMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := fakeProbeDir(t, 0)
			tc.setup(t, dir)
			_, err := New(context.Background())
			wantEnclaveOp(t, err, tc.op)
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("New = %v, want it to match %v", err, tc.is)
			}
			var ate *AttestationTypeError
			if tc.name == "epid attestation_type" && (!errors.As(err, &ate) || ate.Value != "epid") {
				t.Fatalf("New = %v, want an AttestationTypeError with Value epid", err)
			}
		})
	}
}

func TestProbeQuoteStepFailureIsEnclaveError(t *testing.T) {
	fakeProbeDir(t, 0)
	writeReportData = func([]byte) error { return os.ErrPermission }
	_, err := New(context.Background())
	var ee *SGXEnclaveError
	if !errors.As(err, &ee) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("New = %v, want an SGXEnclaveError carrying the write failure", err)
	}
}

func TestAttestRefusesStandInAttestationType(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		dir := fakeAttestation(t)
		if err := os.Remove(filepath.Join(dir, "attestation_type")); err != nil {
			t.Fatal(err)
		}
		_, err := newTestBackend().Attest(context.Background(), []byte("nonce"))
		wantEnclaveOp(t, err, opAttestationType)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Attest = %v, want it to carry the missing file", err)
		}
	})
	t.Run("epid", func(t *testing.T) {
		dir := fakeAttestation(t)
		if err := os.WriteFile(filepath.Join(dir, "attestation_type"), []byte("epid"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := newTestBackend().Attest(context.Background(), []byte("nonce"))
		var ate *AttestationTypeError
		if !errors.As(err, &ate) || ate.Value != "epid" {
			t.Fatalf("Attest = %v, want an AttestationTypeError with Value epid", err)
		}
	})
}
