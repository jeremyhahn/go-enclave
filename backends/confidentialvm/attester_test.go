package confidentialvm

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// useRoot points tsmReportRoot at root for the test and restores it.
func useRoot(t *testing.T, root string) {
	t.Helper()
	old := tsmReportRoot
	tsmReportRoot = root
	t.Cleanup(func() { tsmReportRoot = old })
}

// wantStep fails unless err is a *TSMReportError for op that matches
// ErrTSMReportUnavailable.
func wantStep(t *testing.T, err error, op string) *TSMReportError {
	t.Helper()
	var te *TSMReportError
	if !errors.As(err, &te) || te.Op != op || !errors.Is(err, ErrTSMReportUnavailable) {
		t.Fatalf("err = %v, want a *TSMReportError for %q matching ErrTSMReportUnavailable", err, op)
	}
	return te
}

func TestReportData_NonceIsZeroPaddedTo64Bytes(t *testing.T) {
	for _, n := range [][]byte{nil, {}, make([]byte, reportDataSize+1)} {
		if _, err := reportData(n); !errors.Is(err, enclave.ErrInvalidNonce) {
			t.Fatalf("reportData(%d bytes) = %v, want ErrInvalidNonce", len(n), err)
		}
	}
	rd, err := reportData([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, reportDataSize)
	copy(want, []byte{1, 2, 3})
	if !bytes.Equal(rd[:], want) {
		t.Fatalf("reportData = %x, want %x", rd, want)
	}
	full := bytes.Repeat([]byte{0xa5}, reportDataSize)
	if rd, err = reportData(full); err != nil || !bytes.Equal(rd[:], full) {
		t.Fatalf("reportData(64 bytes) = %x, %v", rd, err)
	}
}

func TestFormatFor_MapsEachProviderAndRefusesAnother(t *testing.T) {
	for provider, want := range map[string]string{"sev_guest": FormatSEVSNPReport, "tdx_guest": FormatTDXQuote} {
		if got, err := formatFor(provider); err != nil || got != want {
			t.Fatalf("formatFor(%q) = %q, %v, want %q", provider, got, err, want)
		}
	}
	for _, provider := range []string{"", "sev", "tdx_guest\n", "arm_cca_guest"} {
		_, err := formatFor(provider)
		wantStep(t, err, "provider")
	}
}

func TestCheckGeneration_CountsOnlyThisCallsWrite(t *testing.T) {
	if err := checkGeneration([]byte("1\n")); err != nil {
		t.Fatalf("generation 1 = %v, want nil", err)
	}
	for _, raw := range []string{"0", "2\n", "7"} {
		err := checkGeneration([]byte(raw))
		wantStep(t, err, "generation")
		if !errors.Is(err, ErrTSMReportConflict) {
			t.Fatalf("generation %q = %v, want ErrTSMReportConflict", raw, err)
		}
	}
	err := checkGeneration([]byte("one"))
	wantStep(t, err, "generation")
	if errors.Is(err, ErrTSMReportConflict) {
		t.Fatalf("unparsable generation = %v, want the parse error, not a conflict", err)
	}
}

func TestNewAttester_RefusesWithoutTheReportInterface(t *testing.T) {
	useRoot(t, filepath.Join(t.TempDir(), "absent"))
	a, err := NewAttester()
	if a != nil {
		t.Fatalf("NewAttester returned %v with %v", a, err)
	}
	if !supported {
		wantStep(t, err, "")
		return
	}
	te := wantStep(t, err, "stat")
	if !errors.Is(te, fs.ErrNotExist) {
		t.Fatalf("Cause = %v, want fs.ErrNotExist", te.Cause)
	}
}

func TestNewAttester_RefusesAnEntryWithNoProviderAndRemovesIt(t *testing.T) {
	if !supported {
		t.Fatal("this test runs on linux/amd64 only; the Makefile runs the module there")
	}
	root := t.TempDir()
	useRoot(t, root)
	_, err := NewAttester()
	wantStep(t, err, "provider")
	left, rerr := os.ReadDir(root)
	if rerr != nil || len(left) != 0 {
		t.Fatalf("entries left under the root: %v, %v", left, rerr)
	}
}

func TestWithEntry_AFailedRemovalIsTheError(t *testing.T) {
	root := t.TempDir()
	err := withEntry(root, func(dir string) error {
		return os.WriteFile(filepath.Join(dir, "stray"), nil, 0o600)
	})
	wantStep(t, err, "rmdir")
	// A failure of fn wins over a failed removal.
	inner := &TSMReportError{Op: "outblob", Cause: errEmptyOutblob}
	err = withEntry(root, func(dir string) error {
		_ = os.WriteFile(filepath.Join(dir, "stray"), nil, 0o600)
		return inner
	})
	if err != inner {
		t.Fatalf("err = %v, want fn's error", err)
	}
	err = withEntry(filepath.Join(root, "nope"), func(string) error { return nil })
	wantStep(t, err, "stat")
}

func TestWithEntry_MkdirRefusedIsNamed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := withEntry(root, func(string) error { return nil })
	wantStep(t, err, "mkdir")
}

func TestRequest_RefusesAnEntryWithNoProvider(t *testing.T) {
	rd := [reportDataSize]byte{1}
	out, err := request(t.TempDir(), providerSEVGuest, &rd)
	if out != nil {
		t.Fatalf("request returned %x", out)
	}
	wantStep(t, err, "provider")
}

func TestWriteAttr_RefusesAMissingAttribute(t *testing.T) {
	dir := t.TempDir()
	if err := writeAttr(filepath.Join(dir, "inblob"), []byte{1}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("writeAttr on a missing attribute = %v, want fs.ErrNotExist", err)
	}
	path := filepath.Join(dir, "attr")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAttr(path, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "abc" {
		t.Fatalf("attr = %q, want abc", got)
	}
}

func TestAttest_ChecksTheNonceAndContextBeforeAnyRequest(t *testing.T) {
	useRoot(t, filepath.Join(t.TempDir(), "absent"))
	a := &Attester{provider: providerTDXGuest, format: FormatTDXQuote}
	if _, err := a.Attest(context.Background(), nil); !errors.Is(err, enclave.ErrInvalidNonce) {
		t.Fatalf("Attest(nil nonce) = %v, want ErrInvalidNonce", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Attest(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest(canceled) = %v, want context.Canceled", err)
	}
	//nolint:staticcheck // a nil ctx is documented as the background context
	ev, err := a.Attest(nil, []byte{1})
	wantStep(t, err, "stat")
	if ev.Format != "" || ev.Data != nil {
		t.Fatalf("Attest returned evidence %+v with %v", ev, err)
	}
}

func TestAttest_RefusesAnAttesterNewAttesterDidNotMake(t *testing.T) {
	for _, a := range []*Attester{nil, {}} {
		_, err := a.Attest(context.Background(), []byte{1})
		wantStep(t, err, "provider")
		if a.Format() != "" {
			t.Fatalf("Format() = %q, want empty", a.Format())
		}
	}
	if got := (&Attester{format: FormatSEVSNPReport}).Format(); got != FormatSEVSNPReport {
		t.Fatalf("Format() = %q", got)
	}
}

func TestAttest_RefusesAnEntryWithNoProvider(t *testing.T) {
	useRoot(t, t.TempDir())
	a := &Attester{provider: providerSEVGuest, format: FormatSEVSNPReport}
	_, err := a.Attest(context.Background(), []byte("nonce"))
	wantStep(t, err, "provider")
}

func TestAttester_IsAnAttesterAndNoBackend(t *testing.T) {
	var v any = &Attester{}
	if _, ok := v.(enclave.Attester); !ok {
		t.Fatal("*Attester is not an enclave.Attester")
	}
	if _, ok := v.(enclave.Backend); ok {
		t.Fatal("*Attester is an enclave.Backend; a confidential VM is not a backend")
	}
}
