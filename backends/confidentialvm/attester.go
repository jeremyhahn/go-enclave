package confidentialvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-enclave"
)

// The evidence formats, the names the [enclave.Evidence] doc comment uses
// (design Q4). Data is the report or quote exactly as outblob returned it.
const (
	// FormatSEVSNPReport is the SEV-SNP firmware's 1184-byte
	// ATTESTATION_REPORT, signed by the chip's VCEK or a VLEK.
	FormatSEVSNPReport = "sev-snp-report"
	// FormatTDXQuote is a TD quote, signed by the Quoting Enclave under the
	// platform's PCK chain.
	FormatTDXQuote = "tdx-quote"
)

// The configfs-tsm provider values the kernel reports.
const (
	providerSEVGuest = "sev_guest"
	providerTDXGuest = "tdx_guest"
)

// reportDataSize is the size of inblob: SNP's REPORT_DATA and TDX's
// REPORTDATA are both 64 bytes.
const reportDataSize = 64

// ownWrites is the generation a report entry reaches with this call's one
// inblob write and no other writer.
const ownWrites = 1

// tsmReportRoot is where configfs-tsm report entries are made. Tests point it
// at a directory of their own.
var tsmReportRoot = "/sys/kernel/config/tsm/report"

// errEmptyOutblob is the Cause when outblob reads empty.
var errEmptyOutblob = errors.New("outblob is empty")

// Attester attests the confidential VM the program runs in. It implements
// [enclave.Attester] and nothing else of the seam: it is no backend and holds
// no material. Its methods are safe for concurrent use; concurrent calls never
// share a report entry.
type Attester struct {
	provider string
	format   string
}

var _ enclave.Attester = (*Attester)(nil)

// NewAttester returns the Attester of the SEV-SNP or TDX guest the program
// runs in. It makes one configfs-tsm report entry, reads its provider and
// removes it, so it succeeds only where a report can be requested. It
// refuses with a *TSMReportError matching [ErrTSMReportUnavailable] naming
// the failing step: no report interface, not permitted, a provider that is
// neither sev_guest nor tdx_guest. Off linux/amd64 it refuses with no Cause.
func NewAttester() (*Attester, error) {
	if !supported {
		return nil, &TSMReportError{}
	}
	provider, err := probeProvider(tsmReportRoot)
	if err != nil {
		return nil, err
	}
	format, err := formatFor(provider)
	if err != nil {
		return nil, err
	}
	return &Attester{provider: provider, format: format}, nil
}

// Format is the [enclave.Evidence] format the Attester returns:
// [FormatSEVSNPReport] or [FormatTDXQuote].
func (a *Attester) Format() string {
	if a == nil {
		return ""
	}
	return a.format
}

// Attest returns the guest's evidence over nonce. The nonce, 1 to 64 bytes,
// is written zero-padded to the 64-byte report data (design Q3): a nonce and
// the same nonce with trailing zeros give one report, so a relying party that
// cares sends 64 bytes. Each call makes its own report entry, checks that its
// provider is the one [NewAttester] saw and that generation counts only its
// own write, and removes the entry on every path.
//
// A bad nonce is [enclave.ErrInvalidNonce] before any request; an ended ctx
// is its error; a refused step is a *TSMReportError matching
// [ErrTSMReportUnavailable], with Cause [ErrTSMReportConflict] when another
// writer moved generation. A nil ctx is the background context.
func (a *Attester) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rd, err := reportData(nonce)
	if err != nil {
		return enclave.Evidence{}, err
	}
	if err := ctx.Err(); err != nil {
		return enclave.Evidence{}, err
	}
	if a == nil || a.format == "" {
		return enclave.Evidence{}, &TSMReportError{Op: "provider", Cause: errors.New("attester not made by NewAttester")}
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	// A configfs read cannot be interrupted; the request runs on its own and
	// removes its entry, while the caller returns ctx.Err() at once.
	go func() {
		data, err := request(tsmReportRoot, a.provider, &rd)
		done <- result{data: data, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return enclave.Evidence{}, r.err
		}
		return enclave.Evidence{Format: a.format, Data: r.data}, nil
	case <-ctx.Done():
		return enclave.Evidence{}, ctx.Err()
	}
}

// reportData lays nonce out as the 64-byte report data, zero-padded.
func reportData(nonce []byte) ([reportDataSize]byte, error) {
	var rd [reportDataSize]byte
	if len(nonce) == 0 || len(nonce) > reportDataSize {
		return rd, fmt.Errorf("%w: confidentialvm: nonce of %d bytes, want 1 to %d",
			enclave.ErrInvalidNonce, len(nonce), reportDataSize)
	}
	copy(rd[:], nonce)
	return rd, nil
}

// formatFor maps a provider to its evidence format.
func formatFor(provider string) (string, error) {
	switch provider {
	case providerSEVGuest:
		return FormatSEVSNPReport, nil
	case providerTDXGuest:
		return FormatTDXQuote, nil
	}
	return "", &TSMReportError{Op: "provider", Cause: fmt.Errorf("provider %q, want %q or %q",
		provider, providerSEVGuest, providerTDXGuest)}
}

// checkGeneration accepts a generation attribute that counts exactly
// [ownWrites]. Any other count is [ErrTSMReportConflict]; text that is not a
// count is the parse error.
func checkGeneration(raw []byte) error {
	got, err := strconv.ParseUint(strings.TrimSuffix(string(raw), "\n"), 10, 64)
	if err != nil {
		return &TSMReportError{Op: "generation", Cause: err}
	}
	if got != ownWrites {
		return &TSMReportError{Op: "generation", Cause: ErrTSMReportConflict}
	}
	return nil
}

// withEntry makes a report entry under root, runs fn on it and removes it on
// every path; a failed removal is the error when fn succeeded.
func withEntry(root string, fn func(dir string) error) (err error) {
	if _, serr := os.Stat(root); serr != nil {
		return &TSMReportError{Op: "stat", Cause: serr}
	}
	dir, err := os.MkdirTemp(root, "go-enclave-")
	if err != nil {
		return &TSMReportError{Op: "mkdir", Cause: err}
	}
	defer func() {
		if rerr := os.Remove(dir); rerr != nil && err == nil {
			err = &TSMReportError{Op: "rmdir", Cause: rerr}
		}
	}()
	return fn(dir)
}

// readProvider reads an entry's provider, without the kernel's newline.
func readProvider(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "provider")) //nolint:gosec // under the report entry this call made
	if err != nil {
		return "", &TSMReportError{Op: "provider", Cause: err}
	}
	return strings.TrimSuffix(string(raw), "\n"), nil
}

// probeProvider makes one entry under root and returns its provider.
func probeProvider(root string) (provider string, err error) {
	err = withEntry(root, func(dir string) error {
		provider, err = readProvider(dir)
		return err
	})
	return provider, err
}

// request makes one entry under root, checks its provider is want, writes
// rd to inblob and returns outblob once generation shows no other writer.
func request(root, want string, rd *[reportDataSize]byte) (out []byte, err error) {
	err = withEntry(root, func(dir string) error {
		got, err := readProvider(dir)
		if err != nil {
			return err
		}
		if got != want {
			return &TSMReportError{Op: "provider", Cause: fmt.Errorf("provider %q, want %q", got, want)}
		}
		if err := writeAttr(filepath.Join(dir, "inblob"), rd[:]); err != nil {
			return &TSMReportError{Op: "inblob", Cause: err}
		}
		data, err := os.ReadFile(filepath.Join(dir, "outblob")) //nolint:gosec // under the report entry this call made
		if err != nil {
			return &TSMReportError{Op: "outblob", Cause: err}
		}
		if len(data) == 0 {
			return &TSMReportError{Op: "outblob", Cause: errEmptyOutblob}
		}
		gen, err := os.ReadFile(filepath.Join(dir, "generation")) //nolint:gosec // under the report entry this call made
		if err != nil {
			return &TSMReportError{Op: "generation", Cause: err}
		}
		if err := checkGeneration(gen); err != nil {
			return err
		}
		out = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// writeAttr writes b to an existing configfs attribute in one write.
func writeAttr(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // under the report entry this call made
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
