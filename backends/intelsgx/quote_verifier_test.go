//go:build unix

package intelsgx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// writeVerifier writes a stand-in for the runner's DCAP verifier: a script
// that records its arguments and the quote it reads, then exits with code.
func writeVerifier(t *testing.T, code int) (path, argsFile, quoteFile string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "verify")
	argsFile = filepath.Join(dir, "args")
	quoteFile = filepath.Join(dir, "quote")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >'" + argsFile + "'\ncat >'" + quoteFile + "'\n" +
		"echo 'stand-in verdict' >&2\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, argsFile, quoteFile
}

// measuredQuote is the unit-test quote with REPORT_DATA bound to nonce and
// MRENCLAVE set to mr: header and body only, no signature.
func measuredQuote(t *testing.T, nonce []byte, mr []byte) []byte {
	t.Helper()
	rd, err := padNonce(nonce)
	if err != nil {
		t.Fatal(err)
	}
	q := quote(quoteVersion, keyTypeECDSAP256, rd)
	copy(q[quoteHeaderSize+mrEnclaveOffset:], mr)
	return q
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestQuoteVerifierFromEnv_RefusesWhatTheRunnerDidNotSupply(t *testing.T) {
	mr := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"nothing", nil, envSGXQuoteVerifier},
		{"no verifier", map[string]string{envSGXMRENCLAVE: mr}, envSGXQuoteVerifier},
		{"relative verifier", map[string]string{envSGXQuoteVerifier: "verify", envSGXMRENCLAVE: mr}, envSGXQuoteVerifier},
		{"no measurement", map[string]string{envSGXQuoteVerifier: "/bin/true"}, envSGXMRENCLAVE},
		{"short measurement", map[string]string{envSGXQuoteVerifier: "/bin/true", envSGXMRENCLAVE: "abcd"}, envSGXMRENCLAVE},
		{"not hex", map[string]string{envSGXQuoteVerifier: "/bin/true", envSGXMRENCLAVE: strings.Repeat("zz", 32)}, envSGXMRENCLAVE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := quoteVerifierFromEnv(envOf(tc.env))
			if v != nil || err == nil {
				t.Fatalf("quoteVerifierFromEnv = %v, %v; want a refusal", v, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestQuoteVerifier_PassesOnlyWhatTheRunnersVerifierAccepts(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	mr := bytes.Repeat([]byte{0xab}, 32)
	q := measuredQuote(t, nonce, mr)
	ev := enclave.Evidence{Format: EvidenceFormat, Data: q}

	accept, argsFile, quoteFile := writeVerifier(t, 0)
	v, err := quoteVerifierFromEnv(envOf(map[string]string{envSGXQuoteVerifier: accept, envSGXMRENCLAVE: hex.EncodeToString(mr)}))
	if err != nil {
		t.Fatalf("quoteVerifierFromEnv: %v", err)
	}
	if err := v.verify(nonce, ev); err != nil {
		t.Fatalf("verify with an accepting verifier = %v", err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	rd, _ := padNonce(nonce)
	if want := hex.EncodeToString(mr) + "\n" + hex.EncodeToString(rd) + "\n"; string(args) != want {
		t.Fatalf("verifier arguments = %q, want %q", args, want)
	}
	got, err := os.ReadFile(quoteFile)
	if err != nil || !bytes.Equal(got, q) {
		t.Fatalf("verifier read %d bytes (%v), want the quote", len(got), err)
	}

	// The unsigned quote passes every local check; only the verifier can
	// refuse it, and its refusal is the result.
	refuse, _, _ := writeVerifier(t, 1)
	v.command = refuse
	err = v.verify(nonce, ev)
	if !errors.Is(err, errQuoteNotVerified) || !strings.Contains(err.Error(), "stand-in verdict") {
		t.Fatalf("verify with a refusing verifier = %v, want errQuoteNotVerified carrying its output", err)
	}
}

func TestQuoteVerifier_LocalChecksRefuseBeforeTheVerifier(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	mr := bytes.Repeat([]byte{0xab}, 32)
	accept, argsFile, _ := writeVerifier(t, 0)
	v, err := quoteVerifierFromEnv(envOf(map[string]string{envSGXQuoteVerifier: accept, envSGXMRENCLAVE: hex.EncodeToString(mr)}))
	if err != nil {
		t.Fatalf("quoteVerifierFromEnv: %v", err)
	}

	debug := measuredQuote(t, nonce, mr)
	debug[quoteHeaderSize+attributesOffset] |= flagDebug
	other := bytes.Repeat([]byte{8}, 32)
	for _, tc := range []struct {
		name  string
		nonce []byte
		ev    enclave.Evidence
		want  error
	}{
		{"format", nonce, enclave.Evidence{Format: "other", Data: measuredQuote(t, nonce, mr)}, errQuoteNotVerified},
		{"nonce", other, enclave.Evidence{Format: EvidenceFormat, Data: measuredQuote(t, nonce, mr)}, ErrReportDataMismatch},
		{"debug", nonce, enclave.Evidence{Format: EvidenceFormat, Data: debug}, ErrDebugEnclave},
		{"measurement", nonce, enclave.Evidence{Format: EvidenceFormat, Data: measuredQuote(t, nonce, bytes.Repeat([]byte{1}, 32))}, errMeasurementMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.verify(tc.nonce, tc.ev); !errors.Is(err, tc.want) {
				t.Fatalf("verify = %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(argsFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the verifier ran on a quote the local checks refuse")
			}
		})
	}
}
