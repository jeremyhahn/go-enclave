// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// These tests are the suite's own deliberate-leak controls, and they are the
// reason anything else here is worth reading.
//
// A conformance suite that cannot fail is worse than none, because it
// certifies: every implementer who runs it comes away believing a property was
// measured. So every property this package claims to check has a planted
// provider here that violates exactly that property and nothing else, and the
// test asserts the suite goes RED and NAMES the right property. A check whose
// planted violator still passes is a check that does not exist.

// ---------------------------------------------------------------------------
// The conforming baseline
// ---------------------------------------------------------------------------

// TestConformingProvider is the positive control for the whole suite: the one
// provider go-enclave ships must pass every property, in both modes. If this
// goes red the suite is over-asserting — demanding something the seam does not
// actually require — and every implementer would be chasing a defect in their
// own code that is really in this package.
func TestConformingProvider(t *testing.T) {
	err := TestProvider(Config{
		New:   func() (any, error) { return enclave.NewSoftwareProvider(), nil },
		Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
		Logf:  t.Logf,
	})
	if err != nil {
		t.Fatalf("the software provider does not pass its own conformance suite:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// wantFail runs the suite and requires it to fail, naming want. The
// property-name match is what separates "the suite failed" from "the suite
// failed FOR THE REASON THIS TEST PLANTED" — without it a planted violator that
// merely broke the round trip would be scored as a caught leak.
func wantFail(t *testing.T, cfg Config, want string) {
	t.Helper()
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	err := TestProvider(cfg)
	if err == nil {
		t.Fatalf("the suite PASSED a provider that deliberately violates %q; the check does not exist", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("the suite failed, but not on %q:\n%v", want, err)
	}
	t.Logf("caught, as required:\n%v", err)
}

// perOp is the Config for a KeyProtector-only violator.
func perOp(new func() (any, error)) Config {
	return Config{New: new, Modes: []enclave.Mode{enclave.ModePerOperation}}
}

// rootOnly is the Config for a RootUnsealer-only violator.
func rootOnly(new func() (any, error)) Config {
	return Config{New: new, Modes: []enclave.Mode{enclave.ModeRootKey}}
}

// software is a fresh conforming provider, which most violators wrap so that
// the ONLY thing wrong with them is the property under test.
func software() *enclave.SoftwareProvider { return enclave.NewSoftwareProvider() }

// ---------------------------------------------------------------------------
// THE HEADLINE CONTROL: a provider that retains a copy on purpose
// ---------------------------------------------------------------------------

// retainingProtector conforms in every visible way and keeps a copy of every
// key it recovers. This is the exact defect the seam cannot see and the issue
// was filed for: the destination is honored, the signature is honored, and
// the plaintext lives in this process forever.
//
// Nothing but the residue sweep can catch it — the spy watches the caller's own
// slices, and this provider never touches them after it returns.
type retainingProtector struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	kept  [][]byte
}

func (p *retainingProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }

func (p *retainingProtector) Unprotect(blob, key []byte) error {
	if err := p.inner.Unprotect(blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.kept = append(p.kept, bytes.Clone(key))
	return nil
}

// TestSuiteCatchesAProviderThatRetainsACopy is the deliberate-leak control the
// whole design is ranked around.
func TestSuiteCatchesAProviderThatRetainsACopy(t *testing.T) {
	if !sweepSupported {
		t.Skipf("the residue sweep is the only instrument for retention by copy and it needs Linux: %s",
			sweepUnsupportedReason)
	}
	kept := &retainingProtector{inner: software()}
	wantFail(t, perOp(func() (any, error) { return kept, nil }),
		"no copy of the key is findable in the process after Unprotect returns")
	// Hold the retained copies past the sweep so the failure cannot be
	// explained away as garbage the collector had not yet reached.
	if len(kept.kept) == 0 {
		t.Fatal("the planted provider retained nothing; the control proved nothing")
	}
}

// TestResidueSweepSkipIsRecordedNotSilent pins the escape hatch's cost: a
// skipped sweep is reported through Logf in the same words every time, so a
// green run cannot hide that its only retention-by-copy instrument did not run.
func TestResidueSweepSkipIsRecordedNotSilent(t *testing.T) {
	var log strings.Builder
	cfg := perOp(func() (any, error) { return &retainingProtector{inner: software()}, nil })
	cfg.SkipResidueSweep = "the KMS response body is owned by net/http"
	cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }

	if err := TestProvider(cfg); err != nil {
		t.Fatalf("with the sweep skipped the retaining provider should pass everything else: %v", err)
	}
	if !strings.Contains(log.String(), "residue sweep SKIPPED") ||
		!strings.Contains(log.String(), "the KMS response body is owned by net/http") {
		t.Errorf("the skip was not reported with its recorded reason; a reader of this green run would not "+
			"know retention by copy went unmeasured. Log was:\n%s", log.String())
	}
}

// ---------------------------------------------------------------------------
// Retention by reference — what the spy is for
// ---------------------------------------------------------------------------

// aliasingProtector files the caller's SLICE rather than its contents: the
// single-character defect (`= key` instead of `= bytes.Clone(key)`) that a
// round-trip test passes and a wipe exposes.
type aliasingProtector struct {
	mu   sync.Mutex
	n    int
	keys map[string][]byte
}

func newAliasingProtector() *aliasingProtector {
	return &aliasingProtector{keys: make(map[string][]byte)}
}

func (p *aliasingProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "aliasing-blob-%08d", p.n)
	p.keys[string(blob)] = key // THE DEFECT: the caller's slice, not a copy.
	return blob, nil
}

func (p *aliasingProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.keys[string(blob)]
	if !ok || len(k) != len(key) {
		return enclave.ErrSealedAuthentication
	}
	copy(key, k)
	return nil
}

func TestSuiteCatchesProtectRetainingTheCallersSlice(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newAliasingProtector(), nil }),
		"Protect does not retain the caller's key slice")
}

// writeBackProtector keeps the last destination it was handed and writes into
// it again on the next call — the "reuse the buffer" optimisation, aimed at
// pages the caller has already wiped and released.
type writeBackProtector struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	last  []byte
	val   []byte
}

func (p *writeBackProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }

func (p *writeBackProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	last, val := p.last, p.val
	p.mu.Unlock()
	if last != nil && len(last) == len(val) {
		copy(last, val) // THE DEFECT: a retained destination, written again.
	}
	if err := p.inner.Unprotect(blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last, p.val = key, bytes.Clone(key)
	return nil
}

func TestSuiteCatchesAWriteBackIntoAWipedDestination(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &writeBackProtector{inner: software()}, nil }),
		"Unprotect does not write into a destination the caller has finished with")
}

// wipingProtector keeps the last destination and WIPES it on the next call —
// the mirror defect, invisible to a zero-stays-zero check, and a fail-open in
// the caller, which is left holding zeros where its key was.
type wipingProtector struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	last  []byte
}

func (p *wipingProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }

func (p *wipingProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	last := p.last
	p.mu.Unlock()
	if last != nil {
		enclave.Wipe(last) // THE DEFECT: a retained destination, wiped later.
	}
	if err := p.inner.Unprotect(blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = key
	return nil
}

func TestSuiteCatchesALaterCallWipingAnEarlierDestination(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &wipingProtector{inner: software()}, nil }),
		"a later provider call does not disturb an earlier destination")
}

// ---------------------------------------------------------------------------
// The controls that keep the spy from reading a false green
// ---------------------------------------------------------------------------

// silentProtector returns nil from Unprotect and writes nothing. Its
// destination is zero after the call, unchanged by later calls, and holds no
// plaintext anywhere — it passes every retention assertion for the worst
// possible reason. Only the at-return-time control separates it from a
// conforming provider, which is exactly why that control is not optional.
type silentProtector struct{ inner *enclave.SoftwareProvider }

func (p *silentProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }
func (p *silentProtector) Unprotect([]byte, []byte) error     { return nil }

func TestSuiteCatchesADestinationThatIsNeverPopulated(t *testing.T) {
	cfg := perOp(func() (any, error) { return &silentProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose Unprotect writes nothing; every retention assertion was vacuous")
	}
	// The point of this test is the CONTROL specifically, not merely that
	// something went red: both spies must report that their setup did not hold
	// rather than scoring a zeroed destination as a pass.
	got := err.Error()
	for _, want := range []string{
		"Unprotect does not write into a destination the caller has finished with: the control did not hold",
		"a later provider call does not disturb an earlier destination: the control did not hold",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the spy did not report its control failing (%q); a zero reading was being taken at "+
				"face value.\nGot:\n%v", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Authenticity
// ---------------------------------------------------------------------------

// unauthenticatedProtector authenticates a PREFIX of the blob and ignores the
// rest — confidentiality without integrity, the shape the KeyProtector contract
// disqualifies by name. No cryptography is hand-rolled here: the "device" is a
// map, and the defect is that the lookup key is shorter than the blob.
type unauthenticatedProtector struct {
	mu   sync.Mutex
	n    int
	keys map[string][]byte
}

const unauthPrefix = 21 // len("unauthenticated-00000001")'s stable head

func newUnauthenticatedProtector() *unauthenticatedProtector {
	return &unauthenticatedProtector{keys: make(map[string][]byte)}
}

func (p *unauthenticatedProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "unauthenticated-%08d-ignored-tail", p.n)
	p.keys[string(blob[:unauthPrefix])] = bytes.Clone(key)
	return blob, nil
}

func (p *unauthenticatedProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(blob) < unauthPrefix {
		return enclave.ErrSealedAuthentication
	}
	k, ok := p.keys[string(blob[:unauthPrefix])] // THE DEFECT: the tail is unauthenticated.
	if !ok || len(k) != len(key) {
		return enclave.ErrSealedAuthentication
	}
	copy(key, k)
	return nil
}

// forgeableProtector is the disqualifying example the KeyProtector contract
// names, reduced to its essence: the blob carries an unauthenticated tail, and
// an attacker who can reach the stored blob chooses what it opens to. It is the
// bare-RSA-OAEP shape — wrapping under a PUBLIC key, so anyone holding that key
// forges a value that opens successfully to material of their choosing.
//
// It is a SEPARATE violator from unauthenticatedProtector because the two are
// caught by different assertions, and a mutant proved it: an accepted forgery
// that hands back the REAL key is also caught by the plaintext-in-destination
// check, so disabling the "Unprotect ACCEPTED this blob" arm did not go red
// until a violator existed whose forgery yields something OTHER than the key.
// No cryptography is written here: the tail is copied out verbatim.
type forgeableProtector struct {
	mu   sync.Mutex
	n    int
	keys map[string][]byte
}

// forgeablePrefix is len("forgeable-00000001|").
const forgeablePrefix = 19

func newForgeableProtector() *forgeableProtector {
	return &forgeableProtector{keys: make(map[string][]byte)}
}

func (p *forgeableProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "forgeable-%08d|", p.n)
	blob = append(blob, make([]byte, len(key))...)
	p.keys[string(blob[:forgeablePrefix])] = bytes.Clone(key)
	return blob, nil
}

func (p *forgeableProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(blob) != forgeablePrefix+len(key) {
		return enclave.ErrSealedAuthentication
	}
	k, ok := p.keys[string(blob[:forgeablePrefix])]
	if !ok || len(k) != len(key) {
		return enclave.ErrSealedAuthentication
	}
	tail := blob[forgeablePrefix:]
	if allZero(tail) {
		copy(key, k)
		return nil
	}
	// THE DEFECT: the tail is unauthenticated and it CHOOSES the material.
	copy(key, tail)
	return nil
}

func TestSuiteCatchesAForgeryOpeningToAttackerChosenMaterial(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newForgeableProtector(), nil }),
		"Unprotect ACCEPTED")
}

func TestSuiteCatchesAnUnauthenticatedProvider(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newUnauthenticatedProtector(), nil }),
		"a blob this provider did not produce is refused")
}

// wrongErrorProtector refuses forgeries but reports them as infrastructure
// faults, which sends an operator hunting a device problem while an attacker is
// feeding it blobs.
type wrongErrorProtector struct{ inner *enclave.SoftwareProvider }

func (p *wrongErrorProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }

func (p *wrongErrorProtector) Unprotect(blob, key []byte) error {
	if err := p.inner.Unprotect(blob, key); err != nil {
		return errors.New("device temporarily unavailable") // THE DEFECT.
	}
	return nil
}

func TestSuiteCatchesAForgeryReportedAsADeviceFault(t *testing.T) {
	cfg := perOp(func() (any, error) { return &wrongErrorProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider that reports forgeries as device faults")
	}
	// Bound to the TAMPER property by name. A bare search for the phrase is
	// satisfied by the wrong-length check, which emits the same sentence — so
	// the tamper-path assertion could be deleted and this test would stay green,
	// which a mutant demonstrated.
	if !strings.Contains(err.Error(), "a blob this provider did not produce is refused: Unprotect refused") ||
		!strings.Contains(err.Error(), "want an error matching ErrSealedAuthentication") {
		t.Fatalf("the suite failed, but not on the error KIND of a refused FORGERY:\n%v", err)
	}
}

// decryptBeforeAuthenticateProtector leaves the recovered key in the caller's
// destination and then reports failure — the caller is told nothing happened
// while its buffer holds the plaintext.
type decryptBeforeAuthenticateProtector struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	last  []byte
}

func (p *decryptBeforeAuthenticateProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	p.last = bytes.Clone(key)
	p.mu.Unlock()
	return p.inner.Protect(key)
}

func (p *decryptBeforeAuthenticateProtector) Unprotect(blob, key []byte) error {
	err := p.inner.Unprotect(blob, key)
	if err != nil {
		p.mu.Lock()
		last := p.last
		p.mu.Unlock()
		if len(last) == len(key) {
			copy(key, last) // THE DEFECT: plaintext into a destination whose owner was told it failed.
		}
	}
	return err
}

func TestSuiteCatchesPlaintextLeftInARefusedDestination(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &decryptBeforeAuthenticateProtector{inner: software()}, nil }),
		"left plaintext key material in the destination")
}

// blobIsTheKeyProtector "protects" by handing the key back as the blob.
type blobIsTheKeyProtector struct{}

func (blobIsTheKeyProtector) Protect(key []byte) ([]byte, error) { return bytes.Clone(key), nil }
func (blobIsTheKeyProtector) Unprotect(blob, key []byte) error {
	if len(blob) != len(key) {
		return enclave.ErrSealedAuthentication
	}
	copy(key, blob)
	return nil
}

func TestSuiteCatchesABlobThatIsThePlaintext(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return blobIsTheKeyProtector{}, nil }),
		"the blob returned by Protect contains the plaintext key")
}

// mutatingProtector overwrites the caller's key slice in place, which aliases
// locked pages the caller still owns.
type mutatingProtector struct{ inner *enclave.SoftwareProvider }

func (p *mutatingProtector) Protect(key []byte) ([]byte, error) {
	blob, err := p.inner.Protect(key)
	if err == nil {
		key[0] ^= 0xFF // THE DEFECT.
	}
	return blob, err
}
func (p *mutatingProtector) Unprotect(blob, key []byte) error { return p.inner.Unprotect(blob, key) }

func TestSuiteCatchesProtectMutatingTheCallersKey(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &mutatingProtector{inner: software()}, nil }),
		"Protect MUTATED the caller's key slice")
}

// looseLengthProtector treats the destination length as a truncation request
// rather than a claim about the plaintext.
type looseLengthProtector struct {
	mu   sync.Mutex
	n    int
	keys map[string][]byte
}

func newLooseLengthProtector() *looseLengthProtector {
	return &looseLengthProtector{keys: make(map[string][]byte)}
}

func (p *looseLengthProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "loose-length-blob-%08d", p.n)
	p.keys[string(blob)] = bytes.Clone(key)
	return blob, nil
}

func (p *looseLengthProtector) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.keys[string(blob)]
	if !ok {
		return enclave.ErrSealedAuthentication
	}
	copy(key, k) // THE DEFECT: a short destination is silently truncated into.
	return nil
}

// silentLengthProtector treats a wrong-length destination as nothing to do and
// reports success, so its caller is handed a buffer it believes holds a key.
//
// Like forgeableProtector, this exists because a mutant showed the assertion it
// targets had no dedicated killer: looseLengthProtector truncates the REAL key
// into the short destination, so it is also caught by the
// plaintext-in-destination check, and the "Unprotect accepted a wrong-length
// destination" arm could be deleted unnoticed.
type silentLengthProtector struct{ inner *enclave.SoftwareProvider }

func (p *silentLengthProtector) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }

func (p *silentLengthProtector) Unprotect(blob, key []byte) error {
	if len(key) != enclave.RootKeyBytes {
		return nil // THE DEFECT: a length mismatch reported as success.
	}
	return p.inner.Unprotect(blob, key)
}

// shortDestinationLeakProtector refuses a wrong-length destination — correctly,
// with ErrSealedAuthentication — after it has already written the key into it.
// The caller is told the call failed and its buffer holds the material.
//
// It is the length path's counterpart to decryptBeforeAuthenticateProtector,
// and it exists so the plaintext-in-destination check on THAT path has a killer
// of its own rather than riding on the accepted-length arm beside it.
type shortDestinationLeakProtector struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	last  []byte
}

func (p *shortDestinationLeakProtector) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	p.last = bytes.Clone(key)
	p.mu.Unlock()
	return p.inner.Protect(key)
}

func (p *shortDestinationLeakProtector) Unprotect(blob, key []byte) error {
	if len(key) != enclave.RootKeyBytes {
		p.mu.Lock()
		last := p.last
		p.mu.Unlock()
		copy(key, last) // THE DEFECT: written before the length is checked.
		return enclave.ErrSealedAuthentication
	}
	return p.inner.Unprotect(blob, key)
}

func TestSuiteCatchesPlaintextLeftInAShortDestination(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &shortDestinationLeakProtector{inner: software()}, nil }),
		"left plaintext key material in it")
}

func TestSuiteCatchesAWrongLengthDestinationReportedAsSuccess(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &silentLengthProtector{inner: software()}, nil }),
		"Unprotect accepted a")
}

func TestSuiteCatchesASilentlyTruncatingDestination(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newLooseLengthProtector(), nil }),
		"a destination of the wrong length is an authentication failure")
}

// ---------------------------------------------------------------------------
// Mode / interface pairing
// ---------------------------------------------------------------------------

// stubRootProvider is a correct KeyProtector carrying a placeholder UnsealRoot,
// added by someone who thought the seam required both halves. A Sealer cannot
// tell the placeholder from an unseal, so ModeRootKey silently seals the whole
// process under a constant.
type stubRootProvider struct{ inner *enclave.SoftwareProvider }

func (p *stubRootProvider) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }
func (p *stubRootProvider) Unprotect(blob, key []byte) error   { return p.inner.Unprotect(blob, key) }
func (p *stubRootProvider) UnsealRoot(dst []byte) error        { clear(dst); return nil }

func TestSuiteCatchesAnUnclaimedModeTheProviderStillSatisfies(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &stubRootProvider{inner: software()}, nil }),
		"mode/interface pairing")
}

// keyProtectorOnly claims a mode its method set cannot serve.
type keyProtectorOnly struct{ inner *enclave.SoftwareProvider }

func (p *keyProtectorOnly) Protect(key []byte) ([]byte, error) { return p.inner.Protect(key) }
func (p *keyProtectorOnly) Unprotect(blob, key []byte) error   { return p.inner.Unprotect(blob, key) }

func TestSuiteCatchesAClaimedModeTheProviderCannotServe(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return &keyProtectorOnly{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider claiming a mode its method set cannot serve")
	}
	if !strings.Contains(err.Error(), "NewSealer refused this provider in ModeRootKey") {
		t.Fatalf("the suite failed, but not on the claimed mode:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// RootUnsealer
// ---------------------------------------------------------------------------

// halfWritingUnsealer writes only the first half of the destination, leaving
// the rest as whatever the caller's pages held.
type halfWritingUnsealer struct{ inner *enclave.SoftwareProvider }

func (p *halfWritingUnsealer) UnsealRoot(dst []byte) error {
	full := make([]byte, enclave.RootKeyBytes)
	if err := p.inner.UnsealRoot(full); err != nil {
		return err
	}
	copy(dst[:len(dst)/2], full) // THE DEFECT.
	return nil
}

func TestSuiteCatchesARootThatIsOnlyPartlyWritten(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return &halfWritingUnsealer{inner: software()}, nil }),
		"destination bytes UNWRITTEN")
}

// constantUnsealer is the placeholder a Sealer cannot tell from an unseal.
type constantUnsealer struct{ fill byte }

func (u constantUnsealer) UnsealRoot(dst []byte) error {
	for i := range dst {
		dst[i] = u.fill
	}
	return nil
}

func TestSuiteCatchesAConstantFillRoot(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return constantUnsealer{fill: 0x42}, nil }),
		"constant-fill root")
}

func TestSuiteCatchesAnAllZeroRoot(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return constantUnsealer{fill: 0x00}, nil }),
		"all-zero root")
}

// nondeterministicUnsealer hands a different root to every caller, so two
// Sealers over one device each believe they hold THE root.
type nondeterministicUnsealer struct{}

func (nondeterministicUnsealer) UnsealRoot(dst []byte) error {
	k, err := randKey()
	if err != nil {
		return err
	}
	copy(dst, k)
	return nil
}

func TestSuiteCatchesANondeterministicRoot(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return nondeterministicUnsealer{}, nil }),
		"DIFFERENT roots")
}

// rootDestRetainer keeps the destination it was handed and wipes it on the next
// call, leaving a Sealer running its whole KEK hierarchy under zeros.
type rootDestRetainer struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	last  []byte
}

func (p *rootDestRetainer) UnsealRoot(dst []byte) error {
	p.mu.Lock()
	last := p.last
	p.mu.Unlock()
	if last != nil {
		enclave.Wipe(last) // THE DEFECT.
	}
	if err := p.inner.UnsealRoot(dst); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = dst
	return nil
}

func TestSuiteCatchesARootUnsealerRetainingTheDestination(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return &rootDestRetainer{inner: software()}, nil }),
		"UnsealRoot does not retain the caller's destination")
}

// oneShotUnsealer consumes its handle on a successful unseal — a sealed blob
// read once, an operator-typed passphrase, an assembled share — and refuses
// every call after the first. It satisfies the runtime contract exactly: the
// seam guarantees only that a Sealer calls UnsealRoot AT MOST ONCE.
//
// It exists because a review found the suite rejecting it. A conformance suite
// that fails a provider for honoring the contract is over-asserting, and
// over-assertion is the same defect as under-measuring wearing the other hat:
// implementers either work around it or stop believing it.
type oneShotUnsealer struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	spent bool
}

func (p *oneShotUnsealer) UnsealRoot(dst []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spent {
		return errors.New("the unseal handle was consumed by the first successful call")
	}
	if err := p.inner.UnsealRoot(dst); err != nil {
		return err
	}
	p.spent = true
	return nil
}

// TestSingleUseRootIsAccommodatedAndRecorded pins both halves: a one-shot root
// FAILS by default — because the default must stay the strong one — and passes
// with Config.SingleUseRoot set, with the relaxation reported in the log rather
// than applied in silence.
func TestSingleUseRootIsAccommodatedAndRecorded(t *testing.T) {
	newOneShot := func() (any, error) { return &oneShotUnsealer{inner: software()}, nil }

	t.Run("refused by default, and the message names the remedy", func(t *testing.T) {
		cfg := rootOnly(newOneShot)
		cfg.Logf = t.Logf
		err := TestProvider(cfg)
		if err == nil {
			t.Fatal("TestProvider = nil for a one-shot root without Config.SingleUseRoot; the default " +
				"relaxed itself, and every repeatable provider now goes unchecked for full-width write")
		}
		if !strings.Contains(err.Error(), "set Config.SingleUseRoot") {
			t.Errorf("the failure does not tell the implementer what to do about it:\n%v", err)
		}
	})

	t.Run("accepted with a recorded reason", func(t *testing.T) {
		var log strings.Builder
		cfg := rootOnly(newOneShot)
		cfg.SingleUseRoot = "the unseal handle is consumed by the first successful call"
		cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }

		if err := TestProvider(cfg); err != nil {
			t.Fatalf("a one-shot root that honors the contract does not pass with SingleUseRoot set:\n%v", err)
		}
		for _, want := range []string{
			"UnsealRoot called ONCE",
			"destination spy was NOT RUN",
			"the unseal handle is consumed by the first successful call",
		} {
			if !strings.Contains(log.String(), want) {
				t.Errorf("the relaxation was applied without reporting %q; a reader of this green run would "+
					"not know what went unmeasured. Log was:\n%s", want, log.String())
			}
		}
	})

	t.Run("a stub is still caught on the single-call path", func(t *testing.T) {
		// The relaxation must not become a way through for a placeholder.
		for _, u := range []enclave.RootUnsealer{constantUnsealer{fill: 0x42}, constantUnsealer{fill: 0x00}, silentUnsealer{}} {
			cfg := rootOnly(func() (any, error) { return u, nil })
			cfg.SingleUseRoot = "test"
			cfg.Logf = t.Logf
			if err := TestProvider(cfg); err == nil {
				t.Errorf("TestProvider = nil for %T with SingleUseRoot set; the relaxation opened a hole", u)
			}
		}
	})
}

// silentUnsealer returns nil and writes nothing, so the destination is zero for
// the worst reason. The control must report itself rather than score a pass.
type silentUnsealer struct{}

func (silentUnsealer) UnsealRoot([]byte) error { return nil }

func TestSuiteCatchesARootDestinationThatIsNeverPopulated(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return silentUnsealer{}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(cfg)
	if err == nil {
		t.Fatal("the suite PASSED a RootUnsealer that writes nothing")
	}
	if !strings.Contains(err.Error(), "UnsealRoot does not retain the caller's destination: the control did not hold") {
		t.Errorf("the spy did not report its control failing; a zero reading was taken at face value:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

func TestConfigIsValidated(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "no provider",
			cfg:  Config{Modes: []enclave.Mode{enclave.ModeRootKey}},
			want: "Config.New is nil",
		},
		{
			name: "no modes claimed",
			cfg:  Config{New: func() (any, error) { return software(), nil }},
			want: "Config.Modes is empty",
		},
		{
			name: "a mode that names nothing",
			cfg: Config{
				New:   func() (any, error) { return software(), nil },
				Modes: []enclave.Mode{enclave.Mode(99)},
			},
			want: "names no sealing mode",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := TestProvider(tc.cfg)
			if err == nil {
				t.Fatalf("TestProvider(%s) = nil, want a configuration error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("TestProvider(%s) = %v, want it to mention %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestSuiteRefusesATypedNilProvider is the case a conformance suite must not
// crash on, found by review: a (*SoftwareProvider)(nil) SATISFIES both seam
// interfaces, so an unchecked type assertion succeeds and the first Protect
// panics on a nil receiver — inside the suite, which then reports nothing.
// NewSealer refuses the same value with ErrProviderMode, and so must this.
//
// The subtests cover both entry paths, because the KeyProtector and
// RootUnsealer halves assert separately.
func TestSuiteRefusesATypedNilProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "typed nil, ModePerOperation",
			cfg:  perOp(func() (any, error) { return (*enclave.SoftwareProvider)(nil), nil }),
		},
		{
			name: "typed nil, ModeRootKey",
			cfg:  rootOnly(func() (any, error) { return (*enclave.SoftwareProvider)(nil), nil }),
		},
		{
			name: "an untyped nil",
			cfg:  perOp(func() (any, error) { return nil, nil }),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Logf = t.Logf
			// A panic here fails the test, which is the point: the suite must
			// REPORT this, not die on it.
			err := TestProvider(cfg)
			if err == nil {
				t.Fatal("TestProvider = nil for a nil provider")
			}
			if !strings.Contains(err.Error(), "returned a nil provider") {
				t.Errorf("TestProvider = %v, want it to name the nil provider", err)
			}
		})
	}
}

// TestConstructionFailureIsReported pins that a provider whose constructor
// fails is a suite failure and not a silent skip.
func TestConstructionFailureIsReported(t *testing.T) {
	sentinel := errors.New("no device")
	cfg := perOp(func() (any, error) { return nil, sentinel })
	cfg.Logf = t.Logf
	err := TestProvider(cfg)
	if err == nil {
		t.Fatal("TestProvider = nil when Config.New always fails")
	}
	if !strings.Contains(err.Error(), sentinel.Error()) {
		t.Errorf("TestProvider = %v, want it to carry the constructor's error", err)
	}
}

// ---------------------------------------------------------------------------
// Instrument unit checks
// ---------------------------------------------------------------------------

// TestIsNilProvider pins the classifier both directions. A false positive here
// refuses a working provider; a false negative is the panic it exists to stop.
func TestIsNilProvider(t *testing.T) {
	var nilPtr *enclave.SoftwareProvider
	var nilMap map[string][]byte
	var nilFunc func()
	var nilIface enclave.KeyProtector

	tests := []struct {
		name string
		p    any
		want bool
	}{
		{"an untyped nil", nil, true},
		{"a typed nil pointer", nilPtr, true},
		{"a nil map", nilMap, true},
		{"a nil func", nilFunc, true},
		{"a nil interface value", nilIface, true},
		{"a live provider", software(), false},
		{"a non-pointer value provider", blobIsTheKeyProtector{}, false},
		{"a zero-valued struct", constantUnsealer{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNilProvider(tc.p); got != tc.want {
				t.Errorf("isNilProvider(%T) = %v, want %v", tc.p, got, tc.want)
			}
		})
	}
}

// TestContainsRun pins the partial-write detector, because an equality test
// against the whole key misses exactly the case it exists for.
func TestContainsRun(t *testing.T) {
	key := bytes.Repeat([]byte{0xC3}, 32)
	for i := range key {
		key[i] = byte(i) + 0x40
	}
	tests := []struct {
		name string
		hay  []byte
		want bool
	}{
		{"empty", nil, false},
		{"unrelated", bytes.Repeat([]byte{0x11}, 64), false},
		{"the whole key", bytes.Clone(key), true},
		{"the leading half, as a partial write leaves it", append(bytes.Clone(key[:16]), make([]byte, 16)...), true},
		{"the trailing half", append(make([]byte, 16), key[16:]...), true},
		{"seven bytes, below the window", bytes.Clone(key[:7]), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsRun(tc.hay, key); got != tc.want {
				t.Errorf("containsRun = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFlipPositions pins the tamper sample: in range, deduplicated, and
// covering both ends and the tag region for any blob a provider can return.
func TestFlipPositions(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 16, 61, 1024} {
		got := flipPositions(n)
		if len(got) == 0 {
			t.Errorf("flipPositions(%d) is empty; no bit-flip case would be exercised", n)
		}
		seen := make(map[int]bool, len(got))
		for _, i := range got {
			if i < 0 || i >= n {
				t.Errorf("flipPositions(%d) yielded %d, out of range", n, i)
			}
			if seen[i] {
				t.Errorf("flipPositions(%d) yielded %d twice", n, i)
			}
			seen[i] = true
		}
		if n >= 4 && (!seen[0] || !seen[n-1]) {
			t.Errorf("flipPositions(%d) = %v, want both the first and last byte", n, got)
		}
	}
}

// TestAddrOfLandsInsideTheMapping is the sanity check under the residue sweep's
// home exclusion: an address that did not point into the needle's mapping would
// make every legitimate match read as a leak.
func TestAddrOfLandsInsideTheMapping(t *testing.T) {
	if _, err := addrOf(nil); err == nil {
		t.Error("addrOf(nil) = nil error; an empty slice has no first element")
	}
	b := make([]byte, 64)
	addr, err := addrOf(b)
	if err != nil {
		t.Fatalf("addrOf: %v", err)
	}
	if addr == 0 {
		t.Error("addrOf returned 0 for a live slice")
	}
}
