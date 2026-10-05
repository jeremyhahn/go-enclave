// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

// Package providertest_test is go-enclave's providertest integration suite:
// the conformance harness driven through its public API exactly as a provider
// author uses it, in the project devcontainer (integration-testing §3-§4).
// The planted providers below each violate one property; the suite must go
// RED naming it, so every check the harness claims is shown to exist.
package providertest_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-enclave/providertest"
	"github.com/jeremyhahn/go-enclave/test/integration/internal/devcontainer"
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
	err := providertest.TestProvider(t.Context(), providertest.Config{
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

// wantFail runs the suite and requires it to fail, naming every string in
// wants. The property-name match is what separates "the suite failed" from
// "the suite failed FOR THE REASON THIS TEST PLANTED" — without it a planted
// violator that merely broke the round trip would be scored as a caught leak.
// A test naming both the property and the specific arm pins that the arm fired
// under the property it belongs to.
func wantFail(t *testing.T, cfg providertest.Config, wants ...string) {
	t.Helper()
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	err := providertest.TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatalf("the suite PASSED a provider that deliberately violates %q; the check does not exist", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the suite failed, but not on %q:\n%v", want, err)
		}
	}
	t.Logf("caught, as required:\n%v", err)
}

// perOp is the Config for a KeyProtector-only violator.
func perOp(new func() (any, error)) providertest.Config {
	return providertest.Config{New: new, Modes: []enclave.Mode{enclave.ModePerOperation}}
}

// rootOnly is the Config for a RootUnsealer-only violator.
func rootOnly(new func() (any, error)) providertest.Config {
	return providertest.Config{New: new, Modes: []enclave.Mode{enclave.ModeRootKey}}
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

func (p *retainingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *retainingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.kept = append(p.kept, bytes.Clone(key))
	return nil
}

// The deliberate-leak control for retainingProtector is
// TestSuiteCatchesAProviderThatRetainsACopy, in residue_linux_test.go: the
// residue sweep is the only instrument that can see a retained copy, and it
// exists only on Linux. Its non-Linux counterpart,
// TestResidueSweepReportsItselfNotRunOffLinux in residue_other_test.go,
// pins that the suite says so there instead of passing in silence (#90).

// TestResidueSweepSkipIsRecordedNotSilent pins the escape hatch's cost: a
// skipped sweep is reported through Logf in the same words every time, so a
// green run cannot hide that its only retention-by-copy instrument did not run.
func TestResidueSweepSkipIsRecordedNotSilent(t *testing.T) {
	var log strings.Builder
	cfg := perOp(func() (any, error) { return &retainingProtector{inner: software()}, nil })
	cfg.SkipResidueSweep = "the KMS response body is owned by net/http"
	cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }

	if err := providertest.TestProvider(t.Context(), cfg); err != nil {
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

func (p *aliasingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "aliasing-blob-%08d", p.n)
	p.keys[string(blob)] = key // THE DEFECT: the caller's slice, not a copy.
	return blob, nil
}

func (p *aliasingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *writeBackProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *writeBackProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	p.mu.Lock()
	last, val := p.last, p.val
	p.mu.Unlock()
	if last != nil && len(last) == len(val) {
		copy(last, val) // THE DEFECT: a retained destination, written again.
	}
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
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

func (p *wipingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *wipingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	p.mu.Lock()
	last := p.last
	p.mu.Unlock()
	if last != nil {
		enclave.Wipe(last) // THE DEFECT: a retained destination, wiped later.
	}
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
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

func (p *silentProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}
func (p *silentProtector) Unprotect(ctx context.Context, _, _ []byte) error { return ctx.Err() }

func TestSuiteCatchesADestinationThatIsNeverPopulated(t *testing.T) {
	cfg := perOp(func() (any, error) { return &silentProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
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

func (p *unauthenticatedProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "unauthenticated-%08d-ignored-tail", p.n)
	p.keys[string(blob[:unauthPrefix])] = bytes.Clone(key)
	return blob, nil
}

func (p *unauthenticatedProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *forgeableProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "forgeable-%08d|", p.n)
	blob = append(blob, make([]byte, len(key))...)
	p.keys[string(blob[:forgeablePrefix])] = bytes.Clone(key)
	return blob, nil
}

func (p *forgeableProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *wrongErrorProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *wrongErrorProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return errors.New("device temporarily unavailable") // THE DEFECT.
	}
	return nil
}

func TestSuiteCatchesAForgeryReportedAsADeviceFault(t *testing.T) {
	cfg := perOp(func() (any, error) { return &wrongErrorProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
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

func (p *decryptBeforeAuthenticateProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	p.last = bytes.Clone(key)
	p.mu.Unlock()
	return p.inner.Protect(ctx, key)
}

func (p *decryptBeforeAuthenticateProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := p.inner.Unprotect(ctx, blob, key)
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

func (blobIsTheKeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(key), nil
}

func (blobIsTheKeyProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *mutatingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	blob, err := p.inner.Protect(ctx, key)
	if err == nil {
		key[0] ^= 0xFF // THE DEFECT.
	}
	return blob, err
}
func (p *mutatingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}

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

func (p *looseLengthProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := fmt.Appendf(nil, "loose-length-blob-%08d", p.n)
	p.keys[string(blob)] = bytes.Clone(key)
	return blob, nil
}

func (p *looseLengthProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *silentLengthProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *silentLengthProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) != enclave.RootKeyBytes {
		return nil // THE DEFECT: a length mismatch reported as success.
	}
	return p.inner.Unprotect(ctx, blob, key)
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

func (p *shortDestinationLeakProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	p.last = bytes.Clone(key)
	p.mu.Unlock()
	return p.inner.Protect(ctx, key)
}

func (p *shortDestinationLeakProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(key) != enclave.RootKeyBytes {
		p.mu.Lock()
		last := p.last
		p.mu.Unlock()
		copy(key, last) // THE DEFECT: written before the length is checked.
		return enclave.ErrSealedAuthentication
	}
	return p.inner.Unprotect(ctx, blob, key)
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

func (p *stubRootProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}
func (p *stubRootProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}
func (p *stubRootProvider) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clear(dst)
	return nil
}

func TestSuiteCatchesAnUnclaimedModeTheProviderStillSatisfies(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return &stubRootProvider{inner: software()}, nil }),
		"mode/interface pairing")
}

// keyProtectorOnly claims a mode its method set cannot serve.
type keyProtectorOnly struct{ inner *enclave.SoftwareProvider }

func (p *keyProtectorOnly) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}
func (p *keyProtectorOnly) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}

func TestSuiteCatchesAClaimedModeTheProviderCannotServe(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return &keyProtectorOnly{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider claiming a mode its method set cannot serve")
	}
	if !strings.Contains(err.Error(), "this provider cannot serve ModeRootKey") {
		t.Fatalf("the suite failed, but not on the claimed mode:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// RootUnsealer
// ---------------------------------------------------------------------------

// halfWritingUnsealer writes only the first half of the destination, leaving
// the rest as whatever the caller's pages held.
type halfWritingUnsealer struct{ inner *enclave.SoftwareProvider }

func (p *halfWritingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	// The full root comes from a LOCKED scratch enclave, so the defect under
	// test — a partial write — is the only thing this fixture gets wrong;
	// its intermediate copy of the root never touches the ordinary heap.
	scratch, err := enclave.NewMemoryEnclaveSized(enclave.RootKeyBytes)
	if err != nil {
		return err
	}
	defer func() { _ = scratch.Destroy() }()
	return scratch.WithBytes(func(full []byte) error {
		if err := p.inner.UnsealRoot(ctx, full); err != nil {
			return err
		}
		copy(dst[:len(dst)/2], full) // THE DEFECT.
		return nil
	})
}

func TestSuiteCatchesARootThatIsOnlyPartlyWritten(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return &halfWritingUnsealer{inner: software()}, nil }),
		"destination bytes UNWRITTEN")
}

// constantUnsealer is the placeholder a Sealer cannot tell from an unseal.
type constantUnsealer struct{ fill byte }

func (u constantUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (nondeterministicUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (p *rootDestRetainer) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	last := p.last
	p.mu.Unlock()
	if last != nil {
		enclave.Wipe(last) // THE DEFECT.
	}
	if err := p.inner.UnsealRoot(ctx, dst); err != nil {
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

func (p *oneShotUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spent {
		return errors.New("the unseal handle was consumed by the first successful call")
	}
	if err := p.inner.UnsealRoot(ctx, dst); err != nil {
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
		err := providertest.TestProvider(t.Context(), cfg)
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

		if err := providertest.TestProvider(t.Context(), cfg); err != nil {
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
			if err := providertest.TestProvider(t.Context(), cfg); err == nil {
				t.Errorf("TestProvider = nil for %T with SingleUseRoot set; the relaxation opened a hole", u)
			}
		}
	})
}

// silentUnsealer returns nil and writes nothing, so the destination is zero for
// the worst reason. The control must report itself rather than score a pass.
type silentUnsealer struct{}

func (silentUnsealer) UnsealRoot(ctx context.Context, _ []byte) error { return ctx.Err() }

func TestSuiteCatchesARootDestinationThatIsNeverPopulated(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return silentUnsealer{}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
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
		name  string
		cfg   providertest.Config
		want  string
		field string
	}{
		{
			name:  "no provider",
			cfg:   providertest.Config{Modes: []enclave.Mode{enclave.ModeRootKey}},
			want:  "Config.New is nil",
			field: "New",
		},
		{
			name:  "no modes claimed",
			cfg:   providertest.Config{New: func() (any, error) { return software(), nil }},
			want:  "Config.Modes is empty",
			field: "Modes",
		},
		{
			name: "a mode that names nothing",
			cfg: providertest.Config{
				New:   func() (any, error) { return software(), nil },
				Modes: []enclave.Mode{enclave.Mode(99)},
			},
			want:  "Config.Modes contains Mode(99), which names no sealing mode",
			field: "Modes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := providertest.TestProvider(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("TestProvider(%s) = nil, want a configuration error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("TestProvider(%s) = %v, want it to mention %q", tc.name, err, tc.want)
			}
			// A harness mistake must be distinguishable from a provider
			// defect without parsing the message.
			if !errors.Is(err, providertest.ErrInvalidConfig) {
				t.Errorf("TestProvider(%s) = %v, want an error matching ErrInvalidConfig", tc.name, err)
			}
			var ce *providertest.ConfigError
			if !errors.As(err, &ce) || ce.Field != tc.field {
				t.Errorf("TestProvider(%s) = %#v, want a *ConfigError naming Config.%s", tc.name, err, tc.field)
			}
		})
	}
}

// TestPropertyFailuresAreTyped pins the other half of that distinction: a
// provider that ran and failed reports every failure as a *PropertyError, and
// none of them matches ErrInvalidConfig.
func TestPropertyFailuresAreTyped(t *testing.T) {
	cfg := perOp(func() (any, error) { return &silentProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose Unprotect writes nothing")
	}
	if errors.Is(err, providertest.ErrInvalidConfig) {
		t.Errorf("a provider defect matched ErrInvalidConfig:\n%v", err)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("TestProvider returned %T, want a joined error that can be walked per property", err)
	}
	for _, e := range joined.Unwrap() {
		var pe *providertest.PropertyError
		if !errors.As(e, &pe) || pe.Property == "" || pe.Detail == "" {
			t.Errorf("a failure is not a populated *PropertyError: %#v", e)
		}
	}
}

// TestSuiteRefusesATypedNilProvider is the case a conformance suite must not
// crash on, found by review: a (*SoftwareProvider)(nil) SATISFIES both seam
// interfaces, so an unchecked type assertion succeeds and the first Protect
// panics on a nil receiver — inside the suite, which then reports nothing.
// NewSealer refuses the same value with ErrInvalidProvider, and so must this.
//
// The subtests cover both entry paths, because the KeyProtector and
// RootUnsealer halves assert separately.
func TestSuiteRefusesATypedNilProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  providertest.Config
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
			err := providertest.TestProvider(t.Context(), cfg)
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
	err := providertest.TestProvider(t.Context(), cfg)
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

// TestContainsRun pins the partial-write detector, because an equality test
// against the whole key misses exactly the case it exists for.

// A NEEDLE shorter than the window can never be found, even in a haystack
// holding it whole: a run that short is a chance collision rather than
// evidence, and reporting it would turn noise into leak findings.

// TestFlipPositions pins the tamper sample: in range, deduplicated, and
// covering both ends and the tag region for any blob a provider can return.

// TestAddrOfLandsInsideTheMapping is the sanity check under the residue sweep's
// home exclusion: an address that did not point into the needle's mapping would
// make every legitimate match read as a leak.

// ---------------------------------------------------------------------------
// The context contract (#87)
// ---------------------------------------------------------------------------

// endedContextProtector wraps the software provider and, when the context it
// is handed has ENDED, does exactly one wrong thing — the defect named by its
// field — and otherwise behaves. Each defect is one arm of the ended-context
// check, so each test below kills exactly one assertion.
type endedContextProtector struct {
	inner *enclave.SoftwareProvider

	ignoreOnProtect   bool  // complete Protect as if the context were live
	ignoreOnUnprotect bool  // complete Unprotect as if the context were live
	reportAs          error // refuse with this error instead of ctx.Err()
	writeThenRefuse   bool  // recover into the destination, then refuse
	wipeKeyOnRefuse   bool  // wipe the caller's key slice, then refuse
	forgetOnRefuse    bool  // drop every protected key, then refuse
}

func (p *endedContextProtector) refusal(ctx context.Context) error {
	if p.reportAs != nil {
		return p.reportAs
	}
	return ctx.Err()
}

func (p *endedContextProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if ctx.Err() == nil || p.ignoreOnProtect {
		return p.inner.Protect(context.WithoutCancel(ctx), key)
	}
	if p.wipeKeyOnRefuse {
		enclave.Wipe(key) // THE DEFECT: the caller's locked pages, wiped on a refusal.
	}
	return nil, p.refusal(ctx)
}

func (p *endedContextProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if ctx.Err() == nil || p.ignoreOnUnprotect {
		return p.inner.Unprotect(context.WithoutCancel(ctx), blob, key)
	}
	if p.writeThenRefuse {
		_ = p.inner.Unprotect(context.WithoutCancel(ctx), blob, key) // THE DEFECT.
	}
	if p.forgetOnRefuse {
		p.inner = enclave.NewSoftwareProvider() // THE DEFECT: state lost on a refusal.
	}
	return p.refusal(ctx)
}

func TestSuiteRequiresAnEndedContextToBeRefused(t *testing.T) {
	const property = "Protect and Unprotect refuse a context that has already ended"
	tests := []struct {
		name string
		p    func() *endedContextProtector
		want string
	}{
		{"Protect ignores it", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), ignoreOnProtect: true}
		}, "Protect ACCEPTED an already-canceled context"},
		{"Unprotect ignores it", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), ignoreOnUnprotect: true}
		}, "Unprotect ACCEPTED an already-canceled context"},
		{"reported as a forgery", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), reportAs: enclave.ErrSealedAuthentication}
		}, "which matches ErrSealedAuthentication"},
		{"a deadline reported as a cancellation", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), reportAs: context.Canceled}
		}, "refused an already-deadline-expired context with context canceled, want an error matching context deadline exceeded"},
		{"plaintext written into a refused destination", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), writeThenRefuse: true}
		}, "still wrote plaintext key material"},
		{"the caller's key wiped by a refusal", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), wipeKeyOnRefuse: true}
		}, "context MUTATED the caller's key slice"},
		{"state lost on a refusal", func() *endedContextProtector {
			return &endedContextProtector{inner: software(), forgetOnRefuse: true}
		}, "a refused call must leave the provider as it found it"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := perOp(func() (any, error) { return tc.p(), nil })
			// Each violator differs from the software provider only on calls
			// made with an ENDED context, which the residue sweep never makes.
			cfg.SkipResidueSweep = "the violator under test differs from the software provider only on ended-context calls"
			wantFail(t, cfg, property+": ", tc.want)
		})
	}
}

// endedContextUnsealer is endedContextProtector's RootUnsealer counterpart.
type endedContextUnsealer struct {
	inner *enclave.SoftwareProvider

	ignore          bool // complete UnsealRoot as if the context were live
	spendOnRefuse   bool // a one-shot handle consumed by a call it refused
	writeThenRefuse bool // write the root, then refuse

	mu    sync.Mutex
	spent bool
}

func (u *endedContextUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.spent {
		return errors.New("the unseal handle was consumed")
	}
	if ctx.Err() == nil || u.ignore {
		return u.inner.UnsealRoot(context.WithoutCancel(ctx), dst)
	}
	if u.writeThenRefuse {
		_ = u.inner.UnsealRoot(context.WithoutCancel(ctx), dst) // THE DEFECT.
	}
	u.spent = u.spendOnRefuse // THE DEFECT, when set.
	return ctx.Err()
}

func TestSuiteRequiresUnsealRootToRefuseAnEndedContext(t *testing.T) {
	const property = "UnsealRoot refuses a context that has already ended, and consumes nothing"
	tests := []struct {
		name string
		u    func() *endedContextUnsealer
		want string
	}{
		{"ignored", func() *endedContextUnsealer {
			return &endedContextUnsealer{inner: software(), ignore: true}
		}, "UnsealRoot ACCEPTED an already-canceled context"},
		{"a one-shot handle spent on a refusal", func() *endedContextUnsealer {
			return &endedContextUnsealer{inner: software(), spendOnRefuse: true}
		}, "a one-shot handle spent on a refusal leaves it no root at all"},
		{"root written into a refused destination", func() *endedContextUnsealer {
			return &endedContextUnsealer{inner: software(), writeThenRefuse: true}
		}, "still wrote root material into the destination"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rootOnly(func() (any, error) { return tc.u(), nil })
			// A one-shot provider is the case the spend arm is about, so it
			// runs with the relaxation an honest one-shot provider would set:
			// the finding must come from the context check, not from the
			// default's second call.
			cfg.SingleUseRoot = "the test violator models a one-shot handle"
			wantFail(t, cfg, property+": ", tc.want)
		})
	}
}

// hangingOnEndedContext blocks, until released, on any call made with an
// ended context — the worst way to ignore one. acceptProtect additionally
// makes Protect COMPLETE an ended-context call, a violation the suite observes
// before the hang. entered is closed when the first hanging call arrives.
type hangingOnEndedContext struct {
	inner         *enclave.SoftwareProvider
	acceptProtect bool
	entered       chan struct{}
	release       chan struct{}
	once          sync.Once
}

func (p *hangingOnEndedContext) hang(ctx context.Context) error {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return ctx.Err()
}

func (p *hangingOnEndedContext) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if ctx.Err() != nil {
		if p.acceptProtect {
			return p.inner.Protect(context.WithoutCancel(ctx), key)
		}
		return nil, p.hang(ctx)
	}
	return p.inner.Protect(ctx, key)
}

func (p *hangingOnEndedContext) Unprotect(ctx context.Context, blob, key []byte) error {
	if ctx.Err() != nil {
		return p.hang(ctx)
	}
	return p.inner.Unprotect(ctx, blob, key)
}

func newHanging(accept bool) *hangingOnEndedContext {
	return &hangingOnEndedContext{
		inner: software(), acceptProtect: accept,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
}

// runAgainstHanging runs the suite against p with a run context the test
// cancels once p is inside a hanging call, so the suite's bounded wait — not
// the provider — decides when the run ends.
func runAgainstHanging(t *testing.T, p *hangingOnEndedContext) error {
	t.Helper()
	t.Cleanup(func() { close(p.release) }) // frees the abandoned goroutine
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() {
		<-p.entered
		cancel()
	}()
	cfg := perOp(func() (any, error) { return p, nil })
	cfg.SkipResidueSweep = "the violator differs from the software provider only on ended-context calls"
	cfg.Logf = t.Logf
	return providertest.TestProvider(ctx, cfg)
}

// TestAnUnfinishedEndedContextCallIsAnAbortNotAFinding is the fourth review
// finding. A call the suite stopped waiting for proves the RUN ended, not that
// the provider misbehaved — the worker goroutine may never have reached it —
// so the run is reported aborted and nothing is charged to the provider.
func TestAnUnfinishedEndedContextCallIsAnAbortNotAFinding(t *testing.T) {
	err := runAgainstHanging(t, newHanging(false))
	assertAbortedOnly(t, err)
}

// TestViolationsObservedBeforeAnAbortAreKept is the other half: an abort does
// not erase what the suite DID observe while the run's context was live. Here
// Protect completes an ended-context call — observed — and Unprotect then
// hangs until the run's context ends.
func TestViolationsObservedBeforeAnAbortAreKept(t *testing.T) {
	err := runAgainstHanging(t, newHanging(true))
	if !errors.Is(err, providertest.ErrAborted) {
		t.Errorf("TestProvider = %v, want it to match ErrAborted", err)
	}
	if err == nil || !strings.Contains(err.Error(), "Protect ACCEPTED an already-canceled context") {
		t.Errorf("the violation observed before the abort was dropped:\n%v", err)
	}
	if strings.Contains(fmt.Sprint(err), "had not returned") {
		t.Errorf("the unfinished call was charged to the provider:\n%v", err)
	}
}

// endsOnFirstWait is a run context that ends the first time anything waits on
// it. The suite's first wait is deriving the ended contexts for the context
// check — after every control has run — so the bounded wait that follows
// finds the run already over whether or not its worker goroutine has started:
// the interleaving the fourth review finding described, made deterministic.
type endsOnFirstWait struct {
	context.Context
	once   sync.Once
	cancel context.CancelFunc
}

func (c *endsOnFirstWait) Done() <-chan struct{} {
	c.once.Do(c.cancel)
	return c.Context.Done()
}

// TestARunEndingBeforeTheWorkerRunsChargesNothing pins the interleaving
// directly: the run's context is already over when the bounded wait begins.
func TestARunEndingBeforeTheWorkerRunsChargesNothing(t *testing.T) {
	p := newHanging(false)
	t.Cleanup(func() { close(p.release) })
	inner, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &endsOnFirstWait{Context: inner, cancel: cancel}

	cfg := perOp(func() (any, error) { return p, nil })
	cfg.SkipResidueSweep = "the violator differs from the software provider only on ended-context calls"
	cfg.Logf = t.Logf
	assertAbortedOnly(t, providertest.TestProvider(ctx, cfg))
}

// TestAnAbortedRunIsNeverAPass pins the run-context half: a run whose context
// has ended returns an error matching ErrAborted — never nil, since nothing was
// measured — and does not charge the provider with failures that are only
// the provider honoring that context.
func TestAnAbortedRunIsNeverAPass(t *testing.T) {
	t.Run("ended before the run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := providertest.TestProvider(ctx, providertest.Config{
			New:   func() (any, error) { return software(), nil },
			Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
			Logf:  t.Logf,
		})
		assertAbortedOnly(t, err)
	})

	t.Run("ended mid-run, by the provider's own call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// The run's context ends inside a provider call, and the provider
		// then honors it — exactly what a conforming provider does when its
		// caller gives up. That refusal must not be scored as a defect.
		p := &cancellingProtector{inner: software(), cancel: cancel}
		err := providertest.TestProvider(ctx, providertest.Config{
			New:   func() (any, error) { return p, nil },
			Modes: []enclave.Mode{enclave.ModePerOperation},
			Logf:  t.Logf,
		})
		assertAbortedOnly(t, err)
	})
}

// cancellingProtector ends the run's context during its first Unprotect and
// then honors it.
type cancellingProtector struct {
	inner  *enclave.SoftwareProvider
	cancel context.CancelFunc
}

func (p *cancellingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *cancellingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	p.cancel()
	return p.inner.Unprotect(ctx, blob, key)
}

func assertAbortedOnly(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("TestProvider = nil for a run whose context ended; an incomplete run certified a provider")
	}
	if !errors.Is(err, providertest.ErrAborted) || !errors.Is(err, context.Canceled) {
		t.Errorf("TestProvider = %v, want an error matching ErrAborted and context.Canceled", err)
	}
	var ae *providertest.AbortedError
	if !errors.As(err, &ae) || !errors.Is(ae.Err, context.Canceled) {
		t.Errorf("TestProvider = %#v, want an *AbortedError carrying the context's error", err)
	}
	var pe *providertest.PropertyError
	if errors.As(err, &pe) {
		t.Errorf("an aborted run charged the provider with %q; a call refused because the RUN's context "+
			"ended is the provider conforming, not failing", pe)
	}
}

// ---------------------------------------------------------------------------
// A provider call that FAILS is a finding, never a pass (#90)
// ---------------------------------------------------------------------------
//
// Every check makes a fixed sequence of provider calls, and every one of those
// calls can fail on a real device — a TPM busy, a KMS throttled, a session
// expired. Each failure has its own branch in each check, and before #90 most
// of those branches were covered by nothing: a regression turning any of them
// into a silent `return` would have let a provider that cannot do the
// operation pass the property that depends on it. These tests drive each call
// ordinal to failure in turn and require the run to fail, under the right
// property, naming the call and carrying the device's own error text.

// errDeviceFault is the failure the planted providers below report.
var errDeviceFault = errors.New("device: transient fault")

// failingProtector is the software provider with ONE call refused: the
// failProtect-th Protect or the failUnprotect-th Unprotect made on this
// instance, counting from 1 and counting every call (ended-context calls,
// which the suite makes on a goroutine of its own, included). Zero refuses
// nothing. Every other call is the conforming software provider's, so the
// refused call is the only thing wrong with it.
type failingProtector struct {
	inner                      *enclave.SoftwareProvider
	failProtect, failUnprotect int

	mu                   sync.Mutex
	protects, unprotects int
}

func (p *failingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	p.protects++
	n := p.protects
	p.mu.Unlock()
	if n == p.failProtect {
		return nil, errDeviceFault
	}
	return p.inner.Protect(ctx, key)
}

func (p *failingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	p.mu.Lock()
	p.unprotects++
	n := p.unprotects
	p.mu.Unlock()
	if n == p.failUnprotect {
		return errDeviceFault
	}
	return p.inner.Unprotect(ctx, blob, key)
}

// failingUnsealer is failingProtector's RootUnsealer counterpart.
type failingUnsealer struct {
	inner  *enclave.SoftwareProvider
	failAt int

	mu    sync.Mutex
	calls int
}

func (p *failingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n == p.failAt {
		return errDeviceFault
	}
	return p.inner.UnsealRoot(ctx, dst)
}

// requireOnlyPropertyFailures runs cfg and requires a run that FAILED, did so
// with nothing but property failures (not an abort, not a Config refusal),
// and names every "<property>: <detail prefix>" in wants.
func requireOnlyPropertyFailures(t *testing.T, cfg providertest.Config, wants ...string) {
	t.Helper()
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose device refused a call it needed; the failure branch " +
			"returned as if the property held")
	}
	if errors.Is(err, providertest.ErrAborted) || errors.Is(err, providertest.ErrInvalidConfig) {
		t.Fatalf("TestProvider = %v; want property failures, not an abort or a Config refusal", err)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("TestProvider returned %T, want the joined property failures", err)
	}
	for _, e := range joined.Unwrap() {
		var pe *providertest.PropertyError
		if !errors.As(e, &pe) {
			t.Errorf("a joined failure is %T (%v), want *PropertyError", e, e)
		}
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the run did not report %q:\n%v", want, err)
		}
	}
}

// TestSuiteReportsEveryFailedKeyProtectorCall walks the call ordinals the
// KeyProtector checks make and requires each refusal to fail the property
// whose check made the call, naming the call and the device's error.
func TestSuiteReportsEveryFailedKeyProtectorCall(t *testing.T) {
	fault := errDeviceFault.Error()
	const (
		roundTrip = "Protect/Unprotect round trip: "
		retain    = "Protect does not retain the caller's key slice: "
		afterWipe = "Unprotect does not write into a destination the caller has finished with: "
		disturb   = "a later provider call does not disturb an earlier destination: "
		tamper    = "a blob this provider did not produce is refused: "
		length    = "a destination of the wrong length is an authentication failure: "
		ended     = "Protect and Unprotect refuse a context that has already ended: "
	)
	tests := []struct {
		name                       string
		failProtect, failUnprotect int
		wants                      []string
	}{
		{
			name:        "the first Protect",
			failProtect: 1,
			wants: []string{
				roundTrip + "Protect: " + fault,
				retain + "Protect: " + fault,
				afterWipe + "Protect: " + fault,
				disturb + "Protect: " + fault,
				tamper + "Protect: " + fault,
				length + "Protect: " + fault,
				ended + "the control did not hold — Protect with a live context: " + fault,
			},
		},
		{
			name:        "the second Protect",
			failProtect: 2,
			wants: []string{
				afterWipe + "Protect: " + fault,
				disturb + "Protect: " + fault,
			},
		},
		{
			name:        "the third Protect",
			failProtect: 3,
			wants: []string{
				afterWipe + "a later Protect failed: " + fault,
				disturb + "a later Protect failed: " + fault,
			},
		},
		{
			name:          "the first Unprotect",
			failUnprotect: 1,
			wants: []string{
				roundTrip + "Unprotect of a blob this provider's own Protect produced: " + fault,
				retain + "the control did not hold — Unprotect before any wipe returned " + fault,
				afterWipe + "Unprotect: " + fault,
				disturb + "Unprotect: " + fault,
				ended + "the control did not hold — Unprotect with a live context returned " + fault,
			},
		},
		{
			name:          "the second Unprotect",
			failUnprotect: 2,
			wants: []string{
				retain + "after the caller wiped the key slice Protect was handed, Unprotect of that blob " +
					"failed with " + fault,
				afterWipe + "a second Unprotect failed: " + fault,
				disturb + "a second Unprotect failed: " + fault,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := perOp(func() (any, error) {
				return &failingProtector{inner: software(), failProtect: tc.failProtect, failUnprotect: tc.failUnprotect}, nil
			})
			requireOnlyPropertyFailures(t, cfg, tc.wants...)
		})
	}
}

// TestSuiteReportsEveryFailedUnsealRootCall is the same walk for the
// RootUnsealer checks.
func TestSuiteReportsEveryFailedUnsealRootCall(t *testing.T) {
	fault := errDeviceFault.Error()
	const (
		fills  = "UnsealRoot writes a root across the whole destination: "
		spy    = "UnsealRoot does not retain the caller's destination: "
		refuse = "UnsealRoot refuses a context that has already ended, and consumes nothing: "
	)
	tests := []struct {
		name   string
		failAt int
		wants  []string
	}{
		{
			name:   "the first UnsealRoot",
			failAt: 1,
			wants: []string{
				fills + "UnsealRoot: " + fault,
				spy + "UnsealRoot: " + fault,
				// The first call of the context check is an ended-context
				// one: a device error there is the wrong refusal.
				refuse + "UnsealRoot refused an already-canceled context with " + fault,
			},
		},
		{
			name:   "the second UnsealRoot",
			failAt: 2,
			wants: []string{
				fills + "a second UnsealRoot on the same provider: " + fault,
				spy + "a second UnsealRoot failed: " + fault,
			},
		},
		{
			name:   "the third UnsealRoot",
			failAt: 3,
			wants: []string{
				spy + "a third UnsealRoot failed: " + fault,
				refuse + "after refusing ended contexts, UnsealRoot on the same provider with a live context " +
					"failed: " + fault,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rootOnly(func() (any, error) { return &failingUnsealer{inner: software(), failAt: tc.failAt}, nil })
			requireOnlyPropertyFailures(t, cfg, tc.wants...)
		})
	}
}

// TestSuiteReportsAProviderThatCannotBeConstructed pins the Config.New
// failure path in every check: a provider that cannot be built has measured
// nothing, so every property it claims fails — naming Config.New and the
// constructor's own error — and none of them passes for want of an instance.

// The step error keeps the constructor's error MATCHABLE, not merely
// printable: that is what lets a caller of the internals tell a device
// fault from a nil provider without parsing a message.

// TestSuiteReportsAKeyProtectorClaimTheProviderCannotServe is the
// KeyProtector half of the missing-seam path: Config.Modes claims
// ModePerOperation for a provider that only unseals roots, and every
// KeyProtector check names the missing interface rather than panicking on a
// failed type assertion or skipping itself.
func TestSuiteReportsAKeyProtectorClaimTheProviderCannotServe(t *testing.T) {
	cfg := perOp(func() (any, error) { return &failingUnsealer{inner: software()}, nil })
	requireOnlyPropertyFailures(t, cfg,
		"mode/interface pairing: this provider cannot serve ModePerOperation",
		"Protect/Unprotect round trip: *providertest_test.failingUnsealer does not implement enclave.KeyProtector, "+
			"which Config.Modes claims it serves ModePerOperation with",
	)
}

// emptyBlobProtector "protects" every key into an empty blob: a provider
// whose device returned nothing and that passed the nothing along.
type emptyBlobProtector struct{ inner *enclave.SoftwareProvider }

func (emptyBlobProtector) Protect(ctx context.Context, _ []byte) ([]byte, error) {
	return []byte{}, ctx.Err()
}

func (p emptyBlobProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}

// TestSuiteCatchesAnEmptyBlob pins the contract's non-empty-blob requirement:
// a Sealer that stored an empty blob would hold a value nothing can recover,
// and the tamper check has nothing to tamper with — which must read as a
// failure, not as a vacuous pass of every tamper case.
func TestSuiteCatchesAnEmptyBlob(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return emptyBlobProtector{inner: software()}, nil }),
		"Protect/Unprotect round trip: Protect returned an empty blob",
		"a blob this provider did not produce is refused: Protect returned an empty blob; nothing to tamper with")
}

// firstDestinationRewriter keeps the FIRST destination it was handed and
// writes the root into it again on every later call. The root is
// deterministic, so the destination the caller is still using never CHANGES —
// the overwrite direction of the spy cannot see this — and the defect is
// visible only once the caller has wiped those pages: the provider puts root
// material back into memory the caller has released.
type firstDestinationRewriter struct {
	inner *enclave.SoftwareProvider
	mu    sync.Mutex
	first []byte
}

func (p *firstDestinationRewriter) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := p.inner.UnsealRoot(ctx, dst); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.first == nil {
		p.first = dst
		return nil
	}
	copy(p.first, dst) // THE DEFECT.
	return nil
}

func TestSuiteCatchesARootWrittenIntoAWipedDestination(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return &firstDestinationRewriter{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := providertest.TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a RootUnsealer that writes root material into a destination the caller wiped")
	}
	if !strings.Contains(err.Error(), "UnsealRoot does not retain the caller's destination: the destination of "+
		"an earlier UnsealRoot was written again after the caller wiped it") {
		t.Fatalf("the suite failed, but not on the wiped-destination write:\n%v", err)
	}
	// The overwrite direction must NOT have fired: the root never changed, so
	// a report of it would be the wrong diagnosis.
	if strings.Contains(err.Error(), "by a later call") {
		t.Errorf("the overwrite arm fired on a destination whose contents never changed:\n%v", err)
	}
}

// hangingUnsealer blocks, until released, on any UnsealRoot made with an
// ended context. entered is closed when the first such call arrives.
type hangingUnsealer struct {
	inner   *enclave.SoftwareProvider
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *hangingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if ctx.Err() != nil {
		p.once.Do(func() { close(p.entered) })
		<-p.release
		return ctx.Err()
	}
	return p.inner.UnsealRoot(ctx, dst)
}

// TestAnUnfinishedEndedContextUnsealIsAnAbortNotAFinding is
// TestAnUnfinishedEndedContextCallIsAnAbortNotAFinding for UnsealRoot: the
// run's context ends while an ended-context UnsealRoot is still inside the
// provider, and the run is reported aborted with nothing charged to it.
func TestAnUnfinishedEndedContextUnsealIsAnAbortNotAFinding(t *testing.T) {
	p := &hangingUnsealer{inner: software(), entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(p.release) }) // frees the abandoned goroutine
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() {
		<-p.entered
		cancel()
	}()
	cfg := rootOnly(func() (any, error) { return p, nil })
	cfg.Logf = t.Logf
	assertAbortedOnly(t, providertest.TestProvider(ctx, cfg))
}

func TestMain(m *testing.M) {
	devcontainer.Refuse("providertest")
	os.Exit(m.Run())
}

// randKey and allZero are the suite-side equivalents of providertest's own
// unexported helpers, which the planted providers below use.
func randKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
