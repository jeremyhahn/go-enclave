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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// testMemlockRequirement is the locked memory this suite needs at once: about
// 1 MiB measured, doubled for headroom. Checked once, so a short environment
// fails with one actionable message rather than conformance failures that read
// as provider defects. An unbounded limit satisfies it.
const testMemlockRequirement = 2 << 20

func TestMain(m *testing.M) {
	lim, err := enclave.DiscoverLockedMemoryLimit()
	if err != nil {
		// The requirement cannot be checked, so it is not assumed met.
		fmt.Fprintf(os.Stderr, "cannot read RLIMIT_MEMLOCK to check the suite's %d-byte requirement: %v\n", testMemlockRequirement, err)
		os.Exit(2)
	}
	if lim.Bounded && lim.Bytes < testMemlockRequirement {
		fmt.Fprintf(os.Stderr, "providertest's tests need RLIMIT_MEMLOCK >= %d bytes (soft); this process has %d. "+
			"Raise it (ulimit -l %d, or the CI runner's --ulimit memlock).\n",
			testMemlockRequirement, lim.Bytes, testMemlockRequirement/1024)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// Every property this package checks has a planted provider here that
// violates exactly that property and nothing else, and the test asserts the
// suite fails and names the right property. A check whose planted violator
// still passes is a check that does not exist.

// ---------------------------------------------------------------------------
// The conforming baseline
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// wantFail runs the suite and requires it to fail, naming every string in
// wants, so a violator caught for the wrong reason does not count.
func wantFail(t *testing.T, cfg Config, wants ...string) {
	t.Helper()
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	err := TestProvider(t.Context(), cfg)
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
func perOp(new func() (any, error)) Config {
	return Config{New: new, Modes: []enclave.Mode{enclave.ModePerOperation}}
}

// rootOnly is the Config for a RootUnsealer-only violator.
func rootOnly(new func() (any, error)) Config {
	return Config{New: new, Modes: []enclave.Mode{enclave.ModeRootKey}}
}

// software is a fresh conforming provider, which most violators wrap so that
// the ONLY thing wrong with them is the property under test.
func software() enclave.SoftwareProvider { return enclave.NewSoftwareProvider() }

// ---------------------------------------------------------------------------
// THE HEADLINE CONTROL: a provider that retains a copy on purpose
// ---------------------------------------------------------------------------

// retainingProtector conforms in every visible way and keeps a copy of every
// key it recovers. Only the residue sweep can catch it: the spy watches the
// caller's slices, which this provider never touches after it returns.
type retainingProtector struct {
	inner enclave.SoftwareProvider
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
// TestSuiteCatchesAProviderThatRetainsACopy, in residue_linux_test.go, since
// the residue sweep exists only on Linux. Its non-Linux counterpart,
// TestResidueSweepReportsItselfNotRunOffLinux in residue_unsupported_test.go, pins
// that the suite reports the sweep unmeasured there instead of passing.

// TestResidueSweepSkipIsRecordedNotSilent pins that a skipped sweep is
// reported through Logf, so a green run cannot hide that it did not run.
func TestResidueSweepSkipIsRecordedNotSilent(t *testing.T) {
	var log strings.Builder
	cfg := perOp(func() (any, error) { return &retainingProtector{inner: software()}, nil })
	cfg.SkipResidueSweep = "the KMS response body is owned by net/http"
	cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }

	if err := TestProvider(t.Context(), cfg); err != nil {
		t.Fatalf("with the sweep skipped the retaining provider should pass everything else: %v", err)
	}
	if !strings.Contains(log.String(), "residue sweep SKIPPED") ||
		!strings.Contains(log.String(), "the KMS response body is owned by net/http") {
		t.Errorf("the skip was not reported with its recorded reason; a reader of this green run would not "+
			"know retention by copy went unmeasured. Log was:\n%s", log.String())
	}
}

// TestAnUnmeasuredResidueSweepIsNotAPass pins fail-closed: a sweep that could
// not measure returns an error matching ErrNotMeasured, never nil, unless the
// caller accepted that through SkipResidueSweep.
func TestAnUnmeasuredResidueSweepIsNotAPass(t *testing.T) {
	const property = "no copy of the key is findable in the process after Unprotect returns"
	tests := []struct {
		name  string
		sweep func([]byte, uintptr) ([]string, error)
	}{
		{"a blind control", func([]byte, uintptr) ([]string, error) { return nil, nil }},
		{"a sweep that cannot read memory", func([]byte, uintptr) ([]string, error) {
			return nil, errors.New("planted: /proc/self/mem unreadable")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := sweepProcess
			sweepProcess = tc.sweep
			t.Cleanup(func() { sweepProcess = orig })

			cfg := Config{
				New:   func() (any, error) { return software(), nil },
				Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
				Logf:  t.Logf,
			}
			err := TestProvider(t.Context(), cfg)
			if !errors.Is(err, ErrNotMeasured) {
				t.Fatalf("TestProvider = %v, want an error matching ErrNotMeasured", err)
			}
			var nm *NotMeasuredError
			if !errors.As(err, &nm) || nm.Property != property || nm.Reason == "" {
				t.Errorf("the unmeasured property is not a populated *NotMeasuredError for %q: %#v", property, nm)
			}
			var pe *PropertyError
			if errors.As(err, &pe) {
				t.Errorf("an unmeasured property was charged to the provider: %v", pe)
			}

			cfg.SkipResidueSweep = "this host cannot sweep; accepted for the test"
			if err := TestProvider(t.Context(), cfg); err != nil {
				t.Errorf("with SkipResidueSweep set the unmeasured sweep is accepted, got %v", err)
			}
		})
	}
}

// TestErrorMessagesNameThePackage pins the error-string prefix every error
// this package returns carries, so a joined report says where it came from.
func TestErrorMessagesNameThePackage(t *testing.T) {
	for _, err := range []error{
		&PropertyError{Property: "p", Detail: "d"},
		&stepError{step: "s", err: errors.New("e")},
		&NotMeasuredError{Property: "p", Reason: "r"},
		ErrNotMeasured,
	} {
		if msg := err.Error(); !strings.HasPrefix(msg, "providertest: ") ||
			strings.HasPrefix(msg, "providertest: providertest: ") {
			t.Errorf("%T renders %q; want exactly one \"providertest: \" prefix", err, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Retention by reference — what the spy is for
// ---------------------------------------------------------------------------

// aliasingProtector files the caller's slice rather than its contents
// (`= key` instead of `= bytes.Clone(key)`): a round trip passes and a wipe
// exposes it.
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
	inner enclave.SoftwareProvider
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
	inner enclave.SoftwareProvider
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

// onlyFirstUnprotectProtector recovers the key on its first Unprotect and
// reports success with zeros on every later one, the second call the spy
// checks make to disturb the first destination.
type onlyFirstUnprotectProtector struct {
	inner enclave.SoftwareProvider
	mu    sync.Mutex
	n     int
}

func (p *onlyFirstUnprotectProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *onlyFirstUnprotectProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n++; p.n > 1 {
		enclave.Wipe(key) // THE DEFECT: a later call returns nil without the key.
	}
	return nil
}

func TestSuiteCatchesASecondUnprotectWithoutTheKey(t *testing.T) {
	const want = "a second Unprotect returned nil but its destination does not hold the second key"
	wantFail(t, perOp(func() (any, error) { return &onlyFirstUnprotectProtector{inner: software()}, nil }),
		"Unprotect does not write into a destination the caller has finished with: "+want,
		"a later provider call does not disturb an earlier destination: "+want)
}

// sharedBufferProtector stages every recovered key in one buffer the instance
// owns, then copies it out after a pause standing in for a device round trip.
// Each access holds the lock, so the race detector stays quiet; the defect is
// that one buffer serves every call, so a concurrent Unprotect overwrites or
// wipes it during the pause and the caller receives what another call left.
type sharedBufferProtector struct {
	inner enclave.SoftwareProvider
	mu    sync.Mutex
	buf   [keyBytes]byte
}

func (p *sharedBufferProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *sharedBufferProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if len(key) != keyBytes {
		return p.inner.Unprotect(ctx, blob, key)
	}
	p.mu.Lock()
	err := p.inner.Unprotect(ctx, blob, p.buf[:])
	p.mu.Unlock()
	if err != nil {
		return err
	}
	time.Sleep(time.Millisecond)
	p.mu.Lock()
	defer p.mu.Unlock()
	copy(key, p.buf[:])
	clear(p.buf[:])
	return nil
}

func TestSuiteCatchesAProviderSharingABufferAcrossCalls(t *testing.T) {
	wantOnlyProperty(t, perOp(func() (any, error) { return &sharedBufferProtector{inner: software()}, nil }),
		"Protect and Unprotect are safe for concurrent use", "Unprotect returned nil but wrote")
}

// ---------------------------------------------------------------------------
// The controls that keep the spy from reading a false green
// ---------------------------------------------------------------------------

// silentProtector returns nil from Unprotect and writes nothing, so it passes
// every retention assertion for the wrong reason. Only the at-return-time
// control separates it from a conforming provider.
type silentProtector struct{ inner enclave.SoftwareProvider }

func (p *silentProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}
func (p *silentProtector) Unprotect(ctx context.Context, _, _ []byte) error { return ctx.Err() }

func TestSuiteCatchesADestinationThatIsNeverPopulated(t *testing.T) {
	cfg := perOp(func() (any, error) { return &silentProtector{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose Unprotect writes nothing; every retention assertion was vacuous")
	}
	// Both spies must report that their setup did not hold, rather than
	// scoring a zeroed destination as a pass.
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

// unauthenticatedProtector authenticates a prefix of the blob and ignores the
// rest: confidentiality without integrity. The "device" is a map whose lookup
// key is shorter than the blob.
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

// forgeableProtector carries an unauthenticated tail in the blob that chooses
// what the blob opens to, the bare RSA-OAEP shape the KeyProtector contract
// disqualifies. It is separate from unauthenticatedProtector because its
// forgery yields something other than the real key, so only the "Unprotect
// ACCEPTED this blob" arm catches it; the plaintext-in-destination check
// cannot.
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
	if memscan.AllZero(tail) {
		copy(key, k)
		return nil
	}
	// The defect: the unauthenticated tail chooses the material.
	copy(key, tail)
	return nil
}

func TestSuiteCatchesAForgeryOpeningToAttackerChosenMaterial(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newForgeableProtector(), nil }),
		"Unprotect ACCEPTED")
}

// publicKeyWrapProtector wraps each key to a P-256 public key (an ephemeral
// key agreement, then AES-GCM under the agreed secret), the ECIES shape of a
// TPM or KMS public-key wrap. Without a signer it is the bare wrap the
// KeyProtector contract disqualifies: its tag refuses every tampered blob, so
// it passes every other check, yet anyone holding the public key builds a blob
// it opens. With a signer it signs each wrap and verifies before opening, the
// composition the contract requires.
type publicKeyWrapProtector struct {
	priv   *ecdh.PrivateKey
	signer ed25519.PrivateKey
}

// p256PublicBytes is the length of an uncompressed P-256 public key. P-256 is
// used because X25519 is prohibited under GODEBUG=fips140=only.
const p256PublicBytes = 65

func newPublicKeyWrapProtector(signed bool) (*publicKeyWrapProtector, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p := &publicKeyWrapProtector{priv: priv}
	if signed {
		if _, p.signer, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// wrapTo is the half of the wrap that needs only the public key: what Protect
// does, and what an attacker does.
func wrapTo(pub *ecdh.PublicKey, key []byte) ([]byte, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	aead, err := wrapAEAD(eph, pub)
	if err != nil {
		return nil, err
	}
	return aead.Seal(eph.PublicKey().Bytes(), nil, key, nil), nil
}

// wrapAEAD derives the AEAD of one wrap. The nonce is random and travels with
// the ciphertext because fips140=only refuses a caller-chosen GCM nonce.
func wrapAEAD(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	kek := sha256.Sum256(shared)
	clear(shared)
	block, err := aes.NewCipher(kek[:])
	clear(kek[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// forgeWrap is Config.Forge for publicKeyWrapProtector: the attacker wraps to
// the public key and, if the provider expects a signature, signs with a key of
// its own.
func forgeWrap(kp enclave.KeyProtector, key []byte) ([]byte, error) {
	p := kp.(*publicKeyWrapProtector)
	blob, err := wrapTo(p.priv.PublicKey(), key)
	if err != nil || p.signer == nil {
		return blob, err
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return append(blob, ed25519.Sign(attacker, blob)...), nil
}

func (p *publicKeyWrapProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blob, err := wrapTo(p.priv.PublicKey(), key)
	if err != nil || p.signer == nil {
		return blob, err
	}
	return append(blob, ed25519.Sign(p.signer, blob)...), nil
}

func (p *publicKeyWrapProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.signer != nil {
		if len(blob) < ed25519.SignatureSize {
			return enclave.ErrSealedAuthentication
		}
		wrap, sig := blob[:len(blob)-ed25519.SignatureSize], blob[len(blob)-ed25519.SignatureSize:]
		if !ed25519.Verify(p.signer.Public().(ed25519.PublicKey), wrap, sig) {
			return enclave.ErrSealedAuthentication
		}
		blob = wrap
	}
	if len(key) != keyBytes || len(blob) < p256PublicBytes {
		return enclave.ErrSealedAuthentication
	}
	eph, err := ecdh.P256().NewPublicKey(blob[:p256PublicBytes])
	if err != nil {
		return enclave.ErrSealedAuthentication
	}
	aead, err := wrapAEAD(p.priv, eph)
	if err != nil {
		return enclave.ErrSealedAuthentication
	}
	if len(blob) != p256PublicBytes+keyBytes+aead.Overhead() {
		return enclave.ErrSealedAuthentication
	}
	// Opened straight into the caller's destination, so there is no transient
	// to wipe; GCM clears it if the tag does not verify.
	if _, err := aead.Open(key[:0], nil, blob[p256PublicBytes:], nil); err != nil {
		return enclave.ErrSealedAuthentication
	}
	return nil
}

// publicKeyWrap configures publicKeyWrapProtector as a public-key provider
// whose Forge is forgeWrap.
func publicKeyWrap(signed bool) Config {
	cfg := perOp(func() (any, error) { return newPublicKeyWrapProtector(signed) })
	cfg.PublicKey = true
	cfg.Forge = forgeWrap
	return cfg
}

const forgeryProperty = "a blob forged from the provider's public key is refused"

func TestSuiteCatchesABarePublicKeyWrap(t *testing.T) {
	wantOnlyProperty(t, publicKeyWrap(false), forgeryProperty,
		"Unprotect ACCEPTED a blob Config.Forge built", "the key the attacker chose")
}

func TestASignedPublicKeyWrapConforms(t *testing.T) {
	cfg := publicKeyWrap(true)
	cfg.Logf = t.Logf
	if err := TestProvider(t.Context(), cfg); err != nil {
		t.Fatalf("a public-key wrap that verifies a signature before opening must pass: %v", err)
	}
}

// TestAPublicKeyProviderWithoutForgeIsNotMeasured also shows why Forge
// exists: with the forgery accepted as unmeasured, the bare wrap passes every
// other check, the tampered-blob cases included.
func TestAPublicKeyProviderWithoutForgeIsNotMeasured(t *testing.T) {
	cfg := publicKeyWrap(false)
	cfg.Forge = nil
	cfg.Logf = t.Logf
	err := TestProvider(t.Context(), cfg)
	if !errors.Is(err, ErrNotMeasured) {
		t.Fatalf("TestProvider = %v, want an error matching ErrNotMeasured", err)
	}
	var nm *NotMeasuredError
	if !errors.As(err, &nm) || nm.Property != forgeryProperty || !strings.Contains(nm.Reason, "Config.Forge is nil") {
		t.Errorf("the unmeasured forgery is not a populated *NotMeasuredError for %q: %#v", forgeryProperty, nm)
	}
	var pe *PropertyError
	if errors.As(err, &pe) {
		t.Errorf("an unmeasured property was charged to the provider: %v", pe)
	}

	var log strings.Builder
	cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }
	cfg.SkipForgery = "the forgery is tested in the device's own suite"
	if err := TestProvider(t.Context(), cfg); err != nil {
		t.Fatalf("with SkipForgery set the bare wrap should pass everything else: %v", err)
	}
	if !strings.Contains(log.String(), "forged-blob check SKIPPED") ||
		!strings.Contains(log.String(), cfg.SkipForgery) {
		t.Errorf("the skip was not reported with its recorded reason. Log was:\n%s", log.String())
	}
}

func TestAForgeThatFailsIsReported(t *testing.T) {
	tests := []struct {
		name  string
		forge func(enclave.KeyProtector, []byte) ([]byte, error)
		want  string
	}{
		{"an error", func(enclave.KeyProtector, []byte) ([]byte, error) {
			return nil, errors.New("planted: no public key")
		}, "Config.Forge: planted: no public key"},
		{"an empty blob", func(enclave.KeyProtector, []byte) ([]byte, error) {
			return []byte{}, nil
		}, "Config.Forge returned an empty blob"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := publicKeyWrap(true)
			cfg.Forge = tc.forge
			wantOnlyProperty(t, cfg, forgeryProperty, tc.want)
		})
	}
}

// wantOnlyProperty requires the run to fail on property, with every finding a
// *PropertyError for it: the planted provider violates that property and
// nothing else.
func wantOnlyProperty(t *testing.T, cfg Config, property string, wants ...string) {
	t.Helper()
	cfg.Logf = t.Logf
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatalf("the suite PASSED a provider that deliberately violates %q; the check does not exist", property)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the suite failed, but not on %q:\n%v", want, err)
		}
	}
	var findings *FindingsError
	if !errors.As(err, &findings) {
		t.Fatalf("TestProvider returned %T, want a *FindingsError holding the property failures", err)
	}
	for _, e := range findings.Findings {
		var pe *PropertyError
		if !errors.As(e, &pe) || pe.Property != property {
			t.Errorf("a finding is not a *PropertyError for %q: %v", property, e)
		}
	}
}

func TestSuiteCatchesAnUnauthenticatedProvider(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return newUnauthenticatedProtector(), nil }),
		"a blob this provider did not produce is refused")
}

// wrongErrorProtector refuses forgeries but reports them as infrastructure
// faults rather than ErrSealedAuthentication.
type wrongErrorProtector struct{ inner enclave.SoftwareProvider }

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
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider that reports forgeries as device faults")
	}
	// Bound to the tamper property by name: the wrong-length check emits the
	// same sentence, so a bare phrase search would not pin the tamper path.
	if !strings.Contains(err.Error(), "a blob this provider did not produce is refused: Unprotect refused") ||
		!strings.Contains(err.Error(), "want an error matching ErrSealedAuthentication") {
		t.Fatalf("the suite failed, but not on the error KIND of a refused FORGERY:\n%v", err)
	}
}

// decryptBeforeAuthenticateProtector leaves the recovered key in the caller's
// destination and then reports failure.
type decryptBeforeAuthenticateProtector struct {
	inner enclave.SoftwareProvider
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
type mutatingProtector struct{ inner enclave.SoftwareProvider }

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
// reports success. It is the only violator that pins the "Unprotect accepted
// a wrong-length destination" arm: looseLengthProtector is also caught by the
// plaintext-in-destination check.
type silentLengthProtector struct{ inner enclave.SoftwareProvider }

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

// shortDestinationLeakProtector refuses a wrong-length destination with
// ErrSealedAuthentication after it has already written the key into it. It
// pins the plaintext-in-destination check on the length path.
type shortDestinationLeakProtector struct {
	inner enclave.SoftwareProvider
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

// stubRootProvider is a correct KeyProtector carrying a placeholder
// UnsealRoot. A Sealer cannot tell the placeholder from an unseal, so in
// ModeRootKey it would seal everything under a constant.
type stubRootProvider struct{ inner enclave.SoftwareProvider }

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
type keyProtectorOnly struct{ inner enclave.SoftwareProvider }

func (p *keyProtectorOnly) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}
func (p *keyProtectorOnly) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}

func TestSuiteCatchesAClaimedModeTheProviderCannotServe(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return &keyProtectorOnly{inner: software()}, nil })
	cfg.Logf = t.Logf
	err := TestProvider(t.Context(), cfg)
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
type halfWritingUnsealer struct{ inner enclave.SoftwareProvider }

func (p *halfWritingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	// The full root comes from a locked scratch enclave, so a partial write is
	// the only thing this fixture gets wrong.
	scratch, err := enclave.NewMemorySized(enclave.RootKeyBytes)
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

// nondeterministicUnsealer hands a different root to every caller.
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

// canaryCollidingUnsealer writes a different fixed root on each call, chosen
// so that byte 0 matches the suite's first two canaries: 0xAA on call 1, 0x55
// on call 2, and neither on any later call. It writes every byte every time.
type canaryCollidingUnsealer struct{ calls int }

func (u *canaryCollidingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u.calls++
	rest, head := byte(0x33), byte(0x66)
	switch u.calls {
	case 1:
		rest, head = 0x11, 0xAA
	case 2:
		rest, head = 0x22, 0x55
	}
	for i := range dst {
		dst[i] = rest
	}
	dst[0] = head
	return nil
}

func TestSuiteCatchesANondeterministicRootThatMatchesTheCanaries(t *testing.T) {
	cfg := rootOnly(func() (any, error) { return &canaryCollidingUnsealer{}, nil })
	wantFail(t, cfg, "DIFFERENT roots")
	cfg.Logf = t.Logf
	if err := TestProvider(t.Context(), cfg); strings.Contains(err.Error(), "UNWRITTEN") {
		t.Fatalf("the suite read a root that changes per call as unwritten bytes:\n%v", err)
	}
}

// thirdCallFailingUnsealer writes a different root on each of its first two
// calls and fails every call after, so the suite's third call, the one that
// tells unwritten bytes from a root that changes per call, is what fails.
type thirdCallFailingUnsealer struct{ calls int }

func (u *thirdCallFailingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	u.calls++
	if u.calls >= 3 {
		return errors.New("the device refuses a third unseal")
	}
	for i := range dst {
		dst[i] = byte(u.calls*0x10 + i)
	}
	return nil
}

func TestSuiteCatchesARootUnsealerWhoseThirdCallFails(t *testing.T) {
	wantFail(t, rootOnly(func() (any, error) { return &thirdCallFailingUnsealer{}, nil }),
		"a third UnsealRoot on the same provider: the device refuses a third unseal", "Config.SingleUseRoot")
}

// rootDestRetainer keeps the destination it was handed and wipes it on the next
// call, leaving a Sealer running its whole KEK hierarchy under zeros.
type rootDestRetainer struct {
	inner enclave.SoftwareProvider
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

// oneShotUnsealer consumes its handle on a successful unseal and refuses every
// call after the first. It satisfies the seam, which guarantees only that a
// Sealer calls UnsealRoot at most once.
type oneShotUnsealer struct {
	inner enclave.SoftwareProvider
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

// TestSingleUseRootIsAccommodatedAndRecorded pins that a one-shot root fails
// by default and passes with Config.SingleUseRoot set, with the relaxation
// reported through Logf.
func TestSingleUseRootIsAccommodatedAndRecorded(t *testing.T) {
	newOneShot := func() (any, error) { return &oneShotUnsealer{inner: software()}, nil }

	t.Run("refused by default, and the message names the remedy", func(t *testing.T) {
		cfg := rootOnly(newOneShot)
		cfg.Logf = t.Logf
		err := TestProvider(t.Context(), cfg)
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

		if err := TestProvider(t.Context(), cfg); err != nil {
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
			if err := TestProvider(t.Context(), cfg); err == nil {
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
	err := TestProvider(t.Context(), cfg)
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
		cfg   Config
		want  string
		field string
	}{
		{
			name:  "no provider",
			cfg:   Config{Modes: []enclave.Mode{enclave.ModeRootKey}},
			want:  "Config.New is nil",
			field: "New",
		},
		{
			name:  "no modes claimed",
			cfg:   Config{New: func() (any, error) { return software(), nil }},
			want:  "Config.Modes is empty",
			field: "Modes",
		},
		{
			name: "a mode that names nothing",
			cfg: Config{
				New:   func() (any, error) { return software(), nil },
				Modes: []enclave.Mode{enclave.Mode(99)},
			},
			want:  "Config.Modes contains Mode(99), which names no sealing mode",
			field: "Modes",
		},
		{
			name: "a public-key declaration without a KeyProtector claim",
			cfg: Config{
				New:       func() (any, error) { return software(), nil },
				Modes:     []enclave.Mode{enclave.ModeRootKey},
				PublicKey: true,
			},
			want:  "Config.PublicKey is set, but Config.Modes does not claim ModePerOperation",
			field: "PublicKey",
		},
		{
			name: "a forge without a KeyProtector claim",
			cfg: Config{
				New:   func() (any, error) { return software(), nil },
				Modes: []enclave.Mode{enclave.ModeRootKey},
				Forge: forgeWrap,
			},
			want:  "Config.Forge is set, but Config.Modes does not claim ModePerOperation",
			field: "Forge",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := TestProvider(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("TestProvider(%s) = nil, want a configuration error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("TestProvider(%s) = %v, want it to mention %q", tc.name, err, tc.want)
			}
			// A harness mistake must be distinguishable from a provider
			// defect without parsing the message.
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("TestProvider(%s) = %v, want an error matching ErrInvalidConfig", tc.name, err)
			}
			var ce *ConfigError
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
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose Unprotect writes nothing")
	}
	if errors.Is(err, ErrInvalidConfig) {
		t.Errorf("a provider defect matched ErrInvalidConfig:\n%v", err)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("TestProvider returned %T, want a joined error that can be walked per property", err)
	}
	for _, e := range joined.Unwrap() {
		var pe *PropertyError
		if !errors.As(e, &pe) || pe.Property == "" || pe.Detail == "" {
			t.Errorf("a failure is not a populated *PropertyError: %#v", e)
		}
	}
}

// TestSuiteRefusesATypedNilProvider pins that a (*stubRootProvider)(nil),
// which satisfies both seam interfaces, is reported as a failure rather than
// panicking inside the suite. The subtests cover both the KeyProtector and the
// RootUnsealer entry paths.
func TestSuiteRefusesATypedNilProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "typed nil, ModePerOperation",
			cfg:  perOp(func() (any, error) { return (*stubRootProvider)(nil), nil }),
		},
		{
			name: "typed nil, ModeRootKey",
			cfg:  rootOnly(func() (any, error) { return (*stubRootProvider)(nil), nil }),
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
			// A panic here fails the test: the suite must report this.
			err := TestProvider(t.Context(), cfg)
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
	err := TestProvider(t.Context(), cfg)
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

// TestIsNilProvider pins the classifier in both directions.
func TestIsNilProvider(t *testing.T) {
	var nilPtr *stubRootProvider
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

// TestContainsRun pins the partial-write detector.
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
	// A needle shorter than the window is never found, even whole: a run that
	// short is a chance collision, not evidence.
	t.Run("a needle shorter than the window", func(t *testing.T) {
		if containsRun(bytes.Clone(key), key[:plaintextRunBytes-1]) {
			t.Error("containsRun matched a needle shorter than its window")
		}
	})
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

// ---------------------------------------------------------------------------
// The context contract
// ---------------------------------------------------------------------------

// endedContextProtector wraps the software provider and, when the context it
// is handed has ended, does exactly the one wrong thing its fields select.
// Each defect kills exactly one assertion of the ended-context check.
type endedContextProtector struct {
	inner enclave.SoftwareProvider

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
	inner enclave.SoftwareProvider

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
			// A one-shot provider runs with the relaxation an honest one would
			// set, so the finding must come from the context check, not from
			// the default's second call.
			cfg.SingleUseRoot = "the test violator models a one-shot handle"
			wantFail(t, cfg, property+": ", tc.want)
		})
	}
}

// rootKeepingUnsealer writes the root into every ended-context destination
// and keeps the slice, so a test can read what the suite left in it. When
// hold is set, an ended-context call blocks until release is closed.
type rootKeepingUnsealer struct {
	inner   enclave.SoftwareProvider
	accept  bool
	hold    bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	kept    [][]byte
}

func (u *rootKeepingUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if ctx.Err() == nil {
		return u.inner.UnsealRoot(ctx, dst)
	}
	if err := u.inner.UnsealRoot(context.WithoutCancel(ctx), dst); err != nil {
		return err
	}
	u.mu.Lock()
	u.kept = append(u.kept, dst)
	u.mu.Unlock()
	if u.hold {
		u.once.Do(func() { close(u.entered) })
		<-u.release
	}
	if u.accept {
		return nil
	}
	return ctx.Err()
}

// keptAllZero reports whether every destination u kept is all zero.
func (u *rootKeepingUnsealer) keptAllZero() (n int, zero bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, d := range u.kept {
		if !memscan.AllZero(d) {
			return len(u.kept), false
		}
	}
	return len(u.kept), true
}

// TestEndedContextRootDestinationsAreWiped pins that a destination handed to
// an ended-context UnsealRoot never keeps root material on the heap once the
// check is done with it, whether the provider refused, accepted, or was
// abandoned mid-call.
func TestEndedContextRootDestinationsAreWiped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept bool
	}{{"refused", false}, {"accepted", true}} {
		t.Run(tc.name, func(t *testing.T) {
			u := &rootKeepingUnsealer{inner: software(), accept: tc.accept}
			cfg := rootOnly(func() (any, error) { return u, nil })
			cfg.Logf = t.Logf
			if err := TestProvider(t.Context(), cfg); err == nil {
				t.Fatal("the suite passed a provider that writes the root on an ended context")
			}
			if n, zero := u.keptAllZero(); n == 0 || !zero {
				t.Errorf("%d ended-context destination(s) kept; all wiped: %v", n, zero)
			}
		})
	}

	t.Run("abandoned", func(t *testing.T) {
		u := &rootKeepingUnsealer{inner: software(), hold: true,
			entered: make(chan struct{}), release: make(chan struct{})}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			<-u.entered
			cancel()
		}()
		cfg := rootOnly(func() (any, error) { return u, nil })
		cfg.Logf = t.Logf
		if err := TestProvider(ctx, cfg); !errors.Is(err, ErrAborted) {
			t.Fatalf("TestProvider = %v, want an abort", err)
		}
		if n, zero := u.keptAllZero(); n != 1 || zero {
			t.Fatalf("before the abandoned call returned: %d kept, all zero %v; want 1 holding the root "+
				"(nothing may touch a destination a provider is still running against)", n, zero)
		}
		wiped := make(chan struct{})
		abandonedCleanupHook = func() { close(wiped) }
		t.Cleanup(func() { abandonedCleanupHook = nil })
		close(u.release)
		select {
		case <-wiped:
		case <-time.After(10 * time.Second):
			t.Fatal("the abandoned call returned and its worker never cleaned up")
		}
		if _, zero := u.keptAllZero(); !zero {
			t.Error("the abandoned call returned, and its destination still holds the root")
		}
	})
}

// hangingOnEndedContext blocks, until released, on any call made with an
// ended context. acceptProtect additionally makes Protect complete an
// ended-context call, a violation the suite observes before the hang. entered
// is closed when the first hanging call arrives.
type hangingOnEndedContext struct {
	inner         enclave.SoftwareProvider
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
	return TestProvider(ctx, cfg)
}

// TestAnUnfinishedEndedContextCallIsAnAbortNotAFinding pins that a call the
// suite stopped waiting for is reported as an aborted run with nothing charged
// to the provider: the worker goroutine may never have reached it.
func TestAnUnfinishedEndedContextCallIsAnAbortNotAFinding(t *testing.T) {
	err := runAgainstHanging(t, newHanging(false))
	assertAbortedOnly(t, err)
}

// TestViolationsObservedBeforeAnAbortAreKept pins that an abort does not
// erase what the suite observed while the run's context was live: Protect
// completes an ended-context call, then Unprotect hangs until the run's
// context ends.
func TestViolationsObservedBeforeAnAbortAreKept(t *testing.T) {
	err := runAgainstHanging(t, newHanging(true))
	if !errors.Is(err, ErrAborted) {
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
// check, after every control has run, so the bounded wait that follows finds
// the run already over whether or not its worker goroutine has started.
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
	assertAbortedOnly(t, TestProvider(ctx, cfg))
}

// TestAnAbortedRunIsNeverAPass pins that a run whose context has ended returns
// an error matching ErrAborted, never nil, and does not charge the provider
// with failures that are only the provider honoring that context.
func TestAnAbortedRunIsNeverAPass(t *testing.T) {
	t.Run("ended before the run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := TestProvider(ctx, Config{
			New:   func() (any, error) { return software(), nil },
			Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
			Logf:  t.Logf,
		})
		assertAbortedOnly(t, err)
	})

	t.Run("ended mid-run, by the provider's own call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// The run's context ends inside a provider call and the provider honors
		// it, as a conforming provider does; that must not be scored a defect.
		p := &cancellingProtector{inner: software(), cancel: cancel}
		err := TestProvider(ctx, Config{
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
	inner  enclave.SoftwareProvider
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
	if !errors.Is(err, ErrAborted) || !errors.Is(err, context.Canceled) {
		t.Errorf("TestProvider = %v, want an error matching ErrAborted and context.Canceled", err)
	}
	var ae *AbortedError
	if !errors.As(err, &ae) || !errors.Is(ae.Cause, context.Canceled) {
		t.Errorf("TestProvider = %#v, want an *AbortedError carrying the context's error", err)
	}
	var pe *PropertyError
	if errors.As(err, &pe) {
		t.Errorf("an aborted run charged the provider with %q; a call refused because the RUN's context "+
			"ended is the provider conforming, not failing", pe)
	}
}

// ---------------------------------------------------------------------------
// A provider call that fails is a finding, never a pass
// ---------------------------------------------------------------------------
//
// Every provider call a check makes can fail on a real device. These tests
// drive each call ordinal to failure in turn and require the run to fail under
// the right property, naming the call and carrying the device's own error.

// errDeviceFault is the failure the planted providers below report.
var errDeviceFault = errors.New("device: transient fault")

// failingProtector is the software provider with one call refused: the
// failProtect-th Protect or the failUnprotect-th Unprotect on this instance,
// counting from 1 and including ended-context calls. Zero refuses nothing.
type failingProtector struct {
	inner                      enclave.SoftwareProvider
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
	inner  enclave.SoftwareProvider
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
func requireOnlyPropertyFailures(t *testing.T, cfg Config, wants ...string) {
	t.Helper()
	cfg.Logf = t.Logf
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a provider whose device refused a call it needed; the failure branch " +
			"returned as if the property held")
	}
	if errors.Is(err, ErrAborted) || errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("TestProvider = %v; want property failures, not an abort or a Config refusal", err)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("TestProvider returned %T, want the joined property failures", err)
	}
	for _, e := range joined.Unwrap() {
		var pe *PropertyError
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

// TestSuiteReportsAProviderThatCannotBeConstructed pins that when Config.New
// fails, every claimed property fails, naming Config.New and the constructor's
// error.
func TestSuiteReportsAProviderThatCannotBeConstructed(t *testing.T) {
	cfg := Config{
		New:   func() (any, error) { return nil, errDeviceFault },
		Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
	}
	want := "providertest: Config.New: " + errDeviceFault.Error()
	requireOnlyPropertyFailures(t, cfg,
		"mode/interface pairing: "+want,
		"Protect/Unprotect round trip: "+want,
		"Protect does not retain the caller's key slice: "+want,
		"Unprotect does not write into a destination the caller has finished with: "+want,
		"a later provider call does not disturb an earlier destination: "+want,
		"a blob this provider did not produce is refused: "+want,
		"a destination of the wrong length is an authentication failure: "+want,
		"Protect and Unprotect refuse a context that has already ended: "+want,
		"UnsealRoot writes a root across the whole destination: "+want,
		"UnsealRoot does not retain the caller's destination: "+want,
		"UnsealRoot refuses a context that has already ended, and consumes nothing: "+want,
	)

	// The step error keeps the constructor's error matchable, not merely
	// printable.
	_, err := newProvider(cfg)
	if !errors.Is(err, errDeviceFault) {
		t.Errorf("newProvider = %v, want it to wrap the constructor's error so errors.Is reaches it", err)
	}
}

// TestSuiteReportsAKeyProtectorClaimTheProviderCannotServe is the
// KeyProtector half of the missing-seam path: Config.Modes claims
// ModePerOperation for a provider that only unseals roots, and every
// KeyProtector check names the missing interface rather than panicking on a
// failed type assertion or skipping itself.
func TestSuiteReportsAKeyProtectorClaimTheProviderCannotServe(t *testing.T) {
	cfg := perOp(func() (any, error) { return &failingUnsealer{inner: software()}, nil })
	requireOnlyPropertyFailures(t, cfg,
		"mode/interface pairing: this provider cannot serve ModePerOperation",
		"Protect/Unprotect round trip: *providertest.failingUnsealer does not implement enclave.KeyProtector, "+
			"which Config.Modes claims it serves ModePerOperation with",
	)
}

// emptyBlobProtector "protects" every key into an empty blob.
type emptyBlobProtector struct{ inner enclave.SoftwareProvider }

func (emptyBlobProtector) Protect(ctx context.Context, _ []byte) ([]byte, error) {
	return []byte{}, ctx.Err()
}

func (p emptyBlobProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.inner.Unprotect(ctx, blob, key)
}

// TestSuiteCatchesAnEmptyBlob pins the non-empty-blob requirement, and that
// the tamper check reports an empty blob as a failure rather than vacuously
// passing every case.
func TestSuiteCatchesAnEmptyBlob(t *testing.T) {
	wantFail(t, perOp(func() (any, error) { return emptyBlobProtector{inner: software()}, nil }),
		"Protect/Unprotect round trip: Protect returned an empty blob",
		"a blob this provider did not produce is refused: Protect returned an empty blob; nothing to tamper with")
}

// firstDestinationRewriter keeps the first destination it was handed and
// writes the root into it again on every later call. The root is
// deterministic, so only the caller-wiped direction of the spy can see it.
type firstDestinationRewriter struct {
	inner enclave.SoftwareProvider
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
	err := TestProvider(t.Context(), cfg)
	if err == nil {
		t.Fatal("the suite PASSED a RootUnsealer that writes root material into a destination the caller wiped")
	}
	if !strings.Contains(err.Error(), "UnsealRoot does not retain the caller's destination: the destination of "+
		"an earlier UnsealRoot was written again after the caller wiped it") {
		t.Fatalf("the suite failed, but not on the wiped-destination write:\n%v", err)
	}
	// The overwrite direction must not have fired: the root never changed.
	if strings.Contains(err.Error(), "by a later call") {
		t.Errorf("the overwrite arm fired on a destination whose contents never changed:\n%v", err)
	}
}

// hangingUnsealer blocks, until released, on any UnsealRoot made with an
// ended context. entered is closed when the first such call arrives.
type hangingUnsealer struct {
	inner   enclave.SoftwareProvider
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
	assertAbortedOnly(t, TestProvider(ctx, cfg))
}
