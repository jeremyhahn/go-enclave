// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package providertest is the conformance suite for the go-enclave provider
// seam. go-enclave ships it; anything implementing [enclave.KeyProtector] or
// [enclave.RootUnsealer] — a TPM, an HSM, a cloud KMS — runs it against its own
// provider, in its own repository, with no dependency in the other direction.
// The shape is [testing/fstest.TestFS]'s: one call, an error naming every
// property that failed, and no import of testing.
//
// # The property this suite exists for is RETENTION, not destination
//
//	Unprotect(ctx context.Context, blob, key []byte) error
//	UnsealRoot(ctx context.Context, dst []byte) error
//
// Those signatures constrain where the plaintext is WRITTEN. They constrain
// nothing about what the provider KEEPS. A provider may write into the caller's
// locked slice and hold its own copy indefinitely, and from go-enclave's side a
// conforming signature and a retaining implementation are indistinguishable.
// That is the unenforced half of [enclave.KeyProtector]'s "protects short key
// material outside this process", and this package is the enforcement.
//
// # What this suite deliberately does NOT assert
//
// It does not assert that a provider never materializes plaintext in its own
// memory. That is unsatisfiable and a suite demanding it would fail every real
// backend: measured against go-xkms's, every one returns a fresh slice from its
// decrypt — the native TPM2 path is RSADecrypt(...) ([]byte, error), the PKCS#11
// wrapper returns a slice, and the AWS, GCP, Azure and Vault backends return
// HTTP response bodies. No hardware decrypts directly into an arbitrary caller
// page. So a conforming provider materializes the plaintext in its own heap and
// copies into the destination; what it must then do is WIPE that transient,
// which is what [enclave.KeyProtector] already requires in words and what the
// residue sweep here measures.
//
// The bulk-AEAD key schedule is likewise out of scope. crypto/aes expands a key
// into ordinary heap on every seal and open; that is inside the FIPS 140-3
// validated Go Cryptographic Module and is accepted under the validated-primitive
// carve-out. Nothing here fails on it.
//
// # The instruments, and why there are two of them in this order
//
// A conformance suite that cannot fail is worse than none, because it certifies.
// Two instruments carry the retention property, and their ranking is not
// stylistic:
//
// The SPY is primary and deterministic. The suite is the caller, so it owns
// every slice the provider is handed and can watch each one afterwards. It
// records the exact destination handed to an [enclave.KeyProtector.Unprotect],
// asserts under a control that the destination held the material at return
// time — without that control a later zero reading cannot be told apart from a
// destination that was never populated at all — and then asserts that no
// subsequent provider call disturbs it, in both directions: a populated
// destination must not be overwritten or wiped, and a caller-wiped destination
// must not be written into again. The same instrument, pointed at Protect's
// input, catches a provider that filed the caller's slice by reference instead
// of copying out of it. None of this can be vacuous: every assertion has a
// control that fails first if the setup did not happen.
//
// The RESIDUE SWEEP is corroboration, and it is second for measured reasons.
// It is the only instrument that can see a retained COPY, so it cannot be
// dropped; but a sweep whose scan buffer is not wiped replants its own needle
// and reports a leak that never existed, and a sweep-based residue claim is
// UNFALSIFIABLE for anything that transits a stack local — a stack growth
// between the fill and the wipe strands the pre-wipe bytes on the freed old
// stack, where no wipe reaches. Both were measured in this repository (#45).
// The sweep here wipes its buffer after every mapping, refuses to report a
// negative it has not first proven it could turn positive, and is skippable
// with a recorded reason for a provider whose transit genuinely cannot be
// reached — an HTTP-backed KMS cannot wipe its client's read buffer.
//
// # Context: the suite honors one, and checks that the provider does
//
// [TestProvider] takes a context and passes it to every provider call it
// makes, so a device-backed run can be bounded from the outside. A run whose
// context ends before it finishes returns an error matching [ErrAborted]: an
// incomplete run is not a verdict, and it never returns nil.
//
// The provider's half of the seam's context contract (see
// [enclave.RootUnsealer]) is checked for every claimed mode: a call made with
// a context that has ALREADY been canceled, or whose deadline has already
// passed, must be refused with an error matching that context's error — not
// accepted, and not reported as [enclave.ErrSealedAuthentication] — must
// write no key material into its destination, and must consume nothing a
// later call needs. What the suite cannot force is cancellation arriving
// MID-call, since only the provider can hold a call open; that half of the
// contract is unmeasured here. Calls made with an ended context run on their
// own goroutine, so a provider that never returns from one cannot hold a run
// whose own context is bounded: when the run's context ends first, the run
// is reported ABORTED — not as a provider failure, because an unfinished call
// proves only that the run stopped waiting, not that the provider did device
// work (the goroutine may not even have been scheduled). Violations observed
// before that point are still reported. With an unbounded run context such a
// provider hangs the run, where go test's -timeout reports it with the
// provider's stack.
//
// # Usage
//
//	func TestConformance(t *testing.T) {
//		err := providertest.TestProvider(t.Context(), providertest.Config{
//			New:   func() (any, error) { return NewTPMProvider(dev) },
//			Modes: []enclave.Mode{enclave.ModePerOperation},
//			Logf:  t.Logf,
//		})
//		if err != nil {
//			t.Fatal(err)
//		}
//	}
package providertest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// keyBytes is the key length every check protects and recovers. It is
// [enclave.RootKeyBytes] because that is the only length go-enclave ever hands
// a provider: the per-operation DEK and the root are both 32 bytes.
const keyBytes = enclave.RootKeyBytes

// Config describes the provider under test.
type Config struct {
	// New returns a provider ready for use. It is called a bounded number of
	// times — once per check group — so that a check which leaves a provider in
	// a terminal state (a spent message budget, a wiped root) cannot silently
	// change the meaning of the next one.
	//
	// The instances need NOT be independent of each other. A device-backed
	// provider whose key lives in the device will hand every instance the same
	// key, and no check here treats that as a fault; in particular the suite
	// never requires that one instance refuse a blob another instance produced,
	// because for a TPM or a KMS that blob IS its own.
	//
	// The returned value is typed any for the same reason
	// [enclave.WithProvider] takes any: which of the two seam interfaces a
	// provider implements is a capability the seam discovers, not something a
	// signature can pin.
	New func() (any, error)

	// Modes lists the sealing modes this provider claims to serve, and it is a
	// CLAIM the suite checks rather than a description it trusts. Each named
	// mode must be accepted by [enclave.NewSealer], and — the half that catches
	// something — each UNNAMED mode must be refused with
	// [enclave.ErrProviderMode].
	//
	// That second direction is what finds a stub. A provider built for
	// ModePerOperation that also carries an UnsealRoot method — added by a
	// developer who thought the seam required both, returning a constant or a
	// zero buffer — is accepted in ModeRootKey by a Sealer that has no way to
	// know the method is a placeholder, and every value in the process is then
	// sealed under a root the provider never really produced. Naming only the
	// modes you serve turns that from a silent misconfiguration into a failure
	// here.
	Modes []enclave.Mode

	// SkipResidueSweep, when non-empty, records WHY the process-memory residue
	// sweep is not run against this provider, and skips it. The string is not
	// decoration: it is echoed through Logf and is the only account anyone
	// reading a green run will have of what was not measured.
	//
	// The legitimate reason is a transit the provider cannot reach — a cloud
	// KMS backend receives its plaintext in an HTTP response body that
	// net/http's reader owns, and no wipe the provider can perform reclaims
	// the bufio buffer behind it. Skipping is then honest; claiming the
	// property is not. It is NOT a legitimate way to quiet a failure whose
	// cause has not been established.
	SkipResidueSweep string

	// SingleUseRoot, when non-empty, records WHY this provider's UnsealRoot can
	// be called only once per instance, and relaxes the two checks that need a
	// second call to say anything.
	//
	// The seam guarantees only that a [enclave.Sealer] calls UnsealRoot AT MOST
	// ONCE, so a provider that consumes a session, an authorization or a
	// one-shot handle on a successful unseal satisfies the runtime contract
	// while failing a suite that calls it twice. Every backend this portfolio
	// actually uses is repeatable — a TPM unseal, a KMS decrypt of a fixed
	// blob, a process-lifetime software root — so the default stays the strong
	// one, and a provider that genuinely is not says so here.
	//
	// What is given up is exact: the full-width-write proof and the
	// destination-retention spy both need a second call. Setting this leaves
	// retention of the ROOT destination unmeasured, and the reason recorded
	// here is the only account a reader of a green run will have of that.
	SingleUseRoot string

	// Logf, if set, receives the suite's notes: what was measured, what was
	// skipped and why, and every result that is neither a pass nor a
	// reportable failure. Pass t.Logf. A nil Logf discards them — and a run
	// with a nil Logf cannot distinguish a property that passed from one that
	// could not be measured on this host, which is why every caller should set
	// it.
	Logf func(format string, args ...any)
}

// TestProvider runs the conformance suite against the provider cfg describes
// and returns nil if it conforms. Otherwise it returns an error joining one
// [*PropertyError] per failed property, each naming the property, what was
// observed and what the seam requires — so a failure is actionable without
// reading this package.
//
// ctx is handed to every provider call the suite makes and bounds the run. If
// it ends before the run finishes, the suite stops at the next check and the
// returned error matches [ErrAborted] (an [*AbortedError] carrying the
// context's error), joined with whatever properties had already failed while
// the context was live; a provider call that failed only because the run's
// context ended is not reported against the provider.
//
// A returned error means the provider does not honor the seam, EXCEPT one
// matching [ErrInvalidConfig] (a [*ConfigError]) — cfg itself could not be
// run, and no provider was tested at all — or [ErrAborted], which means the
// run is incomplete. A nil return means every property the suite could
// MEASURE held; which ones it could not measure, and why, went to
// [Config.Logf].
func TestProvider(ctx context.Context, cfg Config) error {
	if cfg.New == nil {
		return &ConfigError{Field: "New", Reason: "is nil; the suite has no provider to test"}
	}
	if len(cfg.Modes) == 0 {
		return &ConfigError{Field: "Modes", Reason: "is empty; name the modes this provider serves, " +
			"since an unnamed mode is one the suite requires NewSealer to refuse"}
	}

	claims := make(map[enclave.Mode]bool, len(cfg.Modes))
	for _, m := range cfg.Modes {
		switch m {
		case enclave.ModeRootKey, enclave.ModePerOperation:
			claims[m] = true
		default:
			return &ConfigError{Field: "Modes", Reason: "contains " + m.String() + ", which names no sealing mode"}
		}
	}

	r := &report{ctx: ctx, logf: cfg.Logf}
	checks := []func(*report, Config){func(r *report, cfg Config) { checkModePairing(r, cfg, claims) }}
	if claims[enclave.ModePerOperation] {
		checks = append(checks, keyProtectorChecks...)
	}
	if claims[enclave.ModeRootKey] {
		checks = append(checks, rootUnsealerChecks...)
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			break
		}
		check(r, cfg)
	}
	return r.err()
}

// report accumulates the failures of one run. Failures are collected rather
// than returned at the first one so that an implementer sees every property
// that is wrong in a single pass, which is the difference between one fix and
// five rounds.
type report struct {
	// ctx is the run's context: every provider call is made under it, or
	// under a context derived from it.
	ctx      context.Context
	logf     func(format string, args ...any)
	failures []error
}

// fail records a failed property — unless the run's context has ended, in
// which case the failure may be nothing but the provider honoring that
// context, and charging it to the provider would be a false finding. The run
// is then reported as aborted instead (see err), so dropping it cannot turn a
// failing run into a passing one.
func (r *report) fail(property, format string, args ...any) {
	if r.ctx.Err() != nil {
		return
	}
	r.failures = append(r.failures, &PropertyError{Property: property, Detail: fmt.Sprintf(format, args...)})
}

// note records something a reader of a GREEN run needs to know — chiefly, what
// was not measured.
func (r *report) note(format string, args ...any) {
	if r.logf != nil {
		r.logf(format, args...)
	}
}

// err joins the recorded failures, or returns nil. A run whose context ended
// is never nil: it carries an [*AbortedError], because a run that stopped
// early has not measured what a nil return claims.
func (r *report) err() error {
	if cerr := r.ctx.Err(); cerr != nil {
		return errors.Join(append(r.failures, &AbortedError{Err: cerr})...)
	}
	return errors.Join(r.failures...)
}

// endedContext is a context that has already ended, and the error a provider
// handed it must report.
type endedContext struct {
	name string
	ctx  context.Context
	want error
}

// endedContexts derives from the run's context one that is already canceled
// and one whose deadline has already passed — the two ways a context ends,
// which a provider may well check separately. The returned func releases
// them.
func (r *report) endedContexts() ([]endedContext, func()) {
	canceled, cancel := context.WithCancel(r.ctx)
	cancel()
	// A deadline in the past is expired at construction: no timer runs, and
	// Err reports DeadlineExceeded from the first call.
	expired, release := context.WithDeadline(r.ctx, time.Unix(0, 0))
	return []endedContext{
		{name: "canceled", ctx: canceled, want: context.Canceled},
		{name: "deadline-expired", ctx: expired, want: context.DeadlineExceeded},
	}, release
}

// bounded runs call on its own goroutine and waits for it to return or for
// the run's context to end, whichever is first, reporting which. It is used
// ONLY for calls made with an already-ended context, where a provider that
// ignores the context could otherwise hold the suite for as long as its
// device takes — or forever.
//
// returned false is INCOMPLETION, never a finding: an empty result channel
// shows only that the run stopped waiting — the goroutine may not yet have
// been scheduled, let alone reached the provider. The caller therefore records
// nothing and stops the check, and the run is reported through err as
// aborted, which a run whose context ended always is.
//
// If the run's context wins, the goroutine is left running: its only way out
// is the provider returning, and nothing on this side can force that. Its
// result channel is buffered, so it exits the moment the provider does, and
// nothing it writes is read after this returns.
func (r *report) bounded(call func() error) (err error, returned bool) {
	done := make(chan error, 1)
	go func() { done <- call() }()

	select {
	case err := <-done:
		return err, true
	case <-r.ctx.Done():
		// select picks at random among ready cases; a call that finished at
		// the same moment did return, and is not reported as hung.
		select {
		case err := <-done:
			return err, true
		default:
			return nil, false
		}
	}
}

// modeInterface names the seam interface a mode requires, so a pairing failure
// says which method set made a Sealer accept a provider.
func modeInterface(m enclave.Mode) string {
	if m == enclave.ModeRootKey {
		return "enclave.RootUnsealer"
	}
	return "enclave.KeyProtector"
}

// newProvider builds a fresh provider and refuses a nil one.
//
// The typed-nil half is the treacherous one, and it is why this is a function
// rather than a call to cfg.New. A (*MyProvider)(nil) SATISFIES both seam
// interfaces, so the assertions below succeed and the first Protect panics on
// a nil receiver — inside the conformance suite, which then reports nothing at
// all. A suite that crashes instead of reporting is the certifying failure in
// another costume. [enclave.NewSealer] refuses the same value with
// [enclave.ErrProviderMode] for the same reason: a typed nil is a lost pointer,
// not a request for the default.
func newProvider(cfg Config) (any, error) {
	p, err := cfg.New()
	if err != nil {
		return nil, &stepError{step: "Config.New", err: err}
	}
	if isNilProvider(p) {
		return nil, &nilProviderError{provider: p}
	}
	return p, nil
}

// isNilProvider reports whether p is nil or a typed nil.
func isNilProvider(p any) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// newProtector builds a fresh provider and asserts the KeyProtector half of the
// seam.
func newProtector(cfg Config) (enclave.KeyProtector, error) {
	p, err := newProvider(cfg)
	if err != nil {
		return nil, err
	}
	kp, ok := p.(enclave.KeyProtector)
	if !ok {
		return nil, &missingSeamError{provider: p, iface: "enclave.KeyProtector", mode: "ModePerOperation"}
	}
	return kp, nil
}

// newUnsealer builds a fresh provider and asserts the RootUnsealer half.
func newUnsealer(cfg Config) (enclave.RootUnsealer, error) {
	p, err := newProvider(cfg)
	if err != nil {
		return nil, err
	}
	ru, ok := p.(enclave.RootUnsealer)
	if !ok {
		return nil, &missingSeamError{provider: p, iface: "enclave.RootUnsealer", mode: "ModeRootKey"}
	}
	return ru, nil
}

// randKey returns a fresh random key of the length the seam uses.
func randKey() ([]byte, error) {
	k := make([]byte, keyBytes)
	if _, err := rand.Read(k); err != nil {
		return nil, &stepError{step: "generating a test key", err: err}
	}
	return k, nil
}

// allZero reports whether b is entirely zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// plaintextRunBytes is the window containsRun matches on. At eight bytes a
// coincidental match is a 2^-64 event, so a positive reading is a real one,
// while a shorter window would start reporting chance collisions as leaks.
const plaintextRunBytes = 8

// containsRun reports whether haystack contains any run of [plaintextRunBytes]
// consecutive bytes of needle. It is how a PARTIAL plaintext write is caught: a
// provider that decrypts before it authenticates leaves the leading bytes of
// the key in the destination, which an equality test against the whole key
// misses entirely.
func containsRun(haystack, needle []byte) bool {
	n := plaintextRunBytes
	if len(needle) < n {
		return false
	}
	for i := 0; i+n <= len(needle); i++ {
		if bytes.Contains(haystack, needle[i:i+n]) {
			return true
		}
	}
	return false
}

// checkModePairing verifies the claim in [Config.Modes] in both directions.
// Each mode gets its own provider instance because NewSealer binds the one it
// is given.
func checkModePairing(r *report, cfg Config, claims map[enclave.Mode]bool) {
	const property = "mode/interface pairing"

	for _, m := range []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation} {
		p, err := newProvider(cfg)
		if err != nil {
			r.fail(property, "%v", err)
			return
		}
		_, serr := enclave.NewSealer(enclave.WithProvider(p), enclave.WithMode(m))

		switch {
		case claims[m] && serr != nil:
			r.fail(property, "NewSealer refused this provider in %v, which Config.Modes claims it serves: %v "+
				"(the provider's method set does not satisfy %s)", m, serr, modeInterface(m))
		case !claims[m] && serr == nil:
			r.fail(property, "NewSealer ACCEPTED this provider in %v, which Config.Modes does not claim: "+
				"the type satisfies %s, so a caller can select a mode this provider was never built to serve "+
				"and a Sealer has no way to tell the method apart from a real implementation", m, modeInterface(m))
		// serr != nil is redundant against the arm above and stated anyway:
		// without it, deleting that arm makes THIS one fire on a nil error
		// and report an acceptance as "refused ... with <nil>", which is the
		// wrong diagnosis and also masks the deletion from a mutant.
		case !claims[m] && serr != nil && !errors.Is(serr, enclave.ErrProviderMode):
			r.fail(property, "NewSealer refused this provider in %v with %v, want an error matching "+
				"ErrProviderMode so a misconfiguration is distinguishable from a device fault", m, serr)
		}
	}
	r.note("providertest: mode/interface pairing checked for ModeRootKey and ModePerOperation against the claim %v", cfg.Modes)
}

// keyProtectorChecks are the ModePerOperation half of the suite. Each check
// takes its own provider instance.
var keyProtectorChecks = []func(*report, Config){
	checkRoundTrip,
	checkProtectDoesNotRetainTheKey,
	checkDestinationNotWrittenAfterTheCallerWipedIt,
	checkDestinationNotDisturbedByALaterCall,
	checkTamperedBlobRefused,
	checkDestinationLengthIsAuthenticated,
	checkKeyProtectorRefusesAnEndedContext,
	checkNoResidueAfterUnprotect,
}

// checkRoundTrip is the floor: Protect/Unprotect recover the key, Protect does
// not mutate what it was handed, and the blob is not the key wearing a hat.
func checkRoundTrip(r *report, cfg Config) {
	const property = "Protect/Unprotect round trip"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	key, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	want := bytes.Clone(key)

	blob, err := p.Protect(r.ctx, key)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}
	if len(blob) == 0 {
		r.fail(property, "Protect returned an empty blob; the contract requires a non-empty one, and a Sealer "+
			"that stored it would hold a value nothing can recover")
		return
	}
	if !bytes.Equal(key, want) {
		r.fail(property, "Protect MUTATED the caller's key slice; it aliases locked pages the caller still owns")
	}
	if containsRun(blob, want) {
		r.fail(property, "the blob returned by Protect contains the plaintext key: the blob is stored and "+
			"transported as ciphertext, so this is the key in the clear")
	}

	dst := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, dst); err != nil {
		r.fail(property, "Unprotect of a blob this provider's own Protect produced: %v", err)
		return
	}
	if !bytes.Equal(dst, want) {
		r.fail(property, "Unprotect wrote %d bytes that are not the protected key into the destination", len(dst))
	}
}

// checkProtectDoesNotRetainTheKey is the spy pointed at Protect's INPUT.
//
// "Protect must not retain key or any copy of it; the slice aliases locked
// pages that are wiped and unmapped when the caller is done." The reference
// half of that is decidable from outside, and this is how: file the key, then
// destroy the caller's copy exactly as go-enclave does, and ask the provider to
// give it back. A provider that stored the SLICE rather than its contents now
// holds thirty-two zero bytes, and the recovery fails or returns zeros.
//
// The control runs first and is not optional: an unwiped round trip through the
// same provider must succeed, otherwise a failure after the wipe is
// unattributable — it could equally be a provider that cannot round-trip at all.
func checkProtectDoesNotRetainTheKey(r *report, cfg Config) {
	const property = "Protect does not retain the caller's key slice"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	key, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	want := bytes.Clone(key)

	blob, err := p.Protect(r.ctx, key)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	// Control FIRST: this provider round-trips while the caller's key is still
	// intact.
	control := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, control); err != nil || !bytes.Equal(control, want) {
		r.fail(property, "the control did not hold — Unprotect before any wipe returned %v and recovered "+
			"the key correctly: %t. The retention result would be unattributable, so it was not taken",
			err, bytes.Equal(control, want))
		return
	}

	// The caller is done with its key and wipes the pages, which is what
	// go-enclave does to every buffer it hands a provider.
	enclave.Wipe(key)

	dst := make([]byte, keyBytes)
	switch err := p.Unprotect(r.ctx, blob, dst); {
	case err != nil:
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect of that blob "+
			"failed with %v — Protect kept the caller's SLICE rather than copying out of it, so wiping the "+
			"caller's locked pages destroyed the provider's only copy", err)
	case allZero(dst):
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect recovered all "+
			"zeros — Protect kept the caller's SLICE rather than copying out of it")
	case !bytes.Equal(dst, want):
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect recovered "+
			"something other than the protected key — Protect is reading the caller's slice at Unprotect time")
	}
}

// checkDestinationNotWrittenAfterTheCallerWipedIt is the spy in its primary
// form: record the exact destination handed out, prove it held the material at
// return time, wipe it as the caller does, and require it to STAY zero across
// every later provider call.
//
// The failure this catches is a provider that keeps the last destination it was
// given — a "reuse the buffer" optimisation, or a caching layer keyed by blob —
// and writes into it again. The caller has by then wiped and possibly reused
// those pages for something else, so the write puts key material into a buffer
// nobody is guarding, at a moment nobody is watching.
//
// The control is what makes the zero reading mean anything. Without it, a
// provider that never populated the destination at all reads exactly like a
// provider that populated it and then respected the caller's wipe.
func checkDestinationNotWrittenAfterTheCallerWipedIt(r *report, cfg Config) {
	const property = "Unprotect does not write into a destination the caller has finished with"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	first, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	second, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	firstBlob, err := p.Protect(r.ctx, first)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}
	secondBlob, err := p.Protect(r.ctx, second)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	// spy is the exact slice handed out, held for the rest of the check.
	spy := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, firstBlob, spy); err != nil {
		r.fail(property, "Unprotect: %v", err)
		return
	}

	// CONTROL: it held the material at return time. A zero reading below is
	// otherwise indistinguishable from a destination that was never populated.
	if !bytes.Equal(spy, first) {
		r.fail(property, "the control did not hold — Unprotect returned nil but the destination does not hold "+
			"the protected key, so it was never populated and the zero reading below would be vacuous")
		return
	}

	// The caller is done: it wipes its own destination. Nothing the provider
	// does from here may put bytes back.
	enclave.Wipe(spy)

	later := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, secondBlob, later); err != nil {
		r.fail(property, "a second Unprotect failed: %v", err)
		return
	}
	if _, err := p.Protect(r.ctx, first); err != nil {
		r.fail(property, "a later Protect failed: %v", err)
		return
	}

	if !allZero(spy) {
		what := "unrecognized bytes"
		switch {
		case bytes.Equal(spy, first):
			what = "the FIRST key again"
		case bytes.Equal(spy, second):
			what = "the SECOND key"
		}
		r.fail(property, "the destination handed to an earlier Unprotect was written again after the caller "+
			"wiped it, and now holds %s: the provider retained a reference to the caller's slice across calls, "+
			"so it writes key material into pages the caller has released", what)
	}
}

// checkDestinationNotDisturbedByALaterCall is the same spy in the other
// direction: a destination the caller is still USING must not be touched.
//
// It is a separate check from its mirror because the two catch different bugs
// and neither implies the other. A provider that retains the destination and
// WIPES it on the next call leaves a caller holding zeros where its key was —
// invisible to the zero-stays-zero form above, and a fail-open in the caller if
// zeros are then used as a key.
func checkDestinationNotDisturbedByALaterCall(r *report, cfg Config) {
	const property = "a later provider call does not disturb an earlier destination"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	first, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	second, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	firstBlob, err := p.Protect(r.ctx, first)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}
	secondBlob, err := p.Protect(r.ctx, second)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	spy := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, firstBlob, spy); err != nil {
		r.fail(property, "Unprotect: %v", err)
		return
	}
	// CONTROL: it held the material at return time.
	if !bytes.Equal(spy, first) {
		r.fail(property, "the control did not hold — the destination does not hold the protected key at "+
			"return time, so an unchanged reading below would prove nothing")
		return
	}

	later := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, secondBlob, later); err != nil {
		r.fail(property, "a second Unprotect failed: %v", err)
		return
	}
	if _, err := p.Protect(r.ctx, first); err != nil {
		r.fail(property, "a later Protect failed: %v", err)
		return
	}

	if !bytes.Equal(spy, first) {
		detail := "overwritten"
		if allZero(spy) {
			detail = "ZEROED — the caller is now holding zeros where its key was, and will use them as one"
		} else if bytes.Equal(spy, second) {
			detail = "overwritten with the SECOND key"
		}
		r.fail(property, "the destination of an earlier Unprotect was %s by a later call: the provider "+
			"retained a reference to the caller's slice across calls", detail)
	}
}

// checkTamperedBlobRefused covers the authenticity half of the contract:
// "Unprotect returns an error for any blob this provider's Protect did not
// produce". A provider offering confidentiality alone does not satisfy
// [enclave.KeyProtector], and the disqualifying example is bare RSA-OAEP: it
// wraps under a PUBLIC key, so anyone holding that key forges a blob that opens
// successfully to attacker-chosen material.
//
// The error must match [enclave.ErrSealedAuthentication] so that a forgery
// reads as a forgery at every layer above rather than as a device fault, and
// the destination must not be left holding plaintext — a provider that decrypts
// before it authenticates leaves the leading bytes of the key in a buffer whose
// owner has been told the call failed.
//
// Note what is NOT here. The suite does not require that one provider instance
// refuse a blob a DIFFERENT instance produced. For a TPM or a KMS the device
// key is shared across instances, so that blob genuinely is its own, and
// requiring the refusal would fail every hardware backend for conforming.
func checkTamperedBlobRefused(r *report, cfg Config) {
	const property = "a blob this provider did not produce is refused"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	key, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	blob, err := p.Protect(r.ctx, key)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}
	if len(blob) == 0 {
		r.fail(property, "Protect returned an empty blob; nothing to tamper with")
		return
	}

	forged := make([]byte, len(blob))
	if _, err := rand.Read(forged); err != nil {
		r.fail(property, "generating a forged blob: %v", err)
		return
	}

	cases := []struct {
		name string
		blob []byte
	}{
		{"a nil", nil},
		{"an empty", []byte{}},
		{"a truncated", bytes.Clone(blob[:len(blob)-1])},
		{"an extended", append(bytes.Clone(blob), 0x00)},
		{"a random same-length", forged},
	}
	// A bounded sample of single-bit flips: the header, the body and the
	// trailing authentication tag. Bounded because a hardware provider pays a
	// device round trip for each one.
	for _, i := range flipPositions(len(blob)) {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		cases = append(cases, struct {
			name string
			blob []byte
		}{fmt.Sprintf("a bit-flipped (byte %d of %d)", i, len(blob)), bad})
	}

	const canary = 0x5A
	for _, tc := range cases {
		dst := bytes.Repeat([]byte{canary}, keyBytes)
		err := p.Unprotect(r.ctx, tc.blob, dst)
		switch {
		case err == nil:
			r.fail(property, "Unprotect ACCEPTED %s blob; a provider that authenticates nothing lets an "+
				"attacker who can reach the stored blob choose the key every sealed value opens under", tc.name)
		case !errors.Is(err, enclave.ErrSealedAuthentication):
			r.fail(property, "Unprotect refused %s blob with %v, want an error matching "+
				"ErrSealedAuthentication — an infrastructure fault dressed as a forgery, or the reverse, "+
				"sends an operator hunting an attacker who does not exist", tc.name, err)
		}
		if containsRun(dst, key) {
			r.fail(property, "a refused Unprotect of %s blob left plaintext key material in the "+
				"destination: the provider decrypts before it authenticates, and its caller has been told "+
				"the call failed", tc.name)
		}
	}
	r.note("providertest: %d tampered-blob cases refused", len(cases))
}

// flipPositions picks the byte offsets to corrupt: both ends, the middle, and
// the tag region at the tail, deduplicated and in range.
func flipPositions(n int) []int {
	want := []int{0, 1, n / 2, n - 3, n - 2, n - 1}
	seen := make(map[int]bool, len(want))
	var out []int
	for _, i := range want {
		if i < 0 || i >= n || seen[i] {
			continue
		}
		seen[i] = true
		out = append(out, i)
	}
	return out
}

// checkDestinationLengthIsAuthenticated pins the contract's sharpest sentence:
// "a length mismatch is an authentication failure, not a truncation". The
// destination's LENGTH is a claim about the plaintext, so a provider that
// silently truncates into a short destination, or writes a short key into a
// long one and leaves the tail undefined, hands its caller a key that is not
// the one that was sealed.
func checkDestinationLengthIsAuthenticated(r *report, cfg Config) {
	const property = "a destination of the wrong length is an authentication failure"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	key, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	blob, err := p.Protect(r.ctx, key)
	if err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	for _, n := range []int{0, keyBytes - 1, keyBytes + 1} {
		dst := make([]byte, n)
		switch err := p.Unprotect(r.ctx, blob, dst); {
		case err == nil:
			r.fail(property, "Unprotect accepted a %d-byte destination for a %d-byte key", n, keyBytes)
		case !errors.Is(err, enclave.ErrSealedAuthentication):
			r.fail(property, "Unprotect refused a %d-byte destination with %v, want an error matching "+
				"ErrSealedAuthentication", n, err)
		}
		if containsRun(dst, key) {
			r.fail(property, "a refused Unprotect into a %d-byte destination left plaintext key material "+
				"in it", n)
		}
	}
}

// rootUnsealerChecks are the ModeRootKey half.
//
// # There is no residue sweep here, and the asymmetry is the point
//
// A [enclave.RootUnsealer] legitimately RETAINS the root. That is what it is
// for: the device holds the root and yields it on demand, and go-enclave's own
// [enclave.SoftwareProvider] holds it in a locked enclave in this process, which
// its documentation says in as many words ("the root then exists in TWO locked
// enclaves"). Sweeping for it would fail every conforming implementation. The
// retention property belongs to KeyProtector, whose device key is its own and
// whose protected key is the caller's.
var rootUnsealerChecks = []func(*report, Config){
	checkUnsealRootFillsTheDestination,
	checkRootDestinationNotDisturbedByALaterCall,
	checkRootUnsealerRefusesAnEndedContext,
	func(r *report, _ Config) {
		r.note("providertest: the residue sweep does not apply to RootUnsealer — a root unsealer legitimately " +
			"retains the root, which is the whole of what it does")
	},
}

// checkUnsealRootFillsTheDestination proves the provider writes a real root
// across the WHOLE destination, and the instrument is exact rather than
// heuristic.
//
// Two calls are made into destinations pre-filled with DIFFERENT canaries. A
// byte position the provider never wrote keeps its own canary in each, so the
// two destinations disagree there; a position it wrote agrees. Requiring the
// two destinations to be equal therefore proves, position by position, that
// every one was written — with no probabilistic slack, unlike "the result is
// not all zero", which a provider writing only its first half passes.
//
// That equality is also a determinism requirement, and it is a deliberate
// judgement rather than a restatement of the interface. The interface says a
// Sealer calls UnsealRoot at most once, so it alone cannot observe a provider
// whose successive successful calls disagree — but two Sealers over one device
// would then hold two different roots while both believing they hold THE root,
// and every real backend (a TPM unseal, a KMS decrypt of a fixed blob, a
// process-lifetime software root) is deterministic within an instance. A
// provider that consumes a one-shot handle on a successful unseal sets
// [Config.SingleUseRoot] with the reason, which drops to a single call and
// records exactly which proofs were not taken.
func checkUnsealRootFillsTheDestination(r *report, cfg Config) {
	const property = "UnsealRoot writes a root across the whole destination"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	const canary = 0xAA
	first := bytes.Repeat([]byte{canary}, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, first); err != nil {
		r.fail(property, "UnsealRoot: %v", err)
		return
	}

	if cfg.SingleUseRoot != "" {
		// One call is all this provider has, so the exact position-by-position
		// proof is unavailable and what remains is the weaker set. Say so:
		// silently downgrading an instrument is how a suite comes to certify
		// what it did not measure.
		r.note("providertest: UnsealRoot called ONCE — %q. The full-width-write and determinism proofs "+
			"need a second call and were NOT taken; what is checked is that the root is not the caller's "+
			"own fill, not zero, and not a constant", cfg.SingleUseRoot)
		if bytes.Count(first, []byte{canary}) == len(first) {
			r.fail(property, "UnsealRoot wrote NOTHING: the destination still holds the caller's own "+
				"%#x fill across all %d bytes", canary, enclave.RootKeyBytes)
			return
		}
		checkRootIsNotAPlaceholder(r, property, first)
		return
	}

	second := bytes.Repeat([]byte{0x55}, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, second); err != nil {
		r.fail(property, "a second UnsealRoot on the same provider: %v. If this provider consumes a "+
			"one-shot handle on a successful unseal, set Config.SingleUseRoot with the reason; the seam "+
			"guarantees only that a Sealer calls UnsealRoot at most once", err)
		return
	}

	if !bytes.Equal(first, second) {
		var unwritten []int
		for i := range first {
			if first[i] == 0xAA && second[i] == 0x55 {
				unwritten = append(unwritten, i)
			}
		}
		if len(unwritten) > 0 {
			r.fail(property, "UnsealRoot left %d of %d destination bytes UNWRITTEN (first at index %d): each "+
				"kept the caller's own fill, so the root a Sealer runs its whole KEK hierarchy under is part "+
				"caller garbage", len(unwritten), enclave.RootKeyBytes, unwritten[0])
			return
		}
		r.fail(property, "two successive UnsealRoot calls on one provider produced DIFFERENT roots; two "+
			"Sealers over this device would each hold a different value while both believing they hold the root")
		return
	}

	checkRootIsNotAPlaceholder(r, property, first)
}

// checkRootIsNotAPlaceholder is the stub smoke test, shared by both call
// paths: a Sealer cannot tell a placeholder from an unseal, so if UnsealRoot
// returns a constant, every value in the process is sealed under a key an
// attacker already knows.
//
// A real 32-byte root fails these with probability 2^-256 and 2^-248, so a
// positive reading is a placeholder, not a coincidence.
func checkRootIsNotAPlaceholder(r *report, property string, root []byte) {
	if allZero(root) {
		r.fail(property, "UnsealRoot produced an all-zero root; a stub returning a zero buffer is accepted by "+
			"a Sealer that has no way to tell it from a real unseal, and every value in the process is then "+
			"sealed under a key an attacker already knows")
		return
	}
	if bytes.Count(root, root[:1]) == len(root) {
		r.fail(property, "UnsealRoot produced a constant-fill root (every byte %#x); this is a placeholder, "+
			"not an unseal", root[0])
	}
}

// checkRootDestinationNotDisturbedByALaterCall is the destination spy pointed
// at [enclave.RootUnsealer], where dst has the same
// recover-into-caller-memory shape and the same retention exposure.
func checkRootDestinationNotDisturbedByALaterCall(r *report, cfg Config) {
	const property = "UnsealRoot does not retain the caller's destination"

	if cfg.SingleUseRoot != "" {
		r.note("providertest: the UnsealRoot destination spy was NOT RUN — %q. It observes what a LATER "+
			"call does to an earlier destination, so it has nothing to measure against a one-shot root. "+
			"Retention of the root destination is unmeasured for this provider", cfg.SingleUseRoot)
		return
	}

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	spy := make([]byte, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, spy); err != nil {
		r.fail(property, "UnsealRoot: %v", err)
		return
	}
	// CONTROL: it held material at return time, so a later zero or unchanged
	// reading is attributable.
	if allZero(spy) {
		r.fail(property, "the control did not hold — UnsealRoot returned nil and left the destination all "+
			"zero, so nothing below could be told apart from a destination that was never populated")
		return
	}
	want := bytes.Clone(spy)

	later := make([]byte, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, later); err != nil {
		r.fail(property, "a second UnsealRoot failed: %v", err)
		return
	}
	if !bytes.Equal(spy, want) {
		detail := "overwritten"
		if allZero(spy) {
			detail = "ZEROED — a Sealer would run its whole KEK hierarchy under zeros"
		}
		r.fail(property, "the destination of an earlier UnsealRoot was %s by a later call: the provider "+
			"retained a reference to the caller's locked slice", detail)
	}

	// And the caller-wiped direction: once wiped, nothing may put bytes back.
	enclave.Wipe(spy)
	third := make([]byte, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, third); err != nil {
		r.fail(property, "a third UnsealRoot failed: %v", err)
		return
	}
	if !allZero(spy) {
		r.fail(property, "the destination of an earlier UnsealRoot was written again after the caller wiped "+
			"it: the provider writes root material into pages the caller has released")
	}
}

// checkKeyProtectorRefusesAnEndedContext checks the provider's half of the
// seam's context contract for Protect and Unprotect: a call made with a
// context that has already ended is refused, with an error matching that
// context's error, writes no key material, and consumes nothing.
//
// Why each clause is a property rather than politeness:
//
//   - REFUSED, because a Sealer's caller set that deadline, and a provider that
//     completes the call anyway makes the deadline decoration — the "bound is
//     only real at the outermost call" defect, one layer down.
//   - MATCHING ctx.Err(), because that is how every layer above tells "the
//     caller gave up" from "the device failed"; and NOT
//     [enclave.ErrSealedAuthentication], because a canceled open reported as
//     a forgery sends an operator hunting an attacker who does not exist.
//   - NOTHING WRITTEN, because the caller has been told the call failed and
//     will not treat its destination as holding key material it must wipe.
//
// The controls bracket the refusals: the provider round-trips with the run's
// live context before them, and still recovers the same blob after them, so a
// refusal cannot be a provider that refuses everything and the refusals cannot
// have broken the provider.
func checkKeyProtectorRefusesAnEndedContext(r *report, cfg Config) {
	const property = "Protect and Unprotect refuse a context that has already ended"

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	key, err := randKey()
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	want := bytes.Clone(key)

	// CONTROL: with a live context this provider round-trips.
	blob, err := p.Protect(r.ctx, key)
	if err != nil {
		r.fail(property, "the control did not hold — Protect with a live context: %v", err)
		return
	}
	control := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, control); err != nil || !bytes.Equal(control, want) {
		r.fail(property, "the control did not hold — Unprotect with a live context returned %v and recovered "+
			"the key correctly: %t, so a refusal below could not be told from a provider that refuses everything",
			err, bytes.Equal(control, want))
		return
	}

	ended, release := r.endedContexts()
	defer release()

	for _, ec := range ended {
		perr, returned := r.bounded(func() error {
			_, err := p.Protect(ec.ctx, key)
			return err
		})
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		checkRefusal(r, property, "Protect", ec, perr)
		if !bytes.Equal(key, want) {
			r.fail(property, "Protect called with an already-%s context MUTATED the caller's key slice", ec.name)
		}

		const canary = 0x5A
		dst := bytes.Repeat([]byte{canary}, keyBytes)
		uerr, returned := r.bounded(func() error { return p.Unprotect(ec.ctx, blob, dst) })
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		checkRefusal(r, property, "Unprotect", ec, uerr)
		if uerr != nil && containsRun(dst, want) {
			r.fail(property, "Unprotect refused an already-%s context and still wrote plaintext key material "+
				"into the destination; its caller has been told the call failed and will not wipe it", ec.name)
		}
	}

	// CONTROL, after: the refusals consumed nothing — the same blob still
	// recovers the same key.
	after := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, after); err != nil || !bytes.Equal(after, want) {
		r.fail(property, "after refusing ended contexts, Unprotect of the same blob with a live context returned "+
			"%v and recovered the key correctly: %t — a refused call must leave the provider as it found it",
			err, bytes.Equal(after, want))
	}
	r.note("providertest: ended-context refusal checked for Protect and Unprotect (canceled and " +
		"deadline-expired); cancellation arriving MID-call cannot be forced from outside a provider and is unmeasured")
}

// checkRootUnsealerRefusesAnEndedContext is the same contract for UnsealRoot,
// plus the clause that matters most there: a refused call CONSUMES NOTHING.
// A Sealer retries an unseal that failed — a canceled one included — so a
// one-shot provider that spends its handle on a call it then refuses has made
// the Sealer's root permanently unobtainable. The live unseal after the
// refusals, on the SAME instance, is that check, and it is why this runs for
// a [Config.SingleUseRoot] provider too: the refusals are not uses.
func checkRootUnsealerRefusesAnEndedContext(r *report, cfg Config) {
	const property = "UnsealRoot refuses a context that has already ended, and consumes nothing"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	ended, release := r.endedContexts()
	defer release()

	const canary = 0xC3
	refused := make([][]byte, 0, len(ended))
	for _, ec := range ended {
		dst := bytes.Repeat([]byte{canary}, enclave.RootKeyBytes)
		uerr, returned := r.bounded(func() error { return p.UnsealRoot(ec.ctx, dst) })
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		checkRefusal(r, property, "UnsealRoot", ec, uerr)
		if uerr != nil {
			refused = append(refused, dst)
		}
	}

	root := make([]byte, enclave.RootKeyBytes)
	if err := p.UnsealRoot(r.ctx, root); err != nil {
		r.fail(property, "after refusing ended contexts, UnsealRoot on the same provider with a live context "+
			"failed: %v. A refused call must consume nothing a later call needs — a Sealer retries an unseal "+
			"that failed, and a one-shot handle spent on a refusal leaves it no root at all", err)
		return
	}
	if allZero(root) {
		// Without a real root the residue comparison below proves nothing.
		r.fail(property, "the control did not hold — the live UnsealRoot returned nil and an all-zero root")
		return
	}
	for _, dst := range refused {
		if containsRun(dst, root) {
			r.fail(property, "UnsealRoot refused an ended context and still wrote root material into the "+
				"destination; its caller has been told the call failed and will not wipe it")
		}
	}
}

// checkRefusal applies the verdict every ended-context call shares: it must
// fail, with an error matching the context's, and not as a forgery.
func checkRefusal(r *report, property, op string, ec endedContext, err error) {
	switch {
	case err == nil:
		r.fail(property, "%s ACCEPTED an already-%s context and completed: a caller's deadline that a "+
			"provider ignores bounds nothing", op, ec.name)
	case errors.Is(err, enclave.ErrSealedAuthentication):
		r.fail(property, "%s refused an already-%s context with %v, which matches ErrSealedAuthentication: "+
			"a caller that gave up would be reported as a forgery", op, ec.name, err)
	case !errors.Is(err, ec.want):
		r.fail(property, "%s refused an already-%s context with %v, want an error matching %v so every "+
			"layer above can tell a caller that gave up from a device that failed", op, ec.name, err, ec.want)
	}
}
