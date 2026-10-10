// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package providertest is the conformance suite for the go-enclave provider
// seam. Anything implementing [enclave.KeyProtector] or [enclave.RootUnsealer]
// (a TPM, an HSM, a cloud KMS) runs [TestProvider] against its own provider in
// its own repository. Like [testing/fstest.TestFS], it is one call that returns
// an error naming every property that failed, and it does not import testing.
//
// # Retention
//
// The seam's signatures constrain where a provider writes plaintext, not what
// it keeps:
//
//	Unprotect(ctx context.Context, blob, key []byte) error
//	UnsealRoot(ctx context.Context, dst []byte) error
//
// A provider can write into the caller's locked slice and keep its own copy.
// This suite checks that a KeyProtector does not. It does not require that a
// provider never materializes plaintext in its own memory, since every real
// backend decrypts into a fresh slice; it requires that the provider wipe that
// transient, as [enclave.KeyProtector] states. Key expansion inside crypto/aes
// is out of scope.
//
// Two instruments carry the retention checks:
//
//   - The spy. The suite owns every slice it hands the provider and watches it
//     afterwards: a destination must not be overwritten or wiped by a later
//     call, a destination the caller wiped must not be written again, and
//     Protect must copy out of its input rather than keep the slice. Each
//     assertion is preceded by a control that fails if its setup did not
//     happen, so no assertion is vacuous.
//   - The residue sweep (Linux only). After Unprotect returns and the caller
//     wipes its destination, it searches the process's memory for a whole copy
//     of the key. It first proves it can find the key while a legitimate copy
//     is resident; a sweep that cannot run or is blind makes the run return an
//     error matching [ErrNotMeasured], unless [Config.SkipResidueSweep] accepts
//     that. It is the only instrument that sees a retained copy, but a copy
//     stranded on a freed goroutine stack is out of any wipe's reach, so it
//     corroborates the spy rather than replacing it.
//
// # Context
//
// [TestProvider] passes its context to every provider call. A run whose
// context ends before it finishes returns an error matching [ErrAborted]; it
// never returns nil.
//
// For each claimed mode the suite also checks the provider's half of the seam's
// context contract (see [enclave.RootUnsealer]): a call made with a context
// that is already canceled or past its deadline must fail with an error
// matching that context's error, not [enclave.ErrSealedAuthentication], must
// write no key material into its destination, and must consume nothing a later
// call needs. Cancellation arriving mid-call is not measured. Ended-context
// calls run on their own goroutine, so a provider that never returns cannot
// hold a run whose context is bounded; the run is then reported aborted, not as
// a provider failure. With an unbounded context such a provider hangs the run
// until go test -timeout reports it.
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
	"sync"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// keyBytes is the only key length go-enclave hands a provider: the
// per-operation DEK and the root are both 32 bytes.
const keyBytes = enclave.RootKeyBytes

// Config describes the provider under test.
type Config struct {
	// New returns a fresh provider ready for use. It is called at most once
	// per check (twice by the mode-pairing check), so a check that leaves a provider in
	// a terminal state does not affect the next. A nil or typed-nil result is
	// reported as a failure.
	//
	// Instances need not be independent: a device-backed provider may hand
	// every instance the same key, and the suite never requires one instance
	// to refuse a blob another produced.
	//
	// The result is typed any because a provider implements
	// [enclave.KeyProtector], [enclave.RootUnsealer], or both.
	New func() (any, error)

	// Modes lists the sealing modes this provider claims to serve. It must be
	// non-empty and name only valid modes. The claim is checked in both
	// directions: each named mode's interface must be implemented and accepted
	// by [enclave.NewSealer], and each unnamed mode's interface must not be
	// implemented. The second direction catches a stub method, such as a
	// placeholder UnsealRoot on a per-operation provider, that would let a
	// caller select a mode the provider does not really serve.
	Modes []enclave.Mode

	// SkipResidueSweep, when non-empty, records why the process-memory residue
	// sweep is not run against this provider, and skips it. The reason is
	// echoed through Logf. It is also the only way to accept an unmeasured
	// sweep: left empty, a sweep that cannot run (off Linux, without locked
	// memory, or blind on this host) makes [TestProvider] return an error
	// matching [ErrNotMeasured].
	//
	// The legitimate use is a transit the provider cannot wipe, such as a
	// cloud KMS response body owned by net/http's reader. It is not a way to
	// quiet a failure whose cause is unknown.
	SkipResidueSweep string

	// SingleUseRoot, when non-empty, records why this provider's UnsealRoot can
	// succeed only once per instance (for example, it consumes a one-shot
	// handle), and relaxes the two checks that need a second call: the
	// full-width-write and determinism proof, and the root destination spy.
	// Retention of the root destination is then unmeasured. The reason is
	// echoed through Logf. A [enclave.Sealer] calls UnsealRoot at most once,
	// so such a provider still satisfies the seam.
	SingleUseRoot string

	// PublicKey declares that Protect needs no secret: anyone holding the
	// provider's public key can build a blob for Unprotect (an RSA-OAEP, ECIES
	// or HPKE wrap). The seam requires such a provider to authenticate the
	// blob with something an attacker lacks, such as a signature by a device
	// key. The tampered-blob cases cannot tell the difference, since a bare
	// wrap's padding or tag refuses every malformed blob yet opens a well-formed
	// one an attacker built, so the suite needs Forge to build one. Set without
	// Forge, the property is unmeasured and [TestProvider] returns an error
	// matching [ErrNotMeasured], unless SkipForgery accepts that. It requires
	// [enclave.ModePerOperation].
	PublicKey bool

	// Forge plays the attacker against a public-key provider: given the
	// provider under test and a key, it returns a blob wrapping that key built
	// only from what an attacker has, the provider's public material. For
	// example, the key encrypted to the provider's public key and signed, if
	// the provider expects a signature, by a key the attacker generated.
	// Unprotect must refuse it with an error matching
	// [enclave.ErrSealedAuthentication]. Forge runs whether or not PublicKey is
	// set. It requires [enclave.ModePerOperation].
	Forge func(p enclave.KeyProtector, key []byte) ([]byte, error)

	// SkipForgery, when non-empty, records why the forged-blob check is not
	// run, and skips it. The reason is echoed through Logf. Whether Unprotect
	// opens a blob an attacker built from the public key is then unmeasured.
	SkipForgery string

	// Logf, if set, receives the suite's notes: what was measured, what was
	// skipped and why. Pass t.Logf. A nil Logf discards them, leaving no record
	// of what a nil return relaxed.
	Logf func(format string, args ...any)
}

// TestProvider runs the conformance suite against the provider cfg describes
// and returns nil if it conforms. Otherwise it returns a [*FindingsError]
// holding one [*PropertyError] per failed assertion, each naming the property,
// what was observed and what the seam requires.
//
// ctx is handed to every provider call the suite makes and bounds the run. If
// it ends before the run finishes, the suite stops at the next check and the
// returned error matches [ErrAborted] (an [*AbortedError] carrying the
// context's error), alongside whatever properties had already failed while
// the context was live. A call that failed only because the run's context
// ended is not reported against the provider.
//
// A returned error means the provider does not honor the seam, except one
// matching [ErrInvalidConfig] (a [*ConfigError]: cfg could not be run and no
// provider was tested), [ErrAborted] (the run is incomplete), or
// [ErrNotMeasured] (a [*NotMeasuredError]: a property could not be measured on
// this host and cfg did not accept that). A nil return means every property was
// measured and held, except those cfg explicitly relaxed; what those were, and
// why, went to [Config.Logf].
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
	if !claims[enclave.ModePerOperation] {
		if cfg.PublicKey {
			return &ConfigError{Field: "PublicKey", Reason: "is set, but Config.Modes does not claim " +
				"ModePerOperation; a public-key wrap is a KeyProtector"}
		}
		if cfg.Forge != nil {
			return &ConfigError{Field: "Forge", Reason: "is set, but Config.Modes does not claim " +
				"ModePerOperation; only a KeyProtector opens a blob"}
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

// report accumulates the failures of one run.
type report struct {
	ctx      context.Context
	logf     func(format string, args ...any)
	failures []error
}

// fail records a failed property unless the run's context has ended: the
// failure may then be the provider honoring that context. Dropping it cannot
// turn a failing run into a pass, because err reports the run aborted.
func (r *report) fail(property, format string, args ...any) {
	if r.ctx.Err() != nil {
		return
	}
	r.failures = append(r.failures, &PropertyError{Property: property, Detail: fmt.Sprintf(format, args...)})
}

// unmeasured records a property this run could not measure. Like fail, it is
// dropped once the run's context has ended.
func (r *report) unmeasured(property, format string, args ...any) {
	reason := fmt.Sprintf(format, args...)
	r.note("providertest: %s", reason)
	if r.ctx.Err() != nil {
		return
	}
	r.failures = append(r.failures, &NotMeasuredError{Property: property, Reason: reason})
}

func (r *report) note(format string, args ...any) {
	if r.logf != nil {
		r.logf(format, args...)
	}
}

// failed reports whether property has a recorded finding.
func (r *report) failed(property string) bool {
	for _, f := range r.failures {
		var pe *PropertyError
		if errors.As(f, &pe) && pe.Property == property {
			return true
		}
	}
	return false
}

// err reports the recorded failures as a *FindingsError. A run whose context
// ended is never nil: it carries an *AbortedError.
func (r *report) err() error {
	if cerr := r.ctx.Err(); cerr != nil {
		return findingsOf(append(r.failures, &AbortedError{Cause: cerr}))
	}
	return findingsOf(r.failures)
}

type endedContext struct {
	name string
	ctx  context.Context
	want error
}

// endedContexts derives one already-canceled and one already-expired context
// from the run's, since a provider may check the two separately. The returned
// func releases them.
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
// the run's context to end, whichever is first. It is used only for calls made
// with an already-ended context, which a provider that ignores the context
// could otherwise hold forever.
//
// returned false is incompletion, never a finding: the goroutine may not even
// have reached the provider. The caller records nothing and stops the check;
// err reports the run aborted.
//
// Ownership of what call touches follows the outcome. Returned, the caller
// owns it. Abandoned, the worker does: it runs cleanup (if non-nil) once the
// provider returns, so nothing is wiped or freed under a running provider.
func (r *report) bounded(call func() error, cleanup func()) (err error, returned bool) {
	var (
		mu                  sync.Mutex
		finished, abandoned bool
	)
	done := make(chan error, 1)
	go func() {
		err := call()
		mu.Lock()
		finished = true
		owned := abandoned
		mu.Unlock()
		if owned && cleanup != nil {
			cleanup()
			if abandonedCleanupHook != nil {
				abandonedCleanupHook()
			}
		}
		done <- err
	}()

	select {
	case err := <-done:
		return err, true
	case <-r.ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		if finished {
			// The call returned while this side was deciding; it is not
			// abandoned, and its result is already on its way.
			return <-done, true
		}
		abandoned = true
		return nil, false
	}
}

// abandonedCleanupHook, when set by a test, runs after an abandoned call's
// cleanup.
var abandonedCleanupHook func()

// modeInterface names the seam interface a mode requires.
func modeInterface(m enclave.Mode) string {
	if m == enclave.ModeRootKey {
		return "enclave.RootUnsealer"
	}
	return "enclave.KeyProtector"
}

// newProvider builds a fresh provider and refuses a nil or typed-nil one. A
// typed nil satisfies the seam interfaces, so without this the first call
// would panic inside the suite instead of being reported.
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

// isNilProvider reports whether p is the untyped nil or an interface wrapping
// a nil value, by the same test as [enclave.NewSealer]'s provider check. The
// kind switch covers exactly the kinds reflect.Value.IsNil accepts other than
// reflect.Interface, which reflect.ValueOf never returns, so it never panics.
func isNilProvider(p any) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Chan, reflect.Func, reflect.Slice, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

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

func randKey() ([]byte, error) {
	k := make([]byte, keyBytes)
	if _, err := rand.Read(k); err != nil {
		return nil, &stepError{step: "generating a test key", err: err}
	}
	return k, nil
}

// plaintextRunBytes is the window containsRun matches on: a chance match is a
// 2^-64 event, so a positive reading is real.
const plaintextRunBytes = 8

// containsRun reports whether haystack contains any run of plaintextRunBytes
// consecutive bytes of needle, which catches a partial plaintext write that an
// equality test against the whole key misses.
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

// checkModePairing verifies the claim in Config.Modes in both directions.
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
		opt, serves := sealerOption(p, m)
		switch {
		case claims[m] && !serves:
			r.fail(property, "this provider cannot serve %v, which Config.Modes claims: it does not implement %s",
				m, modeInterface(m))
		case !claims[m] && serves:
			r.fail(property, "the provider implements %s, so a caller can select %v, which Config.Modes does not "+
				"claim: a Sealer has no way to tell the method apart from a real implementation", modeInterface(m), m)
		case claims[m]:
			if _, err := enclave.NewSealer(opt); err != nil {
				r.fail(property, "NewSealer refused this provider in %v, which Config.Modes claims it serves: %v", m, err)
			}
		}
	}
	r.note("providertest: mode/interface pairing checked for ModeRootKey and ModePerOperation against the claim %v", cfg.Modes)
}

// sealerOption returns the [enclave.SealerOption] that injects p for m, and
// whether p implements the interface m requires.
func sealerOption(p any, m enclave.Mode) (enclave.SealerOption, bool) {
	if m == enclave.ModePerOperation {
		kp, ok := p.(enclave.KeyProtector)
		return enclave.WithKeyProtector(kp), ok
	}
	ru, ok := p.(enclave.RootUnsealer)
	return enclave.WithRootUnsealer(ru), ok
}

// keyProtectorChecks are the ModePerOperation half of the suite. Each check
// takes its own provider instance.
// The spy properties that catch a provider writing into a destination after
// its call returned, which checkConcurrentUse must not race with.
const (
	noWriteAfterWipeProperty = "Unprotect does not write into a destination the caller has finished with"
	noDisturbanceProperty    = "a later provider call does not disturb an earlier destination"
)

var keyProtectorChecks = []func(*report, Config){
	checkRoundTrip,
	checkProtectDoesNotRetainTheKey,
	checkDestinationNotWrittenAfterTheCallerWipedIt,
	checkDestinationNotDisturbedByALaterCall,
	checkTamperedBlobRefused,
	checkDestinationLengthIsAuthenticated,
	checkForgedBlobRefused,
	checkKeyProtectorRefusesAnEndedContext,
	checkConcurrentUse,
	checkNoResidueAfterUnprotect,
}

// checkRoundTrip checks that Protect/Unprotect recover the key, Protect does
// not mutate its input, and the blob does not contain the plaintext.
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

// checkProtectDoesNotRetainTheKey is the spy pointed at Protect's input:
// protect a key, wipe the caller's slice as go-enclave does, and require
// Unprotect to still recover it. A provider that kept the slice rather than its
// contents recovers zeros or fails. An unwiped round trip runs first as the
// control, so a failure after the wipe is attributable.
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

	control := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, control); err != nil || !bytes.Equal(control, want) {
		r.fail(property, "the control did not hold — Unprotect before any wipe returned %v and recovered "+
			"the key correctly: %t. The retention result would be unattributable, so it was not taken",
			err, bytes.Equal(control, want))
		return
	}

	enclave.Wipe(key)

	dst := make([]byte, keyBytes)
	switch err := p.Unprotect(r.ctx, blob, dst); {
	case err != nil:
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect of that blob "+
			"failed with %v — Protect kept the caller's SLICE rather than copying out of it, so wiping the "+
			"caller's locked pages destroyed the provider's only copy", err)
	case memscan.AllZero(dst):
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect recovered all "+
			"zeros — Protect kept the caller's SLICE rather than copying out of it")
	case !bytes.Equal(dst, want):
		r.fail(property, "after the caller wiped the key slice Protect was handed, Unprotect recovered "+
			"something other than the protected key — Protect is reading the caller's slice at Unprotect time")
	}
}

// checkDestinationNotWrittenAfterTheCallerWipedIt records the destination
// handed to Unprotect, proves it held the key at return time, wipes it as the
// caller does, and requires it to stay zero across later provider calls. It
// catches a provider that keeps the last destination and writes into it again.
func checkDestinationNotWrittenAfterTheCallerWipedIt(r *report, cfg Config) {
	const property = noWriteAfterWipeProperty

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

	// Control: without it a zero reading below cannot be told apart from a
	// destination that was never populated.
	if !bytes.Equal(spy, first) {
		r.fail(property, "the control did not hold — Unprotect returned nil but the destination does not hold "+
			"the protected key, so it was never populated and the zero reading below would be vacuous")
		return
	}

	enclave.Wipe(spy)

	later := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, secondBlob, later); err != nil {
		r.fail(property, "a second Unprotect failed: %v", err)
		return
	}
	if !bytes.Equal(later, second) {
		r.fail(property, "a second Unprotect returned nil but its destination does not hold the second key")
	}
	if _, err := p.Protect(r.ctx, first); err != nil {
		r.fail(property, "a later Protect failed: %v", err)
		return
	}

	if !memscan.AllZero(spy) {
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
// direction: a destination the caller is still using must not be overwritten
// or wiped by a later call. A provider that wipes a retained destination passes
// the zero-stays-zero check but leaves its caller holding zeros as a key.
func checkDestinationNotDisturbedByALaterCall(r *report, cfg Config) {
	const property = noDisturbanceProperty

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
	if !bytes.Equal(later, second) {
		r.fail(property, "a second Unprotect returned nil but its destination does not hold the second key")
	}
	if _, err := p.Protect(r.ctx, first); err != nil {
		r.fail(property, "a later Protect failed: %v", err)
		return
	}

	if !bytes.Equal(spy, first) {
		detail := "overwritten"
		if memscan.AllZero(spy) {
			detail = "ZEROED — the caller is now holding zeros where its key was, and will use them as one"
		} else if bytes.Equal(spy, second) {
			detail = "overwritten with the SECOND key"
		}
		r.fail(property, "the destination of an earlier Unprotect was %s by a later call: the provider "+
			"retained a reference to the caller's slice across calls", detail)
	}
}

// checkTamperedBlobRefused checks that Unprotect refuses blobs this provider's
// Protect did not produce (malformed, random and bit-flipped) with an error
// matching ErrSealedAuthentication, and leaves no plaintext in the
// destination. Confidentiality alone, such as bare RSA-OAEP under a public key,
// does not satisfy the seam. A blob from a different instance is not tested:
// for a TPM or KMS it is genuinely the provider's own.
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
	// Bounded because a hardware provider pays a device round trip per case.
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

// checkDestinationLengthIsAuthenticated checks that a destination of the wrong
// length is refused with ErrSealedAuthentication rather than truncated or
// partially filled.
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

// checkForgedBlobRefused submits the blob Config.Forge builds from the
// provider's public material. The tampered-blob cases cannot catch a bare
// public-key wrap: its padding or tag refuses every malformed blob, but a blob
// an attacker encrypted to the public key is well formed.
func checkForgedBlobRefused(r *report, cfg Config) {
	const property = "a blob forged from the provider's public key is refused"

	switch {
	case cfg.SkipForgery != "":
		r.note("providertest: forged-blob check SKIPPED by Config.SkipForgery — %q. Whether Unprotect opens a "+
			"blob an attacker built from the public key is therefore unmeasured", cfg.SkipForgery)
		return
	case cfg.Forge == nil && cfg.PublicKey:
		r.unmeasured(property, "forged-blob check not run: Config.PublicKey declares a public-key provider but "+
			"Config.Forge is nil, so the suite cannot build the blob an attacker would. Set Forge, or accept that "+
			"with Config.SkipForgery")
		return
	case cfg.Forge == nil:
		r.note("providertest: forged-blob check not run: Config.PublicKey is not set, so Protect is taken to need " +
			"a secret and the tampered-blob cases stand for forgery")
		return
	}

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
	forged, err := cfg.Forge(p, bytes.Clone(key))
	if err != nil {
		r.fail(property, "%v", &stepError{step: "Config.Forge", err: err})
		return
	}
	if len(forged) == 0 {
		r.fail(property, "Config.Forge returned an empty blob, which the tampered-blob cases already submit; "+
			"this check would measure nothing")
		return
	}

	const canary = 0x5A
	dst := bytes.Repeat([]byte{canary}, keyBytes)
	err = p.Unprotect(r.ctx, forged, dst)
	switch {
	case err == nil:
		what := "material the attacker did not choose"
		if bytes.Equal(dst, key) {
			what = "the key the attacker chose"
		}
		r.fail(property, "Unprotect ACCEPTED a blob Config.Forge built without the provider's private key, and "+
			"wrote %s into the destination: anyone who can write a stored blob chooses the key every sealed "+
			"value opens under. A public-key wrap must be authenticated by something an attacker lacks, such "+
			"as a signature by a device key", what)
		return
	case !errors.Is(err, enclave.ErrSealedAuthentication):
		r.fail(property, "Unprotect refused the forged blob with %v, want an error matching "+
			"ErrSealedAuthentication", err)
	}
	if containsRun(dst, key) {
		r.fail(property, "a refused Unprotect of the forged blob left the attacker's key in the destination: "+
			"the provider decrypts before it authenticates")
	}
	r.note("providertest: a blob forged by Config.Forge was refused")
}

// concurrentWorkers goroutines each run concurrentRounds round trips in the
// concurrency check: enough to overlap the calls of a provider that blocks on
// a device, few enough device round trips for a hardware provider.
const (
	concurrentWorkers = 8
	concurrentRounds  = 4
)

// checkConcurrentUse runs round trips from several goroutines at once, as a
// Sealer does, each with keys of its own, and requires each to recover its
// own. A provider staging keys or blobs in shared state mixes them up under
// load, returning another call's key or a false ErrSealedAuthentication. The
// check compares outputs, so it needs no race detector; under -race it is
// also a data-race probe.
//
// It does not run against a provider the spies caught writing into a
// destination after its call returned: those writes would race with this
// check's own reads, and under -race the race report would end the caller's
// test binary instead of the run reporting what the spies found.
func checkConcurrentUse(r *report, cfg Config) {
	const property = "Protect and Unprotect are safe for concurrent use"

	for _, spy := range []string{noWriteAfterWipeProperty, noDisturbanceProperty} {
		if r.failed(spy) {
			r.note("providertest: concurrency check not run: the provider writes into destinations after "+
				"its calls return (%q failed), which concurrent calls would race with", spy)
			return
		}
	}

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	var keys [concurrentWorkers][concurrentRounds][]byte
	for w := range keys {
		for i := range keys[w] {
			if keys[w][i], err = randKey(); err != nil {
				r.fail(property, "%v", err)
				return
			}
		}
	}
	// whose names what a destination holds instead of its own key.
	whose := func(dst []byte) string {
		for w := range keys {
			for i := range keys[w] {
				if bytes.Equal(dst, keys[w][i]) {
					return fmt.Sprintf("the key of goroutine %d, round %d", w, i)
				}
			}
		}
		if memscan.AllZero(dst) {
			return "zeros"
		}
		return "bytes that are no key this check protected"
	}

	var (
		mu       sync.Mutex
		findings []string
		wg       sync.WaitGroup
	)
	record := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		findings = append(findings, fmt.Sprintf(format, args...))
	}
	start := make(chan struct{})
	for w := range concurrentWorkers {
		wg.Go(func() {
			<-start
			for i, key := range keys[w] {
				if r.ctx.Err() != nil {
					return
				}
				// A copy, so a Protect that mutates its input (a finding of
				// the round trip) neither looks like a concurrency defect
				// nor writes the key table other goroutines read.
				blob, err := p.Protect(r.ctx, bytes.Clone(key))
				if err != nil {
					record("goroutine %d, round %d: Protect: %v", w, i, err)
					return
				}
				dst := make([]byte, keyBytes)
				if err := p.Unprotect(r.ctx, blob, dst); err != nil {
					record("goroutine %d, round %d: Unprotect of the blob it had just protected: %v", w, i, err)
					return
				}
				if !bytes.Equal(dst, key) {
					record("goroutine %d, round %d: Unprotect returned nil but wrote %s into its destination",
						w, i, whose(dst))
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()

	for _, f := range findings {
		r.fail(property, "%s, with %d goroutines calling one provider at once: the provider shares state "+
			"across calls without synchronizing it, and a Sealer calls it concurrently", f, concurrentWorkers)
	}
	if len(findings) == 0 {
		r.note("providertest: %d goroutines recovered their own keys from %d concurrent round trips",
			concurrentWorkers, concurrentWorkers*concurrentRounds)
	}
}

// rootUnsealerChecks are the ModeRootKey half. There is no residue sweep: a
// RootUnsealer legitimately retains the root, so a sweep would fail every
// conforming implementation.
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
// across the whole destination. Two calls write into destinations pre-filled
// with different canaries; a byte the provider never wrote keeps its canary, so
// requiring the two to be equal proves every position was written. The
// equality also requires UnsealRoot to be deterministic within an instance, so
// two Sealers over one device hold the same root. With Config.SingleUseRoot set
// only one call is made and only the placeholder checks remain.
func checkUnsealRootFillsTheDestination(r *report, cfg Config) {
	const property = "UnsealRoot writes a root across the whole destination"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	const canary = 0xAA
	// Locked: against a real device these receive its actual root.
	if err := withLocked(2, enclave.RootKeyBytes, func(bufs [][]byte) error {
		first, second := bufs[0], bufs[1]
		fill(first, canary)
		if err := p.UnsealRoot(r.ctx, first); err != nil {
			r.fail(property, "UnsealRoot: %v", err)
			return nil
		}

		if cfg.SingleUseRoot != "" {
			r.note("providertest: UnsealRoot called ONCE — %q. The full-width-write and determinism proofs "+
				"need a second call and were NOT taken; what is checked is that the root is not the caller's "+
				"own fill, not zero, and not a constant", cfg.SingleUseRoot)
			if bytes.Count(first, []byte{canary}) == len(first) {
				r.fail(property, "UnsealRoot wrote NOTHING: the destination still holds the caller's own "+
					"%#x fill across all %d bytes", canary, enclave.RootKeyBytes)
				return nil
			}
			checkRootIsNotAPlaceholder(r, property, first)
			return nil
		}

		fill(second, 0x55)
		if err := p.UnsealRoot(r.ctx, second); err != nil {
			r.fail(property, "a second UnsealRoot on the same provider: %v. If this provider consumes a "+
				"one-shot handle on a successful unseal, set Config.SingleUseRoot with the reason; the seam "+
				"guarantees only that a Sealer calls UnsealRoot at most once", err)
			return nil
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
				return nil
			}
			r.fail(property, "two successive UnsealRoot calls on one provider produced DIFFERENT roots; two "+
				"Sealers over this device would each hold a different value while both believing they hold the root")
			return nil
		}

		checkRootIsNotAPlaceholder(r, property, first)
		return nil
	}); err != nil {
		r.fail(property, "allocating locked destinations for the root: %v", err)
	}
}

// withLocked runs fn over n fresh buffers of size bytes each, every one a
// borrow of its own locked enclave held for the whole of fn, and destroys them
// once fn returns. Every buffer that may hold a provider's root uses it, so the
// suite never copies a real device root onto the heap. A call that can outlive
// the check (a bounded one an ended run may abandon) must not be given these
// buffers: they are unmapped when fn returns.
func withLocked(n, size int, fn func(bufs [][]byte) error) error {
	encs := make([]*enclave.Memory, 0, n)
	defer func() {
		for _, e := range encs {
			_ = e.Destroy()
		}
	}()
	for range n {
		e, err := enclave.NewMemorySized(size)
		if err != nil {
			return err // the library's own typed error; the caller says what it was for
		}
		encs = append(encs, e)
	}
	bufs := make([][]byte, n)
	var nest func(i int) error
	nest = func(i int) error {
		if i == n {
			return fn(bufs)
		}
		return encs[i].WithBytes(func(b []byte) error {
			bufs[i] = b
			return nest(i + 1)
		})
	}
	return nest(0)
}

// checkRootIsNotAPlaceholder fails an all-zero or constant-fill root. A real
// 32-byte root fails these with probability 2^-256 and 2^-248.
func checkRootIsNotAPlaceholder(r *report, property string, root []byte) {
	if memscan.AllZero(root) {
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

// checkRootDestinationNotDisturbedByALaterCall is the destination spy, in both
// directions, pointed at UnsealRoot.
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

	if err := withLocked(4, enclave.RootKeyBytes, func(bufs [][]byte) error {
		spy, want, later, third := bufs[0], bufs[1], bufs[2], bufs[3]
		if err := p.UnsealRoot(r.ctx, spy); err != nil {
			r.fail(property, "UnsealRoot: %v", err)
			return nil
		}
		if memscan.AllZero(spy) {
			r.fail(property, "the control did not hold — UnsealRoot returned nil and left the destination all "+
				"zero, so nothing below could be told apart from a destination that was never populated")
			return nil
		}
		copy(want, spy)

		if err := p.UnsealRoot(r.ctx, later); err != nil {
			r.fail(property, "a second UnsealRoot failed: %v", err)
			return nil
		}
		if !bytes.Equal(spy, want) {
			detail := "overwritten"
			if memscan.AllZero(spy) {
				detail = "ZEROED — a Sealer would run its whole KEK hierarchy under zeros"
			}
			r.fail(property, "the destination of an earlier UnsealRoot was %s by a later call: the provider "+
				"retained a reference to the caller's locked slice", detail)
		}

		enclave.Wipe(spy)
		if err := p.UnsealRoot(r.ctx, third); err != nil {
			r.fail(property, "a third UnsealRoot failed: %v", err)
			return nil
		}
		if !memscan.AllZero(spy) {
			r.fail(property, "the destination of an earlier UnsealRoot was written again after the caller wiped "+
				"it: the provider writes root material into pages the caller has released")
		}
		return nil
	}); err != nil {
		r.fail(property, "allocating locked destinations for the root: %v", err)
	}
}

// checkKeyProtectorRefusesAnEndedContext checks that Protect and Unprotect
// called with an already-ended context fail with an error matching that
// context's error (not ErrSealedAuthentication), write no key material, and
// consume nothing. Live round trips before and after bracket the refusals, so
// a provider that refuses everything, or is broken by a refusal, is caught.
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
		}, nil)
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		checkRefusal(r, property, "Protect", ec, perr)
		if !bytes.Equal(key, want) {
			r.fail(property, "Protect called with an already-%s context MUTATED the caller's key slice", ec.name)
		}

		const canary = 0x5A
		dst := bytes.Repeat([]byte{canary}, keyBytes)
		uerr, returned := r.bounded(func() error { return p.Unprotect(ec.ctx, blob, dst) }, nil)
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		checkRefusal(r, property, "Unprotect", ec, uerr)
		if uerr != nil && containsRun(dst, want) {
			r.fail(property, "Unprotect refused an already-%s context and still wrote plaintext key material "+
				"into the destination; its caller has been told the call failed and will not wipe it", ec.name)
		}
	}

	after := make([]byte, keyBytes)
	if err := p.Unprotect(r.ctx, blob, after); err != nil || !bytes.Equal(after, want) {
		r.fail(property, "after refusing ended contexts, Unprotect of the same blob with a live context returned "+
			"%v and recovered the key correctly: %t — a refused call must leave the provider as it found it",
			err, bytes.Equal(after, want))
	}
	r.note("providertest: ended-context refusal checked for Protect and Unprotect (canceled and " +
		"deadline-expired); cancellation arriving MID-call cannot be forced from outside a provider and is unmeasured")
}

// checkRootUnsealerRefusesAnEndedContext is the same contract for UnsealRoot.
// A Sealer retries a failed unseal, so a refused call must consume nothing: a
// live unseal on the same instance must succeed afterwards. It runs for a
// Config.SingleUseRoot provider too, since refusals are not uses.
func checkRootUnsealerRefusesAnEndedContext(r *report, cfg Config) {
	const property = "UnsealRoot refuses a context that has already ended, and consumes nothing"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	ended, release := r.endedContexts()
	defer release()

	// Heap, not locked: an abandoned call can outlive this check, and only its
	// worker may release its destination. Each holds root material only if
	// the provider broke the contract, and is wiped by whichever side owns it
	// last.
	const canary = 0xC3
	var completed, refused [][]byte
	defer func() {
		for _, d := range completed {
			enclave.Wipe(d)
		}
	}()
	for _, ec := range ended {
		dst := bytes.Repeat([]byte{canary}, enclave.RootKeyBytes)
		uerr, returned := r.bounded(func() error { return p.UnsealRoot(ec.ctx, dst) },
			func() { enclave.Wipe(dst) })
		if !returned {
			return // incomplete, not misconduct; see bounded
		}
		completed = append(completed, dst)
		checkRefusal(r, property, "UnsealRoot", ec, uerr)
		if uerr != nil {
			refused = append(refused, dst)
		}
	}

	if err := withLocked(1, enclave.RootKeyBytes, func(bufs [][]byte) error {
		root := bufs[0]
		if err := p.UnsealRoot(r.ctx, root); err != nil {
			r.fail(property, "after refusing ended contexts, UnsealRoot on the same provider with a live context "+
				"failed: %v. A refused call must consume nothing a later call needs — a Sealer retries an unseal "+
				"that failed, and a one-shot handle spent on a refusal leaves it no root at all", err)
			return nil
		}
		if memscan.AllZero(root) {
			r.fail(property, "the control did not hold — the live UnsealRoot returned nil and an all-zero root")
			return nil
		}
		for _, dst := range refused {
			if containsRun(dst, root) {
				r.fail(property, "UnsealRoot refused an ended context and still wrote root material into the "+
					"destination; its caller has been told the call failed and will not wipe it")
			}
		}
		return nil
	}); err != nil {
		r.fail(property, "allocating a locked destination for the root: %v", err)
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

// fill sets every byte of b to v in place; bytes.Repeat would allocate a heap
// copy.
func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}
