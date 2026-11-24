// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package providertest is the conformance suite for the go-enclave provider seam; run [TestProvider] against a provider.
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
	// New returns a fresh provider, a [enclave.KeyProtector], [enclave.RootUnsealer] or both.
	New func() (any, error)

	// Modes lists the sealing modes the provider claims, checked in both directions.
	Modes []enclave.Mode

	// SkipResidueSweep, when non-empty, is why the residue sweep is skipped; empty, an unmeasured sweep is [ErrNotMeasured].
	SkipResidueSweep string

	// SingleUseRoot, when non-empty, is why UnsealRoot succeeds only once per instance; it relaxes the two second-call checks.
	SingleUseRoot string

	// PublicKey declares that Protect needs no secret; set it with Forge, or SkipForgery accepts the gap.
	PublicKey bool

	// Forge builds a blob from the provider's public material only; Unprotect must refuse it.
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

// TestProvider runs the conformance suite against cfg's provider and returns nil or every finding.
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

// bounded runs call on its own goroutine until it returns or the run's context ends; an abandoned call's worker owns cleanup.
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

// isNilProvider reports whether p is nil or wraps a nil value, as [enclave.NewSealer] checks.
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

// The spy properties that catch writes after a call returned, which checkConcurrentUse must not race with.
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

// checkProtectDoesNotRetainTheKey requires Unprotect to recover a key after the caller wipes Protect's input.
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

// checkDestinationNotWrittenAfterTheCallerWipedIt requires a wiped destination to stay zero across later calls.
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

// checkDestinationNotDisturbedByALaterCall requires a destination in use to survive later calls.
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

// checkTamperedBlobRefused requires Unprotect to refuse foreign blobs with ErrSealedAuthentication and leave no plaintext.
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

// checkForgedBlobRefused submits the blob Config.Forge builds from public material.
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

// checkConcurrentUse runs concurrent round trips and requires each to recover its own key.
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

// checkUnsealRootFillsTheDestination proves UnsealRoot writes every byte, deterministically, using canary-filled destinations.
func checkUnsealRootFillsTheDestination(r *report, cfg Config) {
	const property = "UnsealRoot writes a root across the whole destination"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	const canary = 0xAA
	// Locked: against a real device these receive its actual root.
	if err := withLocked(3, enclave.RootKeyBytes, func(bufs [][]byte) error {
		first, second, third := bufs[0], bufs[1], bufs[2]
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
			// A byte is unwritten only if it kept its fill on three calls under three fills.
			fill(third, 0x3C)
			if err := p.UnsealRoot(r.ctx, third); err != nil {
				r.fail(property, "a third UnsealRoot on the same provider: %v. If this provider consumes a "+
					"one-shot handle on a successful unseal, set Config.SingleUseRoot with the reason; the seam "+
					"guarantees only that a Sealer calls UnsealRoot at most once", err)
				return nil
			}
			var unwritten []int
			for i := range first {
				if first[i] == 0xAA && second[i] == 0x55 && third[i] == 0x3C {
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

// withLocked runs fn over n locked buffers and destroys them when fn returns.
func withLocked(n, size int, fn func(bufs [][]byte) error) error {
	encs := make([]enclave.ByteAccess, 0, n)
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

// checkKeyProtectorRefusesAnEndedContext checks Protect and Unprotect refuse an ended context and consume nothing.
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

// checkRootUnsealerRefusesAnEndedContext checks UnsealRoot refuses an ended context and consumes nothing.
func checkRootUnsealerRefusesAnEndedContext(r *report, cfg Config) {
	const property = "UnsealRoot refuses a context that has already ended, and consumes nothing"

	p, err := newUnsealer(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	ended, release := r.endedContexts()
	defer release()

	// Heap, not locked: an abandoned call can outlive this check.
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
