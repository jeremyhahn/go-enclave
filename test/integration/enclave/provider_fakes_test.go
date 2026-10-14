// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// The providers providertest's conformance suite is run against in
// provider_failure_test.go. Each is a thin wrapper around a real
// SoftwareProvider (or, for the bare public-key wrap, a few lines of real
// arithmetic) that breaks exactly one property of the provider seam, so the
// suite's failure paths run for real: real locked memory, a real residue sweep
// through /proc/self/mem. Nothing here fakes the cryptography a property does
// not depend on.

// The properties providertest reports, as its documentation names them.
const (
	propPairing    = "mode/interface pairing"
	propRoundTrip  = "Protect/Unprotect round trip"
	propRetainKey  = "Protect does not retain the caller's key slice"
	propAfterWipe  = "Unprotect does not write into a destination the caller has finished with"
	propDisturb    = "a later provider call does not disturb an earlier destination"
	propTamper     = "a blob this provider did not produce is refused"
	propDstLength  = "a destination of the wrong length is an authentication failure"
	propForged     = "a blob forged from the provider's public key is refused"
	propConcurrent = "Protect and Unprotect are safe for concurrent use"
	propEnded      = "Protect and Unprotect refuse a context that has already ended"
	propResidue    = "no copy of the key is findable in the process after Unprotect returns"
	propRootFill   = "UnsealRoot writes a root across the whole destination"
	propRootRetain = "UnsealRoot does not retain the caller's destination"
	propRootEnded  = "UnsealRoot refuses a context that has already ended, and consumes nothing"
)

// errFake is the failure of a fake device. It is deliberately not
// enclave.ErrSealedAuthentication: it stands for an infrastructure fault.
var errFake = errors.New("fake device fault")

const keyLen = enclave.RootKeyBytes

// overlap is how long a contended fake holds a call open, so that the suite's
// concurrent workers are certain to be inside the provider together.
const overlap = 5 * time.Millisecond

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func fillBytes(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

// lab owns the real SoftwareProviders one conformance run creates, and releases
// their locked memory afterwards. It also keeps the copies a fake retains, so
// they stay resident for the residue sweep to find.
type lab struct {
	mu    sync.Mutex
	softs []enclave.SoftwareProvider
	hoard [][]byte
}

func (l *lab) adopt(s enclave.SoftwareProvider) enclave.SoftwareProvider {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.softs = append(l.softs, s)
	return s
}

func (l *lab) newSoft() enclave.SoftwareProvider { return l.adopt(enclave.NewSoftwareProvider()) }

func (l *lab) keep(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hoard = append(l.hoard, bytes.Clone(b))
}

func (l *lab) release(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.softs {
		if err := s.Destroy(); err != nil {
			t.Errorf("releasing a software provider: %v", err)
		}
	}
	for _, h := range l.hoard {
		enclave.Wipe(h)
	}
	l.softs, l.hoard = nil, nil
}

// keyFault is a KeyProtector (and only that): a SoftwareProvider whose Protect
// and Unprotect a test replaces. A nil hook is the honest provider.
type keyFault struct {
	soft      enclave.SoftwareProvider
	protect   func(ctx context.Context, key []byte) ([]byte, error)
	unprotect func(ctx context.Context, blob, dst []byte) error
}

func (f *keyFault) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if f.protect != nil {
		return f.protect(ctx, key)
	}
	return f.soft.Protect(ctx, key)
}

func (f *keyFault) Unprotect(ctx context.Context, blob, dst []byte) error {
	if f.unprotect != nil {
		return f.unprotect(ctx, blob, dst)
	}
	return f.soft.Unprotect(ctx, blob, dst)
}

// rootFault is a RootUnsealer (and only that) over a SoftwareProvider.
type rootFault struct {
	soft   enclave.SoftwareProvider
	unseal func(ctx context.Context, dst []byte) error
}

func (f *rootFault) UnsealRoot(ctx context.Context, dst []byte) error {
	if f.unseal != nil {
		return f.unseal(ctx, dst)
	}
	return f.soft.UnsealRoot(ctx, dst)
}

// providerFor builds the Config.New of a run: every call returns a fresh
// provider, wired by wire.
type providerFor func(l *lab) func() (any, error)

func keysWith(wire func(l *lab, f *keyFault)) providerFor {
	return func(l *lab) func() (any, error) {
		return func() (any, error) {
			f := &keyFault{soft: l.newSoft()}
			if wire != nil {
				wire(l, f)
			}
			return f, nil
		}
	}
}

func rootsWith(wire func(l *lab, f *rootFault)) providerFor {
	return func(l *lab) func() (any, error) {
		return func() (any, error) {
			f := &rootFault{soft: l.newSoft()}
			if wire != nil {
				wire(l, f)
			}
			return f, nil
		}
	}
}

// --- KeyProtector faults ---------------------------------------------------

// protectFails: Protect fails on a live context.
func protectFails(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, _ []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errFake
	}
}

// protectReturnsNothing: Protect succeeds with an empty blob.
func protectReturnsNothing(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, _ []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte{}, nil
	}
}

// blobIsTheKey: the "blob" is the key in the clear, and Unprotect copies it
// out without authenticating anything.
func blobIsTheKey(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return bytes.Clone(key), nil
	}
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(dst) != keyLen || len(blob) != keyLen {
			return enclave.ErrSealedAuthentication
		}
		copy(dst, blob)
		return nil
	}
}

// protectMutatesItsInput: Protect corrupts the caller's key after wrapping it.
func protectMutatesItsInput(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		blob, err := f.soft.Protect(ctx, key)
		if err == nil {
			key[0] ^= 0xFF
		}
		return blob, err
	}
}

// protectMutatesOnRefusal: Protect refuses an ended context but corrupts the
// caller's key on the way out.
func protectMutatesOnRefusal(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			key[0] ^= 0xFF
			return nil, err
		}
		return f.soft.Protect(ctx, key)
	}
}

// unprotectFails: Unprotect refuses everything it is given.
func unprotectFails(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, _, _ []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return enclave.ErrSealedAuthentication
	}
}

// unprotectWritesTheWrongBytes: Unprotect reports success and leaves a
// constant in the destination.
func unprotectWritesTheWrongBytes(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if err := f.soft.Unprotect(ctx, blob, dst); err != nil {
			return err
		}
		fillBytes(dst, 0x11)
		return nil
	}
}

// afterWipe is what a provider that kept the caller's key slice does once the
// caller has wiped it.
type afterWipe int

const (
	afterWipeRecoversZeros afterWipe = iota
	afterWipeFails
	afterWipeRecoversOther
)

// keepsTheCallersSlice: Protect keeps the slice it was given instead of
// copying it, and Unprotect consults it. Until the caller wipes the slice the
// provider is indistinguishable from an honest one.
func keepsTheCallersSlice(mode afterWipe) func(*lab, *keyFault) {
	return func(_ *lab, f *keyFault) {
		var (
			mu   sync.Mutex
			held []byte
		)
		f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
			blob, err := f.soft.Protect(ctx, key)
			if err == nil {
				mu.Lock()
				held = key
				mu.Unlock()
			}
			return blob, err
		}
		f.unprotect = func(ctx context.Context, blob, dst []byte) error {
			if err := f.soft.Unprotect(ctx, blob, dst); err != nil {
				return err
			}
			mu.Lock()
			h := held
			mu.Unlock()
			if h == nil || !isAllZero(h) {
				return nil
			}
			switch mode {
			case afterWipeFails:
				return enclave.ErrSealedAuthentication
			case afterWipeRecoversOther:
				fillBytes(dst, 0x77)
			default:
				enclave.Wipe(dst)
			}
			return nil
		}
	}
}

// rewrite is what a provider that kept the last destination does to it on the
// next successful Unprotect.
type rewrite int

const (
	rewriteWithItsOwnKey rewrite = iota
	rewriteWithTheNewKey
	rewriteWithGarbage
	rewriteWithZeros
)

// writesToTheLastDestination: Unprotect keeps the destination it last filled
// and, on its next success, writes into it again.
func writesToTheLastDestination(mode rewrite) func(*lab, *keyFault) {
	return func(_ *lab, f *keyFault) {
		var (
			mu        sync.Mutex
			last, key []byte
		)
		f.unprotect = func(ctx context.Context, blob, dst []byte) error {
			if err := f.soft.Unprotect(ctx, blob, dst); err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			if last != nil {
				switch mode {
				case rewriteWithItsOwnKey:
					copy(last, key)
				case rewriteWithTheNewKey:
					copy(last, dst)
				case rewriteWithGarbage:
					fillBytes(last, 0xEE)
				default:
					enclave.Wipe(last)
				}
			}
			last, key = dst, bytes.Clone(dst)
			return nil
		}
	}
}

// authenticatesNothingWhenTheDestinationFits: Unprotect accepts a blob it
// cannot authenticate, as long as the destination is the right length.
func authenticatesNothingWhenTheDestinationFits(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		err := f.soft.Unprotect(ctx, blob, dst)
		if errors.Is(err, enclave.ErrSealedAuthentication) && len(dst) == keyLen {
			return nil
		}
		return err
	}
}

// misreportsAForgery: Unprotect refuses an unauthentic blob, but as a device
// fault rather than ErrSealedAuthentication.
func misreportsAForgery(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		err := f.soft.Unprotect(ctx, blob, dst)
		if errors.Is(err, enclave.ErrSealedAuthentication) && len(dst) == keyLen {
			return errFake
		}
		return err
	}
}

// recordsTheLastBlob wires Protect to remember the blob of its most recent
// success, which a leaking fake can reopen.
func recordsTheLastBlob(f *keyFault, mu *sync.Mutex, last *[]byte) {
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		blob, err := f.soft.Protect(ctx, key)
		if err == nil {
			mu.Lock()
			*last = blob
			mu.Unlock()
		}
		return blob, err
	}
}

// leaksOnRefusal: Unprotect refuses an unauthentic blob after it has already
// opened a genuine one into the destination.
func leaksOnRefusal(_ *lab, f *keyFault) {
	var (
		mu   sync.Mutex
		last []byte
	)
	recordsTheLastBlob(f, &mu, &last)
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		err := f.soft.Unprotect(ctx, blob, dst)
		if !errors.Is(err, enclave.ErrSealedAuthentication) {
			return err
		}
		mu.Lock()
		good := last
		mu.Unlock()
		if good != nil && len(dst) == keyLen {
			_ = f.soft.Unprotect(ctx, good, dst)
		}
		return err
	}
}

// leaksIntoAMisSizedDestination: Unprotect refuses a destination of the wrong
// length, after copying as much of the key as fits into it.
func leaksIntoAMisSizedDestination(_ *lab, f *keyFault) {
	var (
		mu   sync.Mutex
		last []byte
	)
	recordsTheLastBlob(f, &mu, &last)
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		err := f.soft.Unprotect(ctx, blob, dst)
		if !errors.Is(err, enclave.ErrSealedAuthentication) {
			return err
		}
		mu.Lock()
		good := last
		mu.Unlock()
		if good != nil && len(dst) != keyLen {
			scratch := make([]byte, keyLen)
			if f.soft.Unprotect(ctx, good, scratch) == nil {
				copy(dst, scratch)
			}
			enclave.Wipe(scratch)
		}
		return err
	}
}

// acceptsAnyDestination: Unprotect returns success for a destination of the
// wrong length, writing nothing.
func acceptsAnyDestination(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if len(dst) != keyLen {
			return nil
		}
		return f.soft.Unprotect(ctx, blob, dst)
	}
}

// misreportsAnyDestination: Unprotect refuses a destination of the wrong
// length as a device fault.
func misreportsAnyDestination(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if len(dst) != keyLen {
			return errFake
		}
		return f.soft.Unprotect(ctx, blob, dst)
	}
}

// ignoresTheContext: Protect and Unprotect run to completion whatever the
// caller's context says.
func ignoresTheContext(_ *lab, f *keyFault) {
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		return f.soft.Protect(context.WithoutCancel(ctx), key)
	}
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		return f.soft.Unprotect(context.WithoutCancel(ctx), blob, dst)
	}
}

// refusesAnEndedContextAs: Protect and Unprotect refuse an ended context with
// err instead of the context's own error.
func refusesAnEndedContextAs(err error) func(*lab, *keyFault) {
	return func(_ *lab, f *keyFault) {
		f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
			if ctx.Err() != nil {
				return nil, err
			}
			return f.soft.Protect(ctx, key)
		}
		f.unprotect = func(ctx context.Context, blob, dst []byte) error {
			if ctx.Err() != nil {
				return err
			}
			return f.soft.Unprotect(ctx, blob, dst)
		}
	}
}

// writesWhileRefusingAnEndedContext: Unprotect opens the blob into the
// destination and only then refuses the ended context.
func writesWhileRefusingAnEndedContext(_ *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if err := ctx.Err(); err != nil {
			_ = f.soft.Unprotect(context.WithoutCancel(ctx), blob, dst)
			return err
		}
		return f.soft.Unprotect(ctx, blob, dst)
	}
}

// isBrokenByARefusal: refusing an ended context spends the provider; every
// live Unprotect afterwards fails.
func isBrokenByARefusal(_ *lab, f *keyFault) {
	var spent atomic.Bool
	f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			spent.Store(true)
			return nil, err
		}
		return f.soft.Protect(ctx, key)
	}
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		if err := ctx.Err(); err != nil {
			spent.Store(true)
			return err
		}
		if spent.Load() {
			return errFake
		}
		return f.soft.Unprotect(ctx, blob, dst)
	}
}

// contention is how a provider that shares state between calls goes wrong when
// the suite calls it from several goroutines at once.
type contention int

const (
	contendedSlotHoldsAnotherKey contention = iota
	contendedSlotHoldsZeros
	contendedUnprotectWritesGarbage
	contendedProtectFails
	contendedUnprotectFails
)

// sharesStateAcrossCalls: correct for one caller at a time. Two kinds of
// shared state, neither a data race (the fakes lock what they share): a staging
// slot that a second Protect overwrites before the first has read it, and a
// call that notices another in flight.
func sharesStateAcrossCalls(mode contention) func(*lab, *keyFault) {
	return func(_ *lab, f *keyFault) {
		var (
			mu       sync.Mutex
			slot     []byte
			inflight atomic.Int64
		)
		busy := func() bool {
			inflight.Add(1)
			time.Sleep(overlap)
			shared := inflight.Load() > 1
			inflight.Add(-1)
			return shared
		}
		switch mode {
		case contendedSlotHoldsAnotherKey, contendedSlotHoldsZeros:
			f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
				mu.Lock()
				slot = bytes.Clone(key)
				mu.Unlock()
				time.Sleep(overlap)
				mu.Lock()
				staged := slot
				if mode == contendedSlotHoldsZeros {
					slot = make([]byte, keyLen)
				}
				mu.Unlock()
				return f.soft.Protect(ctx, staged)
			}
		case contendedUnprotectWritesGarbage:
			f.unprotect = func(ctx context.Context, blob, dst []byte) error {
				shared := busy()
				if err := f.soft.Unprotect(ctx, blob, dst); err != nil {
					return err
				}
				if shared {
					fillBytes(dst, 0x77)
				}
				return nil
			}
		case contendedProtectFails:
			f.protect = func(ctx context.Context, key []byte) ([]byte, error) {
				if busy() {
					return nil, errFake
				}
				return f.soft.Protect(ctx, key)
			}
		case contendedUnprotectFails:
			f.unprotect = func(ctx context.Context, blob, dst []byte) error {
				if busy() {
					return enclave.ErrSealedAuthentication
				}
				return f.soft.Unprotect(ctx, blob, dst)
			}
		}
	}
}

// retainsACopyOfTheKey: Unprotect keeps a heap copy of every key it recovers,
// which only the residue sweep can see.
func retainsACopyOfTheKey(l *lab, f *keyFault) {
	f.unprotect = func(ctx context.Context, blob, dst []byte) error {
		err := f.soft.Unprotect(ctx, blob, dst)
		if err == nil {
			l.keep(dst)
		}
		return err
	}
}

// --- RootUnsealer faults ---------------------------------------------------

// unsealFailsFromCall: the nth live UnsealRoot, and every one after it, fails.
func unsealFailsFromCall(n int64) func(*lab, *rootFault) {
	return func(_ *lab, f *rootFault) {
		var calls atomic.Int64
		f.unseal = func(ctx context.Context, dst []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if calls.Add(1) >= n {
				return errFake
			}
			return f.soft.UnsealRoot(ctx, dst)
		}
	}
}

// unsealWritesNothing: UnsealRoot succeeds and leaves the destination as it
// found it.
func unsealWritesNothing(_ *lab, f *rootFault) {
	f.unseal = func(ctx context.Context, _ []byte) error { return ctx.Err() }
}

// unsealWritesAPlaceholder: the "root" is a constant: zero, or v.
func unsealWritesAPlaceholder(v byte) func(*lab, *rootFault) {
	return func(_ *lab, f *rootFault) {
		f.unseal = func(ctx context.Context, dst []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			fillBytes(dst, v)
			return nil
		}
	}
}

// unsealWritesHalf: only the first half of the destination receives the root.
func unsealWritesHalf(_ *lab, f *rootFault) {
	f.unseal = func(ctx context.Context, dst []byte) error {
		root := make([]byte, keyLen)
		defer enclave.Wipe(root)
		if err := f.soft.UnsealRoot(ctx, root); err != nil {
			return err
		}
		copy(dst[:keyLen/2], root)
		return nil
	}
}

// unsealIsDifferentEachTime: every call returns a fresh random root.
func unsealIsDifferentEachTime(_ *lab, f *rootFault) {
	f.unseal = func(ctx context.Context, dst []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := rand.Read(dst)
		return err
	}
}

// forgetful is how a RootUnsealer that kept its callers' destinations treats
// them on later calls.
type forgetful int

const (
	forgetfulZeroesTheLast forgetful = iota
	forgetfulOverwritesTheLast
	forgetfulRewritesWipedOnes
)

// keepsTheDestinations: UnsealRoot keeps every destination it filled. On a
// later call handed a clean destination it zeroes or overwrites the last one;
// or, on any later call, it writes the root into a destination the caller has
// since wiped.
func keepsTheDestinations(mode forgetful) func(*lab, *rootFault) {
	return func(_ *lab, f *rootFault) {
		var (
			mu   sync.Mutex
			dsts [][]byte
		)
		f.unseal = func(ctx context.Context, dst []byte) error {
			clean := isAllZero(dst)
			if err := f.soft.UnsealRoot(ctx, dst); err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			switch mode {
			case forgetfulZeroesTheLast:
				if clean && len(dsts) > 0 {
					enclave.Wipe(dsts[len(dsts)-1])
				}
			case forgetfulOverwritesTheLast:
				if clean && len(dsts) > 0 {
					fillBytes(dsts[len(dsts)-1], 0xEE)
				}
			default:
				for _, d := range dsts {
					if isAllZero(d) {
						copy(d, dst)
					}
				}
			}
			dsts = append(dsts, dst)
			return nil
		}
	}
}

// ignoresTheContextWhenUnsealing: UnsealRoot runs to completion whatever the
// caller's context says.
func ignoresTheContextWhenUnsealing(_ *lab, f *rootFault) {
	f.unseal = func(ctx context.Context, dst []byte) error {
		return f.soft.UnsealRoot(context.WithoutCancel(ctx), dst)
	}
}

// refusesAnEndedContextWhenUnsealingAs: UnsealRoot refuses an ended context
// with err instead of the context's own error.
func refusesAnEndedContextWhenUnsealingAs(err error) func(*lab, *rootFault) {
	return func(_ *lab, f *rootFault) {
		f.unseal = func(ctx context.Context, dst []byte) error {
			if ctx.Err() != nil {
				return err
			}
			return f.soft.UnsealRoot(ctx, dst)
		}
	}
}

// writesTheRootWhileRefusing: UnsealRoot fills the destination and only then
// refuses the ended context.
func writesTheRootWhileRefusing(_ *lab, f *rootFault) {
	f.unseal = func(ctx context.Context, dst []byte) error {
		if err := ctx.Err(); err != nil {
			_ = f.soft.UnsealRoot(context.WithoutCancel(ctx), dst)
			return err
		}
		return f.soft.UnsealRoot(ctx, dst)
	}
}

// isSpentByARefusalWhenUnsealing: refusing an ended context consumes the
// one-shot handle behind the root; every live UnsealRoot afterwards fails.
func isSpentByARefusalWhenUnsealing(_ *lab, f *rootFault) {
	var spent atomic.Bool
	f.unseal = func(ctx context.Context, dst []byte) error {
		if err := ctx.Err(); err != nil {
			spent.Store(true)
			return err
		}
		if spent.Load() {
			return errFake
		}
		return f.soft.UnsealRoot(ctx, dst)
	}
}

// heapRoot is a RootUnsealer that holds its root on the heap, so it runs
// where no locked memory is left.
type heapRoot struct{ root [keyLen]byte }

func newHeapRoot() (*heapRoot, error) {
	r := &heapRoot{}
	_, err := rand.Read(r.root[:])
	return r, err
}

func (r *heapRoot) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(dst) != keyLen {
		return enclave.ErrInvalidSize
	}
	copy(dst, r.root[:])
	return nil
}

// --- A public-key wrap ------------------------------------------------------

// bareWrap is a KeyProtector in the shape of a public-key wrap with nothing an
// attacker lacks to authenticate it: a blob is the key masked with a public
// pad, behind a magic and a tag over both. The tag and the pad are public, so
// anyone can build a blob it accepts; yet it refuses every malformed,
// truncated, extended or bit-flipped blob, which is why only providertest's
// Config.Forge can tell it from a sound provider.
type bareWrap struct {
	// leak makes Unprotect write the unmasked key into the destination before
	// it verifies the tag.
	leak bool
}

var (
	bareWrapMagic = []byte{'B', 'W', '1', 0}
	bareWrapPad   = sha256.Sum256([]byte("go-enclave integration: bareWrap public pad"))
)

const bareWrapTag = 16

func bareWrapTagOf(payload []byte) []byte {
	h := sha256.New()
	h.Write(bareWrapMagic)
	h.Write(payload)
	h.Write(bareWrapPad[:])
	return h.Sum(nil)[:bareWrapTag]
}

// bareWrapBlob is everything an attacker needs to wrap key for a bareWrap.
func bareWrapBlob(key []byte) []byte {
	payload := make([]byte, len(key))
	for i := range key {
		payload[i] = key[i] ^ bareWrapPad[i%len(bareWrapPad)]
	}
	blob := append(bytes.Clone(bareWrapMagic), payload...)
	return append(blob, bareWrapTagOf(payload)...)
}

func (b *bareWrap) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) != keyLen {
		return nil, enclave.ErrInvalidSize
	}
	return bareWrapBlob(key), nil
}

func (b *bareWrap) Unprotect(ctx context.Context, blob, dst []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(dst) != keyLen || len(blob) != len(bareWrapMagic)+keyLen+bareWrapTag ||
		!bytes.Equal(blob[:len(bareWrapMagic)], bareWrapMagic) {
		return enclave.ErrSealedAuthentication
	}
	payload := blob[len(bareWrapMagic) : len(bareWrapMagic)+keyLen]
	unmask := func() {
		for i := range dst {
			dst[i] = payload[i] ^ bareWrapPad[i%len(bareWrapPad)]
		}
	}
	if b.leak {
		unmask()
	}
	if subtle.ConstantTimeCompare(blob[len(blob)-bareWrapTag:], bareWrapTagOf(payload)) != 1 {
		return enclave.ErrSealedAuthentication
	}
	unmask()
	return nil
}

// --- Holding a call open ----------------------------------------------------

// blocker stands for a provider call that never returns on its own. The call
// cancels the run's context and then blocks until release is closed, which
// leaves providertest's bounded call to abandon it.
type blocker struct {
	cancelRun context.CancelFunc
	entered   chan struct{}
	release   chan struct{}
	exited    chan struct{}
	enterOnce sync.Once
	exitOnce  sync.Once
}

func newBlocker(cancelRun context.CancelFunc) *blocker {
	return &blocker{
		cancelRun: cancelRun,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
		exited:    make(chan struct{}),
	}
}

// hold is the body of the blocked call.
func (b *blocker) hold(ctx context.Context) error {
	defer b.exitOnce.Do(func() { close(b.exited) })
	b.enterOnce.Do(func() { close(b.entered) })
	b.cancelRun()
	<-b.release
	return ctx.Err()
}

// finish requires that the call was held, lets it go and waits for it to
// return, so nothing runs on past the test.
func (b *blocker) finish(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	default:
		t.Error("the provider call that was to be held open was never made")
	}
	close(b.release)
	select {
	case <-b.exited:
	case <-time.After(30 * time.Second):
		t.Error("the abandoned provider call did not return once released")
	}
}

// --- Reading a run's verdict --------------------------------------------------

// verdict is what a TestProvider error says, by type.
type verdict struct {
	properties map[string]bool
	unmeasured map[string]bool
	aborted    bool
	other      []error
}

// judge sorts the findings joined in err by their providertest types.
func judge(err error) verdict {
	v := verdict{properties: map[string]bool{}, unmeasured: map[string]bool{}}
	if err == nil {
		return v
	}
	findings := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		findings = j.Unwrap()
	}
	for _, f := range findings {
		var (
			pe *providertest.PropertyError
			nm *providertest.NotMeasuredError
		)
		switch {
		case errors.As(f, &pe):
			v.properties[pe.Property] = true
		case errors.As(f, &nm):
			if !errors.Is(f, providertest.ErrNotMeasured) {
				v.other = append(v.other, f)
			}
			v.unmeasured[nm.Property] = true
		case errors.Is(f, providertest.ErrAborted):
			v.aborted = true
		default:
			v.other = append(v.other, f)
		}
	}
	return v
}

func sameSet(got map[string]bool, want []string) (missing, extra []string) {
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
		if !got[w] {
			missing = append(missing, w)
		}
	}
	for g := range got {
		if !wanted[g] {
			extra = append(extra, g)
		}
	}
	return missing, extra
}
