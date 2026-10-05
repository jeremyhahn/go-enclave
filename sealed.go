// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"sync"
)

var (
	// ErrSealFailed reports that material could not be encrypted because the
	// AEAD, the CSPRNG or the provider failed. The cause is joined and
	// reachable with errors.Is and errors.As.
	ErrSealFailed = errors.New("enclave: could not seal material")

	// ErrOpenFailed reports that sealed material could not be recovered for a
	// reason that says nothing about the material: the caller's context ended
	// before or during the open, or a [ModePerOperation] provider failed with
	// its own infrastructure error. The cause is joined and reachable with
	// errors.Is and errors.As, so a canceled open also matches
	// context.Canceled or context.DeadlineExceeded. The value is intact.
	//
	// [ErrSealedAuthentication], [ErrSealerWiped], [ErrLockedMemoryUnavailable]
	// and the budget refusals are not joined under it, except that when a
	// provider returns one of the first three after the caller's context has
	// ended, the error joins this sentinel, ctx.Err() and the provider's error,
	// and matches all of them.
	ErrOpenFailed = errors.New("enclave: could not open sealed material")

	// ErrSealedAuthentication reports that sealed material did not
	// authenticate: the ciphertext or the wrapped-key blob was altered,
	// truncated or forged, the two were re-paired across values, or the blob
	// was produced by a different provider. A [KeyProtector] returns it for a
	// blob its own Protect did not produce. The causes are deliberately
	// indistinguishable.
	ErrSealedAuthentication = errors.New("enclave: sealed material failed authentication")

	// ErrPlaintextEscaped reports that the AEAD wrote recovered plaintext
	// somewhere other than the locked destination. It is unreachable while
	// every decryption hands crypto/cipher a destination of exact capacity,
	// and is checked rather than assumed; the stray copy is wiped, not used.
	ErrPlaintextEscaped = errors.New("enclave: recovered plaintext did not land in locked memory")

	// ErrMaterialTooLarge reports material longer than AES-GCM will seal in
	// one message, (2^32-2) blocks of 16 bytes (about 64 GiB), or whose sealed
	// form (plaintext plus 28 bytes of nonce and tag) would not fit in an int,
	// about 2 GiB on 32-bit platforms. crypto/cipher would panic on either.
	ErrMaterialTooLarge = errors.New("enclave: material is too large to seal")
)

// dekBytes selects AES-256 for the per-value data key.
const dekBytes = 32

// maxSealedPlaintext is AES-GCM's per-message plaintext ceiling. Typed uint64
// because it does not fit in a 32-bit int.
const maxSealedPlaintext uint64 = (1<<32 - 2) * 16

// sealableLength reports whether n bytes can be sealed in one message. It
// takes a length so the bound is testable without allocating 64 GiB.
func sealableLength(n uint64) error {
	return sealableWithin(n, math.MaxInt)
}

// sealableWithin is sealableLength for a platform whose largest int is
// maxInt, so the 32-bit bound is testable on a 64-bit host.
func sealableWithin(n, maxInt uint64) error {
	if n > maxSealedPlaintext || n > maxInt-sealedOverhead {
		return ErrMaterialTooLarge
	}
	return nil
}

// sealedOverhead is the 12-byte nonce and 16-byte tag AES-GCM with a random
// nonce adds to every sealed message.
const sealedOverhead = 12 + 16

// withAEAD runs fn with an AES-GCM AEAD built from the key in key, borrowed
// for the duration of the call. Every AES operation in this package goes
// through here, and it is the only place a key leaves locked memory:
// aes.NewCipher puts the key schedule, whose first round key is the key
// itself, on the heap, where it stays until the memory is reused. Under
// GOEXPERIMENT=runtimesecret the call runs in secretDo and the schedule is
// erased once unreachable ([KeyScheduleErasure]); no cipher.Block or
// cipher.AEAD outlives the call. See docs/sealing/engineering.md,
// "Key-schedule heap exposure".
func withAEAD(key *MemoryEnclave, fn func(cipher.AEAD) error) error {
	var err error
	secretDo(func() { err = withAEADErasable(key, fn) })
	return err
}

func withAEADErasable(key *MemoryEnclave, fn func(cipher.AEAD) error) error {
	return key.WithBytes(func(k []byte) error {
		block, err := aes.NewCipher(k)
		if err != nil {
			return errors.Join(ErrSealFailed, err)
		}
		// Never fall back to NewGCM: FIPS 140-only mode refuses caller-supplied
		// IVs, and this removes nonce management from callers. It also means
		// GOEXPERIMENT=boringcrypto builds fail here on every seal, by design.
		gcm, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return errors.Join(ErrSealFailed, err)
		}
		return fn(gcm)
	})
}

// sealWithKey encrypts plaintext under the key in ke, binding aad, and
// returns nonce || ciphertext || tag as an ordinary heap slice.
func sealWithKey(ke *MemoryEnclave, plaintext, aad []byte) ([]byte, error) {
	if err := sealableLength(uint64(len(plaintext))); err != nil {
		return nil, err
	}

	var sealed []byte
	if err := withAEAD(ke, func(gcm cipher.AEAD) error {
		// A nil nonce is legal only for an AEAD with NonceSize 0; cipher.NewGCM
		// panics on it, so a change of AEAD fails loudly.
		// TestSealedEnclave_SealIsNonDeterministic catches an explicit fixed nonce.
		/* #nosec G407 -- nil is required by NewGCMWithRandomNonce, which generates the nonce itself; see above */
		sealed = gcm.Seal(nil, nil, plaintext, aad)
		return nil
	}); err != nil {
		return nil, err
	}
	return sealed, nil
}

// openWithKeyInto decrypts sealed under the key in ke, verifying aad, into
// dst and nowhere else. A plaintext whose length is not exactly len(dst) is
// refused as an authentication failure before decrypting, because a longer
// one would make the AEAD's append reallocate onto the heap.
func openWithKeyInto(ke *MemoryEnclave, sealed, aad, dst []byte) error {
	return withAEAD(ke, func(gcm cipher.AEAD) error {
		return openInto(gcm, sealed, aad, dst)
	})
}

// openInto is openWithKeyInto's body for an AEAD already built, separate so
// its guards can be exercised with an AEAD that misbehaves.
func openInto(gcm cipher.AEAD, sealed, aad, dst []byte) error {
	if len(sealed) <= sealedOverhead || len(sealed)-sealedOverhead != len(dst) {
		return ErrSealedAuthentication
	}

	// dst[:0:len(dst)] pins the capacity so the AEAD's append cannot reallocate.
	got, oerr := gcm.Open(dst[:0:len(dst)], nil, sealed, aad)
	if oerr != nil {
		return ErrSealedAuthentication
	}
	// Residency before length: a result that escaped AND has the wrong length
	// must still have its heap copy wiped.
	if len(got) > 0 && &got[0] != &dst[0] {
		wipe(got)
		return ErrPlaintextEscaped
	}
	if len(got) != len(dst) {
		return ErrSealedAuthentication
	}
	return nil
}

// newKeyEnclave returns a [MemoryEnclave] holding n bytes from the CSPRNG,
// generated directly into locked memory.
//
//nolint:unparam // n is always 32 today because dekBytes, kekBytes and RootKeyBytes are three independent decisions that happen to agree; folding them into one constant here would couple them.
func newKeyEnclave(n int) (*MemoryEnclave, error) {
	e, err := NewMemoryEnclaveSized(n)
	if err != nil {
		return nil, err
	}
	if err := e.WithBytes(fillRandom); err != nil {
		if derr := e.Destroy(); derr != nil {
			return nil, errors.Join(ErrSealFailed, err, derr)
		}
		return nil, errors.Join(ErrSealFailed, err)
	}
	return e, nil
}

// SealedEnclave holds material encrypted at rest and decrypts it into a new
// [MemoryEnclave] only when [SealedEnclave.Open] is called. Use it for
// material needed occasionally and held for a long time; use a MemoryEnclave
// for material in continuous use.
//
// Each value is an envelope on the ordinary heap: the material sealed with
// AES-256-GCM under a fresh 32-byte data key (DEK), and the DEK wrapped by
// the [Sealer] (by its provider in [ModePerOperation], by its key hierarchy
// in [ModeRootKey]). The wrapped DEK is bound as additional authenticated
// data, so re-pairing halves from different values fails authentication.
//
// Recovered plaintext never reaches the ordinary heap, but AES key schedules
// do; what a reader of this process's memory can obtain depends on the
// [Mode] the value was sealed under. See [Mode] and [KeyScheduleErasure].
//
// There is no constructor for sealed bytes: the envelope format is internal,
// unversioned and keyed to a process-lifetime Sealer.
//
// A SealedEnclave owns no locked pages and is not destroyed by [WipeAll].
// After a sweep it may still report [SealedEnclave.IsAlive] while
// [SealedEnclave.Open] fails with [ErrSealerWiped]; [SealedEnclave.Openable]
// reports which.
//
// The zero value is not usable; construct one with [NewSealed] or
// [Sealer.Seal]. A nil *SealedEnclave is a valid receiver for every method.
// A SealedEnclave is safe for concurrent use.
type SealedEnclave struct {
	mu sync.RWMutex

	// sealer is nil'd on Destroy so a destroyed value does not pin a Sealer.
	sealer *Sealer

	// sealed is nonce || ciphertext || tag under the DEK; nil once destroyed.
	sealed []byte

	// blob is the wrapped DEK and the AAD sealed was bound to.
	blob []byte

	// size is the plaintext length; Open sizes its destination exactly so the
	// AEAD cannot allocate.
	size int

	// opens counts opens in flight, which use the envelope with mu released.
	// While it is non-zero Destroy leaves the wipe to the last open out.
	// Guarded by mu.
	opens int

	// sealedAtGen is the sweep generation at seal time. Written once at
	// construction, so Openable reads it without the lock.
	sealedAtGen uint64
}

// NewSealed encrypts data under the process [Sealer] and returns the sealed
// enclave. The process Sealer is whatever [SetSealer] installed, or, if
// nothing did before the first seal, a [SoftwareProvider] in [ModeRootKey].
// [Sealer.Seal] does the same for an explicit sealer.
//
// It takes ownership of data as [NewMemoryEnclave] does: the caller's slice
// is wiped before it returns, on every path.
//
// It returns ErrEmptyEnclave when data is empty, ErrMaterialTooLarge above
// AES-GCM's per-message ceiling, ErrSealFailed when the AEAD, the CSPRNG or
// the provider fails, ErrLockedMemoryUnavailable when the kernel refuses a
// locked page, ErrSealerWiped after a shutdown sweep destroyed the sealer's
// keys, and ErrSealerDestroyed after [Sealer.Destroy] on the process Sealer.
//
// ctx bounds every step that can block: the first root unseal in
// [ModeRootKey], and every Protect in [ModePerOperation]. An ended context
// fails the seal with an error matching both ErrSealFailed and ctx.Err(), with
// any underlying failure joined. A context already ended on entry is refused
// before the process Sealer is looked up, so it never installs the default.
// A root unsealed for a caller that then gave up is kept and used by the next
// seal.
//
// On a GOEXPERIMENT=boringcrypto build it always returns ErrSealFailed.
func NewSealed(ctx context.Context, data []byte) (*SealedEnclave, error) {
	// The lookup below installs the default one-shot; an abandoned call must
	// not lock the configuration a later SetSealer is meant to make.
	if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
		Wipe(data)
		return nil, err
	}

	s, err := processSealer()
	if err != nil {
		Wipe(data)
		return nil, err
	}
	return s.Seal(ctx, data)
}

// Open decrypts the material directly into a new [MemoryEnclave] and returns
// it. The caller owns the result and must Destroy it; each call returns an
// independent enclave. Open late and destroy early.
//
// The destination and the transient key pages are allocated outside any
// [Allocator] budget; callers holding a budget use [SealedEnclave.OpenWith].
//
// It returns ErrEnclaveDestroyed once Destroy has run, ErrSealedAuthentication
// if the envelope does not authenticate, ErrLockedMemoryUnavailable when the
// kernel refuses a locked page (the value survives and the open can be
// retried), ErrSealerWiped when a shutdown sweep destroyed the sealer's keys,
// and ErrSealerDestroyed after [Sealer.Destroy]. In [ModePerOperation] a
// provider's own failure is joined under ErrOpenFailed.
//
// ctx bounds the open. In [ModePerOperation] it is passed to the provider's
// Unprotect; in [ModeRootKey] the open makes no provider call and ctx is
// checked on entry only. An ended context fails the open with an error
// matching both ErrOpenFailed and ctx.Err(), and not ErrSealedAuthentication
// unless the provider reported that first (see [ErrOpenFailed]). The value is
// left intact, and a destination recovered for an abandoned caller is
// destroyed.
func (s *SealedEnclave) Open(ctx context.Context) (*MemoryEnclave, error) {
	// nil is how the open path spells "unadmitted"; see allocSized.
	return s.openWith(ctx, nil)
}

// OpenWith is [SealedEnclave.Open] with the destination admitted against a's
// budget, reserved before any locked memory is requested and returned when
// the caller destroys the result. A nil a returns [ErrNilAllocator] and never
// falls back to an unbudgeted open; that check precedes the destroyed check.
//
// Only the destination is admitted, in one reservation taken first, so an
// open the budget refuses allocates nothing. The transient DEK page (and, for
// a value under a retired [ModeRootKey] generation, a KEK page) are not
// charged, so peak use can exceed the budget by one page (two) per open in
// flight.
//
// It returns everything Open returns, plus ErrNilAllocator and
// ErrBudgetExhausted (as a [BudgetError]). A budget refusal leaves the value
// intact and is retryable. A context already ended is refused before the
// reservation. Sealing is never budgeted.
func (s *SealedEnclave) OpenWith(ctx context.Context, a *Allocator) (*MemoryEnclave, error) {
	if s == nil {
		return nil, ErrEnclaveDestroyed
	}
	if a == nil {
		return nil, ErrNilAllocator
	}
	return s.openWith(ctx, a)
}

// openWith is the shared body of Open and OpenWith; a is nil for an
// unadmitted open. The value's lock only pins and unpins the envelope and is
// not held across Sealer.open, which may block in a provider; Destroy takes
// no context and must not wait on that.
func (s *SealedEnclave) openWith(ctx context.Context, a *Allocator) (*MemoryEnclave, error) {
	if s == nil {
		return nil, ErrEnclaveDestroyed
	}

	sealer, blob, sealed, size, ok := s.pin()
	if !ok {
		return nil, ErrEnclaveDestroyed
	}
	defer s.unpin(blob, sealed)

	return sealer.open(ctx, a, blob, sealed, size)
}

// pin registers an open in flight and returns the envelope it may read with
// the lock released, or ok false if the value is destroyed.
func (s *SealedEnclave) pin() (sealer *Sealer, blob, sealed []byte, size int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return nil, nil, nil, 0, false
	}
	s.opens++
	return s.sealer, s.blob, s.sealed, s.size, true
}

// unpin ends an open in flight. The last open out after a Destroy wipes the
// envelope halves Destroy left for it.
func (s *SealedEnclave) unpin(blob, sealed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.opens--
	if s.opens == 0 && s.sealed == nil {
		wipe(sealed)
		wipe(blob)
	}
}

// IsAlive reports whether this value still holds its ciphertext, that is,
// whether [SealedEnclave.Destroy] has not run. It does not mean the value can
// be opened: after a shutdown [WipeAll] a value can report IsAlive while
// [SealedEnclave.Open] fails with [ErrSealerWiped]. Use
// [SealedEnclave.Openable] for that.
func (s *SealedEnclave) IsAlive() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed != nil
}

// Openable reports whether [SealedEnclave.Open] could still recover this
// material, without recovering it. It returns nil if nothing known prevents
// it, [ErrEnclaveDestroyed] if this value was destroyed (or is nil),
// [ErrSealerWiped] if a shutdown [WipeAll] destroyed in-process keys the
// sealer needs, [ErrSealerDestroyed] after [Sealer.Destroy], and
// [ErrOpenabilityUnknown] if a sweep has run since this value was sealed and
// a [ModePerOperation] provider does not implement [HealthReporter]. A
// provider's HealthReporter answer is believed.
//
// The answer is a snapshot for diagnostics, not a reservation, and nil is
// narrower than "will succeed": it does not predict
// [ErrSealedAuthentication], [ErrLockedMemoryUnavailable] or a device's own
// failures. It takes no context and calls no provider other than
// HealthReporter.Health, and holds no lock of this value's while consulting
// the sealer.
func (s *SealedEnclave) Openable() error {
	if s == nil {
		return ErrEnclaveDestroyed
	}

	sealer, sealedAtGen, ok := s.openableSnapshot()
	if !ok {
		return ErrEnclaveDestroyed
	}
	return sealer.openable(sealedAtGen)
}

// openableSnapshot reads what Openable needs under the lock, reporting ok
// false for the destroyed state.
func (s *SealedEnclave) openableSnapshot() (*Sealer, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Destroy clears both together; testing the sealer too keeps ErrNilSealer
	// out of Openable's return set.
	if s.sealed == nil || s.sealer == nil {
		return nil, 0, false
	}
	return s.sealer, s.sealedAtGen, true
}

// Destroy wipes the sealed material and releases it. It is idempotent and
// safe on a nil enclave. Enclaves already returned by [SealedEnclave.Open]
// are unaffected.
//
// It does not wait for opens in flight: they complete against the envelope
// they pinned, the last one wipes it, and every Open starting afterwards
// returns [ErrEnclaveDestroyed]. The error is always nil today; it matches
// [MemoryEnclave.Destroy] and [Sealer.Destroy].
func (s *SealedEnclave) Destroy() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return nil
	}

	// With an open in flight the halves are still being read; unpin wipes
	// them when the last one finishes.
	if s.opens == 0 {
		wipe(s.sealed)
		wipe(s.blob)
	}
	s.sealed = nil
	s.blob = nil
	s.size = 0
	// In ModeRootKey the sealer also retains retired-generation blobs.
	s.sealer = nil
	return nil
}

// String returns a redacted form, so an accidental %v or %s never prints the
// ciphertext.
func (s *SealedEnclave) String() string {
	if !s.IsAlive() {
		return "SealedEnclave(destroyed)"
	}
	return "SealedEnclave(sealed)"
}

// GoString returns the same redacted form as String under %#v.
func (s *SealedEnclave) GoString() string {
	return s.String()
}
