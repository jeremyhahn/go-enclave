// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
)

var (
	// ErrSealerWiped reports that a shutdown sweep ([WipeAll]) destroyed this
	// sealer's keys. Everything sealed through it is permanently unopenable,
	// and the sealer fails closed: it never generates fresh keys. Recovery is
	// constructing a new [Sealer].
	//
	// It is distinct from [ErrSealedAuthentication] so that a lifecycle event
	// is never reported as tampering.
	//
	// In [ModeRootKey] the sweep destroys the root and KEK hierarchy and this
	// error follows. In [ModePerOperation] the device still holds the key, so
	// a sweep does not invalidate sealed values; the exception is the
	// [SoftwareProvider], whose root is an in-process enclave and which
	// reports this error after a sweep.
	ErrSealerWiped = errors.New("enclave: this sealer's keys were destroyed by a shutdown sweep; sealed values are unrecoverable and re-initializing requires constructing a new Sealer")

	// ErrOpenabilityUnknown is returned by [SealedEnclave.Openable] when a
	// shutdown sweep has run since this value was sealed (or during the seal)
	// and the sealer's provider can report nothing about its own sealing
	// state. It occurs only in [ModePerOperation], only after a [WipeAll],
	// and only with a provider that does not implement [HealthReporter].
	//
	// It is neither [ErrSealerWiped] (nothing is known to be destroyed) nor
	// nil. Open the value to find out.
	ErrOpenabilityUnknown = errors.New("enclave: a shutdown sweep has run since this value was sealed and its provider reports no sealing-state health, so openability cannot be determined; open the value to find out")

	// ErrInvalidProvider is returned by [NewSealer] when a provider option is
	// given a nil or typed-nil provider, or when both [WithKeyProtector] and
	// [WithRootUnsealer] are given. A nil provider is a lost configuration
	// step, not a request for the software default.
	ErrInvalidProvider = errors.New("enclave: a sealer takes exactly one non-nil provider, from WithKeyProtector or WithRootUnsealer")

	// ErrSealerExhausted is returned, joined with [ErrSealFailed], by a seal
	// on a [ModeRootKey] sealer that would need a KEK generation past 2^31,
	// the GCM usage bound of the sealer's own wrapping key. Nothing is
	// minted and every value already sealed keeps opening. Only a very small
	// [WithKEKRotationLimit] reaches it in practice; the remedy is a new
	// Sealer.
	ErrSealerExhausted = errors.New("enclave: this sealer has used every KEK generation its wrapping key may wrap; existing values still open, but new seals require constructing a new Sealer")

	// ErrInvalidRotationLimit is returned by [NewSealer] for a
	// [WithKEKRotationLimit] of zero, above 2^31, or given for
	// [ModePerOperation], which has no KEK to rotate.
	ErrInvalidRotationLimit = errors.New("enclave: KEK rotation limit must be between 1 and 2^31 and applies only to ModeRootKey")

	// ErrSealerInstalled is returned by [SetSealer] when the process sealer is
	// already set, by an earlier SetSealer or by the first seal lazily
	// installing the software default.
	ErrSealerInstalled = errors.New("enclave: a process sealer is already installed")

	// ErrNilSealer is returned by [SetSealer] for a nil *Sealer, and by
	// [Sealer.Seal] on a nil receiver.
	ErrNilSealer = errors.New("enclave: sealer is nil")

	// ErrSealerDestroyed is returned by every Seal and Open, and by
	// [SealedEnclave.Openable], once [Sealer.Destroy] has run; and by a
	// [SoftwareProvider] once its own Destroy has run. The sealer fails closed
	// and never re-keys.
	ErrSealerDestroyed = errors.New("enclave: sealer was destroyed; sealed values are unrecoverable and sealing requires constructing a new Sealer")

	// ErrSealerNotConstructed is returned by Seal and Open on a Sealer that
	// was not built by [NewSealer], such as the zero value. The caller's
	// material is wiped as on every other failure.
	ErrSealerNotConstructed = errors.New("enclave: sealer was not constructed with NewSealer")

	// errHierarchyUninitialized marks a ModeRootKey hierarchy not yet built:
	// distinct from wiped, because uninitialized may initialize and wiped
	// must never.
	errHierarchyUninitialized = errors.New("enclave: sealer key hierarchy not yet initialized")

	errProviderEmptyBlob = errors.New("enclave: provider returned an empty blob from Protect")
)

// Mode selects how often a [Sealer] invokes its provider. Both modes share
// the same envelope; they differ in what protects the per-value DEK, and so in
// what an adversary who can read this process's memory obtains.
//
// # ModePerOperation
//
// The provider (a [KeyProtector]) protects each value's 32-byte DEK on every
// seal and open; the material itself never crosses the device boundary, so
// plaintext is always decrypted directly into locked pages. The long-lived key
// never enters this process, so a memory-reading adversary obtains only the
// values open during their window. Suited to an HSM that sustains many
// concurrent sessions.
//
// # ModeRootKey
//
// The provider (a [RootUnsealer]) yields a root key once. The root protects
// key-encryption keys (KEKs) generated in-process, and each value's DEK is
// wrapped under the current KEK. After the single unseal every operation is
// in-process crypto, suited to high-load servers or a TPM that cannot sustain
// many sessions.
//
// ModeRootKey is a scale accommodation, not a security equal of
// ModePerOperation: after the unseal the root and current KEK are in process
// memory, and an adversary who can read it can open everything. What it adds
// over pure software is the origin and gating of the root: it cannot be
// obtained without the device, and can be bound to a TPM PCR policy.
//
// The zero value is ModeRootKey, which the process default uses over the
// [SoftwareProvider].
type Mode uint8

const (
	// ModeRootKey unseals a root once and runs an in-memory KEK hierarchy.
	ModeRootKey Mode = iota

	// ModePerOperation calls the provider on every seal and open, on the DEK
	// only.
	ModePerOperation
)

var modeNames = map[Mode]string{
	ModeRootKey:      "ModeRootKey",
	ModePerOperation: "ModePerOperation",
}

// String names the mode for diagnostics.
func (m Mode) String() string {
	if name, ok := modeNames[m]; ok {
		return name
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

// kekBytes selects AES-256 for the key-encryption keys of [ModeRootKey].
const kekBytes = 32

// kekMessageLimit is how many DEKs one KEK generation may wrap before it is
// retired: half the 2^32 messages crypto/cipher allows a random-nonce GCM key.
const kekMessageLimit = 1 << 31

// wrappingSaltBytes matches the root length, so two sealers over the same
// root share a wrapping key only by a 256-bit salt collision.
const wrappingSaltBytes = 32

// wrappingKeyInfo is the HKDF info that binds a derived wrapping key to its
// one use.
const wrappingKeyInfo = "go-enclave v1 ModeRootKey KEK-wrapping key"

// deriveWrappingKey replaces root, in place, with the key a [ModeRootKey]
// sealer wraps its KEK generations under: HKDF-SHA256 of the provider's root
// under a per-sealer salt. Every sealer over a provider, and every boot of a
// hardware root, gets the same root; the salt makes maxKEKGenerations bound
// a key no other sealer uses. The HKDF output and HMAC state are heap memory,
// wiped or erased as for an AES key schedule.
func deriveWrappingKey(root, salt []byte) error {
	var err error
	secretDo(func() {
		var k []byte
		if k, err = hkdfKey(sha256.New, root, salt, wrappingKeyInfo, len(root)); err == nil {
			copy(root, k)
			wipe(k)
		}
	})
	if err != nil {
		return errors.Join(ErrSealFailed, err)
	}
	return nil
}

// maxKEKGenerations is how many KEK generations one wrapping key may wrap,
// the same bound as kekMessageLimit; it also keeps the uint32 generation
// counter from wrapping onto a retired generation whose blob is retained.
const maxKEKGenerations = 1 << 31

// Blob framing. Every wrapped-key blob this package produces starts with a
// fixed header that is also the AAD of the wrapping, so a blob cannot be
// re-purposed across kinds or generations. [ModePerOperation] provider blobs
// are opaque.
const (
	// blobVersion makes an accidental format change fail authentication
	// instead of misparse. Sealed values do not outlive the process, so there
	// is no cross-version compatibility promise.
	blobVersion = 1

	blobKindDEK byte = 1 // a DEK wrapped under a KEK generation
	blobKindKEK byte = 2 // a KEK wrapped under the root
	// blobKindProvider marks a key protected by [SoftwareProvider]. Kind 4 is
	// reserved (an earlier build framed blobs with it); never assign it.
	blobKindProvider byte = 3

	// blobHeaderLen is version + kind + a 4-byte big-endian generation (zero
	// for kinds without one).
	blobHeaderLen = 6
)

func blobHeader(kind byte, gen uint32) []byte {
	h := make([]byte, blobHeaderLen)
	h[0] = blobVersion
	h[1] = kind
	binary.BigEndian.PutUint32(h[2:], gen)
	return h
}

// parseBlobHeader splits a blob into its frame and body. Any malformation is
// an authentication failure.
func parseBlobHeader(blob []byte) (kind byte, gen uint32, body []byte, err error) {
	if len(blob) < blobHeaderLen || blob[0] != blobVersion {
		return 0, 0, nil, ErrSealedAuthentication
	}
	return blob[1], binary.BigEndian.Uint32(blob[2:blobHeaderLen]), blob[blobHeaderLen:], nil
}

// Test seams for failures the standard library does not produce on demand.
var (
	randRead = rand.Read
	hkdfKey  = hkdf.Key[hash.Hash]
)

func fillRandom(b []byte) error {
	_, err := randRead(b)
	return err
}

// Sealer produces and opens [SealedEnclave] values under an injected crypto
// provider. Construct one with [NewSealer], or use the package-level
// [NewSealed] and [SetSealer] for one sealer per process.
//
// A Sealer is safe for concurrent use. [Sealer.Destroy] releases its keys; a
// shutdown [WipeAll] also reclaims them. After either it fails closed; see
// [ErrSealerDestroyed] and [ErrSealerWiped].
//
// No mutex of a Sealer is held across a provider call. First-time
// [ModeRootKey] initialization is serialized by an init slot that a waiting
// caller abandons when its context ends, so a provider stalled in
// [RootUnsealer.UnsealRoot] stalls only the callers that need that
// initialization, each for no longer than its own context allows. Seals and
// opens on an initialized Sealer, and on every other Sealer, proceed.
type Sealer struct {
	mode Mode

	// Exactly one of kp / ru is non-nil, fixed at construction with the
	// matching protect and unprotect.
	kp KeyProtector
	ru RootUnsealer

	protect   func(ctx context.Context, dek *MemoryEnclave) ([]byte, error)
	unprotect func(ctx context.Context, blob []byte, dek *MemoryEnclave) error

	// mu guards the ModeRootKey hierarchy below and destroyed. It is
	// read-locked to wrap and unwrap DEKs and write-locked only to publish
	// the hierarchy, rotate, and destroy; it is never held across a provider
	// call. Lock order: initSlot, then mu.
	mu sync.RWMutex
	// root holds this sealer's wrapping key (deriveWrappingKey), not the
	// provider's root. It is set once and never cleared, so a swept
	// hierarchy stays detectable as dead enclaves.
	root     *MemoryEnclave
	kek      *MemoryEnclave
	kekGen   uint32
	kekUsed  atomic.Uint64
	kekLimit uint64
	kekBlobs map[uint32][]byte
	// destroyed is set by Destroy and never cleared; every path checks it
	// before the hierarchy state.
	destroyed bool

	// owned is the default provider NewSealer created, which Destroy
	// releases; nil for an injected provider.
	owned *SoftwareProvider

	// initSlot is a one-slot semaphore held by the goroutine running
	// initHierarchy. A channel rather than a mutex so that acquiring it can
	// select on ctx.Done().
	initSlot chan struct{}

	// pendingRoot is a root UnsealRoot delivered whose first KEK mint failed,
	// kept so a retry repeats only the mint: UnsealRoot may not be called
	// again after it succeeded. It is not root, because a non-nil root with
	// no live KEK reads as wiped. A dead pendingRoot is the wiped state of a
	// sealer whose hierarchy was never published. Guarded by initSlot.
	pendingRoot *MemoryEnclave

	// pendingKEK is the first KEK between mint and publication, and after a
	// discard any such KEK whose release the kernel refused, kept so later
	// attempts retry that release. Guarded by initSlot.
	pendingKEK *MemoryEnclave

	// pendingGen is the sweep sequence read before the unseal that produced
	// pendingRoot. Guarded by initSlot.
	pendingGen uint64
}

type sealerConfig struct {
	kp KeyProtector
	ru RootUnsealer
	// providers counts the provider options given, so a nil provider and two
	// providers are both refused.
	providers   int
	kekLimit    uint64
	kekLimitSet bool
}

// SealerOption configures [NewSealer].
type SealerOption func(*sealerConfig)

// WithKeyProtector selects [ModePerOperation] over kp: every seal and open
// calls kp on the per-value data key. If kp implements [HealthReporter], the
// sealer consults it from [SealedEnclave.Openable]. kp must be non-nil; see
// [ErrInvalidProvider].
func WithKeyProtector(kp KeyProtector) SealerOption {
	return func(c *sealerConfig) { c.kp, c.providers = kp, c.providers+1 }
}

// WithRootUnsealer selects [ModeRootKey] over ru: ru is asked for the root at
// most once (again only after a failed call) and the sealer runs an
// in-memory KEK hierarchy under it. ru must be non-nil; see
// [ErrInvalidProvider].
//
// Omitting both provider options selects ModeRootKey over a
// [SoftwareProvider] the sealer creates and destroys with itself.
func WithRootUnsealer(ru RootUnsealer) SealerOption {
	return func(c *sealerConfig) { c.ru, c.providers = ru, c.providers+1 }
}

// WithKEKRotationLimit sets how many DEKs one KEK generation wraps before the
// sealer rotates to a fresh generation (the KEK crypto-period). It applies to
// [ModeRootKey] only.
//
// n must be between 1 and 2^31, the default: half the 2^32 messages
// crypto/cipher allows a random-nonce AES-GCM key. Anything outside that
// range, or the option given for [ModePerOperation], makes [NewSealer] return
// [ErrInvalidRotationLimit]. Rotation keeps every retired generation's
// root-wrapped blob, so values sealed under any generation keep opening; a
// short crypto-period costs bytes per generation, not locked pages.
func WithKEKRotationLimit(n uint64) SealerOption {
	return func(c *sealerConfig) { c.kekLimit, c.kekLimitSet = n, true }
}

// NewSealer returns a Sealer over the provider its options name; the option
// chosen fixes the [Mode].
//
// With no options it is the pure-software default ([SoftwareProvider],
// [ModeRootKey]) and cannot fail. It returns [ErrInvalidProvider] for a nil
// provider or for two providers, and [ErrInvalidRotationLimit] for a rotation
// limit it cannot honor.
//
// The returned Sealer performs no crypto, touches no locked memory and does
// not consult its provider until its first Seal, so a device problem surfaces
// from the first operation that needs it.
func NewSealer(opts ...SealerOption) (*Sealer, error) {
	var cfg sealerConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	s := &Sealer{initSlot: make(chan struct{}, 1), kekLimit: kekMessageLimit}
	switch {
	case cfg.providers > 1:
		return nil, ErrInvalidProvider
	case cfg.kp != nil:
		if isNilInterface(cfg.kp) {
			return nil, ErrInvalidProvider
		}
		s.mode, s.kp = ModePerOperation, cfg.kp
		s.protect, s.unprotect = s.protectPerOperation, s.unprotectPerOperation
	case cfg.ru != nil:
		if isNilInterface(cfg.ru) {
			return nil, ErrInvalidProvider
		}
		s.mode, s.ru = ModeRootKey, cfg.ru
		s.protect, s.unprotect = s.protectRootKey, s.unprotectRootKey
	case cfg.providers == 1:
		return nil, ErrInvalidProvider
	default:
		s.owned = NewSoftwareProvider()
		s.mode, s.ru = ModeRootKey, s.owned
		s.protect, s.unprotect = s.protectRootKey, s.unprotectRootKey
	}

	if cfg.kekLimitSet {
		if s.mode != ModeRootKey || cfg.kekLimit == 0 || cfg.kekLimit > kekMessageLimit {
			return nil, ErrInvalidRotationLimit
		}
		s.kekLimit = cfg.kekLimit
	}
	return s, nil
}

// isNilInterface reports whether v is the untyped nil or an interface
// wrapping a nil value. The kind switch covers exactly the kinds
// reflect.Value.IsNil accepts, so it never panics.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Chan, reflect.Func, reflect.Slice, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// Mode reports the mode this sealer was constructed with.
func (s *Sealer) Mode() Mode {
	return s.mode
}

func (s *Sealer) usable() error {
	if s.protect == nil || s.unprotect == nil {
		return ErrSealerNotConstructed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return ErrSealerDestroyed
	}
	return nil
}

// whileUsable runs fn, which must be in-process work, under the read lock
// unless the sealer is destroyed, so a concurrent Destroy orders entirely
// before or after it.
func (s *Sealer) whileUsable(fn func() error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return ErrSealerDestroyed
	}
	return fn()
}

// Destroy releases every key this sealer holds, including any root or KEK an
// unfinished initialization left pending, and the [SoftwareProvider] if
// [NewSealer] created it by default. An injected provider is never destroyed.
//
// From then on every Seal, Open and [SealedEnclave.Openable] through this
// sealer reports [ErrSealerDestroyed]; values it sealed are unrecoverable.
// Destroy waits for in-process seals and opens, but not for a provider call:
// a seal or open whose provider call straddles Destroy fails with
// ErrSealerDestroyed when the provider returns, and an initialization blocked
// in [RootUnsealer.UnsealRoot] releases what it produced. A release the kernel
// refuses is returned and stays on the [WipeAll] ledger; calling Destroy again
// retries it. Destroy is idempotent and safe on a nil Sealer.
func (s *Sealer) Destroy() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	s.destroyed = true
	var errs []error
	for _, k := range []*MemoryEnclave{s.kek, s.root} {
		if err := k.Destroy(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, b := range s.kekBlobs {
		wipe(b)
	}
	s.kekBlobs = nil
	// Non-blocking: a slot holder may be inside a provider call. It releases
	// the pending state itself, under mu, after seeing destroyed.
	select {
	case s.initSlot <- struct{}{}:
		if err := s.releasePending(); err != nil {
			errs = append(errs, err)
		}
		<-s.initSlot
	default:
	}
	s.mu.Unlock()

	if err := s.owned.Destroy(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// releasePending destroys pendingKEK and pendingRoot, keeping a reference to
// any whose release the kernel refused so a later call retries it. The caller
// holds initSlot.
func (s *Sealer) releasePending() error {
	var errs []error
	if err := s.pendingKEK.Destroy(); err != nil {
		errs = append(errs, err)
	} else {
		s.pendingKEK = nil
	}
	if err := s.pendingRoot.Destroy(); err != nil {
		errs = append(errs, err)
	} else {
		s.pendingRoot = nil
	}
	return errors.Join(errs...)
}

// Seal encrypts data and returns the sealed enclave holding it. It is
// [NewSealed] for an explicitly constructed Sealer; the ownership contract,
// the envelope, the context contract and the failure surface are documented
// there and on [SealedEnclave]. It returns [ErrNilSealer] on a nil receiver.
func (s *Sealer) Seal(ctx context.Context, data []byte) (*SealedEnclave, error) {
	if s == nil {
		Wipe(data)
		return nil, ErrNilSealer
	}
	if len(data) == 0 {
		Wipe(data)
		return nil, ErrEmptyEnclave
	}

	defer Wipe(data)

	// Before any key is touched, so an oversized input costs nothing.
	if err := sealableLength(uint64(len(data))); err != nil {
		return nil, err
	}

	// After the argument checks, so a malformed call is reported as malformed
	// whatever the caller's deadline.
	if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
		return nil, err
	}
	if err := s.usable(); err != nil {
		return nil, err
	}

	// Read before any key is touched: a sweep overlapping this seal then shows
	// up as a changed sequence or an odd one. Read after, a completed sweep
	// would compare clean.
	sealedAtGen := sweepGeneration()

	dek, err := newKeyEnclave(dekBytes)
	if err != nil {
		return nil, err
	}
	defer destroyTransient(dek)

	blob, err := s.protect(ctx, dek)
	if err != nil {
		return nil, err
	}
	// The blob is the AAD. Under whileUsable because Destroy does not wait for
	// the provider call above.
	var sealed []byte
	if err := s.whileUsable(func() error {
		var serr error
		sealed, serr = sealWithKey(dek, data, blob)
		return serr
	}); err != nil {
		return nil, err
	}

	return &SealedEnclave{
		sealer: s, sealed: sealed, blob: blob, size: len(data),
		sealedAtGen: sealedAtGen,
	}, nil
}

// open recovers an envelope this sealer produced into a frozen enclave; a is
// nil for [SealedEnclave.Open]. It runs with no lock held: the envelope is
// pinned by the value's in-flight count, so a value's Destroy never waits on
// a provider call here.
//
// The destination is allocated first because it is the one admitted
// allocation: an open the budget refuses allocates no locked memory and
// touches no key, and the unadmitted DEK page exists only behind a granted
// reservation.
func (s *Sealer) open(ctx context.Context, a *Allocator, blob, sealed []byte, size int) (*MemoryEnclave, error) {
	if err := contextFailure(ctx, ErrOpenFailed, nil); err != nil {
		return nil, err
	}
	if err := s.usable(); err != nil {
		return nil, err
	}

	out, err := allocSized(a, size)
	if err != nil {
		return nil, err
	}

	// Locked before the provider fills it, so a capable provider writes the
	// key straight into locked pages. Not admitted; see [SealedEnclave.OpenWith].
	dek, err := NewMemoryEnclaveSized(dekBytes)
	if err != nil {
		destroyTransient(out)
		return nil, err
	}
	defer destroyTransient(dek)

	if err := s.unprotect(ctx, blob, dek); err != nil {
		destroyTransient(out)
		return nil, err
	}
	if err := s.whileUsable(func() error {
		return out.WithBytes(func(pt []byte) error {
			// The blob is verified as AAD even though the DEK unwrap already
			// authenticated it: this refuses two individually authentic halves
			// that were never sealed together.
			return openWithKeyInto(dek, sealed, blob, pt)
		})
	}); err != nil {
		destroyTransient(out)
		return nil, err
	}

	// Returned read-only, so a stray write through a retained slice faults. A
	// refused freeze fails the open closed.
	if err := out.Freeze(); err != nil {
		if derr := out.Destroy(); derr != nil {
			return nil, errors.Join(err, derr)
		}
		return nil, err
	}
	return out, nil
}

// openable reports whether the in-process key material this sealer depends on
// is still there (see [SealedEnclave.Openable]). It performs no crypto and
// initializes nothing. It dispatches on state rather than [Mode], so a future
// mode cannot fall into a default arm that checks nothing.
func (s *Sealer) openable(sealedAtGen uint64) error {
	if err := s.hierarchyOpenable(); err != nil {
		return err
	}

	// An explicit HealthReporter answer, including nil, is terminal. Applying
	// the sweep fallback on top would stop a provider from ever reporting a
	// value openable after a sweep. Only kp is consulted: in ModeRootKey the
	// hierarchy check above is authoritative.
	if h, ok := s.kp.(HealthReporter); ok {
		return h.Health()
	}

	// No one can answer: suspect the value if a sweep ran since it was sealed
	// or was in flight while it was sealed (the sequence is odd then, and can
	// read equal at both ends).
	if s.kp != nil && (sweepInFlight(sealedAtGen) || sweepGeneration() != sealedAtGen) {
		return ErrOpenabilityUnknown
	}
	return nil
}

// hierarchyOpenable applies the wiped predicate without unwrapping anything.
// It is nil for a sealer with no hierarchy (ModePerOperation, or ModeRootKey
// before the first seal).
func (s *Sealer) hierarchyOpenable() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return ErrSealerDestroyed
	}

	if s.root != nil && (!s.root.IsAlive() || !s.kek.IsAlive()) {
		return ErrSealerWiped
	}
	return nil
}

// protectPerOperation calls the provider inside the DEK's borrow, so the
// provider reads the key from locked pages. The context is checked again
// after the provider returns, discarding a blob the caller stopped waiting
// for.
func (s *Sealer) protectPerOperation(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	var blob []byte
	if err := dek.WithBytes(func(k []byte) error {
		b, perr := s.kp.Protect(ctx, k)
		if cerr := contextFailure(ctx, ErrSealFailed, perr); cerr != nil {
			return cerr
		}
		if perr != nil {
			return perr
		}
		if len(b) == 0 {
			// Sealing under an empty blob would strand the value at its first
			// Open with a misleading authentication error.
			return errors.Join(ErrSealFailed, errProviderEmptyBlob)
		}
		// The provider keeps its slice (see [KeyProtector]).
		blob = bytes.Clone(b)
		return nil
	}); err != nil {
		return nil, providerSealFailure(err)
	}
	return blob, nil
}

// unprotectPerOperation calls the provider with the locked destination and
// checks the context again after it returns. When the provider fails and the
// context has also ended, the error keeps both, so a forgery verdict is not
// erased by a cancellation; see docs/sealing/engineering.md, Context error
// shapes.
func (s *Sealer) unprotectPerOperation(ctx context.Context, blob []byte, dek *MemoryEnclave) error {
	return providerOpenFailure(dek.WithBytes(func(k []byte) error {
		perr := s.kp.Unprotect(ctx, blob, k)
		if cerr := contextFailure(ctx, ErrOpenFailed, perr); cerr != nil {
			return cerr
		}
		return perr
	}))
}

// contextFailure returns nil while ctx is live; otherwise op joined with the
// context's error. A provider error cause is kept: it replaces the bare
// context error when it already matches it, and is joined otherwise. A
// distinct [context.Cause] is joined too.
func contextFailure(ctx context.Context, op, cause error) error {
	ended := ctx.Err()
	if ended == nil {
		return nil
	}

	errs := []error{op}
	switch {
	case cause == nil:
		errs = append(errs, ended)
	case errors.Is(cause, ended):
		errs = append(errs, cause)
	default:
		errs = append(errs, ended, cause)
	}
	if why := context.Cause(ctx); why != nil && !errors.Is(why, ended) {
		errs = append(errs, why)
	}
	return errors.Join(errs...)
}

// providerSealFailure passes this package's own sentinels through and joins
// anything else under [ErrSealFailed].
func providerSealFailure(err error) error {
	return shapeProviderFailure(ErrSealFailed, err,
		ErrSealerWiped, ErrSealerDestroyed, ErrSealFailed, ErrLockedMemoryUnavailable, ErrProviderMessageLimit, ErrEnclaveDestroyed)
}

// providerOpenFailure is providerSealFailure's mirror: an authentication
// verdict passes through as [ErrSealedAuthentication], and anything that is
// not a verdict is joined under [ErrOpenFailed] so it cannot be mistaken for
// one.
func providerOpenFailure(err error) error {
	return shapeProviderFailure(ErrOpenFailed, err,
		ErrSealedAuthentication, ErrSealerWiped, ErrSealerDestroyed, ErrOpenFailed, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed)
}

func shapeProviderFailure(op, err error, passThrough ...error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range passThrough {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	return errors.Join(op, err)
}

// hierarchyFailure turns an [ErrEnclaveDestroyed] into [ErrSealerWiped] only
// when one of the given hierarchy keys is dead. A dead per-call enclave (the
// DEK, or a materialized retired KEK) stays ErrEnclaveDestroyed: the
// hierarchy is intact. Hierarchy keys are used only under s.mu or by the
// initSlot holder, and neither destroys one in use, so a dead one is a
// sweep's doing.
func hierarchyFailure(err error, hierarchy ...*MemoryEnclave) error {
	if !errors.Is(err, ErrEnclaveDestroyed) {
		return err
	}
	for _, k := range hierarchy {
		if k != nil && !k.IsAlive() {
			return ErrSealerWiped
		}
	}
	return err
}

// protectRootKeyInner wraps the DEK under the current KEK generation,
// initializing or rotating first when needed. After either it loops, so the
// wrap always uses a generation re-read under the lock it runs under. The
// context is checked on every pass: an initialization that succeeded after
// the caller's context ended is kept, but that caller is told it was
// abandoned.
func (s *Sealer) protectRootKeyInner(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	for {
		if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
			return nil, err
		}

		s.mu.RLock()

		if s.destroyed {
			s.mu.RUnlock()
			return nil, ErrSealerDestroyed
		}
		if s.root == nil {
			s.mu.RUnlock()
			if err := s.initHierarchy(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if !s.root.IsAlive() || !s.kek.IsAlive() {
			s.mu.RUnlock()
			return nil, ErrSealerWiped // cleanup is retried at the boundary
		}

		// Reserved before wrapping, so a failed wrap still counts: rotating
		// slightly early is the safe direction.
		if s.kekUsed.Add(1) > s.kekLimit {
			s.mu.RUnlock()
			if err := s.rotateKEK(); err != nil {
				return nil, err
			}
			continue
		}

		header := blobHeader(blobKindDEK, s.kekGen)
		var body []byte
		err := dek.WithBytes(func(k []byte) error {
			b, werr := sealWithKey(s.kek, k, header)
			if werr != nil {
				return werr
			}
			body = b
			return nil
		})
		if err != nil {
			// Translated before unlocking: a waiting rotation destroys the
			// outgoing KEK, which would then read as a sweep.
			err = hierarchyFailure(err, s.hierarchyLocked()...)
		}
		s.mu.RUnlock()

		if err != nil {
			return nil, err
		}
		return append(header, body...), nil
	}
}

// protectRootKey and unprotectRootKey are the boundary every root-mode seal
// and open passes through, and the one place a dead hierarchy's key release
// is retried, so no inner exit can skip it.
func (s *Sealer) protectRootKey(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	blob, err := s.protectRootKeyInner(ctx, dek)
	return blob, s.withDeadHierarchyCleanup(err)
}

func (s *Sealer) unprotectRootKey(ctx context.Context, blob []byte, dek *MemoryEnclave) error {
	return s.withDeadHierarchyCleanup(s.unprotectRootKeyRLocked(ctx, blob, dek))
}

// withDeadHierarchyCleanup returns err unchanged unless it reports
// ErrSealerWiped and the published hierarchy is dead; then it retries the
// release of the hierarchy's keys and joins any refusal. The caller must not
// hold s.mu.
func (s *Sealer) withDeadHierarchyCleanup(err error) error {
	if err == nil || !errors.Is(err, ErrSealerWiped) {
		return err
	}
	s.mu.RLock()
	dead := s.root != nil && (!s.root.IsAlive() || !s.kek.IsAlive())
	s.mu.RUnlock()
	if !dead {
		return err
	}
	s.mu.Lock()
	cerr := s.wipeHierarchyLocked(nil)
	s.mu.Unlock()
	if cerr != nil {
		return errors.Join(err, cerr)
	}
	return err
}

// unprotectRootKeyRLocked recovers a DEK: current generation under the live
// KEK, a retired one by first unwrapping its retained blob under the root. It
// makes no provider call, so the context is unused.
func (s *Sealer) unprotectRootKeyRLocked(_ context.Context, blob []byte, dek *MemoryEnclave) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return ErrSealerDestroyed
	}
	if s.root == nil {
		// This sealer has sealed nothing, so no blob can be its own.
		return ErrSealedAuthentication
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		return ErrSealerWiped // cleanup is retried at the boundary
	}

	kind, gen, body, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindDEK {
		return ErrSealedAuthentication
	}
	header := blob[:blobHeaderLen]

	kek := s.kek
	if gen != s.kekGen {
		kekBlob, ok := s.kekBlobs[gen]
		if !ok {
			return ErrSealedAuthentication
		}
		retired, uerr := s.unwrapRetiredKEKLocked(kekBlob)
		if uerr != nil {
			return uerr
		}
		// Materialized for this one unwrap only.
		defer destroyTransient(retired)
		kek = retired
	}

	if uerr := dek.WithBytes(func(k []byte) error {
		return openWithKeyInto(kek, body, header, k)
	}); uerr != nil {
		return hierarchyFailure(uerr, s.hierarchyLocked()...)
	}
	return nil
}

// unwrapRetiredKEKLocked recovers a retired KEK generation into a fresh locked
// enclave the caller must destroy. The caller holds s.mu (read is enough) and
// has verified the hierarchy is alive.
func (s *Sealer) unwrapRetiredKEKLocked(kekBlob []byte) (*MemoryEnclave, error) {
	kek, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		return nil, err
	}
	if uerr := kek.WithBytes(func(k []byte) error {
		return openWithKeyInto(s.root, kekBlob[blobHeaderLen:], kekBlob[:blobHeaderLen], k)
	}); uerr != nil {
		destroyTransient(kek)
		return nil, hierarchyFailure(uerr, s.hierarchyLocked()...)
	}
	return kek, nil
}

// hierarchyLocked is the set of keys whose death means this sealer is wiped:
// the root and the current KEK. Read under s.mu so a rotation cannot change
// it between a failure and its translation.
func (s *Sealer) hierarchyLocked() []*MemoryEnclave {
	return []*MemoryEnclave{s.root, s.kek}
}

// initHierarchy performs the once-per-sealer root unseal and mints the first
// KEK generation. It is retried rather than memoized with sync.Once, because
// a memlock ceiling or transient provider failure can lift. A failed unseal
// is retried with a fresh UnsealRoot call; a successful unseal followed by a
// failed mint keeps the root in pendingRoot and retries only the mint.
//
// The unseal and mint run holding initSlot and nothing else; mu is
// write-locked only to publish root, KEK and generation map as one state. A
// caller queued behind a successful initializer finds the hierarchy published
// and does not call the provider.
//
// A sweep overlapping the initialization leaves the sealer wiped: the sweep
// sequence is read before the unseal and checked before the mint, after a
// failed mint, and at publication. On overlap the root and any KEK are
// destroyed rather than published, the dead root stays in pendingRoot, and
// every later attempt reports [ErrSealerWiped] without asking the provider.
func (s *Sealer) initHierarchy(ctx context.Context) (err error) {
	select {
	case s.initSlot <- struct{}{}:
	case <-ctx.Done():
		return contextFailure(ctx, ErrSealFailed, nil)
	}
	// Released under mu, so a Destroy that found the slot taken is seen here
	// and its pending keys released.
	defer func() {
		s.mu.Lock()
		if s.destroyed {
			err = errors.Join(ErrSealerDestroyed, s.releasePending())
		}
		<-s.initSlot
		s.mu.Unlock()
	}()

	// select picks randomly among ready cases, so an ended context can still
	// win the slot.
	if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
		return err
	}

	return initFailure(ctx, s.initHierarchyHeld(ctx))
}

// initFailure joins a slot holder's failure with the caller's ended context,
// so neither the abandonment nor the cause is lost. An error that already
// carries both is returned as is.
func initFailure(ctx context.Context, err error) error {
	ended := ctx.Err()
	if err == nil || ended == nil || (errors.Is(err, ErrSealFailed) && errors.Is(err, ended)) {
		return err
	}
	return contextFailure(ctx, ErrSealFailed, err)
}

// initHierarchyHeld is initHierarchy's body; the caller holds initSlot.
func (s *Sealer) initHierarchyHeld(ctx context.Context) error {
	if done, err := s.publishedHierarchy(); done {
		return err
	}

	root := s.pendingRoot
	if root == nil {
		// Read before the root exists, as Seal reads sealedAtGen.
		gen := sweepGeneration()

		// Drawn before the unseal, so nothing can fail for want of it once
		// UnsealRoot has succeeded.
		salt := make([]byte, wrappingSaltBytes)
		if err := fillRandom(salt); err != nil {
			return errors.Join(ErrSealFailed, err)
		}
		var err error
		root, err = NewMemoryEnclaveSized(RootKeyBytes)
		if err != nil {
			return err
		}
		// The provider writes the root directly into locked pages, and within
		// the same borrow it is replaced by the derived wrapping key, so no
		// sweep can interleave.
		unsealed := false
		if err := root.WithBytes(func(b []byte) error {
			uerr := s.ru.UnsealRoot(ctx, b)
			if uerr == nil {
				unsealed = true
				return deriveWrappingKey(b, salt)
			}
			if cerr := contextFailure(ctx, ErrSealFailed, uerr); cerr != nil {
				return cerr
			}
			return uerr
		}); err != nil {
			if unsealed {
				// The unseal may not be repeated but no key was derived:
				// retain the root dead, so this sealer reports itself wiped.
				s.pendingRoot, s.pendingGen = root, gen
				if derr := root.Destroy(); derr != nil {
					return errors.Join(ErrSealerWiped, err, derr)
				}
				return errors.Join(ErrSealerWiped, err)
			}
			// The unseal itself failed, so it may be asked again.
			destroyTransient(root)
			return providerSealFailure(err)
		}
		// The unseal succeeded, even if the context ended meanwhile: the root
		// is retained and published, and the caller is told of its context
		// by initFailure or protectRootKeyInner's next pass.
		s.pendingRoot, s.pendingGen = root, gen
	}

	// The overlap check runs first so a root whose release was refused on an
	// earlier attempt is retried, not only reported dead.
	if err := s.discardIfSwept(); err != nil {
		return err
	}
	if !root.IsAlive() {
		return ErrSealerWiped
	}

	kek, blob, err := newGeneration(root, 1)
	if err != nil {
		if derr := s.discardIfSwept(); derr != nil {
			return errors.Join(derr, err)
		}
		// root stays in pendingRoot; the next attempt mints again under it.
		return err
	}

	s.pendingKEK = kek

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return ErrSealerDestroyed // initHierarchy releases the pending keys
	}
	if err := s.discardIfSwept(); err != nil {
		return err
	}

	// Published together, so no reader observes a root without its KEK.
	s.root = root
	s.pendingRoot, s.pendingKEK = nil, nil
	s.kek, s.kekGen = kek, 1
	s.kekBlobs = map[uint32][]byte{1: blob}
	s.kekUsed.Store(0)
	return nil
}

// discardIfSwept returns nil unless a sweep has overlapped the initialization
// that produced pendingRoot (the sequence moved since pendingGen, or was odd
// then). If one has, it destroys pendingKEK and pendingRoot and returns
// [ErrSealerWiped], joined with any refused release. A refused release keeps
// its reference (pendingRoot always, pendingKEK until released), and since
// the sequence never returns to pendingGen, every later attempt retries it.
// The caller holds initSlot.
func (s *Sealer) discardIfSwept() error {
	if !sweepInFlight(s.pendingGen) && sweepGeneration() == s.pendingGen {
		return nil
	}
	errs := []error{ErrSealerWiped}
	if s.pendingKEK != nil {
		if err := s.pendingKEK.Destroy(); err != nil {
			errs = append(errs, err)
		} else {
			s.pendingKEK = nil
		}
	}
	if err := s.pendingRoot.Destroy(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 1 {
		return ErrSealerWiped
	}
	return errors.Join(errs...)
}

// publishedHierarchy reports whether initialization is already decided: done
// with nil for a live published hierarchy, done with [ErrSealerWiped] for a
// swept one (which must not be rebuilt), and not done when nothing is
// published yet.
func (s *Sealer) publishedHierarchy() (done bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.destroyed {
		return true, ErrSealerDestroyed
	}
	if s.root == nil {
		return false, nil
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		return true, ErrSealerWiped
	}
	return true, nil
}

// rotateKEK retires the current KEK generation and mints the next. The
// outgoing KEK's enclave is destroyed (the write lock excludes in-flight
// users) and its root-wrapped blob stays in kekBlobs so values sealed under
// it keep opening. Holding mu across the mint is allowed because rotation
// never calls the provider.
func (s *Sealer) rotateKEK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read before any liveness check, so a sweep that runs at any point from
	// here on shows up as an odd value now or a different one after the mint.
	gen := sweepGeneration()

	if s.destroyed {
		return ErrSealerDestroyed
	}
	if s.root == nil {
		// Unreachable: only a seal that found the hierarchy initialized asks
		// for rotation.
		return errors.Join(ErrSealFailed, errHierarchyUninitialized)
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		if err := s.wipeHierarchyLocked(nil); err != nil {
			return errors.Join(ErrSealerWiped, err)
		}
		return ErrSealerWiped
	}
	if s.kekUsed.Load() <= s.kekLimit {
		// Another goroutine rotated while this one waited for the lock.
		return nil
	}
	if s.kekGen >= maxKEKGenerations {
		return errors.Join(ErrSealFailed, ErrSealerExhausted)
	}

	// WipeAll skips the root while newGeneration borrows it, so a sweep here
	// could kill only the old KEK; publishing the new generation would then
	// re-key after a WipeAll. Any overlap wipes the whole hierarchy.
	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if sweepInFlight(gen) || sweepGeneration() != gen {
		if werr := s.wipeHierarchyLocked(kek); werr != nil {
			err = errors.Join(err, werr)
		}
		if err != nil {
			return errors.Join(ErrSealerWiped, err)
		}
		return ErrSealerWiped
	}
	if err != nil {
		// The current generation stays; the next seal retries the rotation.
		return err
	}

	destroyTransient(s.kek)
	s.kek, s.kekGen = kek, s.kekGen+1
	s.kekBlobs[s.kekGen] = blob
	s.kekUsed.Store(0)
	return nil
}

// wipeHierarchyLocked destroys newKEK (an unpublished generation, may be
// nil), the current KEK and the root, returning every refused release. A
// refused key is already wiped and stays on the WipeAll ledger; the sealer
// also retries its published root and KEK whenever a seal or open finds the
// hierarchy dead. Requires s.mu held exclusively.
func (s *Sealer) wipeHierarchyLocked(newKEK *MemoryEnclave) error {
	var errs []error
	for _, k := range []*MemoryEnclave{newKEK, s.kek, s.root} {
		if k == nil {
			continue
		}
		if err := k.Destroy(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// newGeneration mints KEK generation gen: a fresh key in locked memory, plus
// that key wrapped under the root for retention after retirement.
func newGeneration(root *MemoryEnclave, gen uint32) (*MemoryEnclave, []byte, error) {
	kek, err := newKeyEnclave(kekBytes)
	if err != nil {
		return nil, nil, err
	}

	header := blobHeader(blobKindKEK, gen)
	var body []byte
	if err := kek.WithBytes(func(k []byte) error {
		b, werr := sealWithKey(root, k, header)
		if werr != nil {
			return werr
		}
		body = b
		return nil
	}); err != nil {
		// A refused release is reported, not dropped as destroyTransient would.
		if derr := kek.Destroy(); derr != nil {
			return nil, nil, errors.Join(hierarchyFailure(err, root), derr)
		}
		return nil, nil, hierarchyFailure(err, root)
	}
	return kek, append(header, body...), nil
}

// The process sealer is the one [NewSealed] uses. It is never cleared, not
// even by a shutdown sweep: after one, the installed sealer reports
// [ErrSealerWiped].
var (
	processSealerMu       sync.Mutex
	processSealerInstance *Sealer
)

// SetSealer installs s as the process sealer, the one [NewSealed] uses.
//
// It is one-shot: it returns [ErrSealerInstalled] once any process sealer
// exists, including the software default the first [NewSealed] installs
// lazily, because replacing it would strand every live sealed value. Install
// before anything can seal. It returns [ErrNilSealer] for a nil sealer.
func SetSealer(s *Sealer) error {
	if s == nil {
		return ErrNilSealer
	}

	processSealerMu.Lock()
	defer processSealerMu.Unlock()

	if processSealerInstance != nil {
		return ErrSealerInstalled
	}
	processSealerInstance = s
	return nil
}

// processSealer returns the installed process sealer, lazily installing the
// pure-software default.
func processSealer() (*Sealer, error) {
	processSealerMu.Lock()
	defer processSealerMu.Unlock()

	if processSealerInstance == nil {
		s, err := NewSealer()
		if err != nil {
			// Unreachable: the default construction cannot fail.
			return nil, err
		}
		processSealerInstance = s
	}
	return processSealerInstance, nil
}
