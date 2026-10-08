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
	"math"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
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

// dekBytes selects AES-256 for the per-value data key.
const dekBytes = 32

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
// reflect.Value.IsNil accepts other than reflect.Interface, which
// reflect.ValueOf never returns, so it never panics. providertest's
// isNilProvider is the same test.
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

// whileUsable runs fn, which must be in-process work, under the read lock
// unless the sealer is destroyed, so a concurrent Destroy orders entirely
// before or after it. A nil fn only checks. A zero Sealer, which has no
// provider, is refused as [ErrSealerNotConstructed].
func (s *Sealer) whileUsable(fn func() error) error {
	if s.protect == nil || s.unprotect == nil {
		return ErrSealerNotConstructed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch {
	case s.destroyed:
		return ErrSealerDestroyed
	case fn == nil:
		return nil
	default:
		return fn()
	}
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
	errs := destroyAll(s.kek, s.root)
	for _, b := range s.kekBlobs {
		Wipe(b)
	}
	s.kekBlobs = nil
	// Non-blocking: a slot holder may be inside a provider call. It releases
	// the pending state itself, under mu, after seeing destroyed.
	select {
	case s.initSlot <- struct{}{}:
		errs = withCleanupFailure(errs, s.releasePending())
		<-s.initSlot
	default:
	}
	s.mu.Unlock()

	return withCleanupFailure(errs, s.owned.Destroy())
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
	if err := sealableWithin(uint64(len(data)), math.MaxInt); err != nil {
		return nil, err
	}

	// After the argument checks, so a malformed call is reported as malformed
	// whatever the caller's deadline.
	if err := contextFailure[sealFailed](ctx, nil); err != nil {
		return nil, err
	}
	if err := s.whileUsable(nil); err != nil {
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
	defer func() { _ = dek.Destroy() }()

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
	if err := contextFailure[openFailed](ctx, nil); err != nil {
		return nil, err
	}
	if err := s.whileUsable(nil); err != nil {
		return nil, err
	}

	// A nil allocator leaves the open unbudgeted, as [SealedEnclave.Open] is.
	var out *MemoryEnclave
	var err error
	if a == nil {
		out, err = NewMemoryEnclaveSized(size)
	} else {
		out, err = a.NewSized(size)
	}
	if err != nil {
		return nil, err
	}

	// Locked before the provider fills it, so a capable provider writes the
	// key straight into locked pages. Not admitted; see [SealedEnclave.OpenWith].
	dek, err := NewMemoryEnclaveSized(dekBytes)
	if err != nil {
		_ = out.Destroy()
		return nil, err
	}
	defer func() { _ = dek.Destroy() }()

	if err := s.unprotect(ctx, blob, dek); err != nil {
		_ = out.Destroy()
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
		_ = out.Destroy()
		return nil, err
	}

	// Returned read-only, so a stray write through a retained slice faults. A
	// refused freeze fails the open closed.
	if err := out.Freeze(); err != nil {
		return nil, destroyOnFailure(err, out)
	}
	return out, nil
}

// openable reports whether the in-process key material this sealer depends on
// is still there (see [SealedEnclave.Openable]). It performs no crypto and
// initializes nothing. It dispatches on state rather than [Mode], so a future
// mode cannot fall into a default arm that checks nothing.
func (s *Sealer) openable(sealedAtGen uint64) error {
	// The hierarchy's state, without unwrapping anything. It is nil for a
	// sealer with no hierarchy (ModePerOperation, or ModeRootKey before the
	// first seal).
	s.mu.RLock()
	_, err := s.hierarchyStateLocked()
	s.mu.RUnlock()
	if err != nil {
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

// protectPerOperation calls the provider inside the DEK's borrow, so the
// provider reads the key from locked pages. The context is checked again
// after the provider returns, discarding a blob the caller stopped waiting
// for.
func (s *Sealer) protectPerOperation(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	var blob []byte
	if err := dek.WithBytes(func(k []byte) error {
		b, perr := s.kp.Protect(ctx, k)
		if cerr := contextFailure[sealFailed](ctx, perr); cerr != nil {
			return cerr
		}
		if perr != nil {
			return perr
		}
		if len(b) == 0 {
			// Sealing under an empty blob would strand the value at its first
			// Open with a misleading authentication error.
			return &SealError{Cause: errProviderEmptyBlob}
		}
		// The provider keeps its slice (see [KeyProtector]).
		blob = bytes.Clone(b)
		return nil
	}); err != nil {
		return nil, providerFailure[sealFailed](err)
	}
	return blob, nil
}

// unprotectPerOperation calls the provider with the locked destination and
// checks the context again after it returns. When the provider fails and the
// context has also ended, the error keeps both, so a forgery verdict is not
// erased by a cancellation; see docs/sealing/engineering.md, Context error
// shapes.
func (s *Sealer) unprotectPerOperation(ctx context.Context, blob []byte, dek *MemoryEnclave) error {
	return providerFailure[openFailed](dek.WithBytes(func(k []byte) error {
		perr := s.kp.Unprotect(ctx, blob, k)
		if cerr := contextFailure[openFailed](ctx, perr); cerr != nil {
			return cerr
		}
		return perr
	}))
}

// The process sealer is the one [NewSealed] uses. It is never cleared, not
// even by a shutdown sweep: after one, the installed sealer reports
// [ErrSealerWiped].
var processSealerSlot = processSingleton[Sealer]{
	errNil:   ErrNilSealer,
	errTaken: ErrSealerInstalled,
	// The default construction cannot fail, so a build error is unreachable.
	build: func() (*Sealer, error) { return NewSealer() },
}

// SetSealer installs s as the process sealer, the one [NewSealed] uses.
//
// It is one-shot: it returns [ErrSealerInstalled] once any process sealer
// exists, including the software default the first [NewSealed] installs
// lazily, because replacing it would strand every live sealed value. Install
// before anything can seal. It returns [ErrNilSealer] for a nil sealer.
func SetSealer(s *Sealer) error {
	return processSealerSlot.install(s)
}

// processSealer returns the installed process sealer, lazily installing the
// pure-software default.
func processSealer() (*Sealer, error) {
	return processSealerSlot.get()
}
