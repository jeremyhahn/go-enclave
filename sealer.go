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
	"runtime"
	"runtime/debug"
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

// Sealer produces and opens [Sealed] values under an injected crypto
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
//
// A Sealer must not be copied; use the *Sealer. Its state sits behind one
// pointer, so even a copy shares its lock, its message counters and its keys.
type Sealer struct {
	_ noCopy

	*sealerState
}

// sealerState is everything a [Sealer] holds; nil in a Sealer not built by
// [NewSealer].
type sealerState struct {
	mode Mode

	// Exactly one of kp / ru is non-nil, fixed at construction with the
	// matching protect and unprotect.
	kp KeyProtector
	ru RootUnsealer

	protect   func(ctx context.Context, dek *Memory) ([]byte, error)
	unprotect func(ctx context.Context, blob []byte, dek *Memory) error

	// mu guards the ModeRootKey hierarchy below and destroyed. It is
	// read-locked to wrap and unwrap DEKs and write-locked only to publish
	// the hierarchy, rotate, and destroy; it is never held across a provider
	// call. Lock order: initSlot, then mu.
	mu sync.RWMutex
	// root holds this sealer's wrapping key (deriveWrappingKey), not the
	// provider's root. It is set once and never cleared, so a swept
	// hierarchy stays detectable as dead keys. root and kek are locked
	// memory, or handles of the backend WithBackend named.
	root     Handle
	kek      Handle
	kekGen   uint32
	kekUsed  atomic.Uint64
	kekLimit uint64
	// kekBlobs holds every generation's root-wrapped KEK that a live value
	// may still need, and kekRefs how many live values (each counted until
	// its last open in flight ends) were sealed under it. A retired
	// generation is dropped with its last value.
	kekBlobs map[uint32][]byte
	kekRefs  map[uint32]*atomic.Int64
	// destroyed is set by Destroy and never cleared; every path checks it
	// before the hierarchy state.
	destroyed bool
	// retained holds every handle that refused its Destroy after the sealer
	// stopped needing it: an outgoing KEK, an imported key a failed seal
	// dropped, a plaintext handle an open did not return. Each keeps its
	// material until a retried Destroy releases it; see destroyOrRetain.
	retained []Handle

	// owned is the default provider NewSealer created, which the first
	// successful unseal and Destroy release; nil for an injected provider.
	owned *SoftwareProvider

	// backend is what WithBackend named, or nil. importer is it when keys are
	// imported into it, and nil when they stay in this process's locked
	// memory.
	backend  Backend
	importer Importer

	// initSlot is a one-slot semaphore held by the goroutine running
	// initHierarchy. A channel rather than a mutex so that acquiring it can
	// select on ctx.Done().
	initSlot chan struct{}

	// pendingRoot is a root UnsealRoot delivered whose first KEK mint failed,
	// kept so a retry repeats only the mint: UnsealRoot may not be called
	// again after it succeeded. It is not root, because a non-nil root with
	// no live KEK reads as wiped. A dead pendingRoot is the wiped state of a
	// sealer whose hierarchy was never published. Guarded by initSlot.
	pendingRoot *Memory

	// pendingWrap is the wrapping key derived from pendingRoot, held where it
	// will be published: pendingRoot itself, or its import into the backend.
	// Kept across a failed mint, so a retry repeats only the mint. Guarded by
	// initSlot.
	pendingWrap Handle

	// pendingKEK is the first KEK between mint and publication, and after a
	// discard any such KEK whose release the kernel refused, kept so later
	// attempts retry that release. Guarded by initSlot.
	pendingKEK Handle

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

	backend        Backend
	backendSet     bool
	requireErasure bool
}

// SealerOption configures [NewSealer].
type SealerOption func(*sealerConfig)

// WithKeyProtector selects [ModePerOperation] over kp: every seal and open
// calls kp on the per-value data key. If kp implements [HealthReporter], the
// sealer consults it from [Sealed.Openable]. kp must be non-nil; see
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

// WithBackend makes b hold the keys of a [ModeRootKey] sealer: its wrapping
// key and every KEK are imported into b with [PurposeWrappingKey] and
// [AlgorithmAES256GCM] instead of staying in this process's locked memory. A
// key handle that implements [AEAD] wraps inside the device; one with only
// [ByteAccess] wraps in this process. Data keys are generated per value in
// this process whatever b is.
//
// [NewSealer] returns [ErrInvalidBackend] for a nil or typed-nil b, and a
// [*CapabilityError] for [CapabilityImport] when b is not an [Importer];
// [DefaultBackend] is accepted and keeps the keys in locked memory. A key
// handle with neither AEAD nor ByteAccess is found only when the key is
// imported, at the first unseal or a rotation, and fails that seal with
// [CapabilityAEAD].
//
// In [ModePerOperation] the provider holds every key, and b only answers
// whether it confines this process (see [WithRequireKeyScheduleErasure]).
func WithBackend(b Backend) SealerOption {
	return func(c *sealerConfig) { c.backend, c.backendSet = b, true }
}

// WithRequireKeyScheduleErasure makes [NewSealer] refuse a configuration in
// which an AES key schedule of the sealer's would reach the heap and stay
// there. Each key class is covered when the build erases schedules
// ([KeyScheduleErasure]) or the sealer's backend confines this process (a
// [Confiner] whose ConfinesProcess reports true). Offloading the wrapping key
// and KEKs to an [AEAD] handle never suffices alone: data keys are generated
// and used in this process.
//
// A refusal is a [*KeyScheduleExposedError] matching [ErrKeyScheduleExposed],
// naming the first exposed class: "wrapping-key" for a [ModeRootKey] sealer
// whose keys stay in locked memory, otherwise "dek". The check runs once, in
// NewSealer; seals and opens are not rechecked.
func WithRequireKeyScheduleErasure() SealerOption {
	return func(c *sealerConfig) { c.requireErasure = true }
}

// erasesKeySchedules is keyScheduleErasure, a variable so tests can drive
// strict mode on both builds.
var erasesKeySchedules = keyScheduleErasure

// NewSealer returns a Sealer over the provider its options name; the option
// chosen fixes the [Mode].
//
// With no options it is the pure-software default ([SoftwareProvider],
// [ModeRootKey]) and cannot fail. It returns [ErrInvalidProvider] for a nil
// provider or for two providers, [ErrInvalidRotationLimit] for a rotation
// limit it cannot honor, [ErrInvalidSealerOption] for a nil option, the
// refusals [WithBackend] lists, and a [*KeyScheduleExposedError] under
// [WithRequireKeyScheduleErasure].
//
// The returned Sealer performs no crypto, touches no locked memory and does
// not consult its provider until its first Seal, so a device problem surfaces
// from the first operation that needs it.
func NewSealer(opts ...SealerOption) (*Sealer, error) {
	var cfg sealerConfig
	for _, opt := range opts {
		if opt == nil {
			return nil, ErrInvalidSealerOption
		}
		opt(&cfg)
	}

	s := &sealerState{initSlot: make(chan struct{}, 1), kekLimit: kekMessageLimit}
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
		s.mode = ModeRootKey
		s.protect, s.unprotect = s.protectRootKey, s.unprotectRootKey
	}

	if cfg.kekLimitSet {
		if s.mode != ModeRootKey || cfg.kekLimit == 0 || cfg.kekLimit > kekMessageLimit {
			return nil, ErrInvalidRotationLimit
		}
		s.kekLimit = cfg.kekLimit
	}

	if cfg.backendSet {
		if err := s.useBackend(cfg.backend); err != nil {
			return nil, err
		}
	}
	if cfg.requireErasure {
		if err := s.keySchedulesCovered(); err != nil {
			return nil, err
		}
	}

	// Created last, so a refused configuration leaves no root behind.
	if s.mode == ModeRootKey && s.ru == nil {
		s.owned = NewSoftwareProvider()
		s.ru = s.owned
	}
	return &Sealer{sealerState: s}, nil
}

// useBackend validates b for WithBackend and records where the keys go.
func (s *sealerState) useBackend(b Backend) error {
	if isNilInterface(b) {
		return ErrInvalidBackend
	}
	s.backend = b
	if _, ok := b.(lockedMemory); ok || s.mode != ModeRootKey {
		return nil
	}
	imp, ok := b.(Importer)
	if !ok {
		return &CapabilityError{Backend: b.Name(), Capability: CapabilityImport}
	}
	s.importer = imp
	return nil
}

// keySchedulesCovered is WithRequireKeyScheduleErasure's check.
func (s *sealerState) keySchedulesCovered() error {
	if erasesKeySchedules {
		return nil
	}
	if c, ok := s.backend.(Confiner); ok && c.ConfinesProcess() {
		return nil
	}
	if s.mode == ModeRootKey && s.importer == nil {
		return &KeyScheduleExposedError{Name: "wrapping-key"}
	}
	return &KeyScheduleExposedError{Name: "dek"}
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

// Mode reports the mode this sealer was constructed with. A nil Sealer, or
// one not built by [NewSealer], reports the zero Mode, [ModeRootKey], and
// does not panic; it cannot seal (see [ErrNilSealer] and
// [ErrSealerNotConstructed]).
func (s *Sealer) Mode() Mode {
	if s == nil || s.sealerState == nil {
		return 0
	}
	return s.mode
}

// usable reports, under the read lock, whether the sealer may still be used:
// [ErrSealerDestroyed] once Destroy ran, and [ErrSealerNotConstructed] for a
// zero Sealer, which has no provider.
func (s *Sealer) usable() error {
	if s.sealerState == nil {
		return ErrSealerNotConstructed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return ErrSealerDestroyed
	}
	return nil
}

// releaseBlob is sealerState.releaseBlob, a no-op on a sealer without state.
func (s *Sealer) releaseBlob(blob []byte) {
	if s == nil || s.sealerState == nil {
		return
	}
	s.sealerState.releaseBlob(blob)
}

// destroyOrRetain destroys h, which the operation that failed with failure no
// longer needs; it is destroyOrRetainLocked taking mu. The caller must not
// hold s.mu.
func (s *sealerState) destroyOrRetain(failure error, h Handle) error {
	if isNilInterface(h) {
		return failure
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.destroyOrRetainLocked(failure, h)
}

// destroyOrRetainLocked destroys h and returns failure, which may be nil. If
// h refuses, it still holds its material: it is kept in retained, for every
// Destroy to retry, and the refusal is returned with failure as a
// [CleanupError]. A nil h returns failure. Called with mu write-locked.
func (s *sealerState) destroyOrRetainLocked(failure error, h Handle) error {
	if isNilInterface(h) {
		return failure
	}
	cause := h.Destroy()
	if cause == nil {
		return failure
	}
	s.retained = append(s.retained, h)
	return &CleanupError{Failure: failure, Cause: cause}
}

// releaseRetainedLocked retries the Destroy of every retained handle, keeps
// the ones that refuse again, and returns a [CleanupError] for each. Called
// with mu write-locked.
func (s *sealerState) releaseRetainedLocked() error {
	var errs error
	kept := s.retained[:0]
	for _, h := range s.retained {
		if cause := h.Destroy(); cause != nil {
			kept = append(kept, h)
			errs = withCleanupFailure(errs, &CleanupError{Cause: cause})
		}
	}
	clear(s.retained[len(kept):])
	s.retained = kept
	return errs
}

// Destroy releases every key this sealer holds, including any root or KEK an
// unfinished initialization left pending, and the [SoftwareProvider] if
// [NewSealer] created it by default. An injected provider is never destroyed.
//
// From then on every Seal, Open and [Sealed.Openable] through this
// sealer reports [ErrSealerDestroyed]; values it sealed are unrecoverable.
// Destroy waits for key wraps and unwraps in this process, but not for a
// provider call or a value's own encryption: a seal or open that straddles
// Destroy fails with ErrSealerDestroyed when it finishes, releasing what it
// produced, and an initialization blocked
// in [RootUnsealer.UnsealRoot] releases what it produced. A release the kernel
// refuses is returned and stays on the [WipeAll] ledger; calling Destroy again
// retries it. So does every handle a [CleanupError] reported for this sealer:
// Destroy retries each, and keeps the ones that refuse again. Destroy is
// idempotent and safe on a nil Sealer.
func (s *Sealer) Destroy() error {
	if s == nil || s.sealerState == nil {
		return nil
	}

	s.mu.Lock()
	s.destroyed = true
	errs := withCleanupFailure(destroyKeys(s.kek, s.root), s.releaseRetainedLocked())
	for _, b := range s.kekBlobs {
		Wipe(b)
	}
	s.kekBlobs, s.kekRefs = nil, nil
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
// there and on [Sealed]. It returns [ErrNilSealer] on a nil receiver, and
// [ErrSealSourceReadOnly], wiping nothing, for data this process cannot
// write.
func (s *Sealer) Seal(ctx context.Context, data []byte) (*Sealed, error) {
	// First: every path below wipes data, and wiping a frozen view faults.
	if readOnly(data) {
		return nil, ErrSealSourceReadOnly
	}
	if s == nil {
		Wipe(data)
		return nil, ErrNilSealer
	}
	defer Wipe(data)

	return s.seal(ctx, len(data), func(fn func([]byte) error) error { return fn(data) })
}

// SealFrom encrypts the material src holds and returns the sealed enclave
// holding it. It is [Sealer.Seal] for material already in an enclave, such as
// a frozen [Memory] that Seal would refuse with [ErrSealSourceReadOnly]: src
// is read under its own borrow and left as it was, neither wiped nor
// destroyed. The caller still owns src.
//
// src needs [ByteAccess]; one without it is a [*CapabilityError] naming
// [CapabilityBytes], since material that never leaves its device cannot be
// sealed here. A nil or destroyed src returns [ErrEnclaveDestroyed]. It
// returns [ErrNilSealer] on a nil receiver, and otherwise what Seal returns.
func (s *Sealer) SealFrom(ctx context.Context, src Handle) (*Sealed, error) {
	if s == nil {
		return nil, ErrNilSealer
	}
	if isNilInterface(src) {
		return nil, ErrEnclaveDestroyed
	}
	ba, ok := src.(ByteAccess)
	if !ok {
		return nil, &CapabilityError{Backend: backendName(src), Capability: CapabilityBytes}
	}
	size := ba.Size()
	if size <= 0 && !ba.IsAlive() {
		return nil, ErrEnclaveDestroyed
	}
	return s.seal(ctx, size, ba.WithBytes)
}

// backendName is the name of the backend that made h, guarded against a
// backend breaking Handle's never-nil contract.
func backendName(h Handle) string {
	b := h.Backend()
	if isNilInterface(b) {
		return ""
	}
	return b.Name()
}

// seal is the shared body of Seal and SealFrom. read lends the size bytes of
// material to its argument for one call.
func (s *Sealer) seal(ctx context.Context, size int, read func(func([]byte) error) error) (*Sealed, error) {
	// Before any key is touched, so an empty or oversized input costs nothing.
	// SealFrom's size comes from a ByteAccess, so a negative one is refused
	// as empty too.
	if size <= 0 {
		return nil, ErrEmptyEnclave
	}
	if err := sealableWithin(uint64(size), math.MaxInt); err != nil {
		return nil, err
	}

	// After the argument checks, so a malformed call is reported as malformed
	// whatever the caller's deadline.
	if err := contextFailure[sealFailed](ctx, nil); err != nil {
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
	defer func() { _ = dek.Destroy() }()

	blob, err := s.protect(ctx, dek)
	if err != nil {
		return nil, err
	}

	// The blob is the AAD. The data AEAD runs with mu released, so a long
	// value never holds off Destroy or a rotation. That is safe because it
	// uses only dek, which this call made and destroys, never a key of the
	// hierarchy: those are used only under mu or by the initSlot holder. What
	// Destroy must prevent is a value sealed under a destroyed sealer
	// escaping, so destroyed is re-checked after the AEAD, and a seal it
	// overlapped fails closed and releases its generation's reference.
	var sealed []byte
	err = read(func(p []byte) error {
		var serr error
		sealed, serr = sealWithKey(dek, p, blob)
		size = len(p)
		return serr
	})
	if err == nil {
		err = s.usable()
	}
	if err != nil {
		s.releaseBlob(blob)
		return nil, err
	}

	return &Sealed{sealedState: &sealedState{
		sealer: s, sealed: sealed, blob: blob, size: size,
		sealedAtGen: sealedAtGen,
	}}, nil
}

// readOnly reports whether p, or any part of it, is memory this process
// cannot write, such as a view into a frozen [Memory]. It probes by writing
// one byte of every page p spans back unchanged, with a fault turned into a
// recoverable panic for the probe's length. Those are the pages the wipe
// that follows a seal writes, so a mapping of mixed protection is refused
// rather than faulting in the wipe. Material p is only ever handed to
// sealing, which owns and wipes it, so the probe writes nothing a caller
// could observe.
func readOnly(p []byte) (ro bool) {
	if len(p) == 0 {
		return false
	}
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if _, ok := r.(runtime.Error); !ok {
			panic(r)
		}
		ro = true
	}()
	// A stride of one page from the first byte lands in each page p spans in
	// turn, short of the last one at most, which the last byte is in.
	for i := 0; i < len(p); i += int(pageSize) {
		rewrite(&p[i], p[i])
	}
	rewrite(&p[len(p)-1], p[len(p)-1])
	return false
}

// rewrite stores v into b. Not inlined, so the compiler cannot see that v
// was loaded from b and drop the store as a no-op.
//
//go:noinline
func rewrite(b *byte, v byte) {
	*b = v
}

// open recovers an envelope this sealer produced into a frozen enclave; a is
// nil for [Sealed.Open]. It runs with no lock held: the envelope is
// pinned by the value's in-flight count, so a value's Destroy never waits on
// a provider call here.
//
// The destination is allocated first because it is the one admitted
// allocation: an open the budget refuses allocates no locked memory and
// touches no key, and the unadmitted DEK page exists only behind a granted
// reservation.
func (s *Sealer) open(ctx context.Context, blob, sealed []byte, size int, dst func(int) (*Memory, error), freeze bool) (*Memory, error) {
	if err := contextFailure[openFailed](ctx, nil); err != nil {
		return nil, err
	}
	if err := s.usable(); err != nil {
		return nil, err
	}

	out, err := dst(size)
	if err != nil {
		return nil, err
	}

	// Locked before the provider fills it, so a capable provider writes the
	// key straight into locked pages. Not admitted; see [Sealed.OpenIn].
	dek, err := NewMemorySized(dekBytes)
	if err != nil {
		return nil, destroyOnFailure(err, out)
	}
	defer func() { _ = dek.Destroy() }()

	if err := s.unprotect(ctx, blob, dek); err != nil {
		return nil, destroyOnFailure(err, out)
	}
	// With mu released, as in seal: the AEAD uses only this call's dek.
	// destroyed is re-checked after it, so nothing opened under a sealer
	// destroyed meanwhile is returned.
	err = out.WithBytes(func(pt []byte) error {
		// The blob is verified as AAD even though the DEK unwrap already
		// authenticated it: this refuses two individually authentic halves
		// that were never sealed together.
		return openWithKeyInto(dek, sealed, blob, pt)
	})
	if err == nil {
		err = s.usable()
	}
	if err != nil {
		return nil, destroyOnFailure(err, out)
	}

	if !freeze {
		return out, nil
	}
	// Returned read-only, so a stray write through a retained slice faults. A
	// refused freeze fails the open closed.
	if err := out.Freeze(); err != nil {
		return nil, destroyOnFailure(err, out)
	}
	return out, nil
}

// openable reports whether the in-process key material this sealer depends on
// is still there (see [Sealed.Openable]). It performs no crypto and
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
func (s *sealerState) protectPerOperation(ctx context.Context, dek *Memory) ([]byte, error) {
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
func (s *sealerState) unprotectPerOperation(ctx context.Context, blob []byte, dek *Memory) error {
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
// before anything can seal. It returns [ErrNilSealer] for a nil sealer,
// [ErrSealerNotConstructed] for one not built by [NewSealer], and
// [ErrSealerDestroyed] for one already destroyed.
func SetSealer(s *Sealer) error {
	if s == nil {
		return ErrNilSealer
	}
	// Refused here rather than at the first seal, where the configuration
	// could no longer be corrected.
	if err := s.usable(); err != nil {
		return err
	}
	return processSealerSlot.install(s)
}

// processSealer returns the installed process sealer, lazily installing the
// pure-software default.
func processSealer() (*Sealer, error) {
	return processSealerSlot.get()
}
