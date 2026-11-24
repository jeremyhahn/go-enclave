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

// Mode selects how often a [Sealer] invokes its provider: ModePerOperation per value, ModeRootKey once for a root; the zero value is ModeRootKey.
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

// Sealer produces and opens [Sealed] values under an injected provider; construct one with [NewSealer]. It is safe for concurrent use.
type Sealer interface {
	// Seal is [NewSealed] for an explicitly constructed Sealer.
	Seal(ctx context.Context, data []byte) (Sealed, error)

	// SealFrom seals the material src holds, leaving src as it was; src needs [ByteAccess].
	SealFrom(ctx context.Context, src Handle) (Sealed, error)

	// Mode reports the mode this sealer was constructed with.
	Mode() Mode

	// Destroy releases every key this sealer holds; later calls through it report [ErrSealerDestroyed]. It is idempotent.
	Destroy() error
}

// envelopeSealer is this package's [Sealer]; it must not be copied.
type envelopeSealer struct {
	_ noCopy

	*sealerState
}

var _ Sealer = (*envelopeSealer)(nil)

// sealerState is everything a [Sealer] holds; nil in an envelopeSealer not
// built by [NewSealer].
type sealerState struct {
	mode Mode

	// Exactly one of kp / ru is non-nil, fixed at construction with the
	// matching protect and unprotect.
	kp KeyProtector
	ru RootUnsealer

	protect   func(ctx context.Context, dek *lockedRegion) ([]byte, error)
	unprotect func(ctx context.Context, blob []byte, dek *lockedRegion) error

	// mu guards the ModeRootKey hierarchy and destroyed, never across a provider call; lock order: initSlot, then mu.
	mu sync.RWMutex
	// root holds this sealer's wrapping key, set once and never cleared.
	root     Handle
	kek      Handle
	kekGen   uint32
	kekUsed  atomic.Uint64
	kekLimit uint64
	// kekBlobs holds each generation's root-wrapped KEK a live value may need; kekRefs counts those values.
	kekBlobs map[uint32][]byte
	kekRefs  map[uint32]*atomic.Int64
	// destroyed is set by Destroy and never cleared; every path checks it
	// before the hierarchy state.
	destroyed bool
	// retained holds every handle that refused its Destroy, until a retry releases it.
	retained []Handle

	// owned is the default provider NewSealer created, which the first
	// successful unseal and Destroy release; nil for an injected provider.
	owned *softwareProvider

	// backend is what WithBackend named, or nil. importer is it when keys are
	// imported into it, and nil when they stay in this process's locked
	// memory.
	backend  Backend
	importer Importer

	// initSlot is a one-slot semaphore held by the goroutine running
	// initHierarchy. A channel rather than a mutex so that acquiring it can
	// select on ctx.Done().
	initSlot chan struct{}

	// pendingRoot is a delivered root whose first KEK mint failed, kept for the retry; guarded by initSlot.
	pendingRoot *lockedRegion

	// pendingWrap is the wrapping key derived from pendingRoot, kept for the retry; guarded by initSlot.
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

// WithKeyProtector selects [ModePerOperation] over a non-nil kp.
func WithKeyProtector(kp KeyProtector) SealerOption {
	return func(c *sealerConfig) { c.kp, c.providers = kp, c.providers+1 }
}

// WithRootUnsealer selects [ModeRootKey] over a non-nil ru; with neither option the sealer uses its own [SoftwareProvider].
func WithRootUnsealer(ru RootUnsealer) SealerOption {
	return func(c *sealerConfig) { c.ru, c.providers = ru, c.providers+1 }
}

// WithKEKRotationLimit sets how many DEKs one [ModeRootKey] KEK generation wraps before rotating, from 1 to the default 2^31.
func WithKEKRotationLimit(n uint64) SealerOption {
	return func(c *sealerConfig) { c.kekLimit, c.kekLimitSet = n, true }
}

// WithBackend makes b hold a [ModeRootKey] sealer's wrapping key and KEKs instead of this process's locked memory.
func WithBackend(b Backend) SealerOption {
	return func(c *sealerConfig) { c.backend, c.backendSet = b, true }
}

// WithRequireKeyScheduleErasure makes [NewSealer] refuse a configuration that would leave an AES key schedule on the heap.
func WithRequireKeyScheduleErasure() SealerOption {
	return func(c *sealerConfig) { c.requireErasure = true }
}

// erasesKeySchedules is keyScheduleErasure, a variable so tests can drive
// strict mode on both builds.
var erasesKeySchedules = keyScheduleErasure

// NewSealer returns a Sealer over the provider its options name, fixing the [Mode]; it does no crypto until its first Seal.
func NewSealer(opts ...SealerOption) (Sealer, error) {
	s, err := newEnvelopeSealer(opts...)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// newEnvelopeSealer is [NewSealer] as an *envelopeSealer, for this package's
// own callers.
func newEnvelopeSealer(opts ...SealerOption) (*envelopeSealer, error) {
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
		s.owned = newSoftwareProvider()
		s.ru = s.owned
	}
	return &envelopeSealer{sealerState: s}, nil
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

// isNilInterface reports whether v is nil or an interface wrapping a nil value.
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

// Mode implements [Sealer.Mode]. A nil sealer, or one not built by
// [NewSealer], reports the zero Mode, [ModeRootKey], and does not panic; it
// cannot seal (see [ErrNilSealer] and [ErrSealerNotConstructed]).
func (s *envelopeSealer) Mode() Mode {
	if s == nil || s.sealerState == nil {
		return 0
	}
	return s.mode
}

// usable reports, under the read lock, whether the sealer may still be used:
// [ErrSealerDestroyed] once Destroy ran, and [ErrSealerNotConstructed] for a
// zero Sealer, which has no provider.
func (s *envelopeSealer) usable() error {
	if s == nil || s.sealerState == nil {
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
func (s *envelopeSealer) releaseBlob(blob []byte) {
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

// destroyOrRetainLocked destroys h, keeping it in retained if it refuses; called with mu write-locked.
func (s *sealerState) destroyOrRetainLocked(failure error, h Handle) error {
	if isNilInterface(h) {
		return failure
	}
	cause := h.Destroy()
	if cause == nil {
		return failure
	}
	s.retained = append(s.retained, h)
	return &CleanupError{Failure: failure, Causes: []error{cause}}
}

// releaseRetainedLocked retries the Destroy of every retained handle, keeps
// the ones that refuse again, and returns one [CleanupError] carrying every
// refusal. Called with mu write-locked.
func (s *sealerState) releaseRetainedLocked() error {
	var causes []error
	kept := s.retained[:0]
	for _, h := range s.retained {
		if cause := h.Destroy(); cause != nil {
			kept = append(kept, h)
			causes = append(causes, cause)
		}
	}
	clear(s.retained[len(kept):])
	s.retained = kept
	if len(causes) == 0 {
		return nil
	}
	return &CleanupError{Causes: causes}
}

// Destroy implements [Sealer.Destroy]; it is safe on a nil sealer.
func (s *envelopeSealer) Destroy() error {
	if s == nil || s.sealerState == nil {
		return nil
	}

	s.mu.Lock()
	s.destroyed = true
	refused := []error{destroyKeys(s.kek, s.root), s.releaseRetainedLocked()}
	for _, b := range s.kekBlobs {
		Wipe(b)
	}
	s.kekBlobs, s.kekRefs = nil, nil
	// Non-blocking: a slot holder may be inside a provider call. It releases
	// the pending state itself, under mu, after seeing destroyed.
	select {
	case s.initSlot <- struct{}{}:
		refused = append(refused, s.releasePending())
		<-s.initSlot
	default:
	}
	s.mu.Unlock()

	return withCleanupFailure(nil, append(refused, s.owned.Destroy())...)
}

// Seal implements [Sealer.Seal]. It returns [ErrNilSealer] on a nil receiver.
func (s *envelopeSealer) Seal(ctx context.Context, data []byte) (Sealed, error) {
	return sealedOut(s.sealData(ctx, data))
}

// sealData is [Sealer.Seal] as a *sealedValue, for this package's own callers.
func (s *envelopeSealer) sealData(ctx context.Context, data []byte) (*sealedValue, error) {
	// First: every path below wipes data, and wiping a frozen view faults.
	if readOnly(data) {
		return nil, ErrSealSourceReadOnly
	}
	if s == nil {
		Wipe(data)
		return nil, ErrNilSealer
	}
	defer Wipe(data)

	return s.seal(ctx, sealedVersionCurrent, len(data), func(fn func([]byte) error) error { return fn(data) })
}

// SealFrom implements [Sealer.SealFrom]. It returns [ErrNilSealer] on a nil
// receiver.
func (s *envelopeSealer) SealFrom(ctx context.Context, src Handle) (Sealed, error) {
	return sealedOut(s.sealFromHandle(ctx, src))
}

// sealFromHandle is [Sealer.SealFrom] as a *sealedValue.
func (s *envelopeSealer) sealFromHandle(ctx context.Context, src Handle) (*sealedValue, error) {
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
	return s.seal(ctx, sealedVersionCurrent, size, ba.WithBytes)
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
func (s *envelopeSealer) seal(ctx context.Context, version uint8, size int, read func(func([]byte) error) error) (*sealedValue, error) {
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
	if err := contextFailure[SealError](ctx, nil); err != nil {
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

	aad, err := sealedAAD(version, blob)
	if err != nil {
		s.releaseBlob(blob)
		return nil, err
	}
	defer Wipe(aad)

	// The data AEAD runs with mu released, so destroyed is re-checked after it.
	var sealed []byte
	err = read(func(p []byte) error {
		var serr error
		sealed, serr = sealWithKey(dek, p, aad)
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

	return &sealedValue{sealedState: &sealedState{
		sealer: s, sealed: sealed, blob: blob, size: size,
		version: version, sealedAtGen: sealedAtGen,
	}}, nil
}

// readOnly reports whether any page of p is memory this process cannot write, probing each page with an unchanged write.
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

// open recovers an envelope into a frozen enclave with no lock held, allocating the admitted destination first; a is nil for [Sealed.Open].
func (s *envelopeSealer) open(ctx context.Context, version uint8, blob, sealed []byte, size int, dst func(int) (*lockedRegion, error), freeze bool) (*lockedRegion, error) {
	if err := contextFailure[OpenError](ctx, nil); err != nil {
		return nil, err
	}
	if err := s.usable(); err != nil {
		return nil, err
	}
	// Before the destination or any key: an unknown version allocates nothing.
	aad, err := sealedAAD(version, blob)
	if err != nil {
		return nil, err
	}
	defer Wipe(aad)

	out, err := dst(size)
	if err != nil {
		return nil, err
	}

	// Locked before the provider fills it, so a capable provider writes the
	// key straight into locked pages. Not admitted; see [Sealed.OpenIn].
	dek, err := newMemorySized(dekBytes)
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
		return openWithKeyInto(dek, sealed, aad, pt)
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

// openable reports whether the in-process key material this sealer depends on is still there.
func (s *envelopeSealer) openable(sealedAtGen uint64) error {
	// The hierarchy's state, without unwrapping anything. It is nil for a
	// sealer with no hierarchy (ModePerOperation, or ModeRootKey before the
	// first seal).
	s.mu.RLock()
	_, err := s.hierarchyStateLocked()
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	// An explicit HealthReporter answer, including nil, is terminal.
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

// protectPerOperation calls the provider inside the DEK's borrow and rechecks the context after it returns.
func (s *sealerState) protectPerOperation(ctx context.Context, dek *lockedRegion) ([]byte, error) {
	var blob []byte
	if err := dek.WithBytes(func(k []byte) error {
		b, perr := s.kp.Protect(ctx, k)
		if cerr := contextFailure[SealError](ctx, perr); cerr != nil {
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
		return nil, providerFailure[SealError](err)
	}
	return blob, nil
}

// unprotectPerOperation calls the provider and keeps both its error and the context's; see docs/sealing/engineering.md.
func (s *sealerState) unprotectPerOperation(ctx context.Context, blob []byte, dek *lockedRegion) error {
	return providerFailure[OpenError](dek.WithBytes(func(k []byte) error {
		perr := s.kp.Unprotect(ctx, blob, k)
		if cerr := contextFailure[OpenError](ctx, perr); cerr != nil {
			return cerr
		}
		return perr
	}))
}

// The process sealer is the one [NewSealed] uses. It is never cleared, not
// even by a shutdown sweep: after one, the installed sealer reports
// [ErrSealerWiped].
var processSealerSlot = processSingleton[envelopeSealer]{
	errNil:   ErrNilSealer,
	errTaken: ErrSealerInstalled,
	// The default construction cannot fail, so a build error is unreachable.
	build: func() (*envelopeSealer, error) { return newEnvelopeSealer() },
}

// SetSealer installs s as the process sealer, once and before anything seals.
func SetSealer(s Sealer) error {
	e, err := envelopeOf(s)
	if err != nil {
		return err
	}
	return processSealerSlot.install(e)
}

// envelopeOf returns s as this package's implementation, refusing what [SetSealer] refuses.
func envelopeOf(s Sealer) (*envelopeSealer, error) {
	if isNilInterface(s) {
		return nil, ErrNilSealer
	}
	e, ok := s.(*envelopeSealer)
	if !ok {
		return nil, ErrSealerNotConstructed
	}
	return e, e.usable()
}

// processSealer returns the installed process sealer, lazily installing the
// pure-software default.
func processSealer() (*envelopeSealer, error) {
	return processSealerSlot.get()
}
