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
	"math"
	"sync"
	"sync/atomic"
)

// allocatorIDs issues the lock-ordering ranks TransferTo uses. The first is 1;
// a zero-value Allocator has no rank at all, and is refused before any lock.
var allocatorIDs atomic.Uint64

// Allocator bounds the total locked memory live at once across the enclaves it creates; it is safe for concurrent use.
type Allocator interface {
	// Import admits material into a new frozen enclave per [NewImportSpec], wiping material on every path.
	Importer

	// New admits [LockedSize](len(data)) bytes and moves data into a new frozen enclave; data is wiped on every path.
	New(data []byte) (ByteAccess, error)

	// NewSized admits [LockedSize](n) bytes and returns an enclave over n zeroed locked bytes.
	NewSized(n int) (ByteAccess, error)

	// InUse reports the page-rounded locked bytes reserved through this
	// Allocator. It is a snapshot, not an admission gate. It exceeds Limit
	// only after ForceLimit.
	InUse() int64

	// Limit reports the total budget in locked bytes, as last set by
	// [NewAllocator], SetLimit, ForceLimit or TransferTo.
	Limit() int64

	// Available reports the locked bytes still admissible, clamped at zero.
	// It is a snapshot and an upper bound: a remainder below one page admits
	// nothing.
	Available() int64

	// SetLimit changes the budget to newLimit locked bytes, refusing to shrink below what is reserved.
	SetLimit(newLimit int64) error

	// ForceLimit sets the budget even below current reservations and returns the excess.
	ForceLimit(newLimit int64) (int64, error)

	// TransferTo moves n locked bytes of budget headroom to dst, or changes nothing and returns an error.
	TransferTo(dst Allocator, n int64) error
}

// budgetAllocator is this package's [Allocator]; copies share one budget.
type budgetAllocator struct {
	_ noCopy
	*allocatorState
}

var _ Allocator = (*budgetAllocator)(nil)

// allocatorState is the budget itself, shared by every copy of its Allocator.
type allocatorState struct {
	// free is limit minus reserved and the only word admission reads, so one
	// CAS orders a lowering against an admission. Negative only after
	// ForceLimit. See docs/locked-memory-budget/engineering.md, Invariants.
	free atomic.Int64
	// limit is a reporting shadow of free, written only with mu held.
	limit atomic.Int64
	// mu serializes retunes and makes InUse's read of the pair consistent.
	mu sync.RWMutex
	// id is the rank TransferTo orders its two locks by.
	id uint64
	// rlimitBound: every raise must fit under the current RLIMIT_MEMLOCK.
	rlimitBound bool
	// stalled is a nil-in-production test seam inside withdrawLocked's CAS window.
	stalled func()
}

// NewAllocator returns an Allocator with a total budget of maxBytes locked bytes, unchecked against RLIMIT_MEMLOCK.
func NewAllocator(maxBytes int64) (Allocator, error) {
	return allocatorOut(newBudgetAllocator(maxBytes))
}

// newBudgetAllocator is [NewAllocator] returning the implementation.
func newBudgetAllocator(maxBytes int64) (*budgetAllocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}
	return newAllocator(maxBytes, false), nil
}

// NewAllocatorWithinRLimit is [NewAllocator] that refuses a budget above the RLIMIT_MEMLOCK ceiling, now and on later raises.
func NewAllocatorWithinRLimit(maxBytes int64) (Allocator, error) {
	return allocatorOut(newBudgetAllocatorWithinRLimit(maxBytes))
}

// newBudgetAllocatorWithinRLimit is [NewAllocatorWithinRLimit] returning the
// implementation.
func newBudgetAllocatorWithinRLimit(maxBytes int64) (*budgetAllocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		return nil, err
	}

	if err := limit.refuse(maxBytes); err != nil {
		return nil, err
	}

	// true makes the ceiling check apply to later SetLimit and TransferTo.
	return newAllocator(maxBytes, true), nil
}

// newAllocator trusts its caller to have validated maxBytes: the process
// default may have a zero budget.
func newAllocator(maxBytes int64, rlimitBound bool) *budgetAllocator {
	a := &budgetAllocator{allocatorState: &allocatorState{id: allocatorIDs.Add(1), rlimitBound: rlimitBound}}
	a.limit.Store(maxBytes)
	a.free.Store(maxBytes)
	return a
}

// allocatorOut hands an implementation out as an [Allocator], keeping a
// failure a nil interface rather than one holding a nil pointer.
func allocatorOut(a *budgetAllocator, err error) (Allocator, error) {
	if a == nil {
		return nil, err
	}
	return a, err
}

// budgetOf returns the implementation behind a: [ErrNilAllocator] for a nil
// one, and [ErrAllocatorNotConstructed] for one this package did not build or
// for the zero value.
func budgetOf(a Allocator) (*budgetAllocator, error) {
	if a == nil {
		return nil, ErrNilAllocator
	}
	b, ok := a.(*budgetAllocator)
	if !ok {
		return nil, ErrAllocatorNotConstructed
	}
	return b, b.usable()
}

// usable returns nil for an Allocator built by a constructor, and otherwise
// [ErrNilAllocator] or, for the zero value, [ErrAllocatorNotConstructed].
func (a *budgetAllocator) usable() error {
	switch {
	case a == nil:
		return ErrNilAllocator
	case a.allocatorState == nil:
		return ErrAllocatorNotConstructed
	}
	return nil
}

// ceilingForRaise reads the current ceiling, or returns the zero (non-refusing)
// limit when not rlimitBound. Call it before taking mu: it may be a syscall.
func (a *budgetAllocator) ceilingForRaise() (LockedMemoryLimit, error) {
	if !a.rlimitBound {
		return LockedMemoryLimit{}, nil
	}
	return DiscoverLockedMemoryLimit()
}

// New implements [Allocator.New]. It returns [ErrNilAllocator] when a is
// nil and [ErrAllocatorNotConstructed] when it is the zero value.
func (a *budgetAllocator) New(data []byte) (ByteAccess, error) {
	return byteAccess(a.admitData(data))
}

// admitData is [Allocator.New] returning the implementation.
func (a *budgetAllocator) admitData(data []byte) (*lockedRegion, error) {
	defer Wipe(data)
	if err := a.usable(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrEmptyEnclave
	}
	return a.admit(int64(len(data)), func(locked int64) (*mapping, error) {
		m, err := mapLocked(len(data), locked)
		if err != nil {
			return nil, err
		}
		return m.loadFrozen(data)
	})
}

// NewSized implements [Allocator.NewSized], with the receiver errors of New.
func (a *budgetAllocator) NewSized(n int) (ByteAccess, error) {
	return byteAccess(a.admitSized(n))
}

// admitSized is [Allocator.NewSized] returning the implementation.
func (a *budgetAllocator) admitSized(n int) (*lockedRegion, error) {
	if err := a.usable(); err != nil {
		return nil, err
	}
	// reserve is the size check: it refuses n before mapLocked maps anything.
	return a.admit(int64(n), func(locked int64) (*mapping, error) {
		return mapLocked(n, locked)
	})
}

// aes256KeyBytes is the key length [AlgorithmAES256GCM] takes.
const aes256KeyBytes = 32

// Name returns [LockedMemoryBackendName]: an Allocator is the locked-memory
// backend with a budget. It is nil-safe.
func (a *budgetAllocator) Name() string { return LockedMemoryBackendName }

// Rank implements [Prober.Rank] as the default backend does. It is nil-safe.
func (a *budgetAllocator) Rank() int { return lockedMemory{}.Rank() }

// Probe implements [Prober.Probe] as the default backend does: a budget is no
// host requirement. It is nil-safe.
func (a *budgetAllocator) Probe(ctx context.Context) error { return lockedMemory{}.Probe(ctx) }

// Import implements [Importer.Import] as [Allocator] describes it, with the
// receiver errors of New.
func (a *budgetAllocator) Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error) {
	defer Wipe(material)
	if err := a.usable(); err != nil {
		return nil, err
	}
	spec, err := NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	if spec.Algorithm == AlgorithmAES256GCM && len(material) != aes256KeyBytes {
		return nil, ErrInvalidImport
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	e, err := a.New(material)
	if err != nil {
		// Never a typed nil inside the Handle.
		return nil, err
	}
	return e, nil
}

// admit charges n against the budget, builds the mapping and publishes it with the refund as its release.
func (a *budgetAllocator) admit(n int64, build func(locked int64) (*mapping, error)) (*lockedRegion, error) {
	charge, err := a.reserve(n)
	if err != nil {
		return nil, err
	}
	refund := func() { a.free.Add(charge) }

	m, err := build(charge)
	if err != nil && !lockedPagesHeld(err) {
		refund()
		refund = nil
	}
	return publish(m, err, refund, a)
}

// reserve is the sole admission gate and returns the page-rounded charge the release must return.
func (a *budgetAllocator) reserve(n int64) (int64, error) {
	charge, ok := lockedSize(n)
	if !ok {
		return 0, ErrInvalidSize
	}

	// Not shared with withdrawLocked, to keep its test seam off this path.
	for {
		free := a.free.Load()
		if charge > free {
			limit, inUse := a.budgetSnapshot(free)
			return 0, &BudgetError{Requested: charge, InUse: inUse, Limit: limit}
		}
		if a.free.CompareAndSwap(free, free-charge) {
			return charge, nil
		}
	}
}

// inUseFrom returns limit-free, or false when that is negative: a wrap, or a
// pair read across a lowering.
func inUseFrom(limit, free int64) (int64, bool) {
	used := limit - free
	if used < 0 {
		return 0, false
	}
	return used, true
}

// budgetSnapshot returns (limit, inUse) for a refusal decided on free, re-reading
// under the read lock only when the lock-free pair straddles a retune.
func (a *budgetAllocator) budgetSnapshot(free int64) (int64, int64) {
	limit := a.limit.Load()
	if inUse, ok := inUseFrom(limit, free); ok {
		return limit, inUse
	}

	a.mu.RLock()
	limit = a.limit.Load()
	free = a.free.Load()
	a.mu.RUnlock()

	inUse, _ := inUseFrom(limit, free)
	return limit, inUse
}

// InUse implements [Allocator.InUse]; a nil or zero value reports 0.
func (a *budgetAllocator) InUse() int64 {
	if a.usable() != nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.limit.Load() - a.free.Load()
}

// Limit implements [Allocator.Limit]; a nil or zero value reports 0.
func (a *budgetAllocator) Limit() int64 {
	if a.usable() != nil {
		return 0
	}
	return a.limit.Load()
}

// Available implements [Allocator.Available]; a nil or zero value reports 0.
func (a *budgetAllocator) Available() int64 {
	if a.usable() != nil {
		return 0
	}
	free := a.free.Load()
	if free < 0 {
		return 0
	}
	return free
}

// SetLimit implements [Allocator.SetLimit], with the receiver errors of New.
func (a *budgetAllocator) SetLimit(newLimit int64) error {
	if err := a.usable(); err != nil {
		return err
	}
	if newLimit < 0 {
		return ErrInvalidBudget
	}

	// Read before mu, unconditionally: only under mu is it known to be a raise.
	ceiling, cerr := a.ceilingForRaise()
	return a.setLimit(newLimit, ceiling, cerr)
}

// setLimit is SetLimit with the ceiling reading supplied, so a test can inject a
// discovery failure. cerr is consulted only on the raise branch.
func (a *budgetAllocator) setLimit(newLimit int64, ceiling LockedMemoryLimit, cerr error) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	old := a.limit.Load()
	switch {
	case newLimit > old:
		if err := checkRaise(ceiling, cerr, newLimit); err != nil {
			return err
		}
		a.raiseLocked(old, newLimit)
	case newLimit < old:
		if !a.withdrawLocked(old - newLimit) {
			// withdrawLocked is all or nothing, so nothing was mutated.
			return newBudgetInUseError(newLimit, old, a.free.Load())
		}
		a.limit.Store(newLimit)
	}
	return nil
}

// ForceLimit implements [Allocator.ForceLimit], with the receiver errors of
// New.
func (a *budgetAllocator) ForceLimit(newLimit int64) (int64, error) {
	if err := a.usable(); err != nil {
		return 0, err
	}
	if newLimit < 0 {
		return 0, ErrInvalidBudget
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	old := a.limit.Load()
	var free int64
	switch {
	case newLimit > old:
		a.raiseLocked(old, newLimit)
		free = a.free.Load()
	case newLimit < old:
		// May drive free negative; Add's result is this call's own state.
		free = a.free.Add(newLimit - old)
		a.limit.Store(newLimit)
	default:
		free = a.free.Load()
	}

	if free < 0 {
		return -free, nil
	}
	return 0, nil
}

// TransferTo implements [Allocator.TransferTo], with the receiver errors of
// New. A zero dst is [ErrAllocatorNotConstructed], and a nil *budgetAllocator
// dst [ErrInvalidTransfer].
func (a *budgetAllocator) TransferTo(dst Allocator, n int64) error {
	if err := a.usable(); err != nil {
		return err
	}
	if n <= 0 || dst == nil {
		return ErrInvalidTransfer
	}
	d, ok := dst.(*budgetAllocator)
	switch {
	case !ok:
		// Another implementation has no budget this package can credit.
		return ErrAllocatorNotConstructed
	case d == nil:
		return ErrInvalidTransfer
	}
	if err := d.usable(); err != nil {
		// A zero value has no budget to credit and no rank to lock by.
		return err
	}
	if d.allocatorState == a.allocatorState {
		// A copy shares the mutex, and would deadlock on it.
		return ErrInvalidTransfer
	}

	// Before either lock, so a syscall never stalls both allocators.
	dstCeiling, cerr := d.ceilingForRaise()
	return a.transferTo(d, n, dstCeiling, cerr)
}

// transferTo is TransferTo with dst's ceiling supplied, for tests. Locks are
// taken in ascending id order so opposing transfers cannot deadlock.
func (a *budgetAllocator) transferTo(dst *budgetAllocator, n int64, dstCeiling LockedMemoryLimit, cerr error) error {
	first, second := a, dst
	if second.id < first.id {
		first, second = second, first
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	second.mu.Lock()
	defer second.mu.Unlock()

	// Validate dst before debiting the source, so a refusal needs no undo.
	dstLimit := dst.limit.Load()
	if n > math.MaxInt64-dstLimit {
		return ErrInvalidBudget
	}
	if err := checkRaise(dstCeiling, cerr, dstLimit+n); err != nil {
		return err
	}

	srcLimit := a.limit.Load()
	if !a.withdrawLocked(n) {
		return newBudgetInUseError(srcLimit-n, srcLimit, a.free.Load())
	}

	// Debit before credit: the bytes are briefly in neither, never in both.
	a.limit.Store(srcLimit - n)
	dst.raiseLocked(dstLimit, dstLimit+n)
	return nil
}

// checkRaise refuses a raise on a failed ceiling reading or above the ceiling.
func checkRaise(ceiling LockedMemoryLimit, cerr error, newLimit int64) error {
	if cerr != nil {
		return cerr
	}
	return ceiling.refuse(newLimit)
}

// raiseLocked grows the budget from old to newLimit; the caller holds a.mu
// exclusively and newLimit > old. limit is stored before free is credited, so a
// lock-free reader may overstate usage but never sees ungranted headroom.
func (a *budgetAllocator) raiseLocked(old, newLimit int64) {
	a.limit.Store(newLimit)
	a.free.Add(newLimit - old)
}

// withdrawLocked removes d bytes of headroom, all or nothing; the caller holds a.mu exclusively.
func (a *budgetAllocator) withdrawLocked(d int64) bool {
	for {
		free := a.free.Load()
		if d > free {
			return false
		}
		if a.stalled != nil {
			a.stalled()
		}
		if a.free.CompareAndSwap(free, free-d) {
			return true
		}
	}
}

// processAllocatorSlot holds the process allocator.
var processAllocatorSlot = processSingleton[budgetAllocator]{
	errNil:   ErrNilAllocator,
	errTaken: ErrAllocatorInstalled,
	build: func() (*budgetAllocator, error) {
		limit, err := discoverProcessLimit()
		if err != nil {
			// An unread ceiling is not "no ceiling"; install nothing.
			return nil, err
		}
		return defaultProcessAllocator(limit), nil
	},
}

// discoverProcessLimit is a variable so a test can make discovery fail.
var discoverProcessLimit = DiscoverLockedMemoryLimit

// SetAllocator installs a as the process allocator, once, from main before anything allocates locked memory.
func SetAllocator(a Allocator) error {
	b, err := budgetOf(a)
	if err != nil {
		return err
	}
	return processAllocatorSlot.install(b)
}

// ProcessAllocator returns the installed process allocator, installing a default sized to RLIMIT_MEMLOCK on first call.
func ProcessAllocator() (Allocator, error) {
	return allocatorOut(processAllocatorSlot.get())
}

// InstalledAllocator reports the process allocator if one is installed, without installing the default.
func InstalledAllocator() (Allocator, bool) {
	processAllocatorSlot.mu.Lock()
	defer processAllocatorSlot.mu.Unlock()
	if processAllocatorSlot.value == nil {
		return nil, false
	}
	return processAllocatorSlot.value, true
}

// defaultProcessAllocator is split out so every ceiling shape can be tested.
func defaultProcessAllocator(limit LockedMemoryLimit) *budgetAllocator {
	if !limit.Bounded {
		return newAllocator(math.MaxInt64, false)
	}
	return newAllocator(limit.Bytes, true)
}
