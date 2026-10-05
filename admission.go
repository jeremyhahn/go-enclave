// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
)

var (
	// ErrBudgetExhausted is returned by [Allocator.New] and [Allocator.NewSized]
	// when an allocation would exceed the budget. Every [BudgetError] matches
	// it. It is returned before any locked memory is requested.
	ErrBudgetExhausted = errors.New("enclave: locked-memory budget exhausted")

	// ErrInvalidBudget is returned by [NewAllocator] for a non-positive budget,
	// by [Allocator.SetLimit] and [Allocator.ForceLimit] for a negative one
	// (zero is legal there), and by [Allocator.TransferTo] when the
	// destination's budget would overflow int64.
	ErrInvalidBudget = errors.New("enclave: allocator budget must be positive")

	// ErrBudgetInUse is returned when lowering a budget would put it below the
	// locked bytes already reserved; nothing is changed. Every
	// [BudgetInUseError] matches it. [Allocator.ForceLimit] lowers regardless.
	ErrBudgetInUse = errors.New("enclave: budget would fall below the locked memory already reserved")

	// ErrInvalidTransfer is returned by [Allocator.TransferTo] for a malformed
	// transfer: a non-positive amount, a nil destination, or a destination that
	// is the source.
	ErrInvalidTransfer = errors.New("enclave: invalid headroom transfer")

	// ErrNilAllocator is returned for a nil *Allocator by [SetAllocator],
	// [SealedEnclave.OpenWith] (which never falls back to the unbudgeted
	// [SealedEnclave.Open]), and the Allocator methods that can fail. New still
	// wipes the data it was handed.
	ErrNilAllocator = errors.New("enclave: allocator is nil")
)

// BudgetError reports that an allocation was refused because it would exceed an
// [Allocator]'s budget. Its fields are diagnostic; match on [ErrBudgetExhausted].
type BudgetError struct {
	// Requested is the page-rounded charge of the refused allocation ([LockedSize]).
	Requested int64
	// InUse is a snapshot of the bytes reserved. It is never negative, and
	// exceeds Limit only after [Allocator.ForceLimit].
	InUse int64
	// Limit is the allocator's total budget in locked bytes.
	Limit int64
}

// Error implements error.
func (e *BudgetError) Error() string {
	return fmt.Sprintf("%s: %d requested, %d of %d bytes in use",
		ErrBudgetExhausted.Error(), e.Requested, e.InUse, e.Limit)
}

// Is reports every BudgetError as ErrBudgetExhausted, so callers match the
// sentinel and never have to know about this type.
func (e *BudgetError) Is(target error) bool {
	return target == ErrBudgetExhausted
}

// BudgetInUseError reports that a budget change was refused because the
// requested budget is below the locked memory already reserved; the allocator
// is unchanged. Match on [ErrBudgetInUse].
type BudgetInUseError struct {
	// Requested is the budget asked for; for [Allocator.TransferTo], what the
	// source would have been left with.
	Requested int64
	InUse     int64 // snapshot of the bytes reserved
	Limit     int64 // the unchanged budget
}

// Error implements error.
func (e *BudgetInUseError) Error() string {
	return fmt.Sprintf("%s: %d requested, %d of %d bytes in use",
		ErrBudgetInUse.Error(), e.Requested, e.InUse, e.Limit)
}

// Is reports every BudgetInUseError as ErrBudgetInUse, so callers match the
// sentinel and never have to know about this type.
func (e *BudgetInUseError) Is(target error) bool {
	return target == ErrBudgetInUse
}

// allocatorIDs issues the lock-ordering ranks TransferTo uses. The first is 1,
// so the unusable zero-value Allocator never shares a rank with a real one.
var allocatorIDs atomic.Uint64

// Allocator bounds the total locked memory that may be live at once across the
// enclaves it creates.
//
// RLIMIT_MEMLOCK is process-wide, so one unbounded path can make every other
// path's allocation fail. Admitting an untrusted source's allocations (such as
// pre-authentication buffers) through an Allocator sized well below the ceiling
// turns that denial of service into a local [ErrBudgetExhausted].
//
// [MemoryEnclave.Destroy] returns an enclave's reservation. The zero value is
// not usable; construct one with [NewAllocator] or [NewAllocatorWithinRLimit].
// A nil *Allocator returns [ErrNilAllocator] from every method that can fail
// and reports zero from InUse, Limit and Available. An Allocator is safe for
// concurrent use; admission and release are lock-free.
//
// It does not bound locked memory allocated elsewhere in the process, so an
// admitted allocation can still fail with [ErrLockedMemoryUnavailable]; callers
// must handle both errors. Budgets can be changed at runtime with
// [Allocator.SetLimit], [Allocator.ForceLimit] and [Allocator.TransferTo].
type Allocator struct {
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

// NewAllocator returns an Allocator with the given total budget in locked
// bytes, the unit of RLIMIT_MEMLOCK, which it never checks the budget against
// (see [NewAllocatorWithinRLimit]). Size it in pages: every enclave costs at
// least one ([LockedSize]); guard pages are never locked and do not count.
//
// It returns [ErrInvalidBudget] when maxBytes is not positive.
func NewAllocator(maxBytes int64) (*Allocator, error) {
	return newAllocator(maxBytes, false)
}

func newAllocator(maxBytes int64, rlimitBound bool) (*Allocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}
	return buildAllocator(maxBytes, rlimitBound), nil
}

// buildAllocator does no validation: the process default may have a zero budget.
func buildAllocator(maxBytes int64, rlimitBound bool) *Allocator {
	a := &Allocator{id: allocatorIDs.Add(1), rlimitBound: rlimitBound}
	a.limit.Store(maxBytes)
	a.free.Store(maxBytes)
	return a
}

// ceilingForRaise reads the current ceiling, or returns the zero (non-refusing)
// limit when not rlimitBound. Call it before taking mu: it may be a syscall.
func (a *Allocator) ceilingForRaise() (LockedMemoryLimit, error) {
	if !a.rlimitBound {
		return LockedMemoryLimit{}, nil
	}
	return DiscoverLockedMemoryLimit()
}

// New admits [LockedSize](len(data)) bytes and moves data into a new enclave
// holding that reservation until its Destroy runs; callers must Destroy it or
// the reservation leaks. data is wiped before New returns, on every path.
//
// Errors, each leaving the budget unchanged unless noted:
//   - [ErrNilAllocator] when a is nil;
//   - [ErrEmptyEnclave] when data is empty;
//   - [ErrBudgetExhausted] (as a [BudgetError]), before any syscall;
//   - [ErrLockedMemoryUnavailable] when the kernel refuses the lock. If cleanup
//     also failed and left pages locked, the charge stays until [WipeAll]
//     reclaims them, and the error carries both failures.
func (a *Allocator) New(data []byte) (*MemoryEnclave, error) {
	if a == nil {
		Wipe(data)
		return nil, ErrNilAllocator
	}
	if len(data) == 0 {
		Wipe(data)
		return nil, ErrEmptyEnclave
	}

	n := int64(len(data))

	charge, err := a.reserve(n)
	if err != nil {
		Wipe(data)
		return nil, err
	}

	e, cerr := newMemoryEnclave(data)
	if cerr != nil {
		a.refundFailed(charge, cerr)
		return nil, cerr
	}

	e.release = func() { a.free.Add(charge) }

	// Publish only after release is set, or a concurrent WipeAll could unmap
	// the pages while the budget kept the charge.
	return register(e), nil
}

// NewSized is the admitted form of [NewMemoryEnclaveSized]: it admits
// [LockedSize](n) bytes and returns an enclave over n zeroed locked bytes that
// holds the reservation until its Destroy runs. Errors are as for
// [Allocator.New], with [ErrInvalidSize] for a non-positive or unmappable n in
// place of ErrEmptyEnclave.
func (a *Allocator) NewSized(n int) (*MemoryEnclave, error) {
	if a == nil {
		return nil, ErrNilAllocator
	}
	charge, err := a.reserve(int64(n))
	if err != nil {
		return nil, err
	}

	e, cerr := newMemoryEnclaveSized(n)
	if cerr != nil {
		a.refundFailed(charge, cerr)
		return nil, cerr
	}

	e.release = func() { a.free.Add(charge) }

	// Publish last, as in New.
	return register(e), nil
}

// refundFailed refunds a failed construction's charge now, or, if pages were
// left locked, attaches it to the orphan record for the WipeAll sweep to refund.
func (a *Allocator) refundFailed(charge int64, cerr error) {
	if !lockedPagesHeld(cerr) {
		a.free.Add(charge)
		adoptOrphan(cerr, nil)
		return
	}
	adoptOrphan(cerr, func() { a.free.Add(charge) })
}

// allocSized allocates unadmitted when a is nil, which is how
// [SealedEnclave.Open] stays unbudgeted.
func allocSized(a *Allocator, n int) (*MemoryEnclave, error) {
	if a == nil {
		return NewMemoryEnclaveSized(n)
	}
	return a.NewSized(n)
}

// reserve is the sole admission gate. It returns the page-rounded charge, which
// the release must return exactly. `charge > free` has no addition, so a huge n
// cannot overflow into admission.
func (a *Allocator) reserve(n int64) (int64, error) {
	if n <= 0 {
		return 0, ErrInvalidSize
	}

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
func (a *Allocator) budgetSnapshot(free int64) (int64, int64) {
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

// InUse reports the page-rounded locked bytes reserved through this Allocator.
// It is a snapshot, not an admission gate. It exceeds [Allocator.Limit] only
// after [Allocator.ForceLimit]. A nil Allocator reports 0.
func (a *Allocator) InUse() int64 {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.limit.Load() - a.free.Load()
}

// Limit reports the Allocator's total budget in locked bytes, as last set by
// [NewAllocator], [Allocator.SetLimit], [Allocator.ForceLimit] or
// [Allocator.TransferTo]. A nil Allocator reports 0.
func (a *Allocator) Limit() int64 {
	if a == nil {
		return 0
	}
	return a.limit.Load()
}

// Available reports the locked bytes still admissible, clamped at zero. It is a
// snapshot and an upper bound: a remainder below one page admits nothing. A nil
// Allocator reports 0.
func (a *Allocator) Available() int64 {
	if a == nil {
		return 0
	}
	free := a.free.Load()
	if free < 0 {
		return 0
	}
	return free
}

// SetLimit changes the budget to newLimit locked bytes, refusing to shrink below
// the memory already reserved.
//
// A raise is admissible immediately. A lowering that reservations do not fit
// under returns a [BudgetInUseError] and changes nothing; zero is legal, and
// [Allocator.ForceLimit] lowers regardless. A negative newLimit returns
// [ErrInvalidBudget]. Safe for concurrent use with allocation and release: a
// lowering and an in-flight admission never both get the same bytes.
//
// On an allocator built by [NewAllocatorWithinRLimit], a raise re-reads
// RLIMIT_MEMLOCK and is refused with [ErrBudgetExceedsRLimit] (an [RLimitError])
// above it, or [ErrLimitDiscoveryFailed] if it cannot be read. Lowerings are
// never refused on a ceiling. Passing the check does not rule out
// [ErrLockedMemoryUnavailable].
func (a *Allocator) SetLimit(newLimit int64) error {
	if a == nil {
		return ErrNilAllocator
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
func (a *Allocator) setLimit(newLimit int64, ceiling LockedMemoryLimit, cerr error) error {
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
			return &BudgetInUseError{
				Requested: newLimit,
				InUse:     old - a.free.Load(),
				Limit:     old,
			}
		}
		a.limit.Store(newLimit)
	}
	return nil
}

// ForceLimit sets the budget to newLimit locked bytes even below current
// reservations, and returns the bytes by which reservations exceed it (0 if
// none). Live enclaves are untouched and release normally; nothing is admitted
// until they drain. Zero quiesces the allocator. A negative newLimit returns
// [ErrInvalidBudget] and changes nothing.
//
// It overrides both [Allocator.SetLimit] refusals, including raising an
// [NewAllocatorWithinRLimit] allocator above RLIMIT_MEMLOCK without reading it;
// allocations beyond the real ceiling then fail with [ErrLockedMemoryUnavailable].
func (a *Allocator) ForceLimit(newLimit int64) (int64, error) {
	if a == nil {
		return 0, ErrNilAllocator
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

// TransferTo moves n locked bytes of budget headroom to dst in one call. Live
// enclaves on both sides are untouched. Concurrent and opposing transfers are
// safe; at worst one causes a brief refusal on either side, never over-commit.
//
// It refuses, changing nothing, with:
//   - [ErrInvalidTransfer] when n <= 0, dst is nil, or dst is a;
//   - a [BudgetInUseError] when the source's reservations would not fit, with
//     Requested the budget the source would have been left with;
//   - [ErrInvalidBudget] when dst's budget would overflow int64;
//   - the [Allocator.SetLimit] raise errors when dst was built by
//     [NewAllocatorWithinRLimit]. Only dst is checked.
func (a *Allocator) TransferTo(dst *Allocator, n int64) error {
	if a == nil {
		return ErrNilAllocator
	}
	if n <= 0 || dst == nil || dst == a {
		// dst == a would deadlock on its own mutex.
		return ErrInvalidTransfer
	}

	// Before either lock, so a syscall never stalls both allocators.
	dstCeiling, cerr := dst.ceilingForRaise()
	return a.transferTo(dst, n, dstCeiling, cerr)
}

// transferTo is TransferTo with dst's ceiling supplied, for tests. Locks are
// taken in ascending id order so opposing transfers cannot deadlock.
func (a *Allocator) transferTo(dst *Allocator, n int64, dstCeiling LockedMemoryLimit, cerr error) error {
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
		return &BudgetInUseError{
			Requested: srcLimit - n,
			InUse:     srcLimit - a.free.Load(),
			Limit:     srcLimit,
		}
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
func (a *Allocator) raiseLocked(old, newLimit int64) {
	a.limit.Store(newLimit)
	a.free.Add(newLimit - old)
}

// withdrawLocked takes d > 0 bytes of headroom out of circulation, all or
// nothing, and reports whether it could; the caller holds a.mu exclusively. It
// is the same compare-and-swap as reserve, so a lowering racing an admission
// cannot double-spend the last page.
func (a *Allocator) withdrawLocked(d int64) bool {
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
