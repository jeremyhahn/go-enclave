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

// Allocator bounds the total locked memory that may be live at once across the
// enclaves it creates.
//
// RLIMIT_MEMLOCK is process-wide, so one unbounded path can make every other
// path's allocation fail. Admitting an untrusted source's allocations (such as
// pre-authentication buffers) through an Allocator sized well below the ceiling
// turns that denial of service into a local [ErrBudgetExhausted].
//
// [Memory.Destroy] returns an enclave's reservation. The zero value is
// not usable; construct one with [NewAllocator] or [NewAllocatorWithinRLimit].
// A nil *Allocator returns [ErrNilAllocator], and a zero one
// [ErrAllocatorNotConstructed], from every method that can fail, and both
// report zero from InUse, Limit and Available. An Allocator is safe for
// concurrent use; admission and release are lock-free. It holds only a pointer
// to its budget, so every copy of one shares the budget.
//
// It does not bound locked memory allocated elsewhere in the process, so an
// admitted allocation can still fail with [ErrLockedMemoryUnavailable]; callers
// must handle both errors. Budgets can be changed at runtime with
// [Allocator.SetLimit], [Allocator.ForceLimit] and [Allocator.TransferTo].
//
// An *Allocator is the locked-memory [Backend] with a budget: it is an
// [Importer], and every enclave it admits reports it from [Memory.Backend].
// Its name is [LockedMemoryBackendName], which the unbudgeted default holds
// in the registry, so an Allocator is never registered; pass it where a
// backend is injected.
type Allocator struct {
	_ noCopy
	*allocatorState
}

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

// NewAllocator returns an Allocator with the given total budget in locked
// bytes, the unit of RLIMIT_MEMLOCK, which it never checks the budget against
// (see [NewAllocatorWithinRLimit]). Size it in pages: every enclave costs at
// least one ([LockedSize]); guard pages are never locked and do not count.
//
// It returns [ErrInvalidBudget] when maxBytes is not positive.
func NewAllocator(maxBytes int64) (*Allocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}
	return newAllocator(maxBytes, false), nil
}

// NewAllocatorWithinRLimit is [NewAllocator] with a ceiling check: it discovers
// the process's locked-memory ceiling and refuses a budget that exceeds it,
// naming both figures. Prefer it for a budget that comes from configuration, so
// an unsatisfiable budget fails at startup rather than under load. It never
// exits, logs or panics; acting on the error is the application's choice.
//
// It returns:
//   - [ErrInvalidBudget] when maxBytes is not positive, checked before any
//     syscall.
//   - [ErrBudgetExceedsRLimit] (as an [RLimitError]) when the ceiling is
//     bounded and maxBytes is above it.
//   - [ErrLimitDiscoveryFailed] (as a [LimitDiscoveryError]) if the ceiling
//     could not be read.
//
// Otherwise it returns what [NewAllocator] would. Size the budget in pages and
// leave headroom: a budget equal to the ceiling passes and leaves nothing for
// the rest of the process. Passing does not promise allocations will succeed
// (see [DiscoverLockedMemoryLimit]); the ceiling is not re-read on admission,
// and the kernel's refusal is still reported as [ErrLockedMemoryUnavailable].
//
// The check is sticky: [Allocator.SetLimit] re-reads the ceiling and refuses to
// raise this allocator's budget above it, and [Allocator.TransferTo] does the
// same for the allocator it credits, both with [ErrBudgetExceedsRLimit].
// Lowering is never checked; [Allocator.ForceLimit] is the deliberate override.
func NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error) {
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
func newAllocator(maxBytes int64, rlimitBound bool) *Allocator {
	a := &Allocator{allocatorState: &allocatorState{id: allocatorIDs.Add(1), rlimitBound: rlimitBound}}
	a.limit.Store(maxBytes)
	a.free.Store(maxBytes)
	return a
}

// usable returns nil for an Allocator built by a constructor, and otherwise
// [ErrNilAllocator] or, for the zero value, [ErrAllocatorNotConstructed].
func (a *Allocator) usable() error {
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
//   - [ErrNilAllocator] when a is nil, [ErrAllocatorNotConstructed] when it
//     is the zero value;
//   - [ErrEmptyEnclave] when data is empty;
//   - [ErrBudgetExhausted] (as a [BudgetError]), before any syscall;
//   - [ErrLockedMemoryUnavailable] when the kernel refuses the lock. If cleanup
//     also failed and left pages locked, the charge stays until [WipeAll]
//     reclaims them, and the error carries both failures.
func (a *Allocator) New(data []byte) (*Memory, error) {
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

// NewSized is the admitted form of [NewMemorySized]: it admits
// [LockedSize](n) bytes and returns an enclave over n zeroed locked bytes that
// holds the reservation until its Destroy runs. Errors are as for
// [Allocator.New], with [ErrInvalidSize] for a non-positive or unmappable n in
// place of ErrEmptyEnclave.
func (a *Allocator) NewSized(n int) (*Memory, error) {
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
func (a *Allocator) Name() string { return LockedMemoryBackendName }

// Import is [Allocator.New] behind the [Importer] contract: it resolves opts
// with [NewImportSpec] and admits material into a new frozen enclave, wiping
// material on every path. Locked memory holds every purpose, since the
// enclave's [ByteAccess] meets each purpose's contract; a key for
// [AlgorithmAES256GCM] must be 32 bytes. Nothing is admitted once ctx has
// ended; a nil ctx never ends.
//
// It returns [ErrInvalidImport] for options NewImportSpec refuses or a key of
// the wrong length, ctx's error, and otherwise what New returns.
func (a *Allocator) Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error) {
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

// admit charges n against the budget, builds the mapping and publishes it with
// the refund as its release. A failed build is refunded at once, unless it
// left pages locked: then the orphan carries the refund until a sweep
// releases them.
func (a *Allocator) admit(n int64, build func(locked int64) (*mapping, error)) (*Memory, error) {
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

// reserve is the sole admission gate. It returns the page-rounded charge, which
// the release must return exactly, or [ErrInvalidSize] for an n lockedSize
// refuses. `charge > free` has no addition, so a huge n cannot overflow into
// admission.
func (a *Allocator) reserve(n int64) (int64, error) {
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
// after [Allocator.ForceLimit]. A nil or zero Allocator reports 0.
func (a *Allocator) InUse() int64 {
	if a.usable() != nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.limit.Load() - a.free.Load()
}

// Limit reports the Allocator's total budget in locked bytes, as last set by
// [NewAllocator], [Allocator.SetLimit], [Allocator.ForceLimit] or
// [Allocator.TransferTo]. A nil or zero Allocator reports 0.
func (a *Allocator) Limit() int64 {
	if a.usable() != nil {
		return 0
	}
	return a.limit.Load()
}

// Available reports the locked bytes still admissible, clamped at zero. It is a
// snapshot and an upper bound: a remainder below one page admits nothing. A nil
// or zero Allocator reports 0.
func (a *Allocator) Available() int64 {
	if a.usable() != nil {
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
			return newBudgetInUseError(newLimit, old, a.free.Load())
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

// TransferTo moves n locked bytes of budget headroom to dst in one call. Live
// enclaves on both sides are untouched. Concurrent and opposing transfers are
// safe; at worst one causes a brief refusal on either side, never over-commit.
//
// It refuses, changing nothing, with:
//   - [ErrNilAllocator] when a is nil;
//   - [ErrAllocatorNotConstructed] when a or dst is the zero value;
//   - [ErrInvalidTransfer] when n <= 0, dst is nil, or dst is a or a copy of it;
//   - a [BudgetInUseError] when the source's reservations would not fit, with
//     Requested the budget the source would have been left with;
//   - [ErrInvalidBudget] when dst's budget would overflow int64;
//   - the [Allocator.SetLimit] raise errors when dst was built by
//     [NewAllocatorWithinRLimit]. Only dst is checked.
func (a *Allocator) TransferTo(dst *Allocator, n int64) error {
	if err := a.usable(); err != nil {
		return err
	}
	if n <= 0 || dst == nil {
		return ErrInvalidTransfer
	}
	if err := dst.usable(); err != nil {
		// A zero value has no budget to credit and no rank to lock by.
		return err
	}
	if dst.allocatorState == a.allocatorState {
		// A copy shares the mutex, and would deadlock on it.
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

// processAllocatorSlot holds the process allocator.
var processAllocatorSlot = processSingleton[Allocator]{
	errNil:   ErrNilAllocator,
	errTaken: ErrAllocatorInstalled,
	build: func() (*Allocator, error) {
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

// SetAllocator installs a as the process allocator, the one [ProcessAllocator]
// returns to every library in the process.
//
// It belongs to the binary: call it from main before anything allocates
// locked memory. Libraries call [ProcessAllocator] instead. It is one-shot and
// returns [ErrAllocatorInstalled] once any process allocator exists, including
// the default installed by an earlier ProcessAllocator call, so even a stray
// early ProcessAllocator call locks the configuration.
//
// Build a with [NewAllocatorWithinRLimit] so a budget above the ceiling fails
// at startup, and leave headroom below the ceiling for locked memory taken
// outside the allocator, such as [Sealed.Open]. It returns [ErrNilAllocator]
// for a nil allocator and [ErrAllocatorNotConstructed] for a zero one,
// installing nothing.
func SetAllocator(a *Allocator) error {
	if err := a.usable(); err != nil {
		return err
	}
	return processAllocatorSlot.install(a)
}

// ProcessAllocator returns the process allocator: the one [SetAllocator]
// installed or, if none was, a default installed on this first call. Libraries
// allocate through it ([Allocator.New], [Allocator.NewSized],
// [Sealed.OpenIn]) rather than building their own, because separate
// allocators can together exceed the one ceiling they share.
//
// The default's budget is the discovered RLIMIT_MEMLOCK ceiling when it binds
// ([LockedMemoryLimit.Bounded]), kept for life as with
// [NewAllocatorWithinRLimit]; a zero ceiling gives a zero budget. When no
// ceiling binds the budget is math.MaxInt64. It leaves no headroom; sizing is
// the binary's decision through SetAllocator.
//
// If the ceiling cannot be read it returns [ErrLimitDiscoveryFailed] (as a
// [LimitDiscoveryError]), installs nothing, and a later call retries. Once an
// allocator is installed it never fails.
func ProcessAllocator() (*Allocator, error) {
	return processAllocatorSlot.get()
}

// defaultProcessAllocator is split out so every ceiling shape can be tested.
func defaultProcessAllocator(limit LockedMemoryLimit) *Allocator {
	if !limit.Bounded {
		return newAllocator(math.MaxInt64, false)
	}
	return newAllocator(limit.Bytes, true)
}
