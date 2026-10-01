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
	// ErrBudgetExhausted is the sentinel returned by [Allocator.New] and
	// [Allocator.NewSized] when admitting an allocation would push the total
	// locked bytes held through the allocator past its budget. Every
	// [BudgetError] matches it, so this is what callers test for. It is returned
	// BEFORE any locked memory is requested, so a refusal costs no syscall and
	// cannot itself exhaust anything.
	ErrBudgetExhausted = errors.New("enclave: locked-memory budget exhausted")

	// ErrInvalidBudget is returned by [NewAllocator] for a non-positive
	// budget. A zero or negative budget would refuse every allocation, which
	// is a configuration mistake rather than a runtime condition.
	//
	// [Allocator.SetLimit] and [Allocator.ForceLimit] return it for a NEGATIVE
	// budget only. Zero is legal there and means something different: at
	// construction a zero budget is a mistake nobody makes on purpose, but at
	// runtime driving a budget to zero is the deliberate act of quiescing an
	// allocator — parking its headroom elsewhere and admitting nothing until it
	// is raised again. [Allocator.TransferTo] may leave a source at zero for
	// the same reason.
	//
	// The retune paths also return it when the new budget cannot be expressed —
	// a transfer whose destination limit would overflow int64. That is a
	// programming error at 8 EiB of locked memory, not a runtime condition, but
	// it is reported rather than wrapped around.
	ErrInvalidBudget = errors.New("enclave: allocator budget must be positive")

	// ErrBudgetInUse is the sentinel returned when LOWERING a budget would put
	// the ceiling below the locked bytes already reserved through the allocator.
	// Every [LimitError] matches it, so this is what callers test for.
	//
	// The reservations behind that figure belong to live enclaves, and only
	// their owners may [MemoryEnclave.Destroy] them — an allocator cannot
	// reclaim them, and must never invalidate them to make a budget fit. So the
	// default answer to "shrink below what is in use" is to refuse and leave
	// everything exactly as it was. A caller that genuinely must record a
	// smaller ceiling — the container was resized under it, the kernel's
	// RLIMIT_MEMLOCK moved — uses [Allocator.ForceLimit], which accepts the
	// lower budget, keeps the live enclaves alive, and admits nothing further
	// until usage drains beneath it.
	ErrBudgetInUse = errors.New("enclave: budget would fall below the locked memory already reserved")

	// ErrInvalidTransfer is returned by [Allocator.TransferTo] when the transfer
	// itself is malformed rather than merely unaffordable: a non-positive
	// amount, a nil destination, or a destination that is the source. The last
	// is called out because it is the one a caller writes by accident, in a loop
	// rebalancing a slice of allocators against each other, and because taking
	// the same lock twice would hang rather than fail.
	ErrInvalidTransfer = errors.New("enclave: invalid headroom transfer")

	// ErrNilAllocator is returned by [SealedEnclave.OpenWith] for a nil
	// *Allocator. It REFUSES rather than falling back to an unadmitted
	// allocation, and that is the whole point of the sentinel.
	//
	// A caller reaches OpenWith instead of [SealedEnclave.Open] for exactly
	// one reason: to hold the open's locked memory inside a budget. A nil
	// Allocator arriving there is an uninitialized field or a lost
	// configuration step, and the "helpful" reading — treat nil as no budget
	// and allocate anyway — silently delivers the precise outcome the caller
	// wrote OpenWith to prevent, on a path that keeps working and keeps
	// looking bounded. The unbudgeted allocation is available and spelled
	// differently: call Open.
	//
	// It is a programming error, so it is reported before any state is
	// consulted; a value that happens to be destroyed does not change the
	// answer. Open, by contrast, has nothing to refuse and never returns it.
	//
	// [SetAllocator] returns it too, for the same reason: installing a nil
	// process allocator would turn every library's admitted allocation into
	// a nil dereference.
	ErrNilAllocator = errors.New("enclave: allocator is nil")
)

// BudgetError reports that an allocation was refused because it would exceed an
// [Allocator]'s locked-memory budget.
//
// It carries the sizes involved so an operator can see how tight the budget
// was when the refusal happened; that detail is diagnostic, not contract.
// Match on [ErrBudgetExhausted]; errors.Is reports it for every BudgetError.
type BudgetError struct {
	// Requested is the LOCKED bytes the refused allocation would have consumed
	// — the caller's size rounded up to a whole page, since that is what the
	// kernel charges. A 32-byte credential reports 4096 here on a 4 KiB-page
	// host; see [LockedSize].
	Requested int64
	// InUse is the number of bytes already reserved when the refusal happened.
	// It is a snapshot: under concurrency the true figure may have moved by
	// the time this error is read.
	//
	// It can exceed Limit, and that is not a bug: [Allocator.ForceLimit] lowers
	// a budget beneath live reservations on purpose, and until they drain this
	// is what an over-subscribed allocator looks like from the refusal path.
	//
	// It is never negative. A negative byte count — one that wrapped, or one
	// computed from headroom read before a concurrent lowering — is not a stale
	// reading but an impossible one, and a consumer graphing this or deciding
	// on it cannot tell the difference; see [Allocator.budgetSnapshot] for the
	// windows that would otherwise produce one.
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

// LimitError reports that a budget change was REFUSED because the requested
// ceiling is below the locked memory already reserved through the allocator.
//
// Nothing was changed: an allocator that returns this is exactly as it was
// before the call, budget and reservations both. Match on [ErrBudgetInUse];
// errors.Is reports it for every LimitError.
type LimitError struct {
	// Requested is the budget that was asked for, in locked bytes. For
	// [Allocator.TransferTo] it is what the SOURCE would have been left with,
	// since that is the ceiling the refusal is about.
	Requested int64
	// InUse is the locked bytes reserved when the refusal happened. It is a
	// snapshot for the same reason [BudgetError.InUse] is — an enclave may be
	// destroyed the instant after the refusal, making the change that just
	// failed possible.
	InUse int64
	// Limit is the budget still in force. The change was refused, so this is
	// the unchanged current budget rather than the requested one.
	Limit int64
}

// Error implements error.
func (e *LimitError) Error() string {
	return fmt.Sprintf("%s: %d requested, %d of %d bytes in use",
		ErrBudgetInUse.Error(), e.Requested, e.InUse, e.Limit)
}

// Is reports every LimitError as ErrBudgetInUse, so callers match the sentinel
// and never have to know about this type.
func (e *LimitError) Is(target error) bool {
	return target == ErrBudgetInUse
}

// allocatorIDs hands out the lock-ordering ranks described on [Allocator.id].
// It starts at zero and is only ever read after an Add, so the first allocator
// takes rank 1 and the zero value of Allocator — documented as unusable — can
// never collide with a constructed one.
var allocatorIDs atomic.Uint64

// Allocator bounds the total locked memory that may be live at once across the
// enclaves it creates.
//
// Locked memory is a fixed, process-wide resource: RLIMIT_MEMLOCK is a ceiling
// on the whole process, not on any one caller. So a path that allocates without
// a bound does not merely fail itself when it exhausts the ceiling — it makes
// every OTHER path's allocation fail too, including the ones doing legitimate
// work. An Allocator caps how much a given path may hold, so that an untrusted
// or unauthenticated source cannot starve the rest of the process.
//
// The motivating shape is a network responder that must buffer key material
// before it has authenticated the peer: a flood of half-open connections, each
// holding a locked buffer, exhausts locked memory, and the sessions that DID
// authenticate can no longer allocate. Sizing an Allocator's budget well below
// RLIMIT_MEMLOCK and admitting all pre-auth allocations through it turns that
// remote denial-of-service into a local, typed [ErrBudgetExhausted] on the
// abusive path, leaving headroom for live work.
//
// Before v0.3.0-alpha the stakes were higher and the mechanism different:
// go-enclave's pages lived in memguard's process-global registry, and reaching
// the ceiling made memguard PURGE — unmap — every live locked buffer in the
// process, so one path's exhaustion destroyed unrelated enclaves outright. That
// is gone (issue #2): go-enclave maps its own memory, and reaching the ceiling
// now fails exactly the allocation that reached it.
//
// A reservation is held for exactly the
// lifetime of the enclave it backs: [MemoryEnclave.Destroy] returns it. The
// zero value is not usable; construct one with [NewAllocator]. An Allocator is
// safe for concurrent use, and its accounting is lock-free.
//
// # The obligation an Allocator does not remove
//
// An Allocator bounds the enclaves IT creates. It does not, and cannot, bound
// locked memory allocated elsewhere in the same process — a direct
// [NewMemoryEnclave] call, another Allocator, or any other user of mlock. If
// any of those exhausts RLIMIT_MEMLOCK, allocations THROUGH this Allocator
// start failing with [ErrLockedMemoryUnavailable] even though its own budget
// has room, because the budget is a policy and the ceiling is the kernel's.
// Admitted is not the same as allocated, and callers must handle the second
// error as well as the first.
//
// What a caller no longer has to tolerate, since v0.3.0-alpha: an enclave it
// holds spontaneously reporting [ErrEnclaveDestroyed] because something
// unrelated failed. Enclaves are destroyed when their owner destroys them and
// at no other time.
//
// # Changing the budget at runtime
//
// A budget set once at construction cannot follow a process whose locked-memory
// demand moves — a per-tenant seal barrier gaining and losing tenants, or a
// container resized under a running process so the ceiling itself changed.
// [Allocator.SetLimit] and [Allocator.ForceLimit] retune one allocator;
// [Allocator.TransferTo] moves headroom between two, so a slack allocator can
// fund a pressured one without either being rebuilt.
//
// Retuning is admission control for a finite kernel resource, so the interesting
// part is what happens when a budget change races an admission that is already
// in flight. If both are allowed to decide against the same free bytes, the
// allocator over-commits: it admits memory the process cannot actually lock, and
// the failure surfaces later as [ErrLockedMemoryUnavailable] on some unrelated
// path. The design below makes that race impossible rather than unlikely.
type Allocator struct {
	// free is the admission counter and the ONLY state admission consults: the
	// locked bytes still admissible, which is the budget minus everything
	// reserved. Holding the REMAINDER rather than the usage is what lets a
	// budget move without breaking admission.
	//
	// The reason is that every operation on the budget reduces to one signed
	// adjustment of this single word:
	//
	//   admit n      free -= n   (compare-and-swap; refuses rather than overshoots)
	//   release n    free += n
	//   raise by d   free += d   (headroom appears)
	//   lower by d   free -= d   (headroom is taken out of circulation)
	//
	// Lowering a budget and admitting an allocation are therefore the SAME
	// operation on the same word, and a single compare-and-swap linearizes them
	// against each other. Whichever lands first wins, and the loser sees the
	// other's effect and re-decides. Neither can decide against bytes the other
	// already took, which is exactly the over-commit this type exists to
	// prevent. No lock is involved, and admission is unchanged from the fixed-
	// budget version: it still touches one atomic word and still never calls
	// into the mapping layer for a request the budget cannot cover.
	//
	// A limit and a usage counter in two separate words could not do this. The
	// admission predicate would have to read the limit and then commit the
	// usage, and a lowering that landed between those two steps would be
	// invisible to it — the classic check-then-act, with locked memory as the
	// thing over-committed.
	//
	// free is in [-limit, limit]. It is negative only after
	// [Allocator.ForceLimit] deliberately lowers the budget beneath live
	// reservations; the admission predicate `charge > free` refuses everything
	// while it is, with no special case, because charge is always positive.
	free atomic.Int64

	// limit is the nominal budget in locked bytes. It is a REPORTING shadow of
	// free — [Allocator.Limit] returns it, [Allocator.InUse] subtracts free from
	// it, and refusals quote it — and admission never reads it to make a
	// decision. That split is deliberate: reporting may be a hair stale under a
	// concurrent retune, but admission may not be even slightly wrong.
	//
	// It is written only while mu is held exclusively, and read atomically
	// everywhere, so the lock-free paths can quote it without taking a lock.
	limit atomic.Int64

	// mu serializes budget CHANGES. Admission and release never touch it: they
	// are single-word atomics on free and remain lock-free.
	//
	// It exists because a retune is two writes — the free adjustment that is the
	// real operation, and the limit shadow that reports it — and two concurrent
	// retunes interleaving those writes would leave the shadow describing
	// neither budget. Writers take it exclusively; the observability getters
	// take it shared, which is what makes [Allocator.InUse] an exact figure
	// rather than a torn pair (see there).
	mu sync.RWMutex

	// id is this allocator's rank in the process-wide total order that
	// [Allocator.TransferTo] acquires two mu's in. See the lock-ordering note
	// there for why the order has to be total, and why it is a counter rather
	// than the obvious pointer comparison.
	id uint64

	// rlimitBound records that this allocator was constructed through
	// [NewAllocatorWithinRLimit] and therefore opted into the RLIMIT_MEMLOCK
	// contract: no operation may RAISE its budget above the ceiling the kernel
	// reports at the moment of the raise. [NewAllocator] leaves it false and
	// nothing checks a ceiling for that allocator, ever.
	//
	// The contract is a property of the allocator rather than of the call
	// because that is the only way it can be sticky. A check that lived on the
	// constructor alone bound the budget for exactly as long as it took to call
	// SetLimit — which was issue #46 — and one that lived on every allocator
	// would break callers who deliberately chose the unchecked constructor.
	//
	// It is written once, before the allocator is reachable by any other
	// goroutine, and only read afterwards, so it needs no atomic and no lock.
	rlimitBound bool

	// stalled is a test seam, and the only one in this package. When it is
	// non-nil, [Allocator.withdrawLocked] calls it between reading the headroom
	// counter and the compare-and-swap that acts on what it read — the exact
	// instruction window in which a concurrent admission can take the bytes the
	// withdrawal is about to claim, and therefore the whole reason that swap is
	// a compare-and-swap rather than a subtraction.
	//
	// It exists because that window cannot be entered on purpose from the
	// outside. It is two instructions wide, so a test that hopes to land an
	// admission inside it is a coin flip, and this repository has measured
	// exactly that: against a withdrawLocked regressed to read-then-subtract,
	// the storm form of TestAllocator_Retune_RacesAdmission went red on 3 runs
	// in 10 on an ordinarily loaded 8-core host, and the arranged form on 0 in
	// 10. A test that parks the withdrawal here, performs the conflicting
	// admission, and only then releases it catches the same regression on every
	// run and on one core as readily as on eight — see
	// TestAllocator_Retune_LoweringLosesTheContestedPage.
	//
	// It is nil in every build; nothing outside a test ever sets it. The cost
	// is one predicted branch per iteration of a loop that already runs under
	// the retune mutex, and admission and release never reach it, so the
	// lock-free paths this type is built around are untouched.
	//
	// The other cost a reviewer reaches for is the struct, and it was measured
	// rather than argued: this allocator is 56 bytes without the field and 64
	// with it, free stays at offset 0 and limit at offset 8, and 64 bytes is
	// still one cache line. The two hot atomics do not move and nothing new
	// shares their line, so there is no false-sharing change to weigh.
	stalled func()
}

// NewAllocator returns an Allocator with the given total budget in LOCKED
// bytes — the same unit RLIMIT_MEMLOCK is expressed in, so the two can be
// compared directly.
//
// Size the budget in PAGES, not in the sizes of the things being protected.
// Every enclave occupies at least one whole page, so a budget meant to hold a
// hundred small credentials is a hundred pages; [LockedSize] computes the cost
// of one. A budget below a single page constructs successfully and then admits
// nothing, refusing each allocation with a [BudgetError] whose figures show
// why.
//
// Leave headroom below the process's RLIMIT_MEMLOCK ceiling: reaching it fails
// allocations process-wide, and locked memory is also consumed by any locked
// allocation outside this Allocator. Guard and canary pages are not
// part of that — they are mapped PROT_NONE and never mlock'd, so they cost
// address space and VMAs rather than locked memory.
//
// The budget is a starting point, not a fixed property: see [Allocator.SetLimit],
// [Allocator.ForceLimit] and [Allocator.TransferTo].
//
// It returns ErrInvalidBudget when maxBytes is not positive.
func NewAllocator(maxBytes int64) (*Allocator, error) {
	return newAllocator(maxBytes, false)
}

// newAllocator is the validated construction path, so the two exported
// constructors cannot drift apart on validation, on the zero-value contract, or
// on which fields a fresh allocator starts with. rlimitBound records whether the
// caller came through [NewAllocatorWithinRLimit]; see the field.
func newAllocator(maxBytes int64, rlimitBound bool) (*Allocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}
	return buildAllocator(maxBytes, rlimitBound), nil
}

// buildAllocator is the ONE place an Allocator's fields are initialized. It
// performs no validation: callers either validated the budget already
// ([newAllocator]) or derived it from the kernel's own reading, where a zero
// budget is the true answer rather than a mistake (the process default, whose
// ceiling may be an RLIMIT_MEMLOCK of zero). A zero budget is otherwise legal
// only at runtime, through [Allocator.SetLimit].
func buildAllocator(maxBytes int64, rlimitBound bool) *Allocator {
	a := &Allocator{id: allocatorIDs.Add(1), rlimitBound: rlimitBound}
	a.limit.Store(maxBytes)
	a.free.Store(maxBytes)
	return a
}

// ceilingForRaise reports the ceiling a raise on this allocator must fit under,
// and whether one applies at all.
//
// It returns a zero limit and a nil error for an allocator that never opted in,
// which is every [NewAllocator] one: those have no ceiling and must not acquire
// one, since a caller that chose the unchecked constructor chose it on purpose.
//
// The reading is taken FRESH on every call rather than cached at construction,
// and that is the point of the whole exercise. RLIMIT_MEMLOCK moves — a
// setrlimit from any thread, a container resized underneath the process — and a
// budget compared against a figure from startup would refuse a raise the kernel
// would now permit, or permit one it now would not. The cost is a getrlimit on
// a control-plane path that runs rarely; it is nowhere near the admission path,
// which still reads no ceiling at all.
//
// It is called BEFORE the retune mutex is taken, deliberately. A syscall under
// that lock would block every other retune and every [Allocator.InUse] reader
// for its duration. The reading can therefore go stale between here and the
// store that uses it — but a ceiling can move a nanosecond after any check,
// under any locking, so there is no version of this that is not a snapshot, and
// admission fails safe regardless.
//
// A discovery failure is returned as-is ([ErrLimitDiscoveryFailed]): nothing
// was compared, so the raise cannot be said to have passed.
func (a *Allocator) ceilingForRaise() (LockedMemoryLimit, error) {
	if !a.rlimitBound {
		return LockedMemoryLimit{}, nil
	}
	return DiscoverLockedMemoryLimit()
}

// New admits len(data) bytes against the budget and, if admitted, moves data
// into a new enclave whose Destroy returns the reservation.
//
// It takes ownership of data exactly as [NewMemoryEnclave] does — the slice is
// wiped before this returns, on every path including refusal and construction
// failure.
//
// Returns, all leaving the budget as it was found except where noted:
//   - ErrEmptyEnclave when data is empty (no reservation is taken);
//   - ErrBudgetExhausted (as a [BudgetError]) when the page-rounded cost of
//     len(data) would exceed the budget — decided before any locked memory is
//     requested, so no syscall is made;
//   - ErrLockedMemoryUnavailable if the kernel refuses the lock despite
//     admission. The reservation is released before returning — unless the
//     failed construction's own cleanup was refused too and left locked pages
//     behind, in which case the charge STAYS, because the process still holds
//     that memory and the budget must not offer it again. The error then
//     carries the cleanup failure alongside the original one, and the pages
//     are kept for [WipeAll], which returns the charge once it reclaims them.
//
// On success the returned enclave holds a reservation of [LockedSize](len(data))
// bytes — len(data) rounded up to a whole page — until its Destroy runs.
// Callers must Destroy every enclave New returns, exactly as for
// NewMemoryEnclave; the reservation leaks for the process lifetime otherwise.
func (a *Allocator) New(data []byte) (*MemoryEnclave, error) {
	if len(data) == 0 {
		// Match NewMemoryEnclave's contract: wipe the (empty) slice, take no
		// reservation, refuse. WipeBytes tolerates an empty slice.
		Wipe(data)
		return nil, ErrEmptyEnclave
	}

	n := int64(len(data))

	// n is at least 1 here, so the only refusal reserve can produce is a
	// BudgetError — which is why ErrInvalidSize is absent from this
	// constructor's documented returns.
	charge, err := a.reserve(n)
	if err != nil {
		// Wipe here too: admission failure is a terminal path for data, and the
		// ownership contract says nothing survives it.
		Wipe(data)
		return nil, err
	}

	// Unpublished: an enclave this constructor is still initializing must not be
	// reachable by WipeAll — see the publication note below.
	e, cerr := newMemoryEnclave(data)
	if cerr != nil {
		// Admission succeeded but the OS still refused (or the input was
		// rejected): release the reservation so the failure does not shrink
		// the budget permanently. data was already wiped by newMemoryEnclave.
		a.refundFailed(charge, cerr)
		return nil, cerr
	}

	e.release = func() { a.free.Add(charge) }

	// PUBLICATION IS THE LAST STATEMENT, and the reservation callback is
	// installed before it. Registering inside the constructor instead — where it
	// was until Codex caught it on PR #20 — published a half-initialized enclave:
	// a concurrent WipeAll could destroy it while release was still nil, which
	// races the assignment above AND hands the pages back to the kernel while the
	// budget keeps the charge, permanently. register's lock is also what
	// publishes the write above to a sweeping goroutine.
	return register(e), nil
}

// NewSized admits n bytes against the budget and, if admitted, returns an
// enclave over n bytes of locked, ZEROED memory whose Destroy returns the
// reservation.
//
// It is the admitted form of [NewMemoryEnclaveSized]: the caller fills the
// enclave in place through the borrow, so generated material never touches the
// ordinary heap. That constructor documents the fill pattern, the make-then-move
// shape it replaces, and the obligations that come with pages which stay
// writable — read it before using this.
//
// Admission is decided BEFORE any locked memory is requested, exactly as in
// [Allocator.New], so a refusal costs no syscall. A non-positive size is one of
// the things admission refuses, which is why no separate size check precedes it.
//
// Returns, all leaving the budget as it was found except where noted:
//   - ErrInvalidSize when n is a size no enclave can have — non-positive, or
//     too large to map (no reservation is taken);
//   - ErrBudgetExhausted (as a [BudgetError]) when the page-rounded cost of n
//     would exceed the budget;
//   - ErrLockedMemoryUnavailable if the kernel refuses the lock despite
//     admission. The reservation is released before returning unless the
//     cleanup left locked pages behind, exactly as for [Allocator.New].
//
// On success the returned enclave holds a reservation of [LockedSize](n) bytes
// — n rounded up to a whole page — until its Destroy runs, which callers must
// always call; the reservation leaks for the process lifetime otherwise.
func (a *Allocator) NewSized(n int) (*MemoryEnclave, error) {
	// Admission first, and it is admission that refuses a non-positive size:
	// see reserve. Nothing below this line can be reached by a size the mapping
	// layer would choke on.
	charge, err := a.reserve(int64(n))
	if err != nil {
		return nil, err
	}

	e, cerr := newMemoryEnclaveSized(n)
	if cerr != nil {
		// Admission succeeded but the OS still refused: release the reservation
		// so the failure does not shrink the budget permanently.
		a.refundFailed(charge, cerr)
		return nil, cerr
	}

	e.release = func() { a.free.Add(charge) }

	// Publication last, for the reason spelled out in New.
	return register(e), nil
}

// refundFailed returns a failed construction's charge to the budget — but only
// when the failure left no locked pages behind.
//
// A constructor that fails after mapping and locking rolls the mapping back, and
// that rollback can itself be refused: the kernel that just refused one thing is
// the kernel most likely to refuse the next. Refunding unconditionally then told
// the budget that memory was available which the process still held locked and
// had no handle left to release (#83) — so an allocator sized against
// RLIMIT_MEMLOCK would admit allocations the kernel could only refuse, the late,
// uncorrelated [ErrLockedMemoryUnavailable] admission control exists to prevent.
// The kept charge is refunded LATER, exactly once, when the pages finally go
// back. A failed constructor hands back no enclave to retry through, so the
// mapping goes onto the orphan ledger ([adoptOrphan]) with this refund attached,
// and the [WipeAll] sweep that releases it runs the refund and drops the record.
// Before #83 the mapping was dropped instead, and the charge was lost to the
// budget for the process lifetime even after the refusal lifted.
//
// The policy is NOT Destroy's, and differs in one case. Destroy keeps an
// enclave's reservation until the pages are UNMAPPED, since the enclave itself
// is the handle a retry goes through. Here the charge is kept only while the
// pages are still LOCKED: a cleanup that unlocked them and was then refused the
// munmap costs address space, not locked memory, so it is refunded at once and
// its orphan record carries no refund — a second one would return the charge
// twice.
//
// The answer comes from the mapping layer, which marks such failures with
// [pagesHeldError] and says whether the pages are still LOCKED; see
// [mapping.abandon] for what counts. Every other failure — a refused mmap, a
// refused mlock, a rollback that succeeded, a cleanup that unlocked the pages
// and was then refused the munmap — leaves nothing locked and is refunded in
// full.
func (a *Allocator) refundFailed(charge int64, cerr error) {
	if !lockedPagesHeld(cerr) {
		a.free.Add(charge)
		adoptOrphan(cerr, nil)
		return
	}
	adoptOrphan(cerr, func() { a.free.Add(charge) })
}

// allocSized returns an enclave over n bytes of locked, zeroed memory,
// admitted against a when one was supplied and unadmitted when a is nil.
//
// It exists so that a path which allocates locked memory can be made
// budget-aware by threading ONE parameter, without every allocation site
// growing its own nil branch — and, more importantly, without any of them
// silently choosing the unadmitted constructor. Every caller passes an
// allocator it was given, so nil here means the caller's own caller asked for
// the unbudgeted behavior.
//
// The nil case is deliberately NOT a refusal, unlike [ErrNilAllocator] at the
// public boundary: the refusal belongs at the entry point a caller chose,
// where "you asked for a budget and supplied none" is a statement about the
// call. Down here nil is the legitimate encoding of [SealedEnclave.Open]'s
// unbudgeted contract, which predates the Allocator and must keep working.
func allocSized(a *Allocator, n int) (*MemoryEnclave, error) {
	if a == nil {
		return NewMemoryEnclaveSized(n)
	}
	return a.NewSized(n)
}

// reserve claims n bytes of the budget, lock-free, and is the sole admission
// gate every constructor on this type goes through.
//
// It charges what the KERNEL will charge, not what the caller asked for: n is
// rounded up to a whole page by [lockedSize], and the rounded figure is what is
// reserved, reported and released. The two units are not interchangeable — a
// 32-byte enclave locks a full page — so a budget accounted in requested bytes
// cannot be compared to RLIMIT_MEMLOCK at all, which is the comparison the whole
// type exists to make. It returns the amount charged, which callers must hold on
// to: the release has to return exactly that, not n.
//
// A reservation is a POSITIVE number of bytes: a non-positive n is refused with
// ErrInvalidSize before the counter is touched. That is what keeps the free
// counter from being INFLATED by a bad reservation, which would let a concurrent
// caller admit against headroom that does not exist for as long as it was
// outstanding. And the compare-and-swap refuses rather than overshooting, so
// free never goes below zero on this path even transiently and two concurrent
// reservations can never both squeeze past the last free bytes.
//
// The predicate is `charge > free`, a comparison of two values with no
// arithmetic between them, and that is deliberate. Testing used+charge against a
// limit — the obvious form — overflows for a large enough request and wraps
// negative, which passes the test and admits an allocation the budget cannot
// possibly cover: a fail-open straight into the mapping layer, on the one path
// whose entire purpose is to keep an impossible request away from it.
// [Allocator.NewSized] takes its size from the caller as a plain int, so nothing
// upstream bounds it. Holding the REMAINING budget in a counter removes the
// addition, and with it that whole class of failure; the subtraction below
// cannot overflow either, since it only runs when charge is in (0, free].
//
// It returns ErrInvalidSize or a [BudgetError] on refusal and leaves the counter
// exactly as it found it; callers own whatever else a refusal implies for their
// arguments.
func (a *Allocator) reserve(n int64) (int64, error) {
	if n <= 0 {
		return 0, ErrInvalidSize
	}

	charge, ok := lockedSize(n)
	if !ok {
		// Not a size any enclave can have on this platform. That is a property
		// of the size, not of the budget — a larger limit would not help — so
		// it reports as ErrInvalidSize rather than as a refusal to admit.
		return 0, ErrInvalidSize
	}

	// This loop and [Allocator.withdrawLocked]'s are deliberately the same
	// shape and deliberately NOT the same function. The twin carries a test
	// seam ([Allocator.stalled]) because its window cannot be entered from
	// outside; factoring the two together would carry that branch onto THIS
	// path, which every allocation in the process goes through and which the
	// whole type is arranged to keep lock-free and syscall-free. If a shared
	// helper is ever worth it, the seam does not come with it.
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

// inUseFrom reports the locked bytes reserved, given a budget and the headroom
// counter that goes with it, and reports whether the pair could express it.
//
// The subtraction is not obviously safe, which is why it is a named function
// with its own tests rather than an expression at the call site. A CONSISTENT
// pair -- one read while no retune is moving either word -- always has free no
// greater than limit, since free is the limit minus everything reserved. The
// pairs the lock-free refusal path can actually hold are not always consistent,
// and there are two distinct ways for the result to come out negative.
//
// A WRAP. limit is always in [0, MaxInt64] — every path that writes it refuses
// a negative — but free goes NEGATIVE while an allocator is over-subscribed, and
// limit-free then exceeds int64 for a large enough limit. It wraps to a negative
// byte count. When free is negative the true result is greater than limit and
// therefore positive, while a wrapped one lands in [MinInt64, -2] — the sum
// cannot reach 2^64, so it can wrap at most once and can never come back around
// into the positives.
//
// A STALE HEADROOM. free was read before a LOWERING landed and limit after it,
// so free exceeds limit and the ordinary subtraction is negative with nothing
// wrapped at all: an empty allocator refusing a three-page request at two pages
// free, quiesced by SetLimit(0) between the two loads, pairs a limit of 0 with
// two pages of headroom. An earlier revision tested only for the wrap (free < 0)
// and reported that -2 pages as the bytes in use (#83).
//
// Both are figures that are not merely stale but impossible, and a consumer
// plotting one or deciding on it has no way to tell. Neither can be told apart
// from the other by the result, and neither needs to be: a reserved-byte count
// is never negative, so a negative result means the pair did not describe one
// state, whichever way it failed to. That is the whole test.
func inUseFrom(limit, free int64) (int64, bool) {
	used := limit - free
	if used < 0 {
		return 0, false
	}
	return used, true
}

// budgetSnapshot reports the (budget, bytes-reserved) pair that describes a
// refusal, given the headroom counter the refusal was decided on.
//
// Refusal is the only place admission reads the limit shadow, and it reads it
// only to describe what happened; the DECISION used free alone and is exact.
// The pair is not read atomically, so a retune landing between the two loads
// skews the figures by the size of that retune, which [BudgetError] documents.
//
// Skewed is tolerable. UNREPRESENTABLE is not, and the two are not the same
// thing. Two retunes can leave the lock-free reader holding a pair that
// describes no state the allocator was ever in:
//
//   - [Allocator.raiseLocked] stores the new limit before crediting free, so an
//     over-subscribed allocator being raised to a very large budget has a
//     window — a couple of instructions wide — in which a reader sees a huge
//     limit beside a still-negative free and computes a byte count that
//     wrapped.
//   - A LOWERING — [Allocator.SetLimit], [Allocator.ForceLimit] or a
//     [Allocator.TransferTo] out of this allocator — can land between the
//     refusal's load of free and its load of limit, so the free it was decided
//     on is larger than the limit it is quoted against and the difference is
//     negative without wrapping (#83). This one needs no over-subscription and
//     no extreme budget: quiescing an idle allocator is enough.
//
// [inUseFrom] reports both the same way, as a pair it cannot express, and
// outside a retune the pair is consistent and expressible.
//
// So the fallback takes the read lock, and ONLY there. It excludes retunes, so
// limit is pinned and free is the headroom that belongs to it, which makes
// limit-free exactly the bytes reserved — and representable and non-negative,
// since that difference is the reserved total and a reserved total is a
// non-negative int64 by construction. Because both windows are a few
// instructions wide and need a retune landing at that instant, the ordinary
// refusal — the one an unauthenticated flood drives, and the reason this path
// avoids syscalls and locks in the first place — stays lock-free.
func (a *Allocator) budgetSnapshot(free int64) (int64, int64) {
	limit := a.limit.Load()
	if inUse, ok := inUseFrom(limit, free); ok {
		return limit, inUse
	}

	a.mu.RLock()
	limit = a.limit.Load()
	free = a.free.Load()
	a.mu.RUnlock()

	// Representable by the argument above, so the second return is discarded
	// rather than handled: a branch here could not be reached, and an
	// unreachable branch cannot be verified by breaking it.
	inUse, _ := inUseFrom(limit, free)
	return limit, inUse
}

// InUse reports the locked bytes currently reserved through this Allocator,
// page-rounded as the kernel charges them rather than summed from the sizes
// callers asked for.
//
// It is derived, limit minus free, and the shared lock is what makes that
// subtraction exact rather than a torn pair: limit changes only under the
// exclusive lock, so holding the shared one pins it while free is read, and the
// result is precisely the bytes reserved at the instant free was sampled. The
// lock is not on the admission path — reserve and release never take it — so
// this costs concurrent allocation nothing.
//
// It is still a snapshot, useful for observability; do not build admission logic
// on it, as it can change between the read and any decision. The reservation the
// constructors take is atomic and is the only correct admission gate.
//
// It exceeds [Allocator.Limit] only after [Allocator.ForceLimit] deliberately
// lowered the budget beneath live reservations, and that caller was told the
// excess at the time. Nothing else can produce that state.
func (a *Allocator) InUse() int64 {
	// No overflow guard, for the same reason [Allocator.budgetSnapshot]'s
	// fallback needs none: the lock pins limit to the free that belongs to it,
	// so this difference is the reserved total rather than a skewed pair, and a
	// reserved total is an int64 by construction. The lock-free refusal path is
	// the one that has to defend against the skew.
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.limit.Load() - a.free.Load()
}

// Limit reports the Allocator's total budget in locked bytes, as last set by
// [NewAllocator], [Allocator.SetLimit], [Allocator.ForceLimit] or
// [Allocator.TransferTo].
func (a *Allocator) Limit() int64 { return a.limit.Load() }

// Available reports the locked bytes still admissible, clamped at zero. It is an
// upper bound on what can still be admitted, not a count: a remainder smaller
// than one page admits nothing. Like InUse it is
// a snapshot for observability, not an admission gate.
//
// The clamp is what hides an over-subscribed allocator's negative free counter,
// which is a state [Allocator.ForceLimit] can create; zero is the honest answer
// there, since nothing is admissible until reservations drain.
func (a *Allocator) Available() int64 {
	free := a.free.Load()
	if free < 0 {
		return 0
	}
	return free
}

// SetLimit changes the budget to newLimit locked bytes, refusing rather than
// shrinking below the memory already reserved.
//
// Raising always succeeds, and the new headroom is admissible immediately: an
// allocation refused a moment earlier will be admitted after this returns.
//
// Lowering succeeds only while the reservations already outstanding fit under
// newLimit. If they do not it returns a [LimitError] matching [ErrBudgetInUse]
// and changes NOTHING — the budget, the reservations and every live enclave are
// exactly as they were. That is the safe default because the reservations belong
// to enclaves this allocator does not own and must never invalidate to make a
// number fit; use [Allocator.ForceLimit] when the smaller ceiling is a fact to
// be recorded rather than a request to be granted.
//
// newLimit of zero is legal. LOWERING a positive budget to zero succeeds only
// when nothing is reserved — with live reservations it is a lowering below the
// bytes in use, so it returns [ErrBudgetInUse] and changes nothing, exactly as
// above. A budget that is ALREADY zero (after ForceLimit(0), say) is left as it
// is: a newLimit equal to the current budget changes nothing and returns nil,
// whatever is reserved. To stop admission while live enclaves keep working,
// use [Allocator.ForceLimit] with zero, which records the over-subscription
// and lets each Destroy return its reservation as usual. A negative newLimit
// returns [ErrInvalidBudget].
//
// It is safe to call concurrently with allocation, release and other retunes.
// A lowering and an in-flight admission are decided by the same compare-and-swap
// on the same word, so exactly one of them gets the contested bytes; see the
// [Allocator] free counter for why that is the whole argument.
//
// # RLIMIT_MEMLOCK, for an allocator that opted in
//
// An allocator built by [NewAllocatorWithinRLimit] carries that contract for
// life: a raise here re-reads the process's locked-memory ceiling and is
// REFUSED with [ErrBudgetExceedsRLimit], as an [RLimitError] naming both
// figures, when the new budget is above it. One built by [NewAllocator] never
// opted in and is never checked — a caller who chose the unchecked constructor
// chose it deliberately.
//
// The ceiling is read FRESH, not remembered from construction, because it
// moves: a setrlimit from any thread, a container resized underneath the
// process. A budget compared against a startup figure would refuse a raise the
// kernel now permits. So a ceiling that has genuinely gone UP is seen, and the
// raise it now allows succeeds. If the reading itself fails, the RAISE is
// refused with [ErrLimitDiscoveryFailed]: nothing was compared, so nothing
// passed.
//
// Only raises are checked, and that holds for a failed reading as firmly as for
// a successful one. A lowering is never refused on a ceiling — nor on the
// absence of one — because an allocator above the ceiling has to be able to
// move back towards it, and a host that stops answering getrlimit after
// construction must not be able to strand it up there.
//
// [Allocator.ForceLimit] overrides this, as it overrides every other refusal on
// this type. [Allocator.TransferTo] honors it on the allocator it credits.
//
// None of this makes the budget a promise. The ceiling is process-wide and
// shared, a cgroup may bind below it, and it can move again immediately;
// admission fails safe regardless, with [ErrLockedMemoryUnavailable] from the
// allocation that the kernel actually refused.
func (a *Allocator) SetLimit(newLimit int64) error {
	if newLimit < 0 {
		return ErrInvalidBudget
	}

	// Outside the lock, for the reason given on ceilingForRaise, and
	// unconditionally rather than only when this looks like a raise. Whether it
	// IS a raise is not known until old is read under the lock, and deciding it
	// out here on an unsynchronized read would let a concurrent retune turn a
	// lowering into a raise between the two, skipping the check entirely. A
	// wasted getrlimit on a lowering is the price of not having that hole.
	//
	// The failure is CARRIED rather than returned: discovering unconditionally
	// is what closes the race, but acting on the result unconditionally would
	// refuse lowerings too, which is a contract this method does not have. An
	// earlier revision of this branch returned cerr right here, and Codex caught
	// that it stranded an over-ceiling allocator on a host that had stopped
	// answering getrlimit — refusing the shrink that was the only way back to
	// compliance, in the name of a rule about raises.
	//
	// These two lines must therefore stay two lines. A test cannot defend them:
	// getrlimit does not fail on a healthy host, so cerr is always nil here and
	// a branch added on it is never taken during a test run. Measured — that
	// mutant survives the whole suite. What IS defended is the decision it feeds,
	// in checkRaise, and the parameterized entry point below that lets a test
	// supply the failure this one cannot produce.
	ceiling, cerr := a.ceilingForRaise()
	return a.setLimit(newLimit, ceiling, cerr)
}

// setLimit is [Allocator.SetLimit] with the ceiling reading supplied rather than
// taken, which is the only way the discovery-failure path can be reached in a
// test: getrlimit does not fail on a healthy host, and the case that matters —
// a sandbox installed after construction — cannot be produced from inside the
// process. It is a method rather than four lines inline for the same reason
// [LockedMemoryLimit.refuse] is one.
//
// cerr is the discovery failure, or nil. It is consulted ONLY on the raise
// branch, so a lowering still succeeds on a host that has stopped answering.
func (a *Allocator) setLimit(newLimit int64, ceiling LockedMemoryLimit, cerr error) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	old := a.limit.Load()
	switch {
	case newLimit > old:
		// Only a RAISE is checked. Refusing a lowering that is still above the
		// ceiling would block an over-subscribed allocator from moving TOWARDS
		// compliance — a forced 10 GiB budget under an 8 GiB ceiling could not
		// be set to 9 GiB — which is the opposite of what the contract is for.
		// That applies to a failed reading as much as to a successful one: an
		// allocator whose host stopped answering getrlimit must still be able
		// to shrink.
		if err := checkRaise(ceiling, cerr, newLimit); err != nil {
			return err
		}
		a.raiseLocked(old, newLimit)
	case newLimit < old:
		if !a.withdrawLocked(old - newLimit) {
			// Nothing was mutated: withdrawLocked either takes the whole
			// reduction or takes none of it.
			return &LimitError{
				Requested: newLimit,
				InUse:     old - a.free.Load(),
				Limit:     old,
			}
		}
		a.limit.Store(newLimit)
	}
	return nil
}

// ForceLimit changes the budget to newLimit locked bytes, accepting it even
// when the memory already reserved does not fit under it, and reports the
// resulting over-subscription.
//
// This is the contract for a ceiling that MOVED rather than one being chosen:
// the container was resized, RLIMIT_MEMLOCK was lowered under the process, the
// operator has decided this allocator's share is now smaller. Refusing would
// leave the allocator admitting against a budget the process no longer has.
//
// What it does NOT do is invalidate anything. Live enclaves keep their memory
// and their reservations, and each returns its own on Destroy exactly as
// before — only their owners may destroy them, and an allocator that tore them
// down to make room would be a far worse failure than the over-subscription.
// The allocator simply admits nothing further until enough of them drain, and
// [Allocator.Available] reports zero for as long as that lasts.
//
// It returns the excess: the locked bytes by which reservations exceed the new
// budget, or 0 when they fit and this behaved exactly like [Allocator.SetLimit].
// A caller that ignores it has not been told, which is why the figure is a
// return value and not something to be discovered later through
// [Allocator.InUse]. The excess is a snapshot taken as the change lands; a
// concurrent Destroy can reduce it a moment afterwards.
//
// newLimit of zero is legal and quiesces the allocator. A negative newLimit
// returns [ErrInvalidBudget], and in that case nothing is changed and the
// returned excess is 0.
//
// # It is the override, including for RLIMIT_MEMLOCK
//
// This method exists to do what [Allocator.SetLimit] refuses, and it is exempt
// from BOTH of that method's refusals rather than only the obvious one. It
// lowers beneath live reservations, and on an allocator built by
// [NewAllocatorWithinRLimit] it will also RAISE a budget above the process's
// locked-memory ceiling, without reading that ceiling at all.
//
// That is deliberate and is stated here so the contract is not mistaken for one
// that cannot be bypassed. An operator who knows the ceiling is about to be
// raised, or whose getrlimit is failing and who cannot wait for it, needs a way
// through, and a resource contract with no override is one people work around
// by abandoning the checked constructor entirely — which loses the check on
// every other path too. The override is explicit, it is named Force, and it is
// this one method.
//
// What it does not do is make the budget achievable. Raising above the ceiling
// buys nothing from the kernel; the allocations simply fail later with
// [ErrLockedMemoryUnavailable], which is exactly the late, uncorrelated failure
// [NewAllocatorWithinRLimit] exists to spare a service. Use it when you know
// something the ceiling does not.
func (a *Allocator) ForceLimit(newLimit int64) (int64, error) {
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
		// The unconditional counterpart of withdrawLocked: take the reduction
		// out of circulation whether or not the headroom was there, which is
		// what drives free negative and refuses every subsequent admission. Add
		// returns the value it wrote, so the excess below is the state this call
		// actually produced rather than a re-read that a concurrent Destroy
		// could have moved in between.
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

// TransferTo moves n locked bytes of HEADROOM from this Allocator's budget to
// dst's, in one operation.
//
// It is the rebalance a process needs when demand shifts between two bounded
// paths — a per-tenant seal barrier gaining a tenant while another loses one —
// and neither allocator is rebuilt: live enclaves on both sides are untouched
// and keep their reservations. After it returns, this allocator's Limit is n
// lower and dst's is n higher, and dst can immediately admit an allocation that
// n bytes of headroom makes possible.
//
// It refuses, changing nothing, when:
//   - n is not positive, dst is nil, or dst is this same allocator —
//     [ErrInvalidTransfer];
//   - this allocator does not have n bytes of headroom to give, because giving
//     it would put its budget below its own live reservations — a [LimitError]
//     matching [ErrBudgetInUse], with Requested reporting the budget this side
//     would have been left with. There is deliberately no forcing counterpart:
//     [Allocator.ForceLimit] records a ceiling that already moved, whereas
//     handing another allocator headroom this one cannot spare would create the
//     over-commit outright;
//   - dst's budget would overflow int64 — [ErrInvalidBudget];
//   - dst opted into the RLIMIT_MEMLOCK contract through
//     [NewAllocatorWithinRLimit] and the credit would take its budget above the
//     process's locked-memory ceiling — [ErrBudgetExceedsRLimit], as an
//     [RLimitError]; or the ceiling could not be read at all —
//     [ErrLimitDiscoveryFailed]. Only the DESTINATION is checked, since the
//     source's budget goes down and a shrinking budget needs no ceiling. See
//     [Allocator.SetLimit] for the contract; a transfer is a raise on the
//     receiving side and is treated as one.
//
// # Why two calls would not do
//
// Lowering this budget and raising dst's as separate calls leaves a window in
// which the bytes exist in BOTH allocators or in NEITHER, depending on the
// order. "Both" is the unsafe one: for the length of that window each side
// admits against the same locked bytes, and the process commits memory it
// cannot get — the exact over-commit admission control exists to prevent, and it
// surfaces later as [ErrLockedMemoryUnavailable] somewhere unrelated. So this
// takes the bytes out of the source FIRST and credits the destination second,
// and the intermediate state is always "in neither".
//
// That intermediate state is not eliminated — two independent counters cannot be
// updated by one atomic instruction, and pretending otherwise would mean a lock
// on the admission path, which would cost every allocation in the process to
// serve a rare rebalance. It is instead made CONSERVATIVE and made brief: for
// the few nanoseconds between the two atomics the pair of allocators can admit n
// bytes less than their combined budgets, and the worst outcome is a refusal a
// retry recovers from. No other retune can observe it at all, since both locks
// are held across the whole operation.
//
// # Lock ordering
//
// Two allocators plus a transfer is the textbook deadlock shape: A→B and B→A
// running at once, each holding what the other wants. Both mutexes are therefore
// acquired in a fixed TOTAL order — ascending [Allocator.id], the rank each
// allocator takes from a process-wide counter when it is constructed — so the
// two transfers above acquire the same lock first and one simply waits. A cycle
// in the wait-for graph needs two threads holding locks in opposite orders, and
// a total order over all allocators makes opposite orders unconstructible.
//
// The rank is a counter and not the obvious comparison of the two pointers
// because ordering by address requires converting through uintptr, which the
// language does not promise stays meaningful, and because a counter is stable,
// unique and legible in a panic trace. It is assigned once and never reused.
//
// Nothing else in this package holds two of these locks, and the lock-free
// paths — admission and release — take none, so a concurrent New or Destroy on
// either allocator cannot participate in a cycle and cannot be delayed by a
// transfer.
func (a *Allocator) TransferTo(dst *Allocator, n int64) error {
	if n <= 0 || dst == nil || dst == a {
		// The self-transfer check is a correctness guard, not tidiness: falling
		// through with dst == a would take the same non-reentrant mutex twice
		// and hang the caller instead of returning to it.
		return ErrInvalidTransfer
	}

	// Before either lock: this is a syscall when dst opted in, and holding two
	// retune mutexes across one would stall both allocators' observers.
	dstCeiling, cerr := dst.ceilingForRaise()
	return a.transferTo(dst, n, dstCeiling, cerr)
}

// transferTo is [Allocator.TransferTo] with the destination's ceiling reading
// supplied rather than taken, for the testing reason given on
// [Allocator.setLimit].
//
// Unlike setLimit this consults cerr unconditionally, because a transfer is
// always a raise on the receiving side; there is no lowering branch to spare.
func (a *Allocator) transferTo(dst *Allocator, n int64, dstCeiling LockedMemoryLimit, cerr error) error {
	first, second := a, dst
	if second.id < first.id {
		first, second = second, first
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	second.mu.Lock()
	defer second.mu.Unlock()

	// Validate the destination BEFORE debiting the source, so the impossible
	// case needs no compensating credit back. This is the reason the whole
	// operation is worth a lock: dst.limit is written only under dst.mu, which
	// is held here, so this check cannot be invalidated between here and the
	// store below.
	dstLimit := dst.limit.Load()
	if n > math.MaxInt64-dstLimit {
		return ErrInvalidBudget
	}
	// A transfer RAISES the destination's budget, so a destination that opted
	// into the RLIMIT_MEMLOCK contract is checked here exactly as it would be
	// in SetLimit. Leaving it out would have made a transfer the third entry
	// point to the same allocator with its own opinion about whether the
	// ceiling binds, which is the inconsistency #46 was filed about; a
	// destination is not less over the ceiling for having been pushed there by
	// a sibling rather than by a setter.
	//
	// The argument for leaving it out, recorded because it is a good one and is
	// still wrong: a transfer is process-CONSERVATIVE. It moves headroom rather
	// than creating it, so the process's total commitment is unchanged and the
	// kernel is no worse off than it was a moment ago. That would matter if the
	// ceiling check were process-wide accounting. It is not, and never was —
	// two allocators that each passed it can already sum to twice the ceiling,
	// because each was judged alone. What it asserts is that THIS budget by
	// itself was never satisfiable, and a destination carried over the ceiling
	// by a transfer is in precisely that state.
	//
	// Only the destination is checked: the source's budget goes DOWN, and a
	// shrinking budget needs no ceiling.
	if err := checkRaise(dstCeiling, cerr, dstLimit+n); err != nil {
		return err
	}

	srcLimit := a.limit.Load()
	if !a.withdrawLocked(n) {
		return &LimitError{
			Requested: srcLimit - n,
			InUse:     srcLimit - a.free.Load(),
			Limit:     srcLimit,
		}
	}

	// Source committed, destination not yet credited: the "in neither" window
	// argued above. Everything below this line is unconditional.
	a.limit.Store(srcLimit - n)
	dst.raiseLocked(dstLimit, dstLimit+n)
	return nil
}

// checkRaise reports the refusal a raise to newLimit earns against a ceiling
// reading, and nil when there is none. It is the whole decision the sticky
// RLIMIT_MEMLOCK contract makes, in one place so [Allocator.setLimit] and
// [Allocator.transferTo] cannot drift apart on it.
//
// A failed READING refuses the raise: nothing was compared, so nothing passed,
// and letting a raise through on a ceiling nobody could read would make the
// contract evaporate exactly when the host got strange. It is reported as the
// discovery error rather than as a budget verdict, because those are different
// answers — see [ErrLimitDiscoveryFailed] — and [Allocator.ForceLimit] is the
// way past it for a caller who knows better than the reading that would not
// come.
//
// An allocator that never opted in reaches here with a zero ceiling and a nil
// error, which refuses nothing: the zero [LockedMemoryLimit] is not Bounded.
func checkRaise(ceiling LockedMemoryLimit, cerr error, newLimit int64) error {
	if cerr != nil {
		return cerr
	}
	return ceiling.refuse(newLimit)
}

// raiseLocked grows the budget to newLimit and puts the difference into
// circulation. The caller must hold a.mu exclusively and must have established
// that newLimit > old; raising can never fail, since it only ever adds headroom.
//
// The shadow is stored BEFORE the counter is credited, and the order is not
// arbitrary. A lock-free observer computing InUse as limit-free between the two
// writes sees the new, larger limit against the old, smaller free, which
// OVERSTATES what is in use and understates what is available. The reverse order
// understates usage and advertises headroom that has not been granted yet.
// Everywhere this file writes both words it writes the pessimistic one first, so
// that a racing reader is never told there is more capacity than there is.
//
// The credit cannot overflow: free lands on newLimit minus the bytes reserved,
// both of which are within int64 by construction.
func (a *Allocator) raiseLocked(old, newLimit int64) {
	a.limit.Store(newLimit)
	a.free.Add(newLimit - old)
}

// withdrawLocked takes d bytes of headroom out of circulation, all or nothing,
// and reports whether it could. The caller must hold a.mu exclusively and d must
// be positive.
//
// This is the same compare-and-swap as [Allocator.reserve] and that is the
// point: a budget reduction competes for free bytes on exactly the terms an
// allocation does, against the same word, so a lowering that races an admission
// cannot double-spend the last page. The lock the caller holds serializes this
// against other RETUNES; it does nothing about admissions, and does not need to.
//
// It returns false without touching the counter when the headroom is not there,
// which is what makes [Allocator.SetLimit] and [Allocator.TransferTo] leave the
// allocator untouched on refusal. free is only read and compared here, never
// added to, so no arithmetic in this loop can overflow: d is positive and the
// subtraction runs only when d <= free.
func (a *Allocator) withdrawLocked(d int64) bool {
	for {
		free := a.free.Load()
		if d > free {
			return false
		}
		if a.stalled != nil {
			// The test seam described on [Allocator.stalled]: this is the
			// window a racing admission has to land in for the swap below to
			// matter, and it is nil everywhere but the test that parks here.
			a.stalled()
		}
		if a.free.CompareAndSwap(free, free-d) {
			return true
		}
	}
}
