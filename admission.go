// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package enclave

import (
	"errors"
	"fmt"
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
	ErrInvalidBudget = errors.New("enclave: allocator budget must be positive")
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
type Allocator struct {
	limit int64
	// used is the reserved-byte counter, mutated only by atomic add and CAS so
	// admission needs no lock. It can momentarily exceed nothing: New reserves
	// with a compare-and-swap that refuses rather than overshoots.
	used atomic.Int64
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
// It returns ErrInvalidBudget when maxBytes is not positive.
func NewAllocator(maxBytes int64) (*Allocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}
	return &Allocator{limit: maxBytes}, nil
}

// New admits len(data) bytes against the budget and, if admitted, moves data
// into a new enclave whose Destroy returns the reservation.
//
// It takes ownership of data exactly as [NewMemoryEnclave] does — the slice is
// wiped before this returns, on every path including refusal and construction
// failure.
//
// Returns, all leaving the budget as it was found:
//   - ErrEmptyEnclave when data is empty (no reservation is taken);
//   - ErrBudgetExhausted (as a [BudgetError]) when the page-rounded cost of
//     len(data) would exceed the budget — decided before any locked memory is
//     requested, so no syscall is made;
//   - ErrLockedMemoryUnavailable if the kernel refuses the lock despite
//     admission (the reservation is released before returning).
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
		a.used.Add(-charge)
		return nil, cerr
	}

	e.release = func() { a.used.Add(-charge) }

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
// Returns, all leaving the budget as it was found:
//   - ErrInvalidSize when n is a size no enclave can have — non-positive, or
//     too large to map (no reservation is taken);
//   - ErrBudgetExhausted (as a [BudgetError]) when the page-rounded cost of n
//     would exceed the budget;
//   - ErrLockedMemoryUnavailable if the kernel refuses the lock despite
//     admission (the reservation is released before returning).
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
		a.used.Add(-charge)
		return nil, cerr
	}

	e.release = func() { a.used.Add(-charge) }

	// Publication last, for the reason spelled out in New.
	return register(e), nil
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
// It owns the counter's two invariants, and together they keep used within
// [0, limit] — which the admission predicate below then depends on.
//
// A reservation is a POSITIVE number of bytes: a non-positive n is refused with
// ErrInvalidSize before the counter is touched, so it can never be driven below
// zero, which would otherwise let a concurrent caller admit against an inflated
// budget for as long as the bad reservation was outstanding. And the
// compare-and-swap refuses rather than overshooting, so the counter never
// exceeds the limit even transiently and two concurrent reservations can never
// both squeeze past the last free bytes.
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

	for {
		used := a.used.Load()

		// Compare the charge against the REMAINING budget rather than testing
		// used+charge against the limit. That addition overflows for a large
		// enough request and wraps negative, which passes a `used+n > limit`
		// test and admits an allocation the budget cannot possibly cover — a
		// fail-open straight into the mapping layer, on the one path whose
		// entire purpose is to keep an impossible request away from it.
		// [Allocator.NewSized] takes the size from the caller as a plain int,
		// so nothing upstream bounds it.
		//
		// This form cannot overflow: used is in [0, limit] by the invariants
		// above, so limit-used is in [0, limit], and charge is already
		// positive. The CAS below is safe for the same reason — admitting
		// charge means charge <= limit-used, hence used+charge <= limit.
		if charge > a.limit-used {
			return 0, &BudgetError{Requested: charge, InUse: used, Limit: a.limit}
		}
		if a.used.CompareAndSwap(used, used+charge) {
			return charge, nil
		}
	}
}

// InUse reports the locked bytes currently reserved through this Allocator,
// page-rounded as the kernel charges them rather than summed from the sizes
// callers asked for. It is a
// snapshot, useful for observability; do not build admission logic on it, as
// it can change between the read and any decision. The reservation the
// constructors take is atomic and is the only correct admission gate.
func (a *Allocator) InUse() int64 { return a.used.Load() }

// Limit reports the Allocator's total budget in locked bytes.
func (a *Allocator) Limit() int64 { return a.limit }

// Available reports limit minus in-use locked bytes, clamped at zero. It is an
// upper bound on what can still be admitted, not a count: a remainder smaller
// than one page admits nothing. Like InUse it is
// a snapshot for observability, not an admission gate.
func (a *Allocator) Available() int64 {
	free := a.limit - a.used.Load()
	if free < 0 {
		return 0
	}
	return free
}
