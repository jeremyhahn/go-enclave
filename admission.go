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
	// ErrBudgetExhausted is the sentinel returned by [Allocator.New] when
	// admitting an allocation would push the total locked bytes held through
	// the allocator past its budget. Every [BudgetError] matches it, so this
	// is what callers test for. It is returned BEFORE any locked memory is
	// requested, so a refusal never reaches memguard and can never trigger the
	// process-wide purge described on [purgeMu].
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
	// Requested is the number of bytes the refused allocation asked for.
	Requested int64
	// InUse is the number of bytes already reserved when the refusal happened.
	// It is a snapshot: under concurrency the true figure may have moved by
	// the time this error is read.
	InUse int64
	// Limit is the allocator's total budget in bytes.
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
// It exists for one hazard: memguard aborts the process when it cannot lock
// pages, and before aborting it purges — unmaps — every live locked buffer in
// the process (see [purgeMu]). [NewMemoryEnclave] converts that abort into
// ErrLockedMemoryUnavailable, but it cannot undo the collateral destruction of
// unrelated enclaves. The only defense against the collateral damage is to not
// reach the ceiling. An Allocator lets a caller cap how much locked memory a
// path may hold, so that an untrusted or unauthenticated source cannot drive
// the process to its RLIMIT_MEMLOCK ceiling by making allocations.
//
// The motivating shape is a network responder that must buffer key material
// before it has authenticated the peer: a flood of half-open connections, each
// reserving a locked buffer, exhausts locked memory and triggers the purge,
// killing the key buffers of live, authenticated sessions. Sizing an
// Allocator's budget well below RLIMIT_MEMLOCK and admitting all pre-auth
// allocations through it converts that remote denial-of-service into a local,
// typed [ErrBudgetExhausted] on the abusive path, leaving live work untouched.
//
// Admission is checked before any locked memory is requested, so a refusal
// never itself triggers a purge. A reservation is held for exactly the
// lifetime of the enclave it backs: [MemoryEnclave.Destroy] returns it. The
// zero value is not usable; construct one with [NewAllocator]. An Allocator is
// safe for concurrent use, and its accounting is lock-free.
//
// # The obligation an Allocator does not remove
//
// An Allocator bounds the enclaves IT creates. It does not, and cannot, bound
// locked memory allocated elsewhere in the same process — a direct
// [NewMemoryEnclave] call, another Allocator, or any other memguard user. If
// any of those exhausts locked memory, memguard's purge still unmaps every
// live buffer in the process, including enclaves this Allocator created. An
// in-flight [MemoryEnclave.WithBytes] borrow is held safe across such a purge
// by [purgeMu]; what a caller must additionally tolerate is that an enclave it
// holds can report [ErrEnclaveDestroyed] from that point on, even though it
// never called Destroy. Code that keeps enclaves across untrusted allocation
// activity — exactly the code an Allocator is for — MUST treat
// ErrEnclaveDestroyed on unrelated in-flight work as a survivable runtime
// condition, not an invariant violation: re-establish the material or fail the
// one operation, never assume a live enclave stays live.
type Allocator struct {
	limit int64
	// used is the reserved-byte counter, mutated only by atomic add and CAS so
	// admission needs no lock. It can momentarily exceed nothing: New reserves
	// with a compare-and-swap that refuses rather than overshoots.
	used atomic.Int64
}

// NewAllocator returns an Allocator with the given total budget in bytes.
//
// It returns ErrInvalidBudget when maxBytes is not positive. Size the budget
// comfortably below the process's RLIMIT_MEMLOCK ceiling: the ceiling is what
// triggers memguard's purge, and locked memory is also consumed by guard and
// canary pages and by any locked allocation outside this Allocator.
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
//   - ErrBudgetExhausted (as a [BudgetError]) when admitting len(data) would
//     exceed the budget — decided before any locked memory is requested, so no
//     purge can result;
//   - ErrLockedMemoryUnavailable if the kernel refuses the lock despite
//     admission (the reservation is released before returning).
//
// On success the returned enclave holds a reservation of len(data) bytes until
// its Destroy runs. Callers must Destroy every enclave New returns, exactly as
// for NewMemoryEnclave; the reservation leaks for the process lifetime
// otherwise.
func (a *Allocator) New(data []byte) (*MemoryEnclave, error) {
	if len(data) == 0 {
		// Match NewMemoryEnclave's contract: wipe the (empty) slice, take no
		// reservation, refuse. WipeBytes tolerates an empty slice.
		Wipe(data)
		return nil, ErrEmptyEnclave
	}

	n := int64(len(data))

	// Reserve first, lock-free. CAS refuses rather than overshooting the
	// budget, so the counter never exceeds the limit even transiently and two
	// concurrent New calls can never both squeeze past the last free bytes.
	for {
		used := a.used.Load()
		if used+n > a.limit {
			// Wipe here too: admission failure is a terminal path for data,
			// and the ownership contract says nothing survives it.
			Wipe(data)
			return nil, &BudgetError{Requested: n, InUse: used, Limit: a.limit}
		}
		if a.used.CompareAndSwap(used, used+n) {
			break
		}
	}

	e, err := NewMemoryEnclave(data)
	if err != nil {
		// Admission succeeded but the OS still refused (or the input was
		// rejected): release the reservation so the failure does not shrink
		// the budget permanently. data was already wiped by NewMemoryEnclave.
		a.used.Add(-n)
		return nil, err
	}

	e.release = func() { a.used.Add(-n) }
	return e, nil
}

// InUse reports the bytes currently reserved through this Allocator. It is a
// snapshot, useful for observability; do not build admission logic on it, as
// it can change between the read and any decision. New's own reservation is
// atomic and is the only correct admission gate.
func (a *Allocator) InUse() int64 { return a.used.Load() }

// Limit reports the Allocator's total budget in bytes.
func (a *Allocator) Limit() int64 { return a.limit }

// Available reports limit minus in-use bytes, clamped at zero. Like InUse it is
// a snapshot for observability, not an admission gate.
func (a *Allocator) Available() int64 {
	free := a.limit - a.used.Load()
	if free < 0 {
		return 0
	}
	return free
}
