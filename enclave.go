// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrEmptyEnclave is returned when an enclave is requested for zero bytes
	// of material. An empty enclave protects nothing and is almost always a
	// sign that the caller lost the value it meant to protect.
	ErrEmptyEnclave = errors.New("enclave: refusing to create an enclave over empty material")

	// ErrEnclaveDestroyed is returned when a destroyed enclave is opened or
	// read. The locked pages have already been wiped and released.
	ErrEnclaveDestroyed = errors.New("enclave: enclave has been destroyed")

	// ErrInvalidSize is returned by [NewMemoryEnclaveSized] and
	// [Allocator.NewSized] for a size no enclave can have, and mirrors
	// [ErrInvalidBudget]: it reports a programming mistake rather than a
	// runtime condition.
	//
	// Two conditions produce it. A non-positive size, which has no mapping to
	// make. And a size too large to MAP: an enclave is the data region plus two
	// guard pages, sized as an int, so past a certain size that arithmetic
	// overflows and mmap would be handed a nonsense length — see [LockedSize],
	// which reports 0 for exactly these sizes. A bigger [Allocator] budget does
	// not help with either, which is why this is not ErrBudgetExhausted.
	//
	// It is deliberately distinct from [ErrEmptyEnclave]. That one reports a
	// caller that lost the material it meant to protect; this one reports a
	// caller that asked for an impossible allocation. Both are refused before
	// anything is mapped.
	ErrInvalidSize = errors.New("enclave: enclave size must be positive and small enough to map")

	// ErrLockedMemoryUnavailable is the sentinel for a refusal by the operating
	// system to allocate or lock the pages backing an enclave, which usually
	// means the process has reached its RLIMIT_MEMLOCK ceiling. Every
	// [LockedMemoryError] matches it, so this is what callers test for.
	ErrLockedMemoryUnavailable = errors.New("enclave: could not allocate locked memory")
)

// ErrReleasedWithoutWipe reports that an enclave's pages were returned to the
// kernel WITHOUT the in-process overwrite, because the mprotect that makes a
// frozen region writable was refused.
//
// The material is gone: the pages are unmapped, the kernel zeroes an anonymous
// page before any reuse, and they were mlock'd for their whole life so nothing
// reached swap. Nothing leaked. What it tells an operator is that something in
// the environment -- a seccomp filter, a sandbox -- is denying mprotect, which
// is worth knowing because the same denial reaches every other enclave in the
// process.
//
// It is deliberately NOT [ErrEnclaveCorrupted]: no memory was corrupted, and the
// invariant this package exists to hold -- material does not outlive its enclave
// -- was kept. [MemoryEnclave.Destroy] therefore does not panic on it.
var ErrReleasedWithoutWipe = errors.New("enclave: pages unmapped without an in-process wipe; mprotect was denied")

// UnwipedReleaseError reports a release that fell back to unmapping because the
// mprotect making the region writable was refused. It carries that refusal.
//
// Match on [ErrReleasedWithoutWipe]; errors.Is reports it for every
// UnwipedReleaseError.
type UnwipedReleaseError struct {
	// Cause is the mprotect failure that forced the fallback.
	Cause error
}

// Error implements error.
func (e *UnwipedReleaseError) Error() string {
	if e.Cause == nil {
		return ErrReleasedWithoutWipe.Error()
	}
	return ErrReleasedWithoutWipe.Error() + ": " + e.Cause.Error()
}

// Is reports every UnwipedReleaseError as ErrReleasedWithoutWipe.
func (e *UnwipedReleaseError) Is(target error) bool {
	return target == ErrReleasedWithoutWipe
}

// Unwrap returns the underlying mprotect failure so errors.As can reach it.
func (e *UnwipedReleaseError) Unwrap() error { return e.Cause }

// LockedMemoryError reports that the pages backing an enclave could not be
// allocated or locked.
//
// It carries the failure the kernel reported, which names the failing address
// and the errno — what separates an RLIMIT_MEMLOCK ceiling from any other
// mapping failure. That detail is worth keeping for an operator, but it is
// diagnostic rather than contract. Match on [ErrLockedMemoryUnavailable];
// errors.Is reports it for every LockedMemoryError.
type LockedMemoryError struct {
	// Cause is the underlying mmap, mlock or mprotect failure, and nil when
	// none was reported. It is an any for compatibility with releases before
	// v0.3.0-alpha, where it carried whatever memguard panicked with; every
	// value this package produces now is an error, so errors.As reaches it.
	Cause any
}

// Error implements error.
func (e *LockedMemoryError) Error() string {
	if e.Cause == nil {
		return ErrLockedMemoryUnavailable.Error()
	}
	return ErrLockedMemoryUnavailable.Error() + ": " + fmt.Sprint(e.Cause)
}

// Is reports every LockedMemoryError as ErrLockedMemoryUnavailable, so callers
// match the sentinel and never have to know about this type.
func (e *LockedMemoryError) Is(target error) bool {
	return target == ErrLockedMemoryUnavailable
}

// Unwrap returns the cause when it is an error, so errors.As can reach the
// underlying mmap/mlock/mprotect failure, and nil otherwise.
func (e *LockedMemoryError) Unwrap() error {
	if err, ok := e.Cause.(error); ok {
		return err
	}
	return nil
}

// MemoryEnclave is a region of locked, zeroized memory holding sensitive
// material for its whole lifetime.
//
// The zero value is not usable; construct one with NewMemoryEnclave or
// NewMemoryEnclaveFromString to bring existing material in, or with
// NewMemoryEnclaveSized to generate material directly into locked memory.
// A nil *MemoryEnclave is a valid receiver for
// every method: it reports itself as not alive, opens with
// ErrEnclaveDestroyed, and destroys as a no-op, so callers holding an
// optional enclave do not need nil guards at every use.
//
// A MemoryEnclave is safe for concurrent use through WithBytes, OpenString,
// EqualTo, Size, IsAlive, String and Destroy: each holds the enclave's lock
// across the whole access, so Destroy waits out in-flight readers rather than
// unmapping pages underneath them. Open is the one exception — it hands back a
// slice that outlives the lock, and its documentation says so.
type MemoryEnclave struct {
	mu sync.RWMutex
	m  *mapping

	// release, when non-nil, returns this enclave's reservation to the
	// [Allocator] that created it. Destroy invokes it exactly once, via
	// releaseOnce, after the pages have been released. It is nil for enclaves
	// constructed directly with NewMemoryEnclave or NewMemoryEnclaveFromString,
	// which hold no reservation.
	release     func()
	releaseOnce sync.Once
}

// NewMemoryEnclave moves data into a new locked region and returns the
// enclave holding it.
//
// It TAKES OWNERSHIP of data: the caller's slice is wiped before this returns,
// so there is no unprotected copy left behind. That is the right default and
// should stay the common case. Callers that cannot give up their buffer have
// [NewMemoryEnclaveCopy], which leaves the source intact — and by keeping it
// they accept an unprotected copy, which is exactly what this type exists to
// avoid. Material that has not been produced yet should skip both and be
// generated straight into locked pages with [NewMemoryEnclaveSized].
//
// It returns ErrEmptyEnclave when data is empty, and
// ErrLockedMemoryUnavailable when the kernel refuses to lock the pages.
//
// A successful return can hand back an ALREADY-DESTROYED enclave, in exactly one
// situation: [WipeAll] ran between this enclave's publication and this return,
// and destroyed it. The enclave is valid and every method behaves as documented
// for a destroyed one — it reports itself not alive and opens with
// ErrEnclaveDestroyed — so nothing is unsafe, but a caller that constructs
// concurrently with a shutdown sweep must check rather than assume. Constructing
// during a sweep is a consumer ordering problem; see WipeAll.
func NewMemoryEnclave(data []byte) (*MemoryEnclave, error) {
	e, err := newMemoryEnclave(data)
	if err != nil {
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclave builds the enclave WITHOUT publishing it to the shutdown
// ledger, so a caller with further initialization to do — [Allocator.New],
// installing the reservation callback — can finish before [WipeAll] can reach
// it. Publication is that caller's last statement; see [register].
func newMemoryEnclave(data []byte) (*MemoryEnclave, error) {
	// The caller's slice is wiped on EVERY return path, which is what the
	// ownership contract above promises — including the mapping-failure path,
	// where nothing was copied out and the material would otherwise survive in
	// the caller's memory on exactly the resource-exhaustion case this
	// constructor exists to handle. Wiping again after a successful move is a
	// no-op over already-zeroed bytes. It is also a no-op for the empty slice
	// newMemoryEnclaveCopy refuses, which is why this defer can precede the
	// refusal rather than being repeated after it.
	defer wipe(data)

	// The move constructor IS the copy constructor plus this wipe. Composing
	// them rather than writing the mapping sequence twice is deliberate: the
	// two differ in exactly one dimension — who owns the source — and a second
	// copy of the freeze-and-clean-up dance is how that stops being true. It is
	// the same divergence the duplicated hand-rolled composition in consumers
	// was heading for (#29).
	return newMemoryEnclaveCopy(data)
}

// NewMemoryEnclaveCopy copies src into a new locked region and returns the
// enclave holding it, leaving src UNTOUCHED on every path — success, refusal
// and mapping failure alike.
//
// It is the counterpart to [NewMemoryEnclave], which takes ownership and wipes
// what it is handed. Prefer that one: it leaves nothing behind. This exists for
// the callers that legitimately cannot honor it — a buffer owned by someone
// else that the consumer must not modify, a fixture handed back on every call,
// material compared against the bytes it was built from. Without it those
// callers hand-roll [NewMemoryEnclaveSized] plus WithBytes plus a Destroy on
// the error path, which is easy to get subtly wrong: omitting that Destroy
// leaks a locked page on a path nobody tests.
//
// # What the caller is accepting
//
// An UNPROTECTED copy of the material stays on the ordinary Go heap for as long
// as the caller keeps src — swappable, core-dumpable, and beyond the reach of
// any later wipe, since the compiler and the garbage collector may already have
// copied it elsewhere. That is precisely what this type exists to avoid, and
// this constructor does not undo it. It protects the copy it puts inside the
// enclave and makes no claim whatsoever about the source; nothing here can wipe
// src later either, because only the caller knows when it is done with it, and
// [Wipe] is the most that can be done to heap memory anyway.
//
// So the choice is between two honest positions. Material that should never be
// on the heap at all does not belong here: generate it directly into locked
// pages with [NewMemoryEnclaveSized], the one shape where no unprotected copy
// ever exists. Material that already exists outside an enclave and can be given
// up belongs in [NewMemoryEnclave]. Reach for this constructor only when the
// source genuinely has to survive, and wipe it yourself as soon as it does not.
//
// # Mutability
//
// The result is FROZEN read-only, exactly like [NewMemoryEnclave]'s and unlike
// [NewMemoryEnclaveSized]'s. There is nothing left to fill — the material is
// complete when this returns — so writable pages would buy nothing and would
// cost the protection against a stray write through a retained
// [MemoryEnclave.Open] slice. This is stated rather than left to be inferred
// because the existing constructors disagree, so a caller generalizes from
// whichever it met first, and because guessing wrong is not an error: a write
// through a frozen enclave FAULTS the process.
//
// It returns ErrEmptyEnclave when src is empty, and ErrLockedMemoryUnavailable
// when the kernel refuses to lock the pages — the same refusals as the other
// constructors. Like [NewMemoryEnclave], a successful return can hand back an
// already-destroyed enclave if [WipeAll] ran between publication and return;
// see that constructor.
func NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error) {
	e, err := newMemoryEnclaveCopy(src)
	if err != nil {
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclaveCopy is the body both constructors share, without the
// publication step, for the same reason [newMemoryEnclave] exists.
//
// It never touches src. Everything that wipes a source lives in the caller, so
// there is exactly one place in this package that can, and adding a third
// constructor cannot accidentally acquire the behavior.
func newMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error) {
	if len(src) == 0 {
		return nil, ErrEmptyEnclave
	}

	m, err := newMapping(len(src))
	if err != nil {
		return nil, err
	}

	copy(m.data, src)

	// Freeze once the material is in: from here a write through a retained
	// slice faults rather than corrupting the enclave. This covers BOTH
	// constructors that bring existing material in, which is why a copy-built
	// enclave is read-only too. A sized enclave cannot be frozen at all — it
	// exists to be filled — which is the one behavioral difference between
	// bringing material in and generating it in place; see
	// [NewMemoryEnclaveSized].
	//
	// A freeze failure means an mprotect was refused, and the same refusal is
	// likely to meet the cleanup below. That is survivable in the way that
	// matters: freeze failing leaves the region WRITABLE, so release wipes the
	// material with no syscall before it attempts anything that can be denied.
	// What can still fail is handing the pages back, and that is reported
	// rather than dropped — an unreleasable mapping the caller is told about is
	// a resource leak, one it is not told about is an invisible one.
	if ferr := m.freeze(); ferr != nil {
		if rerr := m.release(); rerr != nil {
			return nil, errors.Join(ferr, rerr)
		}
		return nil, ferr
	}

	return &MemoryEnclave{m: m}, nil
}

// NewMemoryEnclaveSized returns an enclave over n bytes of locked, ZEROED
// memory for the caller to fill IN PLACE.
//
// It exists so that generated material — a freshly drawn key, a derived
// wrapping key, a Shamir share — never exists on the ordinary Go heap, not
// even transiently. Produce it inside the borrow, where the slice aliases the
// locked pages themselves:
//
//	e, err := enclave.NewMemoryEnclaveSized(32)
//	if err != nil {
//	    return err
//	}
//	defer e.Destroy()
//
//	err = e.WithBytes(func(key []byte) error {
//	    _, err := io.ReadFull(rand.Reader, key) // straight into locked memory
//	    return err
//	})
//
// Do NOT use the make-then-move shape this constructor exists to replace:
//
//	tmp := make([]byte, 32)               // WRONG. The key lands on the
//	io.ReadFull(rand.Reader, tmp)         // swappable, core-dumpable heap
//	e, err := enclave.NewMemoryEnclave(tmp) // first, and the wipe that
//	                                        // follows cannot reach copies the
//	                                        // compiler or the collector has
//	                                        // already made of it.
//
// [NewMemoryEnclave] is for material that already exists outside an enclave and
// has to be brought in. When the material is about to be produced, produce it
// here instead.
//
// # Mutability
//
// The pages of an enclave built by NewMemoryEnclave are frozen read-only once
// the material has moved in; the pages behind a sized enclave stay WRITABLE for
// its whole lifetime, because that is what makes filling them possible. Two
// obligations follow.
//
// The fill must complete before the enclave is shared with other goroutines:
// WithBytes takes the read lock, so borrows run concurrently with each other,
// and two of them writing is a data race like any other. And a slice retained
// past the borrow that produced it can silently CORRUPT the material of a sized
// enclave, where the same mistake against a NewMemoryEnclave enclave would
// fault. Never retain what a borrow hands you.
//
// It returns ErrInvalidSize for a size no enclave can have — non-positive, or
// too large to map — and ErrLockedMemoryUnavailable when the kernel refuses to
// map or lock the pages. Both size refusals are decided before anything is
// mapped, so an impossible size never reaches the kernel.
//
// This constructor takes no [Allocator], so that size check is the only thing
// standing between a caller's arithmetic and mmap. What it is NOT, since
// v0.3.0-alpha, is the only thing standing between a caller and a process-wide
// purge: go-enclave maps its own memory and nothing can purge it, so a failure
// here fails this call and touches no other enclave.
//
// Like [NewMemoryEnclave], a successful return can hand back an already-destroyed
// enclave if [WipeAll] ran between publication and return. See that constructor.
func NewMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
	e, err := newMemoryEnclaveSized(n)
	if err != nil {
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclaveSized is [NewMemoryEnclaveSized] without the publication step,
// for the same reason [newMemoryEnclave] exists.
func newMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
	if _, ok := lockedSize(int64(n)); !ok {
		return nil, ErrInvalidSize
	}

	m, err := newMapping(n)
	if err != nil {
		return nil, err
	}

	return &MemoryEnclave{m: m}, nil
}

// NewMemoryEnclaveFromString copies s into a new locked region.
//
// Go strings are immutable and cannot be wiped, so the source string survives
// in unprotected heap memory until it is collected. This constructor exists
// only for the boundary with APIs that hand out strings — configuration
// loaders, flag parsers — and callers with a []byte must prefer
// NewMemoryEnclave, which leaves nothing behind.
func NewMemoryEnclaveFromString(s string) (*MemoryEnclave, error) {
	return NewMemoryEnclave([]byte(s))
}

// withLocked runs fn against the material while HOLDING the read lock, so the
// pages cannot be wiped or unmapped underneath fn: Destroy takes the write
// lock and therefore waits out every in-flight reader. Every access path that
// promises concurrency safety goes through here.
//
// fn must not call any method on the same enclave. The read lock is held for
// the duration of the call, so a nested Destroy deadlocks, and a nested read
// deadlocks whenever a Destroy is already waiting for the write lock.
//
// fn MAY construct, destroy and borrow OTHER enclaves. Until v0.3.0-alpha it
// could not: a process-wide lock serialized every allocation against every
// borrow, so allocating inside a live borrow deadlocked, and a caller holding a
// key across a call that allocates had no way to write the code. That lock
// existed to keep memguard's process-wide purge from unmapping these pages
// mid-read; go-enclave now owns its own mapping and nothing can purge it, so the
// lock is gone and so is the restriction.
func (e *MemoryEnclave) withLocked(fn func([]byte) error) error {
	if e == nil {
		return ErrEnclaveDestroyed
	}

	// This enclave's own lock is now the whole story: only its Destroy can
	// release these pages, and Destroy takes the write lock, so it waits out
	// every in-flight reader.
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.m == nil {
		return ErrEnclaveDestroyed
	}

	return fn(e.m.data)
}

// Open returns a read-only view of the material inside the locked region.
//
// UNSAFE. The returned slice aliases the locked pages and is covered by NO
// lock once this returns. A concurrent Destroy on this enclave unmaps it, and a
// read through it then faults the process rather than returning an error.
//
// There are TWO such destroyers, and the second one is not obvious: this
// enclave's own Destroy, and [WipeAll], which destroys every live enclave in the
// process. A retained Open slice will SIGSEGV if a shutdown sweep runs while the
// caller still holds it — no lock is held to prevent that. Callers that use Open
// must therefore establish that neither can run concurrently, which for WipeAll
// means the slice does not outlive the caller's own shutdown ordering.
//
// What can no longer unmap it: before v0.3.0-alpha any failed allocation
// anywhere in the process could, through memguard's process-wide purge. That is
// gone — WipeAll is called deliberately, never triggered by a fault.
//
// It is not a write path either, and how it fails depends on the constructor:
// the pages of an enclave built by NewMemoryEnclave are frozen read-only, so a
// write there faults, while a sized enclave's pages stay writable and a stray
// write silently CORRUPTS the material instead of announcing itself. See
// [NewMemoryEnclaveSized].
//
// Prefer WithBytes, OpenString or EqualTo, which hold the read lock across the
// whole access and make Destroy wait. Open remains for callers that can
// establish from their own structure that no Destroy can run concurrently —
// single-goroutine setup code, or a value the caller alone owns — and the
// slice must never be retained past that window.
func (e *MemoryEnclave) Open() ([]byte, error) {
	if e == nil {
		return nil, ErrEnclaveDestroyed
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.m == nil {
		return nil, ErrEnclaveDestroyed
	}

	return e.m.data, nil
}

// OpenString returns the material as a string.
//
// This deliberately materializes an UNPROTECTED copy that cannot be wiped, and
// exists only for the boundary with legacy APIs that take plain strings (for
// example a backend settings map[string]string). Materialize as late as
// possible, and never store the result. Prefer WithBytes everywhere else.
//
// The copy is taken under the read lock, so it is safe against a concurrent
// Destroy.
func (e *MemoryEnclave) OpenString() (string, error) {
	var s string
	if err := e.withLocked(func(b []byte) error {
		s = string(b)
		return nil
	}); err != nil {
		return "", err
	}
	return s, nil
}

// WithBytes calls fn with a view of the material and returns fn's error. The
// view is valid only for the duration of the call; fn must not retain it, and
// must not call back into the same enclave. This is the preferred way to
// consume an enclave, because it scopes the borrow to the call and holds the
// read lock across it — a concurrent Destroy blocks until fn returns instead
// of unmapping the pages fn is using.
//
// It is also how an enclave from [NewMemoryEnclaveSized] is FILLED: the view
// aliases the locked pages themselves, so material generated into it is never
// anywhere else. The view is read-only in practice for every enclave built
// from existing material, whose pages are frozen read-only; a sized enclave's
// stay writable, with the obligations documented on that constructor.
func (e *MemoryEnclave) WithBytes(fn func([]byte) error) error {
	return e.withLocked(fn)
}

// Size reports the number of bytes held, or 0 once destroyed.
func (e *MemoryEnclave) Size() int {
	if e == nil {
		return 0
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.m == nil {
		return 0
	}

	return len(e.m.data)
}

// IsAlive reports whether the locked region still holds material.
func (e *MemoryEnclave) IsAlive() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.m != nil
}

// EqualTo reports whether the enclave holds exactly other, comparing in
// constant time under the read lock.
//
// A destroyed or nil enclave reports false. That is deliberate and it is
// FAIL-CLOSED for the shape this is nearly always used in —
// `if e.EqualTo(secret) { grant() }` — but it means false carries two different
// facts: the material did not match, and there was no material to compare.
// Callers that need to tell those apart, or that invert the test, must use
// [MemoryEnclave.EqualToErr]; inverting this one treats a destroyed enclave as
// a mismatch, which is the opposite of fail-closed.
func (e *MemoryEnclave) EqualTo(other []byte) bool {
	equal, err := e.EqualToErr(other)
	return err == nil && equal
}

// EqualToErr reports whether the enclave holds exactly other, distinguishing a
// comparison that ran and said no from one that could not run at all.
//
// It returns [ErrEnclaveDestroyed] for a destroyed or nil enclave, where
// [MemoryEnclave.EqualTo] returns a bare false. "I compared them and they
// differ" and "there was nothing to compare" are different answers, and a
// caller that acts on the first when it was handed the second is acting on a
// fact it does not have. That collapse is invisible at the call site precisely
// because the safe-looking spelling is the common one.
//
// The comparison itself is constant time and runs under the read lock, so a
// concurrent Destroy waits rather than unmapping the pages mid-compare.
func (e *MemoryEnclave) EqualToErr(other []byte) (bool, error) {
	equal := false
	if err := e.withLocked(func(b []byte) error {
		equal = subtle.ConstantTimeCompare(b, other) == 1
		return nil
	}); err != nil {
		return false, err
	}
	return equal, nil
}

// Destroy zeroizes the material and releases the locked region. It is
// idempotent and safe on a nil enclave, so it can always be deferred.
//
// It takes the write lock, so it BLOCKS until every in-flight WithBytes,
// OpenString or EqualTo has returned. Nothing is wiped or unmapped while a
// reader still holds a view obtained through those methods. A slice taken
// from Open is outside that guarantee — see Open.
//
// # When the canary fails
//
// Releasing the pages verifies the canary sitting ahead of the data. If it
// does not match, something wrote into memory it did not own — a buffer
// underflow through a retained slice, or corruption from elsewhere in the
// process — and Destroy PANICS with [ErrEnclaveCorrupted] after wiping and
// releasing everything it holds.
//
// A panic from a foundational library is close to never right, and this is the
// exception the rest of the package is built to avoid: detected memory
// corruption is not a condition a caller can handle, because the state the
// caller would act on is the state that is wrong. The material is wiped and the
// pages are returned before the panic, so nothing leaks either way. It is also
// what this method already did before v0.3.0-alpha — memguard's canary check
// called core.Panic — except that it no longer destroys every other enclave in
// the process on its way out.
func (e *MemoryEnclave) Destroy() {
	// The non-fatal report is discarded here and only here. Destroy is the
	// deferable form and cannot return anything; DestroyErr is the same teardown
	// with the report kept, exactly as EqualToErr is EqualTo with the reason
	// kept. A caller that cares whether the environment is denying the
	// wipe-enabling mprotect must use that one.
	_ = e.DestroyErr()
}

// DestroyErr is [MemoryEnclave.Destroy] with its non-fatal report returned
// rather than discarded.
//
// It returns [ErrReleasedWithoutWipe] when the pages had to be handed back with
// a bare unmap because the mprotect that makes a frozen region writable was
// refused. Nothing leaked -- the pages are gone and the kernel zeroes an
// anonymous page before reuse -- but the denial reaches every other enclave in
// the process, and `defer e.Destroy()` is the pattern this library is used
// through, so without this the only signal that a sandbox has removed part of
// the teardown contract is invisible on the main path.
//
// It returns nil for an ordinary release, and PANICS on detected corruption for
// the reasons given on Destroy: that is the one condition a caller cannot act
// on, because the state it would act on is the state that is wrong.
func (e *MemoryEnclave) DestroyErr() error {
	if e == nil {
		return nil
	}

	err := e.releaseMapping()

	// The reservation goes back only once the PAGES have. A corrupted canary
	// still counts as released — the region was wiped and unmapped, and the
	// error is a report about what already happened — but a failed unlock or
	// unmap does not: the kernel still holds those pages, and telling the
	// allocator they are available would let it admit allocations the process
	// cannot satisfy. releaseOnce keeps the accounting exact across the retry.
	if e.release != nil && releasedPages(err) {
		e.releaseOnce.Do(e.release)
	}

	// Off the registry once the pages are actually gone. A release that failed
	// leaves it registered so a later WipeAll still tries.
	if releasedPages(err) {
		deregister(e)
	}

	// ErrReleasedWithoutWipe is NOT a panic. The pages are gone and nothing
	// leaked; what it reports is a denied mprotect in the environment, which is
	// an operator's problem and not a state a caller cannot reason about. Only
	// detected corruption keeps the panic, because there the state a caller
	// would act on is the state that is wrong.
	if err != nil && !errors.Is(err, ErrReleasedWithoutWipe) {
		panic(err)
	}

	return err
}

// releasedPages reports whether err came back with the pages actually returned
// to the kernel. Three cases qualify: a clean release, a failed canary (a report
// about what already happened), and a release that fell back to unmapping
// because mprotect was denied. Everything else means the region is still mapped.
//
// It exists so the handle-drop, the reservation return and the deregistration
// cannot answer this question differently -- three copies of one predicate drift,
// and the failure mode is an enclave that is alive over freed memory.
func releasedPages(err error) bool {
	return err == nil ||
		errors.Is(err, ErrEnclaveCorrupted) ||
		errors.Is(err, ErrReleasedWithoutWipe)
}

// releaseMapping wipes, verifies and unmaps the pages under the write lock, and
// is idempotent. It is the memory half of Destroy, split out so Destroy can run
// the reservation release and the panic in the right order around it.
//
// The handle is dropped only when the pages are actually gone. If the region
// could not be unmapped — or could not be made writable, so it was never wiped —
// the enclave KEEPS its mapping: the memory is still resident, and discarding
// the only reference to it would strand it for the process lifetime with no way
// to retry. The enclave still reports itself alive in that case, which is the
// truth, and a caller that recovers from the panic can call Destroy again to
// retry the release.
func (e *MemoryEnclave) releaseMapping() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.releaseLocked()
}

// tryReleaseMapping is releaseMapping without the wait: released is false and
// nothing is done if the lock is unavailable, instead of blocking until it is.
//
// The lock it tries for is the WRITE lock, so it loses to any concurrent
// READER, not merely to a long WithBytes borrow — an IsAlive, a Size and an
// EqualTo all take the read lock, and each is enough to make this report false.
// Callers must therefore treat false as "not right now", never as "cannot be
// released": [WipeAll] retries on its next pass for exactly this reason.
//
// It exists for WipeAll, which must not hang a shutdown behind a goroutine that
// is still reading. Nothing else should use it — an ordinary Destroy is supposed
// to wait its turn.
func (e *MemoryEnclave) tryReleaseMapping() (released bool, err error) {
	if !e.mu.TryLock() {
		return false, nil
	}
	defer e.mu.Unlock()
	return true, e.releaseLocked()
}

// releaseLocked is the body both paths share. The caller holds e.mu.
func (e *MemoryEnclave) releaseLocked() error {
	if e.m == nil {
		return nil
	}

	err := e.m.release()
	// Drop the handle exactly when the PAGES are gone. Two errors are returned
	// with the memory already released -- a failed canary, and a release that
	// fell back to unmapping because mprotect was denied -- and keeping the
	// mapping for either would leave the enclave reporting itself alive over
	// memory the kernel has taken back, which is a use-after-free waiting for a
	// reader. Every other error means the region is still mapped, so the handle
	// is kept and Destroy can be retried.
	if err != nil && !errors.Is(err, ErrEnclaveCorrupted) && !errors.Is(err, ErrReleasedWithoutWipe) {
		return err
	}
	e.m = nil
	return err
}

// String masks the contents. It exists so that an enclave reached by an
// accidental %v or %s — a log line, a struct dump — cannot spill the material
// it protects.
func (e *MemoryEnclave) String() string {
	if !e.IsAlive() {
		return "MemoryEnclave(destroyed)"
	}
	return "MemoryEnclave(redacted)"
}

// Wipe overwrites b with zeroes. It is for callers that must hand plain bytes
// to an API outside this package and want the transient copy cleared as soon
// as that API returns.
//
// It is a best-effort measure on ordinary heap memory and nothing more: the
// bytes were swappable and core-dumpable for as long as they existed, and the
// compiler or the garbage collector may already have copied them somewhere this
// cannot reach. Prefer never materializing them — see [NewMemoryEnclaveSized]
// for generating material directly into locked memory instead.
func Wipe(b []byte) {
	wipe(b)
}
