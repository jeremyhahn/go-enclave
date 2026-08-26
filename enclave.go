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
// so there is no unprotected copy left behind. Callers that need to keep the
// original bytes must copy them first — and by doing so accept an unprotected
// copy, which is exactly what this type exists to avoid.
//
// It returns ErrEmptyEnclave when data is empty, and
// ErrLockedMemoryUnavailable when the kernel refuses to lock the pages.
func NewMemoryEnclave(data []byte) (*MemoryEnclave, error) {
	if len(data) == 0 {
		return nil, ErrEmptyEnclave
	}

	// The caller's slice is wiped on EVERY return path, which is what the
	// ownership contract above promises — including the mapping-failure path,
	// where nothing was copied out and the material would otherwise survive in
	// the caller's memory on exactly the resource-exhaustion case this
	// constructor exists to handle. Wiping again after a successful move is a
	// no-op over already-zeroed bytes.
	defer wipe(data)

	m, err := newMapping(len(data))
	if err != nil {
		return nil, err
	}

	copy(m.data, data)

	// Freeze once the material is in: from here a write through a retained
	// slice faults rather than corrupting the enclave. A sized enclave cannot
	// do this, which is the one behavioral difference between the two
	// constructors — see [NewMemoryEnclaveSized].
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
func NewMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
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
// borrow, so allocating inside a live borrow deadlocked, and consumers holding
// a key across a call that allocates had no way to write the code (issue #2,
// go-qrdb #74/#145). That lock existed to keep memguard's process-wide purge
// from unmapping these pages mid-read; go-enclave now owns its own mapping and
// nothing can purge it, so the lock is gone and so is the restriction.
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
// read through it then faults the process rather than returning an error. That
// is now the ONLY way it can be unmapped underneath the caller: before
// v0.3.0-alpha any failed allocation anywhere in the process could do it too,
// through memguard's process-wide purge.
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
// constant time under the read lock. A destroyed or nil enclave equals
// nothing.
func (e *MemoryEnclave) EqualTo(other []byte) bool {
	equal := false
	if err := e.withLocked(func(b []byte) error {
		equal = subtle.ConstantTimeCompare(b, other) == 1
		return nil
	}); err != nil {
		return false
	}
	return equal
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
	if e == nil {
		return
	}

	err := e.releaseMapping()

	// The reservation goes back only once the PAGES have. A corrupted canary
	// still counts as released — the region was wiped and unmapped, and the
	// error is a report about what already happened — but a failed unlock or
	// unmap does not: the kernel still holds those pages, and telling the
	// allocator they are available would let it admit allocations the process
	// cannot satisfy. releaseOnce keeps the accounting exact across the retry.
	if e.release != nil && (err == nil || errors.Is(err, ErrEnclaveCorrupted)) {
		e.releaseOnce.Do(e.release)
	}

	if err != nil {
		panic(err)
	}
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

	if e.m == nil {
		return nil
	}

	err := e.m.release()
	if err != nil && !errors.Is(err, ErrEnclaveCorrupted) {
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
