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

	"github.com/awnumar/memguard"
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
	// [Allocator.NewSized] for a non-positive size, and mirrors
	// [ErrInvalidBudget]: asking for zero or fewer bytes of locked memory is a
	// configuration or programming mistake rather than a runtime condition.
	//
	// It is deliberately distinct from [ErrEmptyEnclave]. That one reports a
	// caller that lost the material it meant to protect; this one reports a
	// caller that asked for an impossible allocation. Both are refused before
	// memguard is entered, because memguard's own answer to a size below one is
	// a dead buffer rather than an error.
	ErrInvalidSize = errors.New("enclave: enclave size must be positive")

	// ErrLockedMemoryUnavailable is the sentinel for a refusal by the operating
	// system to allocate or lock the pages backing an enclave, which usually
	// means the process has reached its RLIMIT_MEMLOCK ceiling. Every
	// [LockedMemoryError] matches it, so this is what callers test for.
	ErrLockedMemoryUnavailable = errors.New("enclave: could not allocate locked memory")
)

// LockedMemoryError reports that the pages backing an enclave could not be
// allocated or locked.
//
// It carries the cause memguard reported before it would have aborted the
// process. That detail names the failing address and the kernel's errno, which
// is what separates an RLIMIT_MEMLOCK ceiling from any other allocation
// failure — worth keeping for an operator, but diagnostic rather than
// contract. Match on [ErrLockedMemoryUnavailable]; errors.Is reports it for
// every LockedMemoryError.
type LockedMemoryError struct {
	// Cause is the value memguard panicked with. It is an any because that is
	// what recover yields, and nil when the allocation failed without panicking.
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

// Unwrap returns the cause when memguard panicked with an error value, so
// errors.As can reach it, and nil otherwise.
func (e *LockedMemoryError) Unwrap() error {
	if err, ok := e.Cause.(error); ok {
		return err
	}
	return nil
}

// purgeMu serializes memguard ALLOCATION against every borrow in this process.
//
// It exists because memguard's failure path is process-wide. When it cannot
// allocate or lock pages it calls core.Panic, which calls core.Purge first
// (memguard v0.23.0 core/exit.go:84-87); Purge takes a snapshot of every live
// buffer and destroys each one, and destroy() ends in memcall.Free — the pages
// are UNMAPPED, not merely wiped (core/buffer.go:225). Purge holds only
// memguard's own key and registry locks, so it cannot see, and does not wait
// for, any MemoryEnclave's mutex.
//
// A per-enclave lock therefore cannot make a borrow safe: goroutine A can be
// inside WithBytes on one enclave, holding a slice into its locked pages,
// while goroutine B exhausts locked memory constructing an unrelated enclave
// and unmaps A's pages underneath it. That is a fault, not an error return.
//
// Allocation takes this lock exclusively and every borrow takes it shared, so
// no purge can begin while any borrow is live, and no borrow can begin while
// an allocation that might purge is in flight. Borrows still run concurrently
// with each other; only allocation is exclusive, and allocation is a setup-time
// operation.
var purgeMu sync.RWMutex

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
	mu     sync.RWMutex
	buffer *memguard.LockedBuffer

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
	// ownership contract above promises. memguard.NewBufferFromBytes moves and
	// wipes its source only after it has successfully allocated a locked
	// buffer, so on the allocation-failure and recovered-panic paths the
	// secret would otherwise survive in the caller's memory — on exactly the
	// resource-exhaustion path this constructor exists to handle. Wiping again
	// after a successful move is a no-op over already-zeroed bytes.
	defer memguard.WipeBytes(data)

	return lockedEnclave(func() *memguard.LockedBuffer {
		return memguard.NewBufferFromBytes(data)
	})
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
// memguard freezes the pages of an enclave built by NewMemoryEnclave once the
// material has moved in; the pages behind a sized enclave stay WRITABLE for its
// whole lifetime, because that is what makes filling them possible. Two
// obligations follow.
//
// The fill must complete before the enclave is shared with other goroutines:
// WithBytes takes the read lock, so borrows run concurrently with each other,
// and two of them writing is a data race like any other. And a slice retained
// past the borrow that produced it can silently CORRUPT the material of a sized
// enclave, where the same mistake against a NewMemoryEnclave enclave would
// fault. Never retain what a borrow hands you.
//
// It returns ErrInvalidSize when n is not positive, decided before memguard is
// entered, and ErrLockedMemoryUnavailable when the kernel refuses to lock the
// pages.
func NewMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
	if n <= 0 {
		return nil, ErrInvalidSize
	}

	return lockedEnclave(func() *memguard.LockedBuffer {
		return memguard.NewBuffer(n)
	})
}

// lockedEnclave allocates through alloc and wraps the result. It is the single
// point at which this package enters memguard's allocator, so every constructor
// inherits the same three guarantees.
//
// The allocation is serialized against every live borrow: memguard purges and
// UNMAPS every live buffer in the process before it panics, so an attempt that
// might fail must not overlap a borrow in another goroutine (see purgeMu).
//
// memguard's abort is converted into a typed error. It aborts the process when
// it cannot allocate, lock or protect the pages it needs, and a foundational
// library must not kill its host over an RLIMIT_MEMLOCK ceiling it does not
// control. memguard purges every live locked buffer before panicking and
// documents recovery from that panic as safe; the cost is that other enclaves
// in the process are destroyed and will report ErrEnclaveDestroyed from that
// point on.
//
// A buffer that comes back dead without a panic — memguard's answer to an
// invalid size — is reported as ErrLockedMemoryUnavailable rather than handed
// out. Constructors reject such sizes before calling here, so in practice this
// is the belt to the callers' braces.
func lockedEnclave(alloc func() *memguard.LockedBuffer) (e *MemoryEnclave, err error) {
	purgeMu.Lock()
	defer purgeMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			e = nil
			err = &LockedMemoryError{Cause: r}
		}
	}()

	buffer := alloc()
	if !buffer.IsAlive() {
		return nil, &LockedMemoryError{}
	}

	return &MemoryEnclave{buffer: buffer}, nil
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
// fn must not construct, destroy, or borrow ANY enclave, not merely this one.
// Allocation and Destroy take purgeMu exclusively while a borrow holds it
// shared, and Go's RWMutex blocks new readers once a writer is queued — so a
// nested borrow of a second enclave deadlocks against an allocation that
// started after the outer borrow. Materialize what you need first, then
// borrow.
func (e *MemoryEnclave) withLocked(fn func([]byte) error) error {
	if e == nil {
		return ErrEnclaveDestroyed
	}

	// purgeMu first, then the enclave's own lock — always this order, so the
	// two can never deadlock against each other. purgeMu keeps a
	// process-wide memguard purge from unmapping these pages mid-read; e.mu
	// keeps this enclave's own Destroy from doing the same.
	purgeMu.RLock()
	defer purgeMu.RUnlock()

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.buffer == nil || !e.buffer.IsAlive() {
		return ErrEnclaveDestroyed
	}

	return fn(e.buffer.Bytes())
}

// Open returns a read-only view of the material inside the locked region.
//
// UNSAFE. The returned slice aliases the locked pages and is covered by NO
// lock once this returns. Two separate things can unmap it underneath the
// caller: a concurrent Destroy on this enclave, and — with no Destroy involved
// at all — a process-wide memguard purge triggered by any failed allocation
// anywhere in the process (see purgeMu). Either way a read through the slice
// faults the process rather than returning an error.
//
// It is not a write path either, and how it fails depends on the constructor:
// memguard freezes the pages of an enclave built by NewMemoryEnclave, so a
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

	if e.buffer == nil || !e.buffer.IsAlive() {
		return nil, ErrEnclaveDestroyed
	}

	return e.buffer.Bytes(), nil
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
// from existing material, whose pages memguard has frozen; a sized enclave's
// stay writable, with the obligations documented on that constructor.
func (e *MemoryEnclave) WithBytes(fn func([]byte) error) error {
	return e.withLocked(fn)
}

// Size reports the number of bytes held, or 0 once destroyed.
func (e *MemoryEnclave) Size() int {
	if e == nil {
		return 0
	}

	// Size is len(buffer.Bytes()) inside memguard, so it reads a slice header
	// a concurrent purge rewrites. Coordinate it like any other read.
	purgeMu.RLock()
	defer purgeMu.RUnlock()

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.buffer == nil || !e.buffer.IsAlive() {
		return 0
	}

	return e.buffer.Size()
}

// IsAlive reports whether the locked region still holds material.
func (e *MemoryEnclave) IsAlive() bool {
	if e == nil {
		return false
	}

	purgeMu.RLock()
	defer purgeMu.RUnlock()

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.buffer != nil && e.buffer.IsAlive()
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
func (e *MemoryEnclave) Destroy() {
	if e == nil {
		return
	}

	// Destroy is an ALLOCATION-CLASS operation, not a read: memguard's
	// Buffer.Destroy calls core.Panic when releasing the pages fails
	// (core/buffer.go:180-183), and Panic purges the whole process. So it takes
	// purgeMu exclusively, like NewMemoryEnclave, and in the same order —
	// purgeMu then e.mu — so the two can never deadlock.
	e.destroyBuffer()

	// Return the Allocator reservation, if any, exactly once — after the pages
	// are released, and on EVERY call so a caller that defers Destroy always
	// frees its budget: on a second Destroy, and after a collateral memguard
	// purge that wiped the buffer without passing through this method (see
	// purgeMu). releaseOnce makes the accounting exact under either.
	if e.release != nil {
		e.releaseOnce.Do(e.release)
	}
}

// destroyBuffer zeroizes and unmaps the locked pages under the allocation-class
// lock ordering (purgeMu then e.mu), and is idempotent. It is the buffer half
// of Destroy, split out so Destroy can always run the reservation release even
// when the buffer is already gone.
func (e *MemoryEnclave) destroyBuffer() {
	purgeMu.Lock()
	defer purgeMu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.buffer == nil {
		return
	}

	e.buffer.Destroy()
	e.buffer = nil
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
func Wipe(b []byte) {
	memguard.WipeBytes(b)
}
