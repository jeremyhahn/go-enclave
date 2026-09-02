// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math"
	"os"
	"runtime"

	"github.com/awnumar/memcall"
)

// This file owns go-enclave's memory: it maps, locks, guards, wipes and
// releases every page the package hands out.
//
// # Why this is not memguard
//
// go-enclave used memguard's LockedBuffer until v0.3.0-alpha. The layout below
// is deliberately the same one — guard pages either side of an mlock'd inner
// region, a random canary in the slack ahead of the data, wipe and verify on
// release — because that design is sound and well reviewed. What changed is the
// FAILURE POLICY, and it could not be changed from the outside.
//
// memguard registers every buffer in a process-global list and, on any mapping
// failure, calls core.Panic: Purge() first, which destroys and UNMAPS every
// live buffer in the process, then panic. A library whose whole purpose is to
// hold key material safely cannot have "some unrelated allocation failed" mean
// "your key's pages are gone". go-enclave converted the panic into a typed
// error from v0.1.0-alpha, but a recover cannot undo a purge that already ran —
// so it also needed purgeMu, a process-wide lock serializing every allocation
// against every borrow, whose cost was that allocating inside a live borrow
// deadlocked — a shape real consumers had no way to write around.
//
// Owning the mapping removes the mechanism instead of guarding it. There is no
// registry, so nothing can purge these pages; every failure is a returned
// error; and purgeMu is gone because there is no longer anything for it to
// serialize. The reasoning: mapping memory is not cryptography, and a library
// whose whole purpose is locked memory should own that discipline rather than
// inherit someone else's failure policy for it.

// coreDumpErr records whether the process-wide core-dump hardening took. It is
// written once, from init, before any goroutine can observe it.
var coreDumpErr = memcall.DisableCoreDumps()

// protectMemory is memcall.Protect behind a package-private seam so a test can
// deny the release-path mprotect and observe what the code does about it.
//
// Unexported and never assigned outside this package's own tests, so nothing
// downstream can swap a syscall out from under a security primitive. It exists
// because the condition it models -- a seccomp filter refusing mprotect -- is
// not reachable any other way from a unit test, and the behavior under it is
// exactly what #12 is about: without the fallback the material stays resident
// for the process lifetime.
var protectMemory = memcall.Protect

// unmapDirectFn is unmapDirect behind the same kind of package-private seam, so
// a test can deny the fallback as well and pin what happens when BOTH the wipe
// path and the bypass are refused. Never assigned outside this package's tests.
var unmapDirectFn = unmapDirect

// CoreDumpsDisabled reports whether this package succeeded in disabling core
// dumps process-wide at import, returning the failure if it did not.
//
// A core dump writes a process's memory to disk in plaintext, locked pages
// included, so this is real hardening rather than housekeeping. It is applied at
// two levels and this reports only the first:
//
//   - PROCESS-WIDE, by lowering RLIMIT_CORE to zero on import. It is best
//     effort: a sandbox or seccomp filter can deny setrlimit, and anything else
//     in the process can raise the limit again afterwards, so no library can
//     promise it. That is what this function exposes, so an application whose
//     threat model requires it can assert it rather than assume it.
//
//   - PER MAPPING, by marking every enclave's pages MADV_DONTDUMP as they are
//     locked. That one is NOT best effort: it is verified, and a failure fails
//     the allocation with [ErrLockedMemoryUnavailable] rather than handing back
//     an enclave whose pages could reach disk. On platforms with no per-mapping
//     equivalent there is nothing to verify and this function is the only
//     signal available.
//
// Constructors do not consult this. A host that cannot lower RLIMIT_CORE still
// gets mlock, the guard pages, the canary and — on Linux — the per-mapping
// exclusion, and refusing to build an enclave at all would remove those too.
func CoreDumpsDisabled() error { return coreDumpErr }

// pageSize is both the locked-memory accounting unit and the mapping's
// granularity. The kernel charges RLIMIT_MEMLOCK in whole pages and mmap works
// in whole pages, so everything here rounds to it. Read once: it cannot change
// for a running process.
var pageSize = int64(os.Getpagesize())

// maxInt is the largest value of type int on this platform, and therefore the
// ceiling a whole mapping has to fit under.
const maxInt = int64(^uint(0) >> 1)

// ErrEnclaveCorrupted reports that an enclave's canary did not verify when its
// memory was released, which means something wrote into the slack region ahead
// of the data — a buffer underflow, or memory corruption from elsewhere in the
// process.
//
// It is the one condition this package treats as unrecoverable. See
// [MemoryEnclave.Destroy] for what happens when it is detected and why.
var ErrEnclaveCorrupted = errors.New("enclave: canary verification failed; memory ahead of the enclave was overwritten")

// LockedSize reports how much locked memory an enclave of n bytes actually
// consumes, which is n rounded UP to a whole page.
//
// Callers need this to size an [Allocator] budget, because the kernel's unit
// and the caller's are not the same one. An enclave of 32 bytes occupies a
// full page — measured against /proc/self/status VmLck, 4096 bytes on a
// 4 KiB-page host — so a budget meant to hold a hundred small credentials must
// be a hundred PAGES, not a hundred times thirty-two bytes. Without this the
// correct budget is folklore.
//
// Only the data region is charged. Each enclave is fenced by two guard pages,
// but those are mapped PROT_NONE and never mlock'd, so they cost address space
// and VMAs rather than locked memory — verified against the kernel's own
// accounting, not inferred from the mapping code.
//
// It returns int64 to match [NewAllocator]'s budget, so sizing a budget from it
// needs no conversion: NewAllocator(100 * LockedSize(32)) type-checks as
// written, and the conversion it removes sits exactly where a truncation would
// bite.
//
// It returns 0 when n is not a size any enclave can have — see [ErrInvalidSize]
// for what that covers.
func LockedSize(n int) int64 {
	locked, ok := lockedSize(int64(n))
	if !ok {
		return 0
	}
	return locked
}

// lockedSize reports the locked memory an enclave of n bytes consumes — n
// rounded up to a whole page — and whether such an enclave can be mapped here
// at all.
//
// Three conditions, and each one is a fault or a corrupt mapping if it is
// missed.
//
// n must be positive: there is no zero-byte mapping to make.
//
// The rounding must not overflow. The obvious form, n+pageSize-1 masked down,
// overflows for a large enough n and wraps NEGATIVE — the same shape as the
// admission fail-open fixed in PR #3, and it would reach mmap with a nonsense
// length. Dividing first cannot overflow for n >= 1, and the multiplication
// back is guarded.
//
// And the whole MAPPING must be representable, not just the locked part. The
// allocation is the data region plus two guard pages, sized as an int, so a
// size whose data region rounds representably can still overflow once the guard
// pages are added. The guard pages cost no LOCKED memory — they are PROT_NONE
// and never mlock'd, so they stay out of the charge — but they are part of the
// mapping, and it is the mapping that has to fit.
func lockedSize(n int64) (int64, bool) {
	if n <= 0 {
		return 0, false
	}
	pages := (n-1)/pageSize + 1
	if pages > math.MaxInt64/pageSize {
		return 0, false
	}
	locked := pages * pageSize
	if locked > maxInt-2*pageSize {
		return 0, false
	}
	return locked, true
}

// mapping is one guarded, locked allocation: a region of mlock'd pages holding
// the caller's data, fenced on both sides by inaccessible guard pages and
// preceded by a random canary.
//
// The layout, for a request of n bytes:
//
//	| preguard | canary … data | postguard |
//	|<- page ->|<-- innerLen ->|<- page  ->|
//
// innerLen is n rounded up to a whole page, and data sits at the END of it, so
// the first byte past the data is the postguard — an overflow past the end
// faults immediately rather than corrupting anything. The slack ahead of the
// data holds the canary, which cannot fault (it is readable, writable memory),
// so an underflow into it is detected at release instead. The same canary bytes
// are copied into both guard pages before they are made inaccessible, which is
// what lets release check that the guards themselves were not remapped.
//
// A mapping is not safe for concurrent use; [MemoryEnclave] provides the
// locking around it.
type mapping struct {
	// memory is the whole allocation. Every other field is a sub-slice of it.
	memory []byte
	// data is the caller-visible region.
	data []byte
	// inner is the mlock'd region: canary plus data, a whole number of pages.
	inner []byte
	// preguard and postguard are the inaccessible pages either side of inner.
	preguard  []byte
	postguard []byte
	// canary is the slack ahead of data, filled with random bytes and verified
	// on release. It is EMPTY when the requested size is an exact multiple of
	// the page size, because there is no slack — see newMapping.
	canary []byte
	// mutable records whether inner is currently writable, so freeze is
	// idempotent and release knows it has to restore write access first.
	mutable bool
	// corrupted records a failed canary, so release can finish unmapping and
	// still report it afterwards rather than having to choose between the two.
	corrupted bool
	// wiped records that the material is GONE while the pages are still held.
	//
	// It exists for the failed-release path: when the wipe succeeded but the
	// munlock or munmap that follows was refused, the mapping is deliberately
	// KEPT so the caller can retry -- and without this flag it then read as a
	// perfectly ordinary live enclave. IsAlive said true, Size said 21, Open
	// handed back 21 bytes of zeroes, and both guard pages had been left
	// READ-WRITE by the release path, so the guards were off as well.
	//
	// A caller that recovers from Destroy's panic and READS rather than
	// re-Destroying would then derive from an all-zero secret with no guard
	// protection, and nothing would say so. The pages being retained is the
	// truth about the MAPPING; it was never the truth about the ENCLAVE.
	wiped bool
}

// newMapping allocates, locks and guards a region for size bytes, and returns
// it mutable and zeroed.
//
// Every failure path returns a typed [LockedMemoryError] and releases whatever
// it had already taken — a mapping that could not be locked is never left
// mapped, and no other enclave in the process is affected. That is the whole
// difference from memguard, which aborts the process instead and unmaps every
// live buffer on its way out.
//
// size must already have been validated by [lockedSize]; callers do that so
// they can report an impossible size as ErrInvalidSize rather than as a
// mapping failure.
func newMapping(size int) (*mapping, error) {
	innerLen, ok := lockedSize(int64(size))
	if !ok {
		return nil, ErrInvalidSize
	}
	total := int(innerLen) + 2*int(pageSize)

	// mmap gives back zeroed pages, and memcall wipes them again before
	// returning, so the region is zeroed on arrival. Nothing here needs to
	// zero it a second time.
	memory, err := memcall.Alloc(total)
	if err != nil {
		return nil, &LockedMemoryError{Cause: err}
	}

	page := int(pageSize)
	inner := memory[page : page+int(innerLen) : page+int(innerLen)]
	m := &mapping{
		memory:    memory,
		inner:     inner,
		preguard:  memory[0:page:page],
		postguard: memory[page+int(innerLen) : total : total],
		// data sits at the end of inner so that the byte after it is the
		// postguard.
		data:    inner[len(inner)-size : len(inner) : len(inner)],
		canary:  inner[0 : len(inner)-size : len(inner)-size],
		mutable: true,
	}

	locked := false
	// Lock before anything sensitive can be written, so the pages are never
	// swappable while they hold material. This is the call that fails when the
	// process is at its RLIMIT_MEMLOCK ceiling.
	if err := memcall.Lock(m.inner); err != nil {
		return nil, m.abandon(err, locked)
	}
	locked = true

	// Keep these pages out of any core dump, and CHECK that it took. memcall's
	// Lock already attempts the same madvise and discards the result, which is
	// no guarantee at all; the process-wide RLIMIT_CORE hardening is likewise
	// best effort and can be undone by anything else in the process. This is the
	// one core-dump control that is verified, so it is the one an enclave's
	// pages actually rest on — a failure fails the allocation rather than
	// handing back memory that could be written to disk in plaintext.
	if err := excludeFromCoreDump(m.inner); err != nil {
		return nil, m.abandon(err, locked)
	}

	// The canary is random so that an overflow cannot reproduce it by writing a
	// predictable pattern. It is empty when size is an exact page multiple,
	// which is a known gap documented on the type.
	if _, err := rand.Read(m.canary); err != nil {
		return nil, m.abandon(err, locked)
	}

	// The guard pages carry a copy of the canary before they are made
	// inaccessible, so release can tell they are still the pages it mapped.
	copyConstantTime(m.preguard, m.canary)
	copyConstantTime(m.postguard, m.canary)

	if err := memcall.Protect(m.preguard, memcall.NoAccess()); err != nil {
		return nil, m.abandon(err, locked)
	}
	if err := memcall.Protect(m.postguard, memcall.NoAccess()); err != nil {
		return nil, m.abandon(err, locked)
	}

	return m, nil
}

// abandon gives back everything a partially built mapping has taken and reports
// the failure that caused the rollback.
//
// Nothing sensitive has been written at this point — callers copy material in
// only after [newMapping] returns — so a mapping left behind here is empty. It
// is still reported rather than discarded: a leak nobody is told about is one
// nobody can act on, and this path only runs when the kernel is already refusing
// things, which is exactly when the cleanup is most likely to be refused too.
//
// locked says whether the inner region was successfully mlock'd before the
// failure, since unlocking pages that were never locked is itself an error.
func (m *mapping) abandon(cause error, locked bool) error {
	failure := error(&LockedMemoryError{Cause: cause})

	var cleanup error
	if locked {
		if err := memcall.Unlock(m.inner); err != nil {
			cleanup = errors.Join(cleanup, err)
		}
	}
	if err := memcall.Free(m.memory); err != nil {
		cleanup = errors.Join(cleanup, err)
	}
	if cleanup != nil {
		return errors.Join(failure, &LockedMemoryError{Cause: cleanup})
	}
	return failure
}

// freeze makes the data region read-only, so a write through a retained slice
// faults instead of silently corrupting the material. It is idempotent.
func (m *mapping) freeze() error {
	if !m.mutable {
		return nil
	}
	if err := memcall.Protect(m.inner, memcall.ReadOnly()); err != nil {
		return &LockedMemoryError{Cause: err}
	}
	m.mutable = false
	return nil
}

// wipeAndVerify zeroes the whole mapping and checks the canary, reporting
// [ErrEnclaveCorrupted] if the region ahead of the data was overwritten.
//
// The data is wiped BEFORE the canary is checked, so a detected corruption
// still leaves nothing readable behind — the check reports what happened, it
// does not decide whether to clean up. It is split out from release so that a
// test can inspect the wiped memory before it is handed back to the kernel.
func (m *mapping) wipeAndVerify() error {
	// FIRST, destroy the material, before any syscall that could be refused.
	// While the inner region is still writable — which it is unless a freeze
	// succeeded — this needs no call that anything can deny. Doing it after the
	// mprotect below meant a denied mprotect left the secret sitting in locked
	// memory (Codex round 3 on PR #9); doing it here means the worst a refusal
	// can cost is an empty mapping that could not be handed back.
	//
	// ONLY the data region. The canary shares the inner pages and is the thing
	// the verification below compares against the guards, so wiping it here
	// would report every clean release as corrupted — measured, on the first
	// attempt at this fix.
	if m.mutable {
		wipe(m.data)

		// The material is gone from HERE, not from the later assignment after
		// the mprotect. This early wipe is the whole point of doing it first,
		// and the mprotect below can be refused -- so a mutable mapping whose
		// data has already been zeroed would otherwise sit at wiped=false all
		// the way through release's fallback, and if that fallback is refused
		// too the mapping is KEPT and reads as a live enclave over zeroes.
		// That is the same defect the flag exists to close, reached down the
		// other branch.
		m.wiped = true
	}

	// The rest needs the WHOLE region readable and writable: the guard pages are
	// PROT_NONE, and inner is read-only if it was frozen. A refusal here is
	// reported, and release will keep the mapping rather than strand it.
	if err := protectMemory(m.memory, memcall.ReadWrite()); err != nil {
		return &LockedMemoryError{Cause: err}
	}
	m.mutable = true

	wipe(m.data)

	m.corrupted = !equalConstantTime(m.preguard, m.postguard) ||
		!equalConstantTime(m.preguard[:len(m.canary)], m.canary)

	wipe(m.memory)

	// From here the material is gone whatever happens next. Set BEFORE the
	// error return below, because the case this exists for is precisely the one
	// where a later step fails and the mapping is kept.
	m.wiped = true

	if m.corrupted {
		return ErrEnclaveCorrupted
	}
	return nil
}

// release wipes the mapping, verifies the canary, unlocks the pages and returns
// them to the kernel.
//
// It clears its fields ONLY when the pages have actually gone back. If any step
// that must precede unmapping fails — the transition to writable, so the wipe
// could not have happened — or if unlocking or unmapping itself fails, the
// mapping is left fully intact and the error is returned. Dropping the slices
// would strand a region that is still mapped, possibly still locked, and
// possibly still holding material, with no handle left to retry through; the
// caller's [Allocator] would then be told those bytes are available while the
// kernel still holds them. Keeping the state means a caller that recovers can
// simply call Destroy again.
//
// ErrEnclaveCorrupted is the one error returned WITH the memory released: a
// failed canary is a report about what already happened, not a reason to hold
// on to pages that were successfully wiped and unmapped.
func (m *mapping) release() error {
	// A corrupted canary still means the region was wiped, so it falls through
	// and is reported after the pages are gone. Any other error here means the
	// region could not be made writable and therefore was NOT wiped: unmapping
	// now would hand the kernel back pages that may still hold material, and
	// would lose the only handle for trying again.
	if err := m.wipeAndVerify(); err != nil && !errors.Is(err, ErrEnclaveCorrupted) {
		// The region could not be made writable, so it was NOT wiped. For a
		// FROZEN enclave that is the whole exposure: wipeAndVerify skips its
		// early wipe when the pages are read-only, so under a PERMANENT denial
		// of this mprotect -- a seccomp filter is the realistic threat -- the
		// material would stay resident in locked memory for the process
		// lifetime. Retrying cannot help; the denial does not go away.
		//
		// So hand the pages back to the kernel with a bare munmap instead of
		// giving up. memcall.Free cannot do this: it begins with the same
		// Protect(ReadWrite()) that was just refused. The kernel zeroes an
		// anonymous page before reuse and these were mlock'd for their whole
		// life, so nothing can read the material afterwards and no copy reached
		// swap.
		//
		// Reported, never silent. Returning nil here would collapse "released
		// the normal way" into "released after the wipe was refused", and the
		// caller could not tell a healthy teardown from a sandbox quietly
		// removing a security step.
		if uerr := unmapDirectFn(m.memory); uerr != nil {
			// The bypass failed too: keep everything: the region is still
			// mapped and may still hold material, and dropping the handle
			// would strand it with no way to retry.
			return errors.Join(err, uerr)
		}

		m.memory, m.data, m.inner = nil, nil, nil
		m.preguard, m.postguard, m.canary = nil, nil, nil
		m.mutable, m.corrupted = false, false

		return &UnwipedReleaseError{Cause: err}
	}

	if err := memcall.Unlock(m.inner); err != nil {
		return &LockedMemoryError{Cause: err}
	}
	if err := memcall.Free(m.memory); err != nil {
		return &LockedMemoryError{Cause: err}
	}

	corrupted := m.corrupted
	m.memory, m.data, m.inner = nil, nil, nil
	m.preguard, m.postguard, m.canary = nil, nil, nil
	m.mutable, m.corrupted = false, false

	if corrupted {
		return ErrEnclaveCorrupted
	}
	return nil
}

// wipe overwrites b with zeroes.
//
// The KeepAlive is what stops the compiler removing the loop as a dead store to
// memory nothing reads afterwards — golang/go#33325. Without it this function
// can legally compile to nothing at all.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// copyConstantTime copies min(len(dst), len(src)) bytes without branching on
// their contents.
func copyConstantTime(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	subtle.ConstantTimeCopy(1, dst[:n], src[:n])
}

// equalConstantTime compares two slices without branching on their contents.
func equalConstantTime(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}
