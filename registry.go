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
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// This file is the one thing v0.3.0-alpha removed and a consumer still needed.
//
// Option B (#2) deleted memguard's process-global registry because of what
// memguard did WITH it: on any mapping failure it purged the whole thing —
// unmapping every live buffer in the process — and then panicked. That is a
// fault handler, and a library must not have one that destroys unrelated data.
//
// A COOPERATIVE sweep is a different mechanism wearing a similar shape, and the
// difference is the whole design:
//
//	memguard's purge          WipeAll
//	triggered by a FAULT      called explicitly, at teardown
//	panics afterwards         never panics
//	runs mid-operation        runs when operations are finished
//	unmaps live borrows       waits for a live borrow, as long as its context
//	                          allows, and counts it if the context ends first
//
// So the registry here is a shutdown ledger, not a coordinator. It is touched
// on construction, on destruction and by WipeAll, and by NOTHING on the borrow
// path — which is what keeps purgeMu from coming back. A borrow takes only its
// own enclave's lock, exactly as it has since v0.3.0-alpha, and allocating
// inside a live borrow still works. What a borrow does add since #88 is two
// atomic adds on its own enclave's holder count and one load of sweepWaiting,
// which is how a sweep waiting for that borrow hears it end: neither is a lock,
// neither allocates, and the only package-level word involved is one a borrow
// reads and never writes.
//
// Two costs this does carry, stated plainly because a ledger that hides them
// would be the same mistake in a smaller size:
//
// registryMu SERIALIZES CONSTRUCTION AND DESTRUCTION process-wide. Every
// constructor takes it once to publish, every Destroy takes it once to
// deregister. That is a real contention point for a program creating enclaves on
// many goroutines at once, and it is new in this version. It is emphatically not
// purgeMu: purgeMu sat on the BORROW path, so reading an enclave contended with
// every other enclave's reads and a borrow could deadlock against a purge. This
// lock is held for a single map operation and never while any enclave lock is
// held, so it cannot deadlock against a borrow and cannot be held across a
// syscall.
//
// AN ENCLAVE WHOSE RELEASE KEEPS FAILING IS RETAINED FOR THE PROCESS LIFETIME.
// It stays on the ledger — deliberately, so a later sweep can retry it — and the
// map therefore holds a pointer that will never be collected. The alternative is
// dropping the only reference to memory the kernel still has mapped, which
// strands it with no way to retry and no way to find it again. A leak that is
// still reachable and still reported is the better of the two.
//
// The same reasoning covers a construction that FAILS and whose cleanup is
// refused too. It returns no enclave, but its pages are still mapped, so the
// mapping goes onto a second ledger, of orphans, that WipeAll retries the same
// way (#83). Before that, those pages were the one allocation in the package
// with no handle anywhere.

// The sweep's wait for a borrow to end (#88).
//
// [WipeAll] never blocks on an enclave's lock: a blocked Lock cannot be
// abandoned when the caller's context ends, and a pending writer stalls every
// new reader of that enclave behind it. So it TRIES for the lock, and when an
// enclave it owes is held it has to wait for the holder to let go. Until #88
// that wait was a fixed 200µs sleep between at most eight passes — a guess at
// how long a reader takes, which a health probe on a loaded host lost, and
// which made "momentary" mean "about 1.4ms, nominally". It is now an event: the
// release that frees an enclave wakes the sweep, and the sweep's context is the
// only bound on how long it waits.
//
// The mechanism is a one-slot channel and a flag, chosen so that a borrow
// outside a sweep pays one atomic load and nothing else:
//
//   - sweepWaiting is armed for the whole of a sweep. A holder of an enclave's
//     lock reads it after letting go, and only when it is set does it touch
//     the channel (see [MemoryEnclave.unhold]).
//   - sweepWake carries at most one pending wake-up. A send that finds the
//     slot full is dropped, because one pending wake-up already means "go
//     again", so wake-ups coalesce and a sender never blocks.
//
// The sweep drains the slot at the start of every pass, BEFORE it tries any
// lock, so a wake-up found waiting afterwards was sent after the drain — by a
// release the pass may not have seen. Spurious wake-ups are possible and
// harmless: they cost a pass. Lost ones are not possible; the argument is on
// [MemoryEnclave.holders].
//
// Both are package-level rather than per-sweep because sweepSlot admits one
// sweep at a time. A slot left full by a release after the previous sweep
// returned is drained by the next sweep's first pass.
var (
	sweepWaiting atomic.Bool
	sweepWake    = make(chan struct{}, 1)

	// sweepWaitingForTest runs each time the sweep is about to BLOCK waiting
	// for a borrow: its pass found something it owes held, and its context has
	// not ended. nil in every build
	// but the tests that need to act at exactly that moment — end the borrow,
	// cancel the context — rather than hoping the sweep has got there.
	sweepWaitingForTest func()

	// sweepPassForTest runs at the start of every pass, after the drain, with
	// the pass's ordinal from 1. nil outside the tests that have to observe a
	// pass that ends in neither a wait nor a return — the immediate retry of a
	// contended lock — which nothing else makes visible.
	sweepPassForTest func(pass int)
)

// wakeSweep posts a wake-up to a waiting sweep, dropping it if one is already
// pending. It never blocks and never allocates.
func wakeSweep() {
	select {
	case sweepWake <- struct{}{}:
	default:
	}
}

var (
	registryMu sync.Mutex
	// live holds every enclave that has been constructed and not yet released.
	// A map rather than a slice: deregistration happens on every Destroy and is
	// far more frequent than the single sweep, so it is the operation to keep
	// cheap.
	live = make(map[*MemoryEnclave]struct{})
	// orphans holds the mappings failed constructions could not give back; see
	// orphanRecord. Guarded by registryMu like live, for the same reason: it is
	// written by constructors running concurrently with a sweep, and a second
	// lock would be a second lock order to get right.
	orphans = make(map[*orphanRecord]struct{})
	// destroyedCorrupt holds enclaves whose Destroy detected a failed canary
	// since the last admitted sweep, which reports and clears them. Guarded by
	// registryMu.
	destroyedCorrupt = make(map[*MemoryEnclave]struct{})

	// sweepGen is the sweep sequence behind [SealedEnclave.Openable]'s
	// fallback for providers that can report nothing about their own sealing
	// state. [WipeAll] bumps it TWICE — once before it destroys anything and
	// once after it finishes — so its PARITY carries the extra fact a plain
	// counter cannot:
	//
	//	even  no sweep is running
	//	odd   a sweep is in flight RIGHT NOW
	//
	// The parity is not decoration. A plain counter cannot distinguish a value
	// sealed safely from one sealed while a sweep was midway through: the seal
	// would record the already-bumped number, later compare equal to it, and
	// report nil about material the rest of that same sweep went on to
	// destroy. That is the fail-open this mechanism exists to close, so a
	// value sealed under an ODD generation is treated as suspect no matter
	// what the count later says. It is the standard sequence-lock reading of a
	// counter and is used here for the standard reason.
	//
	// Monotonic and never reset — a reset would make a later value read as
	// older than an earlier one, which is the one thing the comparison must
	// never do. Written ONLY by WipeAll.
	sweepGen atomic.Uint64

	// sweepParkedForTest runs after the generation is bumped and BEFORE
	// anything is destroyed. It is nil in every build but the test that pins
	// that ordering, which is the only way to observe the window from
	// outside. Same shape as the Allocator's stalled seam and for the same
	// reason: an ordering claim that cannot be entered cannot be tested.
	sweepParkedForTest func()

	// sweepSlot serializes [WipeAll] end to end: a sweep runs only while it
	// holds the slot's one token. The parity of sweepGen is a
	// SINGLE-WRITER invariant — the standard requirement of the sequence-lock
	// reading it uses — and two concurrent sweeps break it outright: the
	// second one's opening bump takes the sequence from odd back to EVEN
	// while both are still running, so a value sealed in that window records
	// an even sequence, reads "no sweep was in flight", and can then be
	// reported openable after one of those sweeps has already destroyed the
	// provider's key. That is the fail-open the sequence exists to close.
	//
	// Serializing rather than counting active sweeps: a count needs a second
	// word, and reading two words that must agree is the problem this design
	// avoided in the first place. WipeAll is a teardown operation called once
	// or twice in a process's life, so the contention cost is nil, and a
	// second caller waiting for the first to finish is the behavior a
	// concurrent caller wanted anyway — for as long as ITS context allows.
	//
	// A channel rather than a sync.Mutex for exactly that last clause (Codex
	// on #95). A sweep can wait on a borrow for as long as its own context
	// allows, which under context.Background is indefinitely, and a mutex
	// cannot be abandoned: a second caller with a deadline would queue behind
	// the first for as long as the FIRST caller's context allowed, which
	// repeals the second caller's bound. Acquiring is a send, so it can sit in
	// a select beside ctx.Done() without a helper goroutine; releasing is the
	// matching receive. The memory model gives the slot the same
	// happens-before a mutex has — the k-th receive from a channel of capacity
	// 1 is synchronized before the (k+1)-th send completes — so everything one
	// sweep wrote is visible to the next one admitted.
	//
	// Taken BEFORE registryMu and never while holding it, which is the whole
	// lock order in this file.
	sweepSlot = make(chan struct{}, 1)

	// sweepAdmissionWaitForTest runs when a sweep finds the slot taken and is
	// about to BLOCK for it under a non-nil ctx. nil outside the test that
	// cancels a context at exactly that moment.
	sweepAdmissionWaitForTest func()
)

// ErrSweepInProgress is returned by [WipeAll] when it was never admitted:
// another sweep held the process's single sweep slot, and this call stopped
// waiting for it — when its ctx ended, or at once for a nil ctx, which never
// waits. It is an ADMISSION result, not a sweep finding: it reports nothing
// about the memory, and it is not a [SweepError].
//
// Such a call reclaimed NOTHING. Its count is still the truth — the ledgers
// read under their lock at the moment it gave up, exactly what an admitted
// sweep reports — so a shutdown path logs the same figure either way. A nil
// error there would claim that a sweep ran and found nothing to report, which
// is false; a [SweepError] would claim findings it never looked for. The
// sweep that does hold the slot is still running and will reclaim what it
// can for its own caller.
var ErrSweepInProgress = errors.New("enclave: another WipeAll is in progress; nothing was swept")

// admitSweep takes the sweep slot, waiting for it no longer than ctx allows.
// A free slot is taken even under a done ctx — an expired deadline still
// sweeps what needs no waiting, and admission is the first such step. A nil
// ctx only tries. It never starts a goroutine.
func admitSweep(ctx context.Context) bool {
	select {
	case sweepSlot <- struct{}{}:
		return true
	default:
	}
	if ctx == nil {
		return false
	}
	if sweepAdmissionWaitForTest != nil {
		sweepAdmissionWaitForTest()
	}
	select {
	case sweepSlot <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// ledgerCount is how many entries still hold this package's pages, read under
// the ledger lock: the count every WipeAll return reports.
func ledgerCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(live) + len(orphans)
}

// orphanRecord is a mapping a failed construction could not hand back to the
// kernel, kept so [WipeAll] can retry it (#83).
//
// A constructor that fails after mapping rolls the mapping back, and the
// rollback can be refused — the kernel that just refused one thing is the one
// most likely to refuse the next. The constructor then returns nil and an error,
// and before this ledger that dropped the only handle to the pages: no sweep
// could reclaim them even after the refusal lifted, and an [Allocator] charge
// kept for still-locked pages was kept for the process lifetime.
//
// refund returns that charge, and is nil when there is nothing to return: an
// unadmitted constructor took none, and an admitted one refunds at once when
// the pages were no longer locked (see [Allocator.refundFailed]). It runs
// exactly once, from the sweep that releases the pages: only WipeAll touches a
// record after adoption, sweepSlot serializes WipeAll, and the record leaves the
// ledger in the same step that runs the refund.
type orphanRecord struct {
	m      *mapping
	refund func()
}

// adoptOrphan puts the mapping a failed construction's err carries onto the
// orphan ledger, with refund to run when a sweep releases it. It is a no-op
// for every failure that left nothing mapped, so every public constructor can
// call it on every failure without inspecting the error first.
//
// It is called from the PUBLIC constructors, after the refund decision is made
// and never before, for the same publication-last reason as [register]: a
// record a sweep could reach before its refund was attached could be released
// with the charge never returned.
func adoptOrphan(err error, refund func()) {
	var held *pagesHeldError
	if !errors.As(err, &held) || held.orphan == nil {
		return
	}
	o := &orphanRecord{m: held.orphan, refund: refund}
	// One adoption per mapping: the error stays with the caller, and nothing
	// else may use it to put the same pages on the ledger twice.
	held.orphan = nil

	registryMu.Lock()
	orphans[o] = struct{}{}
	registryMu.Unlock()
}

// releaseOrphan retries o's release. On success — the pages went back, by the
// same [releasedPages] predicate Destroy and the enclave sweep use — it runs the
// refund and drops the record, and reports true. The caller holds the sweep
// slot.
func releaseOrphan(o *orphanRecord) (released bool, err error) {
	err = o.m.release()
	if !releasedPages(err) {
		return false, err
	}
	if o.refund != nil {
		o.refund()
	}
	registryMu.Lock()
	delete(orphans, o)
	registryMu.Unlock()
	return true, err
}

// sweepGeneration reports the current sweep sequence. A sealed value records
// it BEFORE it seals and [SealedEnclave.Openable] compares against it; an odd
// value means a sweep was in flight at that moment. See [sweepGen].
func sweepGeneration() uint64 { return sweepGen.Load() }

// sweepInFlight reports whether g was taken while a sweep was running.
func sweepInFlight(g uint64) bool { return g%2 == 1 }

// register adds e to the shutdown ledger and returns it, so constructors can
// wrap their return value rather than growing a second statement that a future
// constructor might forget.
//
// It PUBLISHES e: from the moment it returns, a concurrent [WipeAll] may destroy
// e and invoke its release callback. So it must be the LAST step of
// construction, after every field a sweep reads is set — which is why the
// unexported constructors return an unregistered enclave and each entry point
// registers for itself. An enclave published before [MemoryEnclave.release] is
// installed can be swept while that field is still nil: a data race on the
// assignment, and pages handed back with the Allocator charge never returned.
// Its lock doubles as the happens-before edge that makes those fields visible to
// a sweeping goroutine.
//
// Publishing last does leave a window in which locked pages exist and [WipeAll]
// cannot see them. It is bounded by construction: everything between the inner
// constructor's return and the register call is an error check and a closure
// assignment — no syscall, no lock, no path that can fail or return early.
// The closure is a heap allocation and so could be preempted, which widens the
// window in TIME without changing what it means — a sweep concurrent with it
// simply predates the enclave, the same answer it gives for one constructed a
// moment later. What the window cannot do is what the old order did: hand a
// sweep an enclave it will act on before the fields it acts on exist.
func register(e *MemoryEnclave) *MemoryEnclave {
	registryMu.Lock()
	live[e] = struct{}{}
	registryMu.Unlock()
	return e
}

// deregister removes e from the shutdown ledger. It is a no-op for an enclave
// that is not on it, so a double Destroy costs a map lookup and nothing else.
func deregister(e *MemoryEnclave) {
	registryMu.Lock()
	delete(live, e)
	registryMu.Unlock()
}

// noteCorrupted records that Destroy found e's canary broken, so the next
// [WipeAll] reports it even when Destroy's caller discarded the error.
func noteCorrupted(e *MemoryEnclave) {
	registryMu.Lock()
	destroyedCorrupt[e] = struct{}{}
	registryMu.Unlock()
}

// SweepError reports what a [WipeAll] sweep FOUND that is not a held page: a
// memory-safety event, an environment removing a teardown step, or both.
//
// It is what an ADMITTED sweep returns when it found something — a call that
// was never admitted returns [ErrSweepInProgress] instead — and it answers a
// different question from the count. Neither condition leaves pages held — a corrupt enclave is
// ordinarily wiped and unmapped like any other, and an unwiped one was unmapped
// too — so the count cannot carry either, and without this the fact that
// something wrote into memory it did not own would vanish at exit behind a
// zero that looks like success.
//
// Match it with errors.Is against the sentinels — [ErrEnclaveCorrupted] when
// Corrupt is non-zero, [ErrReleasedWithoutWipe] when Unwiped is — exactly as a
// caller matches Destroy's report. Read the numbers with errors.As. WipeAll
// returns one only when at least one field is non-zero, and never a nil
// *SweepError behind a non-nil error.
type SweepError struct {
	// Corrupt is how many entries this sweep found with a failed canary:
	// enclaves, and the mappings of failed constructions that had material
	// copied in before they failed. It also counts every enclave whose
	// [MemoryEnclave.Destroy] reported [ErrEnclaveCorrupted] since the
	// previous admitted sweep, whether or not that caller checked the error.
	// Each is counted once per sweep however many attempts its release took,
	// and is counted whether or not its pages then went back — a corrupt
	// entry the kernel would not release is ALSO in the count WipeAll
	// returns, the one overlap between the two.
	Corrupt int

	// Unwiped is how many entries this sweep unmapped WITHOUT the in-process
	// overwrite, because the mprotect that makes a frozen region writable was
	// denied. Their pages are gone, so they are never in the count; the denial
	// reaches every other enclave in the process, which is why it is reported.
	Unwiped int
}

// Error implements error. Each non-zero condition is one line naming its
// count and ending in its sentinel's text; both lines appear when both hold.
func (e *SweepError) Error() string {
	var b strings.Builder
	if e.Corrupt > 0 {
		b.WriteString("enclave: ")
		b.WriteString(strconv.Itoa(e.Corrupt))
		b.WriteString(" of the swept enclaves failed canary verification: ")
		b.WriteString(ErrEnclaveCorrupted.Error())
	}
	if e.Unwiped > 0 {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("enclave: ")
		b.WriteString(strconv.Itoa(e.Unwiped))
		b.WriteString(" of the swept enclaves were unmapped without an in-process wipe because mprotect was denied: ")
		b.WriteString(ErrReleasedWithoutWipe.Error())
	}
	if b.Len() == 0 {
		// Only a SweepError built by hand can get here; WipeAll never returns
		// one with nothing in it.
		return "enclave: sweep reported nothing"
	}
	return b.String()
}

// Is reports whether e carries the condition target names:
// [ErrEnclaveCorrupted] when Corrupt is non-zero, [ErrReleasedWithoutWipe]
// when Unwiped is. A zero field never matches its sentinel.
func (e *SweepError) Is(target error) bool {
	switch target {
	case ErrEnclaveCorrupted:
		return e.Corrupt > 0
	case ErrReleasedWithoutWipe:
		return e.Unwiped > 0
	}
	return false
}

// WipeAll destroys every enclave holding LOCKED MEMORY that this package has
// handed out and not yet reclaimed, and retries the release of every mapping a
// failed construction could not give back. It reports how many it could not
// reclaim, and anything it found that a caller must hear about.
//
// It is for ORDERLY SHUTDOWN — a signal handler, a defer in main — where the
// process is about to exit and any locked memory still held is material that
// should not outlive it. It is not a fault handler and not a garbage collector:
// nothing calls it for you.
//
// ctx bounds how long it WAITS — for another sweep to finish, for borrows
// still in progress, and for contended locks to come free — and never stops
// it reclaiming what needs no waiting; see "How long it runs". Give a
// shutdown sweep a deadline:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
//	defer cancel()
//	if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
//	    log.Printf("enclave: %d still held at exit, err=%v", n, err)
//	}
//
// # What "every enclave" covers, and what a sweep does to sealing
//
// The ledger holds [MemoryEnclave]s — the things that own locked pages, which
// is what the sweep is for. That includes every key a [Sealer] or
// [SoftwareProvider] holds: a root, a live KEK generation, the software
// provider's root. They are swept like any other enclave, deliberately —
// leaving the key that opens everything mapped and locked at exit is
// precisely what the sweep exists to prevent, so there is no exemption.
//
// A [SealedEnclave] owns no locked pages — its envelope is heap ciphertext —
// so the sweep does not touch it, and what a sweep means for sealed values
// splits by [Mode]:
//
//   - [ModeRootKey] (and the software default): the hierarchy's keys are
//     gone, so every sealed value in the process is permanently unopenable —
//     the STRONGER outcome; one key page wiped is every value destroyed at
//     once. The sealer fails closed from then on with [ErrSealerWiped], and
//     never silently re-keys; that error documents why.
//   - [ModePerOperation] with a hardware provider: there is no in-process
//     root to destroy. The device still holds the key, sealed values still
//     open, and sealing still works. A sweep is a statement about THIS
//     process's memory, and in this mode the material was never protected by
//     this process's memory.
//
// Either way each swept-out value still reports IsAlive — that method answers
// "the ciphertext is still here", which stays true. Whether it can still be
// OPENED is [SealedEnclave.Openable]: nil, [ErrSealerWiped] once this sweep
// has taken the keys it needed, or [ErrOpenabilityUnknown] when the provider
// reports no health and this call is all that is known to have happened.
//
// This call BUMPS A SWEEP GENERATION BEFORE IT DESTROYS ANYTHING, which is
// what lets a sealed value tell that a sweep ran during its lifetime. The
// order is deliberate and load-bearing; see the comment at the top of the
// function body. Destroy sealed values alongside this
// call if a live handle to unopenable material would mislead the code holding
// them.
//
// The sweep will NOT be extended to cover them (#33, decided), for three
// reasons worth stating where the count is defined. The COUNT means "still
// holding this package's pages" and that invariant is this function's whole
// value; a SealedEnclave holds none, so including it would either corrupt the number
// or require a second one. Sweeping would also be WRONG rather than merely
// costly: in [ModePerOperation] the device still holds the key, so destroying
// sealed values would destroy recoverable application data that this
// process's memory never protected — under a call whose callers are
// documented as sweeping and continuing to run. And it would REGRESS
// diagnostics, since a swept value would then report ErrEnclaveDestroyed
// ("you destroyed this") in place of ErrSealerWiped ("a sweep did"), which
// sends an operator to the wrong code.
//
// # It belongs to the program, never to a library
//
// Call it only from the code that OWNS THE PROCESS. A library must not call it,
// because it destroys every enclave in the process — including those belonging
// to subsystems the library knows nothing about, whose owners are still using
// them. There is no way for a library to know it is safe, and no way for the
// owner of another enclave to defend against it.
//
// This is stated because two independent consumers reached it on their own and
// declined to call WipeAll for exactly this reason. An API that two callers
// separately decide to avoid is inviting the mistake, which makes it a
// documentation defect rather than a coincidence.
//
// # What it does not do
//
// It never panics, including on an enclave whose canary fails. A sweep that
// aborted partway would leave every enclave after the failure untouched, which
// is the opposite of what a caller wants at exit; the corruption is REPORTED
// through the returned [SweepError] and the sweep goes on.
//
// It never unmaps underneath a reader, and it never blocks on an enclave's
// lock. An enclave being read when the sweep reaches it is left alone and
// WAITED FOR — not by sleeping, but until the release that frees it wakes the
// sweep — for as long as ctx allows. One still held when ctx ends is skipped
// and counted: memory being actively read must not be unmapped underneath the
// reader, and a shutdown that hangs behind a goroutine still reading a key is
// worse than one that reports what it could not reach. "Being read" means any
// holder of the enclave's lock: a WithBytes, Open, OpenString, EqualTo, Size or
// IsAlive in progress, a Freeze, or a Destroy waiting its turn.
//
// [MemoryEnclave.Open] hands back a slice that outlives the enclave's lock, and
// a sweep CAN destroy the enclave behind such a slice. Open's own documentation
// says so; WipeAll is one of the concurrent destroyers it means.
//
// Never call it from INSIDE a borrow. The sweep would wait for the very borrow
// that is waiting for it, and only ctx ending would break the cycle.
//
// # How long it runs
//
// One sweep runs at a time. A call that finds another sweep running waits for
// it — but only as long as ITS OWN ctx allows, so a caller with a deadline is
// never held hostage by a sweep running under [context.Background]. If ctx
// ends first, or ctx is nil, the call sweeps nothing and returns the ledger
// count with [ErrSweepInProgress]; see that error for why that is the truthful
// answer.
//
// An admitted sweep works in passes. Each pass re-reads both ledgers and tries
// every entry on them, without blocking on any lock. The entries present at the
// FIRST pass are what this call owes, and after each pass it does exactly one
// of four things:
//
//   - It goes again AT ONCE if it reclaimed something it owes. Giving pages
//     back changes the kernel's state, so a release refused earlier in the
//     pass — ENOMEM at vm.max_map_count is the realistic one — can succeed
//     now, and anything that registered meanwhile gets a pass. This is the
//     one retry that does not consult ctx, and it cannot repeat forever: each
//     one is paid for by an owed entry leaving the ledger.
//   - Otherwise, if ctx is still live and an owed enclave's lock was
//     CONTENDED — its TryLock failed while nobody was counted as holding it,
//     so no release will announce it — it goes again at once.
//   - Otherwise, if ctx is still live and an owed enclave is HELD, it waits
//     until a holder lets go or ctx ends, and then goes again.
//   - Otherwise it stops. Everything left is held past ctx, a release the
//     kernel refused with nothing changed since that could make a retry
//     succeed, or an entry that arrived after the sweep began.
//
// So the bound is structural rather than a budget. Retries earned by
// reclamation are finite; every other retry and every wait is gated on ctx,
// and a wait ends only when a borrow ends or ctx does. A ctx that ends
// therefore bounds the call, including admission. Under [context.Background]
// nothing bounds it but the borrows themselves: the call ends once every owed
// enclave has been free at a moment the sweep could take it. A borrow that
// never returns, or a goroutine that reads one owed enclave in a loop forever,
// holds that enclave for as long as it runs — which, with no deadline, is how
// long the sweep waits, and how long a second Background caller waits to be
// admitted. That is the reason to pass a deadline.
//
// An already-done ctx is not a refusal: if no other sweep is running, the call
// is admitted and makes every pass reclamation pays for, so everything not
// currently held is reclaimed; it only declines to wait or to retry
// contention. A nil ctx is treated the same way rather than as
// [context.Background] — a programming error in a shutdown path must not turn
// into a shutdown that never finishes — and is otherwise never dereferenced,
// so WipeAll keeps its promise never to panic.
//
// # Constructors racing the sweep
//
// A constructor CAN register while the sweep is running. An enclave that does
// is tried on every later pass the sweep makes, so one created during an
// orderly shutdown is still reclaimed. What it never does is EXTEND the sweep:
// the sweep does not wait for a borrow on it, and reclaiming it does not earn
// another pass. A goroutine that never stops constructing therefore cannot
// keep the sweep running, under any ctx including [context.Background]; its
// latest enclaves show up in the count instead, which is the truth.
//
// The corollary is that a constructor racing a sweep can return an
// ALREADY-DESTROYED enclave to its caller — the sweep reached it between
// publication and return. That is documented on the constructors, and it is why
// allocating during shutdown is a consumer ordering problem rather than
// something this function can paper over.
//
// # The return values
//
// They answer DIFFERENT QUESTIONS, and neither can be derived from the other.
//
// The COUNT is what is still HELD when the sweep returns: enclaves still being
// read when ctx ended, enclaves whose release the kernel refused, enclaves that
// registered mid-sweep and were not reached, and the mappings of failed
// constructions whose release is still being refused (#83). It is read from
// the ledgers themselves under the lock rather than tallied while sweeping, so
// zero means both were empty at that instant — everything this package had
// allocated was unmapped — rather than merely that this call was happy with the
// entries it happened to see.
//
// A non-zero count is therefore "these were still held," not a diagnosis. Most
// often a worker outlived the shutdown — still reading when ctx ended, or still
// constructing — which is a shutdown-ordering problem in the caller; otherwise
// it is a kernel still refusing to take pages back. Calling again at once does
// not help with either: a borrow still live will be waited for again, and a
// refusal with nothing changed will be refused again. Callers that must be
// certain stop their workers first, which is the ordering the count is telling
// them they got wrong.
//
// The ERROR is nil, [ErrSweepInProgress] when this call was never admitted,
// or a [*SweepError] reporting what the sweep FOUND:
// enclaves that failed their canary, in this sweep or in a Destroy since the
// previous admitted sweep (matching [ErrEnclaveCorrupted], exactly as
// Destroy's report does), and enclaves that had to be unmapped without an
// in-process wipe because the wipe-enabling mprotect was denied (matching
// [ErrReleasedWithoutWipe]). Neither is a held page, so the count cannot carry
// them; they overlap only for a corrupt enclave whose pages the kernel then
// refused to give back, which is in both. The corruption tally is kept while
// sweeping rather than read from the ledger — the opposite of how the count is
// derived, and correct for the opposite reason: the ledger can express what is
// still held, but it cannot express what was corrupt and is now gone; only
// this call and the Destroy that detected it report that. ctx ending DURING
// an admitted sweep is NOT an error: it is what bounded the wait, and the count
// already says what it left behind. Only a call that was never admitted
// reports it, as ErrSweepInProgress, because that call swept nothing at all.
//
// Both are worth acting on and they are different actions. A non-zero count is
// most often a shutdown-ordering bug in the caller. A [*SweepError] is a
// memory-safety event that has already happened somewhere in the process, or a
// sandbox removing a teardown step from every enclave in it, and it deserves a
// log line at minimum whatever the count says. [ErrSweepInProgress] is neither:
// it says only that this call never swept, because another sweep was running
// when it stopped waiting. Its count is still current, and the findings of the
// sweep that was running go to that sweep's own caller.
//
// It is safe to call again, and safe to call when nothing is registered. The
// error describes what THIS sweep found, so a corruption stops being reported
// only once its pages have been RECLAIMED: a corrupt enclave whose release the
// kernel kept refusing stays on the ledger, the next sweep retries it, and that
// sweep reports the corruption again — including the one that finally releases
// it — because the detection is sticky for as long as the mapping is held
// (see mapping.corrupted). After that the enclave is gone and no later sweep
// mentions it.
func WipeAll(ctx context.Context) (int, error) {
	// Held for the whole sweep, so the sequence's odd/even meaning is true for
	// a sweep's entire lifetime rather than only when one runs at a time by
	// luck. See sweepSlot. Admission honors ctx: a caller whose context ends
	// while another sweep holds the slot is turned away rather than held
	// hostage by that sweep's context.
	if !admitSweep(ctx) {
		return ledgerCount(), ErrSweepInProgress
	}
	defer func() { <-sweepSlot }()

	// THE GENERATION IS BUMPED BEFORE ANYTHING IS DESTROYED, and the order is
	// the correctness of the openability fallback rather than a detail of it.
	//
	// Bump-then-destroy leaves, at worst, a window where a sweep is in flight
	// and a value whose provider cannot be interrogated reports
	// ErrOpenabilityUnknown while its key material is in fact still intact —
	// a brief false "I cannot tell", which is the SAFE direction and resolves
	// as soon as the sweep finishes.
	//
	// Destroy-then-bump would invert exactly that: a window in which the keys
	// are already gone and the generation still reads old, so Openable returns
	// nil — "nothing prevents an open" — about a value that can no longer be
	// opened. That is the fail-open this fallback exists to close, narrowed to
	// a race that only appears under load, which is the worst form to ship it
	// in. Pinned by TestWipeAll_BumpsTheGenerationBeforeDestroying, which
	// parks in the window rather than trusting the statement order to survive
	// a later edit.
	sweepGen.Add(1)
	// Balancing bump on EVERY return path, so the sequence returns to even
	// however this call ends. A sweep that exited early while leaving the
	// count odd would mark every later seal in the process suspect forever.
	defer sweepGen.Add(1)

	if sweepParkedForTest != nil {
		sweepParkedForTest()
	}

	// ARMED BEFORE THE FIRST TryLock, and for the whole sweep. This is the
	// sweep's half of the handshake on MemoryEnclave.holders: every holder
	// count read below happens after this store, which is what guarantees a
	// holder seen there will see the arm when it lets go.
	sweepWaiting.Store(true)
	defer sweepWaiting.Store(false)

	// A nil ctx must neither panic nor wait. It cannot be told apart by its
	// Done channel — context.Background's is nil too, and that one means
	// "wait as long as it takes" — so it is decided here, once.
	mayWait := ctx != nil
	var done <-chan struct{}
	if mayWait {
		done = ctx.Done()
	}

	// Tallied, not read from the ledger, for the reason given above: a corrupt
	// enclave is deregistered like any other, so by the time the count is taken
	// this fact exists nowhere else.
	//
	// Corruption is keyed by enclave rather than counted per release attempt.
	// Detection and reclamation can be separate attempts: a release that finds a
	// failed canary and is then refused the munlock or munmap keeps the mapping
	// (its error carries ErrEnclaveCorrupted AND marks the pages held), and the
	// retry that finally reclaims it reports the corruption again. Counting
	// attempts would report one enclave twice; counting only the reclaiming
	// attempt would drop the corruption entirely whenever reclamation never
	// succeeds — the memory-safety event this error exists to surface (#83).
	//
	// Keyed by any, because two kinds of entry can be corrupt: an enclave, and
	// an orphan whose construction copied material in before failing.
	corrupted := make(map[any]struct{})
	unwiped := 0

	// owed is the first pass's snapshot: what this call is obliged to see
	// through. Entries that register later are tried on every pass but never
	// waited for and never earn a pass, which is what lets a goroutine that
	// constructs forever coexist with a sweep that ends; see "Constructors
	// racing the sweep".
	var owed map[any]struct{}

sweep:
	for pass := 1; ; pass++ {
		// Drain BEFORE trying any lock. A wake-up pending after this was sent
		// by a release this pass may have missed; one pending before it is
		// stale, and keeping it would cost a pass for nothing.
		select {
		case <-sweepWake:
		default:
		}

		if sweepPassForTest != nil {
			sweepPassForTest(pass)
		}

		// Snapshot under the lock, then release it before destroying anything.
		// Destroy deregisters, which takes this same lock — holding it across
		// the sweep would deadlock on the first enclave. It also means a Destroy
		// racing the sweep is fine: whichever gets the enclave's own lock first
		// wins, and the other finds it already released.
		//
		// EVERY still-registered enclave goes into every pass, with no
		// already-seen set. An earlier revision skipped anything a previous pass
		// had looked at, which quietly turned a momentary reader into permanent
		// abandonment: tryReleaseMapping's TryLock is a WRITE try, so it loses to
		// any concurrent RLock — IsAlive, Size, EqualTo, a health probe polling
		// the enclave during shutdown — not just to a long WithBytes borrow. One
		// lost microsecond marked the enclave seen, no later pass reconsidered it,
		// and the process exited with the material still mapped and locked while
		// WipeAll blamed the caller's shutdown ordering. That is the exact failure
		// this function exists to prevent.
		registryMu.Lock()
		batch := make([]*MemoryEnclave, 0, len(live))
		for e := range live {
			batch = append(batch, e)
		}
		strays := make([]*orphanRecord, 0, len(orphans))
		for o := range orphans {
			strays = append(strays, o)
		}
		registryMu.Unlock()

		if owed == nil {
			owed = make(map[any]struct{}, len(batch)+len(strays))
			for _, e := range batch {
				owed[e] = struct{}{}
			}
			for _, o := range strays {
				owed[o] = struct{}{}
			}
		}

		if len(batch) == 0 && len(strays) == 0 {
			break
		}

		// progressed: an owed entry's pages went back on this pass — the only
		// thing that earns an immediate pass, and a finite resource.
		// held: an owed enclave is held by someone whose release will wake us.
		// contended: an owed enclave's TryLock failed with nobody to wake us;
		// it gets an immediate retry, never a wait.
		var progressed, held, contended bool

		for _, e := range batch {
			_, isOwed := owed[e]
			outcome, err := e.tryReleaseMapping()
			switch outcome {
			case tryHeld:
				// Left registered AND left eligible. Waited for if owed;
				// otherwise counted if still held when the sweep stops.
				held = held || isOwed
				continue
			case tryContended:
				contended = contended || isOwed
				continue
			case tryReleased:
			}

			// Return the Allocator reservation on the same terms Destroy uses:
			// only when the pages actually went back. THE SAME PREDICATE, not a
			// second copy of it -- this sweep and Destroy previously each spelled
			// out "nil or corrupted", and when a third released-with-pages-gone
			// case appeared only one of them learned about it. The enclave was
			// then destroyed but left registered with its reservation unreturned,
			// and a final pass reported it as still held.
			if e.release != nil && releasedPages(err) {
				e.releaseOnce.Do(e.release)
			}

			if errors.Is(err, ErrEnclaveCorrupted) {
				// Recorded whether or not the pages went back: a corrupt
				// enclave whose release was refused stays on the ledger and in
				// the count, and is ALSO corrupt — the count cannot say so.
				corrupted[e] = struct{}{}
			}

			if !releasedPages(err) {
				// The pages are still mapped, so it stays on the ledger.
				continue
			}

			if errors.Is(err, ErrReleasedWithoutWipe) {
				// Wiped-by-unmapping because mprotect was denied. The pages ARE
				// gone, so like reclaimed corruption it never appears in the count --
				// which is exactly why it needs reporting of its own. A sweep
				// that retried and then saw nil would swallow it entirely, and
				// the denial reaches every other enclave in the process.
				unwiped++
			}

			deregister(e)
			// A release that found the enclave already released (a racing
			// Destroy won) also lands here, and still counts: the entry left
			// the ledger, which is all progress has to mean for the bound.
			progressed = progressed || isOwed
		}

		// Orphans have no lock and no reader: nothing but this sweep touches a
		// record once it is adopted, and the sweep slot makes this sweep the only one.
		// Each is retried on every pass, exactly like an enclave whose release
		// was refused, and reported on the same terms.
		for _, o := range strays {
			released, err := releaseOrphan(o)
			if errors.Is(err, ErrEnclaveCorrupted) {
				corrupted[o] = struct{}{}
			}
			if released && errors.Is(err, ErrReleasedWithoutWipe) {
				unwiped++
			}
			if released {
				_, isOwed := owed[o]
				progressed = progressed || isOwed
			}
		}

		// Reclaiming an owed entry earns an immediate pass, and that is the
		// only retry that does not consult ctx: it is FINITE, paid for by an
		// owed entry leaving the ledger, which happens once per entry.
		if progressed {
			continue
		}
		if !held && !contended {
			break
		}

		// Every other retry is gated on ctx, the contention retry included
		// (Codex on #95). Contention is not paid for by anything: a TryLock
		// can keep failing with the holder count at zero for as long as
		// readers keep arriving and leaving between the sweep's two reads, so
		// an ungated retry would be a loop around the caller's deadline. A nil
		// ctx never retries contention and never waits, so it is bounded to
		// the passes reclamation pays for.
		//
		// Checked before waiting, too, so an already-done ctx stops here even
		// when a wake-up is also pending — select would pick between the two
		// at random, and the documented behavior is "never waits", not
		// "usually".
		if !mayWait || ctx.Err() != nil {
			break
		}
		if contended {
			// Nobody is there to wake us, so retry at once rather than wait.
			continue
		}
		if sweepWaitingForTest != nil {
			sweepWaitingForTest()
		}
		// No timer anywhere: the sweep wakes because a holder let go, or
		// because the caller's ctx ended. context.Background's done channel
		// is nil, so for it only a wake-up can end the wait.
		select {
		case <-sweepWake:
		case <-done:
			break sweep
		}
	}

	// The count is the ledger itself, read under the lock, not a tally kept
	// while sweeping. A tally counts what this call decided about the enclaves
	// it happened to see; the ledger is what is actually still held. Those
	// differ exactly when something registered mid-sweep, and reporting zero
	// while such an enclave is alive is a fail-open on the one guarantee this
	// function makes (Codex, PR #20).
	//
	// Orphans are counted on the same terms: still on their ledger means still
	// mapped, and leaving them out would report zero over pages the kernel has
	// not taken back.
	registryMu.Lock()
	remaining := len(live) + len(orphans)
	for e := range destroyedCorrupt {
		corrupted[e] = struct{}{}
	}
	clear(destroyedCorrupt)
	registryMu.Unlock()

	// One error however many were corrupt, carrying the counts. Joining N
	// copies of a sentinel that has no per-enclave identity would repeat the
	// same sentence N times and say less than the number does.
	if len(corrupted) > 0 || unwiped > 0 {
		return remaining, &SweepError{Corrupt: len(corrupted), Unwiped: unwiped}
	}
	return remaining, nil
}
