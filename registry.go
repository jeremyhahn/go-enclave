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
	"sync"
	"sync/atomic"
	"time"
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
//	unmaps live borrows       leaves a live borrow alone and says so
//
// So the registry here is a shutdown ledger, not a coordinator. It is touched
// on construction, on destruction and by WipeAll, and by NOTHING on the borrow
// path — which is what keeps purgeMu from coming back. A borrow takes only its
// own enclave's lock, exactly as it has since v0.3.0-alpha, and allocating
// inside a live borrow still works.
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

// maxSweepPasses bounds how many times [WipeAll] re-reads the ledger.
//
// It has to loop for two reasons. A constructor can register between the
// snapshot and the end of the sweep. And an enclave can be momentarily
// unavailable — [MemoryEnclave.tryReleaseMapping] takes the write lock without
// waiting, so it loses to any concurrent reader, including a cheap one like
// IsAlive — and such an enclave must get another chance rather than being
// written off on one lost race.
//
// It must not loop forever, because a goroutine still constructing, or one
// parked inside a borrow, would then hang the shutdown — the failure the
// skip-and-count design exists to avoid, arriving by a different road. In an
// orderly shutdown nothing is constructing and the second pass finds nothing;
// against a goroutine that never stops or a borrow that never returns, the bound
// is reached and the count comes back non-zero, which is the truth and is the
// caller's cue that their ordering is wrong.
const maxSweepPasses = 8

// sweepBackoff is how long [WipeAll] waits between passes when something is
// still held.
//
// WHY THIS EXISTS. Without it the retry loop is temporally degenerate: all
// eight passes complete in about 966 NANOSECONDS, so "still held after every
// pass" means "held for more than roughly a microsecond." A reader doing
// anything realistic — a health probe calling IsAlive, a Size, an EqualTo —
// loses its enclave every time, measured 20/20 at 20µs, 100µs, 500µs and 2ms.
// The documented promise that a momentary reader "costs the sweep a pass, not
// the enclave" was false for every reader that actually exists.
//
// WHY THIS IS A BACKOFF AND NOT SYNCHRONIZATION, which matters because this
// package otherwise forbids sleeping: the test is whether CORRECTNESS depends
// on the duration. Delete this wait and the sweep is still correct — an enclave
// simply is not reclaimed on THIS call, the count stays honest, and the
// documented remedy still works. Nothing is racing; the sweep is only less
// likely to win. A sleep standing in for an ordering guarantee would instead
// become WRONG when removed, and flakiness would be its symptom. That is the
// pattern the convention bans, and this is not it.
//
// There is also nothing to wait ON. The party being waited for is another
// goroutine's read lock, and sync.RWMutex exposes no "notify when free" — so
// there is no channel to select on, and runtime.Gosched() grants scheduling
// opportunities rather than wall-clock time. Making readers observable would
// mean registering every borrow on the hot path to serve a shutdown-only
// sweep, which is the wrong trade and is deliberately not done.
//
// COST, stated as measured rather than as arithmetic: the nominal figure is
// (maxSweepPasses-1) * sweepBackoff = 1.4ms, but that is a LOWER BOUND. Timer
// granularity means each short sleep overshoots, and a real sweep against a
// held enclave was measured at 7.5ms — about 5.4x nominal. Either way it is
// milliseconds at shutdown, and only when something is genuinely still held: a
// sweep that finds everything on the first pass breaks out before ever reaching
// the wait and pays nothing.
//
// Anything comparing itself against this budget must use the MEASURED cost, not
// the nominal one. A test that assumed 1.4ms picked a "well over budget" hold
// of 5.6ms, which is under the real 7.5ms, and failed for that reason alone.
const sweepBackoff = 200 * time.Microsecond

var (
	registryMu sync.Mutex
	// live holds every enclave that has been constructed and not yet released.
	// A map rather than a slice: deregistration happens on every Destroy and is
	// far more frequent than the single sweep, so it is the operation to keep
	// cheap.
	live = make(map[*MemoryEnclave]struct{})

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

	// sweepMu serializes [WipeAll] end to end. The parity of sweepGen is a
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
	// concurrent caller wanted anyway.
	//
	// Taken BEFORE registryMu and never while holding it, which is the whole
	// lock order in this file.
	sweepMu sync.Mutex
)

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

// WipeAll destroys every enclave holding LOCKED MEMORY that this package has
// handed out and not yet reclaimed. It reports how many it could not, and
// whether any of them turned out to be corrupt.
//
// It is for ORDERLY SHUTDOWN — a signal handler, a defer in main — where the
// process is about to exit and any locked memory still held is material that
// should not outlive it. It is not a fault handler and not a garbage collector:
// nothing calls it for you.
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
// holding locked memory" and that invariant is this function's whole value; a
// SealedEnclave holds none, so including it would either corrupt the number
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
// through the returned error and the sweep goes on. [MemoryEnclave.Destroy]
// panics on that same condition, deliberately — a single enclave's caller cannot
// act on state that is by definition wrong — but a sweep is not one enclave, and
// non-fatal must not mean invisible.
//
// It never waits indefinitely for a reader. An enclave being read when the
// sweep reaches it is SKIPPED, not blocked on — a shutdown that hangs behind a
// goroutine still reading a key is worse than one that reports what it could
// not reach. It is RETRIED on later passes rather than written off, with a
// short wait between them ([sweepBackoff]), so a reader that finishes inside
// the retry budget costs the sweep a pass rather than the enclave.
//
// That budget is BOUNDED and worth knowing: (maxSweepPasses-1) * sweepBackoff,
// about 1.4ms. A read that finishes well inside it is reclaimed on a later
// pass; one still in flight after the whole budget is skipped and counted. So
// "momentary" here means milliseconds, not any duration — a long-running
// operation holding an enclave across a shutdown will be counted, correctly.
//
// A non-zero count therefore means SOMETHING WAS STILL BEING READ. That is
// often a shutdown-ordering problem in the caller, and it is not necessarily
// one: a read that simply took longer than the budget produces the same
// number. Treat it as "these were still in use," not as a diagnosis.
//
// It never unmaps underneath a reader, which is the other half of the same
// decision: [MemoryEnclave.Open] hands back a slice that outlives the enclave's
// lock, and a sweep CAN destroy the enclave behind such a slice. Open's own
// documentation says so; WipeAll is one of the concurrent destroyers it means.
//
// # The return values
//
// They are ORTHOGONAL, and neither implies the other.
//
// The COUNT is the number of enclaves still holding locked memory when the sweep
// finished: those still being read after every pass, plus those whose release
// failed, plus anything that registered mid-sweep and could not be reached. It is
// read from the ledger itself under the lock rather than tallied while sweeping,
// so zero means the ledger was empty at that instant — everything this package
// had allocated was wiped and unmapped — rather than merely that this call was
// happy with the enclaves it happened to see.
//
// The ERROR reports DETECTED CORRUPTION and nothing else. It matches
// [ErrEnclaveCorrupted] through errors.Is, exactly as Destroy's panic value does,
// and it names how many enclaves failed their canary. A corrupt enclave is NOT
// part of the count: its pages were wiped and unmapped like any other, so it is
// not still held — which is precisely why it needs the second return value.
// Without one, the single fact that something wrote into memory it did not own
// would vanish at exit, reported by a zero that looks like success.
//
// So a still-held enclave is reported by the count and never by the error, and
// corruption is reported by the error and never by the count. The corruption
// tally is kept while sweeping rather than read from the ledger — the opposite of
// how the count is derived, and correct for the opposite reason: the ledger can
// express what is still held, but it cannot express what was corrupt and is now
// gone. This call is the only place that fact exists.
//
// Both are worth acting on and they are different actions. A non-zero count is a
// shutdown-ordering bug in the caller. A non-nil error is a memory-safety event
// that has already happened somewhere in the process, and it deserves a log line
// at minimum whatever the count says.
//
// A constructor CAN register while the sweep is running. The sweep re-reads the
// ledger for anything new, up to [maxSweepPasses] times, so an enclave created
// during an orderly shutdown is still reclaimed; a goroutine that never stops
// constructing exhausts the bound and shows up in the count instead of hanging
// the shutdown.
//
// The corollary is that a constructor racing a sweep can return an
// ALREADY-DESTROYED enclave to its caller — the sweep reached it between
// publication and return. That is documented on the constructors, and it is why
// allocating during shutdown is a consumer ordering problem rather than
// something this function can paper over.
//
// A non-zero count is not worth retrying in a tight loop — if a borrow is still
// live, the goroutine holding it has not finished, and calling again immediately
// will skip it again. Callers that must be certain should stop their workers
// first, which is the ordering the count is telling them they got wrong.
//
// It is idempotent and safe to call when nothing is registered. A second call
// reports no corruption: the corrupt enclaves are gone, and the error describes
// what THIS sweep detected rather than a standing condition.
func WipeAll() (int, error) {
	// Held for the whole sweep, so the sequence's odd/even meaning is true for
	// a sweep's entire lifetime rather than only when one runs at a time by
	// luck. See sweepMu.
	sweepMu.Lock()
	defer sweepMu.Unlock()

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

	// Tallied, not read from the ledger, for the reason given above: a corrupt
	// enclave is deregistered like any other, so by the time the count is taken
	// this fact exists nowhere else.
	corrupt := 0
	unwiped := 0

	for pass := 0; pass < maxSweepPasses; pass++ {
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
		//
		// Re-reading everything costs a TryLock per pass on whatever is left, and
		// termination never depended on the seen-set: the pass count is the bound.
		registryMu.Lock()
		batch := make([]*MemoryEnclave, 0, len(live))
		for e := range live {
			batch = append(batch, e)
		}
		registryMu.Unlock()

		if len(batch) == 0 {
			break
		}

		// After the break, so a sweep that finds nothing left pays nothing.
		// See sweepBackoff for why a wait is the right primitive here and why
		// it is a backoff rather than synchronization.
		if pass > 0 {
			time.Sleep(sweepBackoff)
		}

		for _, e := range batch {
			released, err := e.tryReleaseMapping()
			if !released {
				// A reader holds the lock. Left registered AND left eligible, so
				// the next pass tries again — a momentary reader clears within a
				// pass or two. A genuinely long borrow still outlives all
				// [maxSweepPasses] and is skipped and counted, which is correct:
				// memory being actively read must not be unmapped underneath the
				// reader.
				continue
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

			if !releasedPages(err) {
				// The pages are still mapped, so it stays on the ledger.
				continue
			}

			if errors.Is(err, ErrReleasedWithoutWipe) {
				// Wiped-by-unmapping because mprotect was denied. The pages ARE
				// gone, so like corruption this never appears in the count --
				// which is exactly why it needs reporting of its own. A sweep
				// that retried and then saw nil would swallow it entirely, and
				// the denial reaches every other enclave in the process.
				unwiped++
			}

			if errors.Is(err, ErrEnclaveCorrupted) {
				// Wiped and unmapped like any other, and about to be
				// deregistered — so it will not appear in the count. Recorded
				// here or nowhere.
				corrupt++
			}

			deregister(e)
		}
	}

	// The count is the ledger itself, read under the lock, not a tally kept
	// while sweeping. A tally counts what this call decided about the enclaves
	// it happened to see; the ledger is what is actually still held. Those
	// differ exactly when something registered mid-sweep, and reporting zero
	// while such an enclave is alive is a fail-open on the one guarantee this
	// function makes (Codex, PR #20).
	registryMu.Lock()
	remaining := len(live)
	registryMu.Unlock()

	// Both conditions are reported, and both can hold at once. Neither appears
	// in the count -- the pages went back in either case -- which is the whole
	// reason each needs a return value rather than being inferred from a number.
	var errs []error
	if corrupt > 0 {
		// One error however many were corrupt, carrying the count. Joining N
		// copies of a sentinel that has no per-enclave identity would repeat the
		// same sentence N times and say less than the number does.
		errs = append(errs, fmt.Errorf("enclave: %d of the swept enclaves failed canary verification: %w",
			corrupt, ErrEnclaveCorrupted))
	}
	if unwiped > 0 {
		errs = append(errs, fmt.Errorf("enclave: %d of the swept enclaves were unmapped without an in-process wipe because mprotect was denied: %w",
			unwiped, ErrReleasedWithoutWipe))
	}
	if len(errs) > 0 {
		return remaining, errors.Join(errs...)
	}
	return remaining, nil
}
