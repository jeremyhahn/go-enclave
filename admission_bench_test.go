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
	"testing"
)

// refusalRequestBytes is what the refusal benchmarks ask for: a
// credential-sized allocation, the shape [Allocator] is documented around. It
// is charged at page granularity, so the budget below refuses it.
const refusalRequestBytes = 32

// refusalBudgetBytes is the allocator budget the refusal benchmarks run
// against: one byte, which is below a single page and so admits nothing.
const refusalBudgetBytes = 1

// newRefusedAllocator returns an Allocator that refuses every allocation.
//
// Its budget is refusalBudgetBytes — below a single page — so admission refuses through
// the ordinary predicate, `charge > free`, with no special case. No locked
// memory is ever requested and none is held.
//
// That is not a contrivance to keep the benchmark cheap. Refusal is decided
// BEFORE any locked memory is requested (see [Allocator.reserve]), so an
// allocator that can never allocate executes exactly the same instructions a
// saturated one executes when it refuses. The useful consequence is that these
// benchmarks measure the same path on a host with no RLIMIT_MEMLOCK headroom at
// all, and cannot be perturbed by mlock latency or by the mapping layer.
//
// Identical in INSTRUCTIONS is not identical in CACHELINE STATE, and the
// difference is worth naming because it is the dimension this benchmark is
// about. Nothing here ever writes free, so it stays a read-only line for the
// whole run; a live saturated allocator under a flood has admits and Destroy
// releases doing free.Add concurrently with the refusals. The quiet baseline is
// the deliberate choice: a line nothing else writes is what makes a
// read-modify-write ADDED to the refusal path show up at full amplitude.
//
// What it does NOT cover, so that nobody reads more into a green run than is
// there: the rare [Allocator.budgetSnapshot] fallback, which takes the read
// lock deliberately and only in the overflow window, is never reached from
// here — limit and free are both small and the pair is representable. That is
// the intended coverage. The fallback is not the path a flood drives, and a
// benchmark that entered it would be measuring the exception rather than the
// rule.
// It also PROVES, before any timer starts, that a refusal here is a
// budget-exhaustion refusal and not some other error that happens to be
// non-nil. That check is the point of the function and not a formality: the
// benchmark loops below can only afford to test err against nil, so on its own
// the loop would happily publish timings for an [ErrInvalidSize] early return
// that never reached the budget branch at all — a plausible number measuring
// the wrong path, which is the exact failure mode these benchmarks exist to
// prevent in the code they guard. The documented reproduction runs with
// -run '^$', so no functional test is present to notice on the loop's behalf.
//
// The assertion is on the error's SHAPE, not its presence: the sentinel, the
// concrete type, and the figures inside it. Requested must be the page-rounded
// charge, because a refusal quoting the caller's raw byte count would mean
// admission is accounting in a unit RLIMIT_MEMLOCK cannot be compared to.
func newRefusedAllocator(tb testing.TB) *Allocator {
	tb.Helper()
	a, err := NewAllocator(refusalBudgetBytes)
	if err != nil {
		tb.Fatalf("NewAllocator(%d): %v", refusalBudgetBytes, err)
	}

	e, err := a.NewSized(refusalRequestBytes)
	if e != nil {
		// Nothing to measure if this admitted: destroy it so the probe does
		// not leak locked memory into the run it is validating.
		e.Destroy()
		tb.Fatalf("NewSized(%d) was ADMITTED against a %d-byte budget; the benchmark would time admission, not refusal",
			refusalRequestBytes, refusalBudgetBytes)
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		tb.Fatalf("NewSized(%d) refused with %v, want ErrBudgetExhausted; the benchmark would time some other early return, not the budget branch",
			refusalRequestBytes, err)
	}
	var be *BudgetError
	if !errors.As(err, &be) {
		tb.Fatalf("refusal error is %T, want *BudgetError", err)
	}
	if want := LockedSize(refusalRequestBytes); be.Requested != want {
		tb.Fatalf("BudgetError.Requested = %d, want %d (the page-rounded charge)", be.Requested, want)
	}
	if be.Limit != refusalBudgetBytes {
		tb.Fatalf("BudgetError.Limit = %d, want %d", be.Limit, refusalBudgetBytes)
	}

	return a
}

// BenchmarkRefusalSerial and [BenchmarkRefusalParallel] guard the property that
// the admission refusal path is LOCK-FREE and therefore SCALES with concurrency.
// They exist because that property is otherwise protected only by a doc comment
// and by whoever remembers the argument: a lock reintroduced on this path stays
// functionally correct, so no test in this package would catch it.
//
// # The property
//
// Refusal is what an unauthenticated flood drives. It is the path this type
// exists to make cheap — a bounded, typed [ErrBudgetExhausted] is the whole
// answer to a remote denial-of-service, and it is worth nothing if refusing is
// itself expensive under load. So refusal must be cheap SERIALLY and must not
// degrade when many goroutines refuse at once.
//
// # The mechanism, which is the part a reader has to keep
//
// On refusal the shipped path performs only atomic LOADS of shared state: a
// refusal commits nothing, so there is no compare-and-swap. Concurrent refusers
// therefore share a read-only cacheline, every core keeps it in the shared
// state, and parallel refusal is FASTER per operation than serial refusal.
//
// A read-modify-write on shared state destroys that. A mutex — even
// sync.RWMutex's read side — is an atomic RMW on one shared word, so every
// refuser must take that cacheline exclusively and they serialize on it.
// Parallel refusal stops being faster than serial and becomes SLOWER than it.
// Any atomic Add or CompareAndSwap added to this path does the same thing; the
// defect is the RMW, not the mutex specifically.
//
// # Reference measurements — what a regression looks like
//
// Taken with these two benchmarks on an i5-1145G7 (GOMAXPROCS=8), benchstat
// over 8 paired samples at -benchtime 2s. The right-hand column is the same
// tree with an unconditional mu.RLock/RUnlock around the refusal path's reads
// — the change proposed during #35 review, restored in a throwaway copy purely
// to confirm these benchmarks can see it:
//
//	                    shipped        with RLock       delta
//	RefusalSerial-8     16.99n ± 5%    26.31n ±25%      +54.86%  (p=0.000 n=8)
//	RefusalParallel-8   10.17n ±13%    44.83n ±25%     +340.54%  (p=0.000 n=8)
//
// Allocations are identical in both arms — 24 B/op, 1 alloc/op, the
// [BudgetError] a refusal returns — which is what places the cost in contention
// rather than in allocation.
//
// # Read the RATIO, not the nanoseconds
//
// The absolute figures are host-specific and will not reproduce elsewhere. The
// finding that does reproduce is the relationship between the two benchmarks:
//
//	shipped     parallel / serial = 0.60   (refusing in parallel is CHEAPER)
//	with RLock  parallel / serial = 1.70   (refusers serialize)
//
// Parallel refusal at or below serial refusal is the property. Parallel rising
// above serial is the regression, and it is visible on any host with more than
// one core. Note that serial refusal also gets slower — an uncontended RLock
// still costs two atomics — so a serial-only measurement is not blind to this,
// but it understates it by roughly six times and would not survive being called
// noise. The parallel arm is the one that settles the argument.
//
// # How small a regression this catches
//
// A fair question is whether the ratio rule only catches something as heavy as
// a mutex. It was asked in review, so it was measured rather than argued. The
// smallest possible defect of this kind is one atomic read-modify-write on the
// shared word — `a.free.Add(0)`, semantically a no-op, still a LOCK XADD on
// exactly the line refusals share. Added to the refusal branch, measured
// interleaved against the shipped tree over 8 paired rounds:
//
//	shipped        parallel / serial = 0.75
//	+free.Add(0)   parallel / serial = 1.88      parallel +183.61% (p=0.000 n=8)
//
// So the rule catches the minimal case, and catches it HARDER than the RWMutex
// above (1.88 against 1.70). There is no need for a more sensitive instrument.
//
// That inversion is worth holding on to, because the obvious reasoning gets it
// backwards. Ranking these defects by their SERIAL cost — an RWMutex pair is
// two atomics, a bare Add is one — predicts the Add is the milder of the two
// and might hide under a ratio of 1.0. It is the opposite. The property here is
// contention, and on that axis severity is set by WHICH LINE the
// read-modify-write lands on, not by how many instructions it is:
// sync.RWMutex contends on its own readerCount word, while an Add on free
// contends on the line every refuser is already loading. THE MINIMAL DEFECT OF
// THIS CLASS IS THE WORST ONE. Anyone arriving here with "we validated this
// against a mutex, and I am only adding one atomic" has the argument exactly
// inverted.
//
// (Those figures came from a busier machine than the reference table — shipped
// serial read 26.11n there against 16.99n above. That is exactly why the rule
// is a ratio: the interleaved pairing survives a loaded host, and the absolute
// numbers do not.)
//
// One real limit, since the guard should be honest about its own reach: each
// iteration allocates the [BudgetError] it measures, and that allocation is
// itself shared-resource traffic, so the parallel arm cannot scale to the core
// count and the healthy ratio sits near 0.6-0.75 rather than near 1/N. Hoisting
// the allocation would widen the margin and stop measuring the real refusal
// path, which is the wrong trade. The margin that remains is ample for what
// this guards, as the two mutation results above show.
//
// Issue #47, which asked for these benchmarks, quotes different figures —
// 17.12n/19.71n shipped against 24.39n/77.83n locked, +294.88% parallel. That
// measurement came from a throwaway harness that was not kept, so it is history
// rather than a baseline for this code: its arms are not these functions. The
// direction, the significance and the scaling flip agree; the magnitudes do not
// (it saw locked-parallel at 3.2x locked-serial, this harness sees 1.70x). If a
// number here has to be trusted, re-measure rather than trusting either set.
//
// # Reproducing
//
//	go test -run '^$' -bench 'Refusal' -benchtime 2s -count 8 . > new.txt
//	benchstat old.txt new.txt
//
// # Deliberately not a CI gate
//
// No threshold is wired into CI, and one should not be. This repository's
// runners are shared and contended, and a nanosecond threshold on a contended
// runner fails for reasons that have nothing to do with the code — which
// retires the signal by teaching everyone to ignore it. The value here is that
// the measurement exists, is reproducible, and settles the question with
// benchstat instead of by argument. Run it when changing the refusal path;
// paste the before/after into the PR.
func BenchmarkRefusalSerial(b *testing.B) {
	a := newRefusedAllocator(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.NewSized(refusalRequestBytes); err == nil {
			// The benchmark is measuring the wrong path entirely if this
			// fires, so it fails rather than reporting a fast admission.
			b.Fatal("NewSized was admitted; the benchmark is not measuring refusal")
		}
	}
}

// BenchmarkRefusalParallel measures the same refusal against ONE shared
// Allocator from GOMAXPROCS goroutines at once. It is the arm that can see the
// regression [BenchmarkRefusalSerial] documents: a lock on the refusal path
// costs serial refusal something modest and costs parallel refusal several
// times over, and a benchmark that only measured serial refusal would be worth
// nothing for this purpose.
//
// The allocator is shared deliberately — the contended cacheline is the thing
// under test, so a per-goroutine allocator would measure nothing at all. For
// the same reason the loop body writes to no shared variable: a sink the
// goroutines all stored through would be a shared RMW of the benchmark's own
// making, and would mask the effect it is here to detect. Nothing is elided for
// want of a sink: NewSized is well past the inlining budget, and its result is
// branched on. A future compiler that inlined far enough to see that only
// nilness is consumed could in principle drop the [BudgetError] allocation, but
// not the atomic loads and the refusal decision, which are what is being
// measured.
func BenchmarkRefusalParallel(b *testing.B) {
	a := newRefusedAllocator(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := a.NewSized(refusalRequestBytes); err == nil {
				// b.Fatal is not usable from a RunParallel goroutine; Error
				// marks the benchmark failed, which is what a reader needs.
				b.Error("NewSized was admitted; the benchmark is not measuring refusal")
				return
			}
		}
	})
}
