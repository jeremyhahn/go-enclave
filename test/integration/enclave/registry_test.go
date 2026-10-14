// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers registry.go: WipeAll, the shutdown sweep a BINARY runs at exit. Every
// test owns its process (the ledger is process-global), so each count it reads
// is exactly its own enclaves.

// TestShutdownSweep_WipeAllReclaimsEverythingAndLeavesNoResidue places one secret in every
// kind of enclave a process accumulates and requires one WipeAll to leave a
// zero count, no error, no readable copy, no locked memory, every enclave
// destroyed, reservations returned, and the sealers wiped (ErrSealerWiped).
func TestShutdownSweep_WipeAllReclaimsEverythingAndLeavesNoResidue(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		n := newNeedle(t)
		page := enclave.LockedSize(1)
		alloc, err := enclave.NewAllocator(8 * page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		var held []enclave.ByteAccess
		frozen := enclaveFromNeedle(t, n)
		if err := frozen.(enclave.Freezer).Freeze(); err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		held = append(held, frozen)

		src := heapBytes(needleLen)
		n.fill(src)
		constructed, err := enclave.NewMemory(src)
		if err != nil {
			t.Fatalf("NewMemory: %v", err)
		}
		held = append(held, constructed)

		admitted, err := alloc.NewSized(needleLen)
		if err != nil {
			t.Fatalf("Allocator.NewSized: %v", err)
		}
		if err := admitted.WithBytes(func(b []byte) error { n.fill(b); return nil }); err != nil {
			t.Fatalf("filling: %v", err)
		}
		held = append(held, admitted)

		var sealedValues []enclave.Sealed
		for _, mode := range sealerModes {
			s, err := enclave.NewSealer(providerOption(enclave.NewSoftwareProvider(), mode))
			if err != nil {
				t.Fatalf("NewSealer(%v): %v", mode, err)
			}
			v := sealNeedle(t, ctx, s, n)
			sealedValues = append(sealedValues, v)
			o, err := openInAllocator(t, ctx, v, alloc)
			if err != nil {
				t.Fatalf("OpenIn(%v): %v", mode, err)
			}
			held = append(held, o)
		}

		var where []uintptr
		for _, e := range held {
			where = append(where, dataAddr(t, e))
		}
		hits, scanned := sweep(t, n)
		requireHitsExactly(t, "before the sweep, one copy per enclave", hits, scanned, where...)
		if alloc.InUse() != 3*page {
			t.Fatalf("allocator InUse = %d before the sweep, want %d", alloc.InUse(), 3*page)
		}

		ctxDL, cancel := context.WithTimeout(ctx, 30*time.Second)
		count, err := enclave.WipeAll(ctxDL)
		cancel()
		if count != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", count, err)
		}

		hits, scanned = sweep(t, n)
		requireHitsExactly(t, "after WipeAll", hits, scanned)
		if got := lockedVMAs(readSmaps(t)); len(got) != 0 {
			t.Errorf("after WipeAll %d locked mapping(s) remain; first: %s", len(got), got[0])
		}
		if got := vmLck(t); got != 0 {
			t.Errorf("after WipeAll VmLck = %d, want 0", got)
		}
		if alloc.InUse() != 0 {
			t.Errorf("after WipeAll allocator InUse = %d, want 0: the sweep did not return the reservations", alloc.InUse())
		}
		for i, e := range held {
			if e.IsAlive() {
				t.Errorf("enclave %d alive after WipeAll", i)
			}
			if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("enclave %d: WithBytes after WipeAll = %v, want ErrEnclaveDestroyed", i, err)
			}
			if err := e.Destroy(); err != nil {
				t.Errorf("enclave %d: Destroy after WipeAll = %v, want nil (already reclaimed)", i, err)
			}
		}
		for _, v := range sealedValues {
			if err := v.Openable(); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Errorf("Openable after WipeAll = %v, want ErrSealerWiped", err)
			}
		}
		if count, err := enclave.WipeAll(ctx); count != 0 || err != nil {
			t.Fatalf("a second WipeAll = (%d, %v), want (0, nil)", count, err)
		}
	})
}

// TestShutdownSweep_WipeAllWaitsForLiveBorrowsUntilItsDeadline: with a borrow held and a
// deadline, WipeAll reclaims everything else, counts the borrowed enclave, and
// the borrower still reads its material intact. With no deadline, a second
// sweep waits for the borrow to end and then reclaims it. No timing involved:
// the borrow is held until after the deadline-bounded sweep returns.
func TestShutdownSweep_WipeAllWaitsForLiveBorrowsUntilItsDeadline(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		n := newNeedle(t)
		borrowed := enclaveFromNeedle(t, n)
		others := []enclave.ByteAccess{enclaveFromNeedle(t, newNeedle(t)), enclaveFromNeedle(t, newNeedle(t))}
		page := enclave.LockedSize(needleLen)

		entered := make(chan struct{})
		release := make(chan struct{})
		backgroundSweep := make(chan sweepResult, 1)
		borrowDone := make(chan error, 1)
		var intactWhileHeld, sweepReturnedWhileHeld bool
		go func() {
			borrowDone <- borrowed.WithBytes(func(b []byte) error {
				close(entered)
				<-release
				intactWhileHeld = n.equals(b)
				select {
				case <-backgroundSweep:
					sweepReturnedWhileHeld = true
				default:
				}
				return nil
			})
		}()
		<-entered

		// The deadline is the test's to end, and only once the sweep is shown
		// WAITING on the borrow: it consults Err only after a full pass that
		// left something held, immediately before it waits.
		dl := newManualDeadline()
		bounded := make(chan sweepResult, 1)
		go func() {
			c, e := enclave.WipeAll(dl)
			bounded <- sweepResult{c, e}
		}()
		requireWaiting(t, "a deadline-bounded sweep before its deadline", dl.waiting, bounded)
		dl.expire()
		r := <-bounded
		count, err := r.count, r.err
		if count != 1 || err != nil {
			t.Fatalf("WipeAll with a borrow held past its deadline = (%d, %v), want (1, nil)", count, err)
		}
		for i, e := range others {
			if e.IsAlive() {
				t.Errorf("unborrowed enclave %d survived the sweep", i)
			}
		}
		if !borrowed.IsAlive() {
			t.Fatalf("the borrowed enclave was reclaimed under its reader")
		}
		if got := vmLck(t); got != page {
			t.Errorf("VmLck = %d with only the borrowed enclave left, want %d", got, page)
		}

		bg, waiting := errObservingContext(context.Background())
		go func() {
			c, e := enclave.WipeAll(bg)
			backgroundSweep <- sweepResult{c, e}
		}()
		// Released only once the sweep has met the held borrow and is about
		// to wait for it, so the check inside the borrow below sees a sweep
		// that had to wait.
		requireWaiting(t, "a context.Background sweep", waiting, backgroundSweep)
		close(release)
		if err := <-borrowDone; err != nil {
			t.Fatalf("the borrow returned %v", err)
		}
		if !intactWhileHeld {
			t.Fatalf("the borrowed material changed while the sweeps ran")
		}
		if sweepReturnedWhileHeld {
			t.Fatalf("a context.Background sweep returned while a borrow it owed was still live")
		}
		if r := <-backgroundSweep; r.count != 0 || r.err != nil {
			t.Fatalf("the waiting sweep = (%d, %v), want (0, nil)", r.count, r.err)
		}
		if borrowed.IsAlive() || vmLck(t) != 0 {
			t.Fatalf("after the borrow ended: IsAlive %t, VmLck %d; want reclaimed", borrowed.IsAlive(), vmLck(t))
		}
		hits, scanned := sweep(t, n)
		requireHitsExactly(t, "after the waiting sweep reclaimed the borrowed enclave", hits, scanned)
	})
}

// manualDeadline is a context whose deadline the TEST decides: it ends when
// expire is called, never by a clock, so a test can order "the library is
// waiting" before "the deadline passed" instead of hoping a timer lands
// between them. Done's first call closes observed, which is how a test learns
// the library has started selecting on it.
type manualDeadline struct {
	context.Context
	once     sync.Once
	observed chan struct{}
	errOnce  sync.Once
	waiting  chan struct{}
	done     chan struct{}
	expired  atomic.Bool
}

func newManualDeadline() *manualDeadline {
	return &manualDeadline{Context: context.Background(), observed: make(chan struct{}), waiting: make(chan struct{}), done: make(chan struct{})}
}

func (c *manualDeadline) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.done
}

func (c *manualDeadline) Err() error {
	c.errOnce.Do(func() { close(c.waiting) })
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *manualDeadline) expire() {
	c.expired.Store(true)
	close(c.done)
}

// requireWaiting blocks until a sweep consults ctx.Err, which WipeAll does only
// when it is about to wait for a held borrow, and fails if the sweep returns
// first.
func requireWaiting(t *testing.T, what string, waiting <-chan struct{}, res <-chan sweepResult) {
	t.Helper()
	select {
	case <-waiting:
	case r := <-res:
		t.Fatalf("%s returned (%d, %v) without waiting for a borrow it owed", what, r.count, r.err)
	}
}

// errObservingContext wraps parent so that the first call to Err closes the
// returned channel.
func errObservingContext(parent context.Context) (context.Context, <-chan struct{}) {
	c := &observedErr{Context: parent, waiting: make(chan struct{})}
	return c, c.waiting
}

type observedErr struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *observedErr) Err() error {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Err()
}

type sweepResult struct {
	count int
	err   error
}

// TestShutdownSweep_WipeAllTurnsAwayAConcurrentCaller: while one sweep runs — held open by a
// borrow it is waiting for — a second caller whose context ends is turned away
// with ErrSweepInProgress and the CURRENT count, having swept nothing, whether
// its context had already ended on arrival or reached its deadline while
// waiting to be admitted. The running sweep then finishes and reports to its
// own caller.
func TestShutdownSweep_WipeAllTurnsAwayAConcurrentCaller(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		e := enclaveFromNeedle(t, newNeedle(t))
		entered := make(chan struct{})
		release := make(chan struct{})
		borrowDone := make(chan error, 1)
		go func() {
			borrowDone <- e.WithBytes(func([]byte) error {
				close(entered)
				<-release
				return nil
			})
		}()
		<-entered

		first := make(chan sweepResult, 1)
		bg, waiting := errObservingContext(context.Background())
		go func() {
			c, err := enclave.WipeAll(bg)
			first <- sweepResult{c, err}
		}()
		// The first sweep is admitted and waiting on the borrow: it holds the
		// sweep slot from here until the borrow ends.
		requireWaiting(t, "the first sweep", waiting, first)

		// A caller whose context has already ended is turned away at once,
		// with the current count, rather than waiting or sweeping.
		ended, cancel := context.WithCancel(context.Background())
		cancel()
		count, err := enclave.WipeAll(ended)
		if !errors.Is(err, enclave.ErrSweepInProgress) {
			t.Fatalf("a caller with an ended context while a sweep runs = (%d, %v), want ErrSweepInProgress", count, err)
		}
		if count != 1 {
			t.Fatalf("turned-away caller's count = %d, want 1 (the current count)", count)
		}

		// A second caller whose deadline passes WHILE it waits to be admitted.
		// Admission selects on Done only when the slot is taken, so observing
		// Done proves this caller was waiting, not refused on arrival.
		dl := newManualDeadline()
		second := make(chan sweepResult, 1)
		go func() {
			c, e := enclave.WipeAll(dl)
			second <- sweepResult{c, e}
		}()
		<-dl.observed
		dl.expire()
		r := <-second
		count, err = r.count, r.err
		if count != 1 || !errors.Is(err, enclave.ErrSweepInProgress) {
			t.Fatalf("a deadline-bounded second caller = (%d, %v), want (1, ErrSweepInProgress)", count, err)
		}
		var se *enclave.SweepError
		if errors.As(err, &se) {
			t.Fatalf("ErrSweepInProgress is an admission result, not a finding; got a SweepError %v", se)
		}
		if !e.IsAlive() {
			t.Fatalf("a turned-away caller reclaimed something")
		}

		close(release)
		if err := <-borrowDone; err != nil {
			t.Fatalf("the borrow returned %v", err)
		}
		if r := <-first; r.count != 0 || r.err != nil {
			t.Fatalf("the running sweep = (%d, %v), want (0, nil)", r.count, r.err)
		}
		if e.IsAlive() {
			t.Fatalf("the running sweep did not reclaim the enclave once its borrow ended")
		}
	})
}

// TestShutdownSweep_WipeAllReportsCanaryCorruptionWithoutPanicking simulates a one-byte
// underflow and requires the sweep to reclaim and wipe the enclave and report a
// SweepError counting one corrupt enclave (ErrEnclaveCorrupted only), without
// panicking. Healthy enclaves are unaffected, and a later sweep is clean.
func TestShutdownSweep_WipeAllReportsCanaryCorruptionWithoutPanicking(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		n := newNeedle(t)
		corrupt := enclaveFromNeedle(t, n)
		healthy := enclaveFromNeedle(t, newNeedle(t))
		underflowOneByte(t, corrupt)

		count, err := enclave.WipeAll(context.Background())
		var se *enclave.SweepError
		if count != 0 || !errors.As(err, &se) {
			t.Fatalf("WipeAll over a corrupted enclave = (%d, %v), want (0, a *SweepError)", count, err)
		}
		if se.Corrupt != 1 || se.Unwiped != 0 {
			t.Fatalf("SweepError = %+v, want {Corrupt:1 Unwiped:0}", *se)
		}
		if msg := se.Error(); !strings.Contains(msg, "1") || !strings.Contains(msg, "canary") {
			t.Errorf("SweepError message %q does not report the one corrupted enclave", msg)
		}
		if !errors.Is(err, enclave.ErrEnclaveCorrupted) || errors.Is(err, enclave.ErrReleasedWithoutWipe) {
			t.Fatalf("SweepError matches ErrEnclaveCorrupted %t, ErrReleasedWithoutWipe %t; want true, false",
				errors.Is(err, enclave.ErrEnclaveCorrupted), errors.Is(err, enclave.ErrReleasedWithoutWipe))
		}
		if corrupt.IsAlive() || healthy.IsAlive() {
			t.Fatalf("after the sweep: corrupt alive %t, healthy alive %t; want both reclaimed", corrupt.IsAlive(), healthy.IsAlive())
		}
		hits, scanned := sweep(t, n)
		requireHitsExactly(t, "the corrupted enclave's material after the sweep", hits, scanned)
		if count, err := enclave.WipeAll(context.Background()); count != 0 || err != nil {
			t.Fatalf("the next WipeAll = (%d, %v), want (0, nil): a reclaimed corruption is not reported twice", count, err)
		}
	})
}

// TestShutdownSweep_DestroyReturnsCanaryCorruptionAfterWiping: on the same simulated
// underflow, Destroy wipes the material, releases the pages and RETURNS an
// error matching ErrEnclaveCorrupted without panicking; the next WipeAll
// reports the detection once more, and the one after it is clean.
func TestShutdownSweep_DestroyReturnsCanaryCorruptionAfterWiping(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		n := newNeedle(t)
		e := enclaveFromNeedle(t, n)
		underflowOneByte(t, e)

		var derr error
		recovered := func() (r any) {
			defer func() { r = recover() }()
			derr = e.Destroy()
			return nil
		}()
		if recovered != nil {
			t.Fatalf("Destroy of a corrupted enclave panicked with %v, want a returned error", recovered)
		}
		if !errors.Is(derr, enclave.ErrEnclaveCorrupted) {
			t.Fatalf("Destroy of a corrupted enclave = %v, want an error matching ErrEnclaveCorrupted", derr)
		}
		if e.IsAlive() {
			t.Fatalf("the corrupted enclave is alive after Destroy")
		}
		if got := vmLck(t); got != 0 {
			t.Fatalf("VmLck = %d after Destroy, want 0: the pages were not released", got)
		}
		hits, scanned := sweep(t, n)
		requireHitsExactly(t, "the corrupted enclave's material after Destroy", hits, scanned)
		var se *enclave.SweepError
		if count, err := enclave.WipeAll(context.Background()); count != 0 || !errors.As(err, &se) || se.Corrupt != 1 {
			t.Fatalf("WipeAll = (%d, %v), want (0, SweepError{Corrupt:1}): Destroy's detection must reach the next sweep", count, err)
		}
		if count, err := enclave.WipeAll(context.Background()); count != 0 || err != nil {
			t.Fatalf("the next WipeAll = (%d, %v), want (0, nil)", count, err)
		}
	})
}

// underflowOneByte writes the canary's last byte, just before the data, through
// the writable pages of an unfrozen sized enclave, as a consumer's off-by-one
// underflow would. A frozen enclave would fault instead.
func underflowOneByte(t *testing.T, e enclave.ByteAccess) {
	t.Helper()
	if err := e.WithBytes(func(b []byte) error {
		p := (*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(b)), -1)) //#nosec G103 -- deliberate underflow to corrupt the canary
		*p ^= 0xff
		return nil
	}); err != nil {
		t.Fatalf("writing before the enclave's data: %v", err)
	}
}

// TestShutdownSweep_RefusedCleanupLeavesAnOrphanTheSweepReclaims: construction fails (the
// freeze is refused) and so does its rollback's unmap. The library must keep
// the mapping — on the orphan ledger, counted by WipeAll — refund an admitted
// charge for pages it managed to unlock, keep the charge for pages still
// locked, and reclaim everything, refunding exactly once, when the refusal
// lifts.
func TestShutdownSweep_RefusedCleanupLeavesAnOrphanTheSweepReclaims(t *testing.T) {
	const n = 64
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, mappingLen(n))
		page := enclave.LockedSize(n)
		a, err := enclave.NewAllocator(16 * page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		material := func() []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i + 1)
			}
			return b
		}

		// Unlocked but still mapped: the charge goes back at once.
		f.refuseProt(unix.SYS_MPROTECT, unix.EPERM, unix.PROT_READ)
		f.refuse(unix.SYS_MUNMAP, unix.ENOMEM, 0)
		if _, err := a.New(material()); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Fatalf("Allocator.New with the freeze and the rollback's unmap refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		requireRefused(t, f, unix.SYS_MPROTECT)
		requireRefused(t, f, unix.SYS_MUNMAP)
		if used := a.InUse(); used != 0 {
			t.Errorf("InUse = %d with only an unlocked mapping left, want 0 (it pins no locked memory)", used)
		}
		if c, err := enclave.WipeAll(context.Background()); c != 1 || err != nil {
			t.Errorf("WipeAll with the unmap still refused = (%d, %v), want (1, nil): the orphan must be counted", c, err)
		}

		// Still locked: the charge is kept until the pages actually go.
		f.refuse(unix.SYS_MUNLOCK, unix.EPERM, 0)
		if _, err := a.New(material()); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Fatalf("Allocator.New with munlock refused too = %v, want ErrLockedMemoryUnavailable", err)
		}
		requireRefused(t, f, unix.SYS_MUNLOCK)
		if used := a.InUse(); used != page {
			t.Errorf("InUse = %d with a still-locked orphan, want %d (the charge stays until the pages go)", used, page)
		}

		f.allow(unix.SYS_MPROTECT)
		f.allow(unix.SYS_MUNLOCK)
		f.allow(unix.SYS_MUNMAP)
		if c, err := enclave.WipeAll(context.Background()); c != 0 || err != nil {
			t.Fatalf("WipeAll once the refusals lifted = (%d, %v), want (0, nil)", c, err)
		}
		if used := a.InUse(); used != 0 {
			t.Errorf("InUse = %d after the orphans were reclaimed, want 0 (refunded exactly once)", used)
		}
		if avail := a.Available(); avail != 16*page {
			t.Errorf("Available = %d, want the whole budget %d: a refund was lost or doubled", avail, 16*page)
		}
	})
}

// TestShutdownSweep_SweepErrorRendersEveryValue: SweepError is exported, so a caller can
// build any value of it. The zero value still renders, a value with both
// findings reports both, and it matches only the sentinels its counts earn.
func TestShutdownSweep_SweepErrorRendersEveryValue(t *testing.T) {
	if msg := (&enclave.SweepError{}).Error(); !strings.HasPrefix(msg, "enclave: ") {
		t.Errorf("SweepError{}.Error() = %q, want a message in the package's voice", msg)
	}
	both := &enclave.SweepError{Corrupt: 1, Unwiped: 2}
	if msg := both.Error(); !strings.Contains(msg, "canary") || !strings.Contains(msg, "without") {
		t.Errorf("SweepError{Corrupt:1 Unwiped:2}.Error() = %q, want both findings", msg)
	}
	if errors.Is(&enclave.SweepError{Unwiped: 1}, enclave.ErrEnclaveCorrupted) {
		t.Error("a SweepError with only unwiped releases matches ErrEnclaveCorrupted")
	}
}
