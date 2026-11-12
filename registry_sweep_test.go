package enclave

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// drainSweepWake empties the sweep wake-up channel and reports whether it
// held a token.
func drainSweepWake() bool {
	select {
	case <-sweepWake:
		return true
	default:
		return false
	}
}

// isolateSweepWake starts a test with an empty wake-up channel and
// sweepWaiting cleared, and restores both when it ends.
func isolateSweepWake(t *testing.T) {
	t.Helper()
	waiting := sweepWaiting.Load()
	hadToken := drainSweepWake()
	sweepWaiting.Store(false)
	t.Cleanup(func() {
		drainSweepWake()
		sweepWaiting.Store(waiting)
		if hadToken {
			wakeSweep()
		}
	})
}

// isolateSweepSlot starts a test with a free sweep slot and no admission
// hook, and restores both when it ends.
func isolateSweepSlot(t *testing.T) {
	t.Helper()
	hook := sweepAdmissionWaitForTest
	held := false
	select {
	case <-sweepSlot:
		held = true
	default:
	}
	sweepAdmissionWaitForTest = nil
	t.Cleanup(func() {
		select {
		case <-sweepSlot:
		default:
		}
		if held {
			sweepSlot <- struct{}{}
		}
		sweepAdmissionWaitForTest = hook
	})
}

func TestRegistrySweepWakeSweepCoalesces(t *testing.T) {
	isolateSweepWake(t)

	done := make(chan struct{})
	go func() {
		wakeSweep()
		wakeSweep()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wakeSweep blocked on a full channel")
	}
	if !drainSweepWake() {
		t.Fatal("wakeSweep left no token")
	}
	if drainSweepWake() {
		t.Fatal("two wakeSweep calls left more than one token")
	}
}

func TestRegistrySweepUnholdWakes(t *testing.T) {
	tests := []struct {
		name    string
		holders int32
		waiting bool
		want    bool
	}{
		{name: "last holder, sweep waiting", holders: 1, waiting: true, want: true},
		{name: "last holder, no sweep waiting", holders: 1, waiting: false, want: false},
		{name: "holders remain, sweep waiting", holders: 2, waiting: true, want: false},
		{name: "holders remain, no sweep waiting", holders: 2, waiting: false, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolateSweepWake(t)
			sweepWaiting.Store(tc.waiting)
			e := &memoryState{}
			e.holders.Store(tc.holders)

			e.unhold()

			if got := e.holders.Load(); got != tc.holders-1 {
				t.Fatalf("holders = %d, want %d", got, tc.holders-1)
			}
			if got := drainSweepWake(); got != tc.want {
				t.Fatalf("woke = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRegistrySweepAdmitFreeSlot(t *testing.T) {
	isolateSweepSlot(t)
	if !admitSweep(nil) { //nolint:staticcheck // a nil ctx is a documented input
		t.Fatal("admitSweep(nil) on a free slot = false")
	}
	if len(sweepSlot) != 1 {
		t.Fatal("admitSweep did not take the slot")
	}
}

func TestRegistrySweepAdmitHeldSlotNilContext(t *testing.T) {
	isolateSweepSlot(t)
	sweepSlot <- struct{}{}
	var hooked atomic.Bool
	sweepAdmissionWaitForTest = func() { hooked.Store(true) }

	if admitSweep(nil) { //nolint:staticcheck // a nil ctx is a documented input
		t.Fatal("admitSweep(nil) on a held slot = true")
	}
	if hooked.Load() {
		t.Fatal("admitSweep(nil) waited on a held slot")
	}
}

func TestRegistrySweepAdmitCancelledWhileWaiting(t *testing.T) {
	isolateSweepSlot(t)
	sweepSlot <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sweepAdmissionWaitForTest = cancel

	if admitSweep(ctx) {
		t.Fatal("admitSweep with a context cancelled while waiting = true")
	}
	if len(sweepSlot) != 1 {
		t.Fatal("admitSweep changed the held slot")
	}
}

func TestRegistrySweepAdmitSlotFreedWhileWaiting(t *testing.T) {
	isolateSweepSlot(t)
	sweepSlot <- struct{}{}
	sweepAdmissionWaitForTest = func() { <-sweepSlot }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !admitSweep(ctx) {
		t.Fatal("admitSweep with the slot freed while waiting = false")
	}
	if len(sweepSlot) != 1 {
		t.Fatal("admitSweep did not take the freed slot")
	}
}

// trackState puts e on the named ledgers and removes it from all three
// ledgers when the test ends.
func trackState(t *testing.T, e *memoryState, onLive, onOrphans bool) {
	t.Helper()
	registryMu.Lock()
	if onLive {
		live[e] = struct{}{}
	}
	if onOrphans {
		orphans[e] = struct{}{}
	}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		delete(live, e)
		delete(orphans, e)
		delete(corruptNoted, e)
		registryMu.Unlock()
	})
}

func ledgers(e *memoryState) (onLive, onOrphans, noted bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	_, onLive = live[e]
	_, onOrphans = orphans[e]
	_, noted = corruptNoted[e]
	return onLive, onOrphans, noted
}

func TestRegistrySweepSettleRelease(t *testing.T) {
	refusal := &pagesHeldError{err: errors.New("pages still locked")}
	tests := []struct {
		name         string
		err          error
		orphan       bool
		wantReleased bool
		wantNoted    bool
	}{
		{name: "nil error, live", err: nil, wantReleased: true},
		{name: "nil error, orphan", err: nil, orphan: true, wantReleased: true},
		{name: "released without wipe", err: ErrReleasedWithoutWipe, wantReleased: true},
		{name: "corrupted", err: fmt.Errorf("wipe: %w", ErrEnclaveCorrupted), wantReleased: true, wantNoted: true},
		{name: "refusal", err: refusal, wantReleased: false},
		{name: "corrupted refusal", err: &pagesHeldError{err: ErrEnclaveCorrupted}, wantReleased: false, wantNoted: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			e := &memoryState{release: func() { calls.Add(1) }}
			trackState(t, e, !tc.orphan, tc.orphan)

			for i := range 2 {
				if got := settleRelease(e, tc.err); got != tc.wantReleased {
					t.Fatalf("call %d: settleRelease = %v, want %v", i+1, got, tc.wantReleased)
				}
			}

			onLive, onOrphans, noted := ledgers(e)
			if tc.wantReleased {
				if onLive || onOrphans {
					t.Fatalf("released state still on a ledger: live=%v orphans=%v", onLive, onOrphans)
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("release ran %d times, want 1", got)
				}
			} else {
				if onLive != !tc.orphan || onOrphans != tc.orphan {
					t.Fatalf("refused state moved: live=%v orphans=%v", onLive, onOrphans)
				}
				if got := calls.Load(); got != 0 {
					t.Fatalf("release ran %d times on a refusal, want 0", got)
				}
			}
			if noted != tc.wantNoted {
				t.Fatalf("corruptNoted = %v, want %v", noted, tc.wantNoted)
			}
		})
	}
}

func TestRegistrySweepSettleReleaseNilRelease(t *testing.T) {
	e := &memoryState{}
	trackState(t, e, true, false)
	if !settleRelease(e, nil) {
		t.Fatal("settleRelease(nil release, nil error) = false")
	}
	if onLive, _, _ := ledgers(e); onLive {
		t.Fatal("released state still live")
	}
}

// sweepFake is a Sweeper that reports a fixed count and error.
type sweepFake struct {
	name  string
	held  int
	err   error
	calls atomic.Int32
}

func (f *sweepFake) Name() string { return f.name }

func (f *sweepFake) Sweep(context.Context) (int, error) {
	f.calls.Add(1)
	return f.held, f.err
}

func TestRegistrySweepBackends(t *testing.T) {
	errA := errors.New("sweep-a failed")
	errC := errors.New("sweep-c failed")
	fakes := []*sweepFake{
		{name: "sweep-test-a", held: 2, err: errA},
		{name: "sweep-test-b", held: -5},
		{name: "sweep-test-c", held: 3, err: errC},
		{name: "sweep-test-d", held: 0},
	}
	baseHeld, _ := sweepBackends(context.Background())
	for _, f := range fakes {
		registerForTest(t, f)
	}

	held, failures := sweepBackends(context.Background())

	if got := held - baseHeld; got != 5 {
		t.Fatalf("held = %d over the baseline, want 5", got)
	}
	byName := map[string]error{}
	for _, f := range failures {
		if strings.HasPrefix(f.Backend, "sweep-test-") {
			byName[f.Backend] = f.Err
		}
	}
	if len(byName) != 2 || !errors.Is(byName["sweep-test-a"], errA) || !errors.Is(byName["sweep-test-c"], errC) {
		t.Fatalf("failures = %v, want sweep-test-a and sweep-test-c", failures)
	}
	for _, f := range fakes {
		if got := f.calls.Load(); got != 1 {
			t.Fatalf("%s swept %d times, want 1", f.name, got)
		}
	}
}
