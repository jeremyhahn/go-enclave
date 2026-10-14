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
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sweepLog records, in call order, every fakeSweeper.Sweep a test observes.
type sweepLog struct {
	names []string
	ctxs  []context.Context
}

// fakeSweeper is a registered Sweeper with a scripted result. during, when
// set, runs inside Sweep, where backend code runs.
type fakeSweeper struct {
	name   string
	held   int
	err    error
	log    *sweepLog
	during func()
}

func (s *fakeSweeper) Name() string { return s.name }

func (s *fakeSweeper) Sweep(ctx context.Context) (int, error) {
	s.log.names = append(s.log.names, s.name)
	s.log.ctxs = append(s.log.ctxs, ctx)
	if s.during != nil {
		s.during()
	}
	return s.held, s.err
}

// TestWipeAll_SweepsRegisteredBackendsAfterLockedMemory pins the second
// phase: locked memory is reclaimed first, then every registered Sweeper in
// name order under the caller's ctx; held counts add up, and each failure is
// one Backends entry reachable through errors.Is and errors.As.
func TestWipeAll_SweepsRegisteredBackendsAfterLockedMemory(t *testing.T) {
	e, err := newMemory([]byte("reclaimed in phase one"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	log := &sweepLog{}
	errA := &BackendNotRegisteredError{Name: "a backend's own typed error"}
	errC := errors.New("test-sweep-c could not release a session")
	aliveDuringPhaseTwo := true
	registerForTest(t, &fakeSweeper{name: "test-sweep-c", err: errC, log: log})
	registerForTest(t, &fakeSweeper{name: "test-sweep-a", held: 1, err: errA, log: log,
		during: func() { aliveDuringPhaseTwo = e.IsAlive() }})
	registerForTest(t, &fakeSweeper{name: "test-sweep-b", held: 2, log: log})
	registerForTest(t, &fakeBackend{name: "test-sweep-not-a-sweeper"})

	ctx := t.Context()
	n, err := WipeAll(ctx)

	if want := []string{"test-sweep-a", "test-sweep-b", "test-sweep-c"}; !slices.Equal(log.names, want) {
		t.Fatalf("Sweep calls = %q, want %q: one call each, in name order", log.names, want)
	}
	for i, got := range log.ctxs {
		if got != ctx {
			t.Errorf("%s got a ctx other than WipeAll's", log.names[i])
		}
	}
	if aliveDuringPhaseTwo {
		t.Error("a Sweeper ran while locked memory was still unswept: phase two came first")
	}
	if n != 3 {
		t.Errorf("WipeAll count = %d, want 3: the sum of every held count", n)
	}

	var se *SweepError
	if !errors.As(err, &se) {
		t.Fatalf("WipeAll error = %v, want a *SweepError", err)
	}
	want := []BackendSweepFailure{{Backend: "test-sweep-a", Err: errA}, {Backend: "test-sweep-c", Err: errC}}
	if !slices.Equal(se.Backends, want) || se.Corrupt != 0 || se.Unwiped != 0 {
		t.Errorf("SweepError = %+v, want only the failures %+v", se, want)
	}
	if !errors.Is(err, errC) || !errors.Is(err, ErrBackendNotRegistered) {
		t.Error("a failed backend's own error is not reachable through the SweepError")
	}
	var typed *BackendNotRegisteredError
	if !errors.As(err, &typed) || typed != errA {
		t.Error("errors.As did not reach a failed backend's typed error")
	}
	if errors.Is(err, ErrEnclaveCorrupted) || errors.Is(err, ErrReleasedWithoutWipe) {
		t.Error("backend failures alone matched a locked-memory sentinel")
	}
	for _, name := range []string{"test-sweep-a", "test-sweep-c"} {
		if !strings.Contains(err.Error(), strconv.Quote(name)) {
			t.Errorf("Error() = %q, want a line naming %q", err.Error(), name)
		}
	}
}

// TestWipeAll_PassesCtxThroughUnchanged pins that a Sweeper sees exactly the
// ctx WipeAll was given, nil and done included, and is still called under both.
func TestWipeAll_PassesCtxThroughUnchanged(t *testing.T) {
	log := &sweepLog{}
	registerForTest(t, &fakeSweeper{name: "test-sweep-ctx", log: log})

	ctxs := map[string]context.Context{"nil": nil}
	for name, ended := range endedContexts(t) {
		ctxs[name] = ended.ctx
	}
	for name, ctx := range ctxs {
		log.names, log.ctxs = nil, nil
		if n, err := WipeAll(ctx); n != 0 || err != nil {
			t.Errorf("%s ctx: WipeAll = (%d, %v), want (0, nil)", name, n, err)
		}
		if len(log.ctxs) != 1 || log.ctxs[0] != ctx {
			t.Errorf("%s ctx: Sweep calls %d with ctxs %v, want one call with WipeAll's ctx", name, len(log.ctxs), log.ctxs)
		}
	}
}

// TestWipeAll_SnapshotsSweepersOutsideTheRegistryLock pins that Sweep runs
// with the registry unlocked, so it may Register (which takes the write lock),
// and that a backend registered after the snapshot waits for the next WipeAll.
func TestWipeAll_SnapshotsSweepersOutsideTheRegistryLock(t *testing.T) {
	log := &sweepLog{}
	late := &fakeSweeper{name: "test-sweep-late", held: 1, log: log}
	t.Cleanup(func() {
		backendsMu.Lock()
		delete(backends, late.name)
		backendsMu.Unlock()
	})
	registerForTest(t, &fakeSweeper{name: "test-sweep-early", log: log, during: func() {
		if err := Register(late); err != nil && !errors.Is(err, ErrBackendExists) {
			t.Errorf("Register from inside Sweep = %v", err)
		}
	}})

	if n, err := WipeAll(t.Context()); n != 0 || err != nil {
		t.Fatalf("first WipeAll = (%d, %v), want (0, nil)", n, err)
	}
	if want := []string{"test-sweep-early"}; !slices.Equal(log.names, want) {
		t.Fatalf("first sweep called %q, want %q: a backend registered mid-sweep was swept", log.names, want)
	}

	log.names = nil
	if n, err := WipeAll(t.Context()); n != 1 || err != nil {
		t.Fatalf("second WipeAll = (%d, %v), want (1, nil): the late backend's held count", n, err)
	}
	if want := []string{"test-sweep-early", "test-sweep-late"}; !slices.Equal(log.names, want) {
		t.Fatalf("second sweep called %q, want %q", log.names, want)
	}
}

// TestSweepError_BackendFailures pins the error's shape for backend failures:
// one quoted line each after the count lines, and Unwrap returning every
// failure's error in order.
func TestSweepError_BackendFailures(t *testing.T) {
	first, second := errors.New("first cause"), errors.New("second cause")
	se := &SweepError{Unwiped: 1, Backends: []BackendSweepFailure{
		{Backend: "tdx", Err: first},
		{Backend: "se050", Err: second},
	}}

	lines := strings.Split(se.Error(), "\n")
	if len(lines) != 3 {
		t.Fatalf("Error() has %d lines, want 3: %q", len(lines), se.Error())
	}
	if !strings.HasSuffix(lines[0], ErrReleasedWithoutWipe.Error()) {
		t.Errorf("first line = %q, want the Unwiped line", lines[0])
	}
	if want := `enclave: backend "tdx" failed its sweep: first cause`; lines[1] != want {
		t.Errorf("second line = %q, want %q", lines[1], want)
	}
	if want := `enclave: backend "se050" failed its sweep: second cause`; lines[2] != want {
		t.Errorf("third line = %q, want %q", lines[2], want)
	}
	if got := se.Unwrap(); !slices.Equal(got, []error{first, second}) {
		t.Errorf("Unwrap() = %v, want both causes in order", got)
	}
	if !errors.Is(se, ErrReleasedWithoutWipe) || errors.Is(se, ErrEnclaveCorrupted) {
		t.Error("the counts no longer decide the locked-memory sentinels")
	}
}
