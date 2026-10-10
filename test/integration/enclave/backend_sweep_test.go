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
	"strconv"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// WipeAll's second phase: the registered backends that can sweep.

// registerSweeper registers a sweeper under a fresh name with the given
// letter after "sweep-", so the sweepers' names sort in the letters' order.
func registerSweeper(t *testing.T, letter string, held int, err error) *sweepingBackend {
	t.Helper()
	b := &sweepingBackend{name: uniqueBackendName("sweep-" + letter), held: held, err: err}
	if rerr := enclave.Register(b); rerr != nil {
		t.Fatalf("Register(%q): %v", b.name, rerr)
	}
	return b
}

func TestShutdownSweep_WipeAllSweepsEveryRegisteredBackendAndReportsTheFailures(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		errA := errors.New("sweepers: backend a cannot reach its device")
		errB := &enclave.CapabilityError{Backend: "sweep-b", Capability: enclave.CapabilitySweep}

		// Registered out of name order, with a backend that cannot sweep among
		// them: only the sweepers are called, in name order.
		c := registerSweeper(t, "c", 5, nil)
		b := registerSweeper(t, "b", 0, errB)
		a := registerSweeper(t, "a", 2, errA)
		plain := &fakeBackend{name: uniqueBackendName("plain")}
		if err := enclave.Register(plain); err != nil {
			t.Fatalf("Register: %v", err)
		}

		held, err := enclave.WipeAll(context.Background())
		if held != 7 {
			t.Errorf("WipeAll = %d, want 7: what the backends still hold, 2 and 5, and nothing of the ledger", held)
		}
		var se *enclave.SweepError
		if !errors.As(err, &se) {
			t.Fatalf("WipeAll error = %v, want a *SweepError", err)
		}
		for _, s := range []*sweepingBackend{a, b, c} {
			if got := s.calls.Load(); got != 1 {
				t.Errorf("%s was swept %d times, want 1", s.name, got)
			}
		}
		if len(se.Backends) != 2 || se.Backends[0].Backend != a.name || se.Backends[1].Backend != b.name {
			t.Fatalf("SweepError.Backends = %+v, want the failures of %q then %q", se.Backends, a.name, b.name)
		}
		if se.Backends[0].Err != errA || se.Backends[1].Err != error(errB) {
			t.Errorf("SweepError.Backends carry %v and %v, want each backend's own error", se.Backends[0].Err, se.Backends[1].Err)
		}
		if se.Corrupt != 0 || se.Unwiped != 0 {
			t.Errorf("SweepError = %+v, want only backend failures", se)
		}

		// Each backend's error is reachable, the counters' sentinels are not.
		var ce *enclave.CapabilityError
		if !errors.Is(err, errA) || !errors.As(err, &ce) || ce.Capability != enclave.CapabilitySweep {
			t.Errorf("WipeAll error %v does not reach both backends' errors", err)
		}
		if errors.Is(err, enclave.ErrEnclaveCorrupted) || errors.Is(err, enclave.ErrReleasedWithoutWipe) {
			t.Errorf("WipeAll error %v matches a sentinel whose count is zero", err)
		}
		msg := err.Error()
		for _, s := range []*sweepingBackend{a, b} {
			if !strings.Contains(msg, strconv.Quote(s.name)) {
				t.Errorf("error %q does not name the failed backend %s", msg, strconv.Quote(s.name))
			}
		}
		if strings.Contains(msg, strconv.Quote(c.name)) || strings.Contains(msg, plain.name) {
			t.Errorf("error %q names a backend that did not fail", msg)
		}

		// Another sweep is a fresh one, and a backend that has stopped
		// failing leaves the error.
		a.err, b.err = nil, nil
		held, err = enclave.WipeAll(context.Background())
		if err != nil || held != 7 {
			t.Errorf("second WipeAll = %d, %v; want 7 and no error", held, err)
		}
		if a.calls.Load() != 2 || c.calls.Load() != 2 {
			t.Errorf("swept %d and %d times, want 2 each", a.calls.Load(), c.calls.Load())
		}
	})
}

func TestShutdownSweep_ASweepErrorRendersAndUnwrapsWhatItHolds(t *testing.T) {
	boom := errors.New("sweepers: boom")
	se := &enclave.SweepError{
		Corrupt: 2,
		Unwiped: 1,
		Backends: []enclave.BackendSweepFailure{
			{Backend: "first", Err: boom},
			{Backend: "second"},
		},
	}
	msg := se.Error()
	for _, want := range []string{
		"2 of the swept enclaves failed canary verification",
		"1 of the swept enclaves were unmapped without an in-process wipe",
		strconv.Quote("first") + " failed its sweep: " + boom.Error(),
		strconv.Quote("second") + " failed its sweep: <nil>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("SweepError renders %q, want it to contain %q", msg, want)
		}
	}
	if !errors.Is(se, enclave.ErrEnclaveCorrupted) || !errors.Is(se, enclave.ErrReleasedWithoutWipe) || !errors.Is(se, boom) {
		t.Errorf("SweepError does not match the sentinels of its counts and its backend's error")
	}
	if errs := se.Unwrap(); len(errs) != 1 || errs[0] != boom {
		t.Errorf("Unwrap = %v, want only the failure that has an error", errs)
	}

	empty := &enclave.SweepError{}
	if empty.Error() == "" || errors.Is(empty, enclave.ErrEnclaveCorrupted) || errors.Is(empty, enclave.ErrReleasedWithoutWipe) {
		t.Errorf("an empty SweepError renders %q or matches a sentinel", empty.Error())
	}
	if errs := empty.Unwrap(); len(errs) != 0 {
		t.Errorf("an empty SweepError unwraps to %v, want nothing", errs)
	}
}

func TestShutdownSweep_ABackendSweepHoldsTheSweepSlot(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		slow := registerSweeper(t, "slow", 1, nil)
		slow.enter = func(context.Context) {
			close(entered)
			<-release
		}
		freed := false
		free := func() {
			if !freed {
				freed = true
				close(release)
			}
		}
		defer free()

		type result struct {
			held int
			err  error
		}
		done := make(chan result, 1)
		go func() {
			held, err := enclave.WipeAll(context.Background())
			done <- result{held, err}
		}()
		<-entered

		// A sweep that finds the slot taken is turned away without waiting,
		// whether its context is nil or already done.
		// A nil context is the documented non-waiting call.
		if _, err := enclave.WipeAll(nil); !errors.Is(err, enclave.ErrSweepInProgress) {
			t.Errorf("WipeAll(nil) during a sweep: %v, want ErrSweepInProgress", err)
		}
		ended, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := enclave.WipeAll(ended); !errors.Is(err, enclave.ErrSweepInProgress) {
			t.Errorf("WipeAll with an ended context during a sweep: %v, want ErrSweepInProgress", err)
		}

		free()
		if r := <-done; r.err != nil || r.held != 1 {
			t.Errorf("the sweep that held the slot = %d, %v; want 1 and no error", r.held, r.err)
		}
		if got := slow.calls.Load(); got != 1 {
			t.Errorf("the slow backend was swept %d times, want 1: a turned-away sweep must not reach it", got)
		}
	})
}
