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
	"sync"
	"sync/atomic"
	"testing"
)

var (
	errTestNil   = errors.New("nil value")
	errTestTaken = errors.New("already installed")
)

// newTestSingleton returns a slot whose default is a fresh int, counting builds.
func newTestSingleton(builds *int, fail *bool) *processSingleton[int] {
	return &processSingleton[int]{
		errNil:   errTestNil,
		errTaken: errTestTaken,
		build: func() (*int, error) {
			*builds++
			if *fail {
				return nil, errors.New("build failed")
			}
			return new(int), nil
		},
	}
}

func TestProcessSingleton_DefaultIsBuiltOnceAndLocksTheSlot(t *testing.T) {
	var builds int
	fail := true
	s := newTestSingleton(&builds, &fail)

	if _, err := s.get(); err == nil {
		t.Fatal("get succeeded through a failing build")
	}
	fail = false
	first, err := s.get()
	if err != nil {
		t.Fatalf("get after a failed build: %v", err)
	}
	again, _ := s.get()
	if again != first || builds != 2 {
		t.Fatalf("builds = %d, same value = %v; want a retry after the failure, then one value", builds, again == first)
	}
	if err := s.install(new(int)); !errors.Is(err, errTestTaken) {
		t.Fatalf("install after the default = %v, want errTaken", err)
	}
}

func TestProcessSingleton_InstallRefusesNilAndLeavesTheSlotEmpty(t *testing.T) {
	var builds int
	fail := false
	s := newTestSingleton(&builds, &fail)

	if err := s.install(nil); !errors.Is(err, errTestNil) {
		t.Fatalf("install(nil) = %v, want errNil", err)
	}
	if v, err := s.get(); err != nil || v == nil || builds != 1 {
		t.Fatalf("get after install(nil) = %v, %v with %d builds; want a built default", v, err, builds)
	}
}

func TestProcessSingleton_InstallWinsOverTheDefaultAndOnlyOnce(t *testing.T) {
	var builds int
	fail := false
	s := newTestSingleton(&builds, &fail)

	first := new(int)
	if err := s.install(first); err != nil {
		t.Fatalf("install = %v", err)
	}
	if err := s.install(new(int)); !errors.Is(err, errTestTaken) {
		t.Fatalf("second install = %v, want errTaken", err)
	}
	got, err := s.get()
	if err != nil || got != first || builds != 0 {
		t.Fatalf("get = %p, %v with %d builds; want the first installed value and no build", got, err, builds)
	}
}

func TestProcessSingleton_ConcurrentGetBuildsOnce(t *testing.T) {
	var builds atomic.Int32
	s := &processSingleton[int]{
		errNil:   errTestNil,
		errTaken: errTestTaken,
		build: func() (*int, error) {
			builds.Add(1)
			return new(int), nil
		},
	}

	const n = 16
	got := make([]*int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err := s.get()
			if err != nil {
				t.Errorf("get = %v", err)
			}
			got[i] = v
		}()
	}
	close(start)
	wg.Wait()

	if b := builds.Load(); b != 1 {
		t.Fatalf("builds = %d, want 1", b)
	}
	for i, v := range got {
		if v == nil || v != got[0] {
			t.Fatalf("goroutine %d saw %p, want %p", i, v, got[0])
		}
	}
}
