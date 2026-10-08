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

func TestProcessSingleton_InstallIsOneShotAndRefusesNil(t *testing.T) {
	var builds int
	var fail bool
	s := newTestSingleton(&builds, &fail)

	if err := s.install(nil); !errors.Is(err, errTestNil) {
		t.Fatalf("install(nil) = %v, want errNil", err)
	}
	v := new(int)
	if err := s.install(v); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := s.install(new(int)); !errors.Is(err, errTestTaken) {
		t.Fatalf("second install = %v, want errTaken", err)
	}
	got, err := s.get()
	if err != nil || got != v {
		t.Fatalf("get = (%p, %v), want the installed value", got, err)
	}
	if builds != 0 {
		t.Fatalf("an installed value still built the default %d times", builds)
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
