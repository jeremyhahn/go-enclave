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
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// registryRace records one run of goroutines that register, re-register,
// look up and list backends at once, sorted by the property each finding
// bears on.
type registryRace struct {
	names      []string
	winners    []atomic.Pointer[fakeBackend] // the backend whose Register returned nil, per name
	duplicates atomic.Int64                  // Register calls refused with *BackendExistsError

	mu        sync.Mutex
	once      []error // a name registered twice, or a refusal of the wrong kind
	snapshots []error // a BackendNames result that breaks its contract
	lookups   []error // a Lookup that failed after its Register returned nil
}

func (r *registryRace) fail(list *[]error, format string, args ...any) {
	r.mu.Lock()
	*list = append(*list, fmt.Errorf(format, args...))
	r.mu.Unlock()
}

// register registers a fresh backend under names[i] and records the outcome.
func (r *registryRace) register(i int) {
	name := r.names[i]
	b := &fakeBackend{name: name}
	err := Register(b)
	var exists *BackendExistsError
	switch {
	case err == nil:
		if !r.winners[i].CompareAndSwap(nil, b) {
			r.fail(&r.once, "Register(%q) returned nil twice", name)
		}
		if err := lookupIs(b); err != nil {
			r.fail(&r.lookups, "after its Register: %w", err)
		}
	case errors.As(err, &exists) && exists.Name == name:
		r.duplicates.Add(1)
	default:
		r.fail(&r.once, "Register(%q) = %v; want nil or *BackendExistsError for that name", name, err)
	}
}

// read takes a BackendNames snapshot, checks it against prev (the reader's
// previous snapshot), looks up every name registered so far, and returns the
// snapshot.
func (r *registryRace) read(prev []string) []string {
	names := BackendNames()
	if !slices.IsSorted(names) {
		r.fail(&r.snapshots, "BackendNames() = %q, not sorted", names)
	}
	if len(slices.Compact(slices.Clone(names))) != len(names) {
		r.fail(&r.snapshots, "BackendNames() = %q, holds a duplicate", names)
	}
	if !slices.Contains(names, LockedMemoryBackendName) {
		r.fail(&r.snapshots, "BackendNames() = %q, lacks %q", names, LockedMemoryBackendName)
	}
	for _, name := range prev {
		if !slices.Contains(names, name) {
			r.fail(&r.snapshots, "BackendNames() dropped %q a previous call returned", name)
			break
		}
	}
	for i := range r.winners {
		if b := r.winners[i].Load(); b != nil {
			if err := lookupIs(b); err != nil {
				r.fail(&r.lookups, "after its Register: %w", err)
			}
		}
	}
	return names
}

// lookupIs reports an error unless Lookup returns b under b's name.
func lookupIs(b *fakeBackend) error {
	if got, err := Lookup(b.name); err != nil || got != Backend(b) {
		return fmt.Errorf("Lookup(%q) = %v, %v; want the registered backend", b.name, got, err)
	}
	return nil
}

// runRegistryRace starts, at one signal, one writer per name, duplicators
// that each register every name again, and readers that list and look up
// until the writers are done, then once more. Every name is removed from the
// registry when t ends.
func runRegistryRace(t *testing.T, names, duplicators, readers int) *registryRace {
	t.Helper()
	r := &registryRace{
		names:   make([]string, names),
		winners: make([]atomic.Pointer[fakeBackend], names),
	}
	for i := range r.names {
		r.names[i] = "test-registry-race-" + strconv.Itoa(i)
	}
	t.Cleanup(func() {
		backendsMu.Lock()
		defer backendsMu.Unlock()
		for _, name := range r.names {
			delete(backends, name)
		}
	})

	start, done := make(chan struct{}), make(chan struct{})
	var writes, reads sync.WaitGroup
	for i := range names {
		writes.Go(func() {
			<-start
			r.register(i)
		})
	}
	for g := range duplicators {
		writes.Go(func() {
			<-start
			for k := range names {
				r.register((k + g) % names)
			}
		})
	}
	for range readers {
		reads.Go(func() {
			<-start
			var prev []string
			for stop := false; !stop; {
				select {
				case <-done:
					stop = true
				default:
				}
				prev = r.read(prev)
			}
		})
	}
	close(start)
	writes.Wait()
	close(done)
	reads.Wait()
	return r
}

// reportRace reports the first few findings and how many more there were.
func reportRace(t *testing.T, errs []error) {
	t.Helper()
	const shown = 5
	for i, err := range errs {
		if i == shown {
			t.Errorf("... and %d more", len(errs)-shown)
			return
		}
		t.Error(err)
	}
}

func TestRegistryConcurrent(t *testing.T) {
	const names, duplicators, readers = 32, 4, 4
	r := runRegistryRace(t, names, duplicators, readers)

	t.Run("RegisterOnce", func(t *testing.T) {
		reportRace(t, r.once)
		for i, name := range r.names {
			if r.winners[i].Load() == nil {
				t.Errorf("Register(%q) never returned nil", name)
			}
		}
		if got, want := r.duplicates.Load(), int64(names*duplicators); got != want {
			t.Errorf("%d Register calls refused with *BackendExistsError, want %d", got, want)
		}
	})

	t.Run("NamesSnapshots", func(t *testing.T) {
		reportRace(t, r.snapshots)
		final := BackendNames()
		for _, name := range r.names {
			if !slices.Contains(final, name) {
				t.Errorf("BackendNames() after every Register lacks %q", name)
			}
		}
	})

	t.Run("LookupAfterRegister", func(t *testing.T) {
		reportRace(t, r.lookups)
		for i := range r.winners {
			if b := r.winners[i].Load(); b != nil {
				if err := lookupIs(b); err != nil {
					t.Error(err)
				}
			}
		}
	})
}
