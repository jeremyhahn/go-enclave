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
	"strconv"
	"sync"
	"testing"
)

// fakeBackend is a backend with a chosen name.
type fakeBackend struct{ name string }

func (b *fakeBackend) Name() string { return b.name }

// registerForTest registers b and unregisters it when t ends, which only a
// test may do: the registry never rebinds a name.
func registerForTest(t *testing.T, b Backend) {
	t.Helper()
	if err := Register(b); err != nil {
		t.Fatalf("Register(%q) = %v", b.Name(), err)
	}
	t.Cleanup(func() {
		backendsMu.Lock()
		delete(backends, b.Name())
		backendsMu.Unlock()
	})
}

func TestRegister_ConcurrentRegistrationsAndLookups(t *testing.T) {
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		b := &fakeBackend{name: "test-concurrent-" + strconv.Itoa(i)}
		t.Cleanup(func() {
			backendsMu.Lock()
			delete(backends, b.name)
			backendsMu.Unlock()
		})
		wg.Go(func() {
			errs[i] = Register(b)
			if got, err := Lookup(b.name); err == nil && got != b {
				errs[i] = errors.New("lookup returned another backend")
			}
			_ = BackendNames()
		})
	}
	// Meanwhile n more race to register one name; exactly one may win.
	var dup sync.WaitGroup
	won := make(chan struct{}, n)
	for range n {
		dup.Go(func() {
			if Register(&fakeBackend{name: "test-concurrent-dup"}) == nil {
				won <- struct{}{}
			}
		})
	}
	t.Cleanup(func() {
		backendsMu.Lock()
		delete(backends, "test-concurrent-dup")
		backendsMu.Unlock()
	})
	wg.Wait()
	dup.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if len(won) != 1 {
		t.Fatalf("%d concurrent Registers of one name succeeded, want exactly 1", len(won))
	}
}

func TestBackendErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		sentinel error
		text     string
	}{
		{"BackendNotRegisteredError", &BackendNotRegisteredError{Name: "tdx"}, ErrBackendNotRegistered,
			`enclave: no backend is registered under this name: "tdx"`},
		{"BackendExistsError", &BackendExistsError{Name: "locked-memory"}, ErrBackendExists,
			`enclave: a backend is already registered under this name: "locked-memory"`},
		{"CapabilityError", &CapabilityError{Backend: "se050", Capability: CapabilityBytes}, ErrCapabilityUnsupported,
			`enclave: the backend does not provide a capability this operation needs: backend "se050" does not provide "bytes"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.text {
				t.Errorf("Error() = %q, want %q", got, tc.text)
			}
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("does not match its sentinel %v", tc.sentinel)
			}
			for _, other := range []error{
				ErrBackendNotRegistered, ErrBackendExists, ErrInvalidBackend, ErrCapabilityUnsupported,
				ErrInvalidImport, ErrInvalidNonce, ErrAEADAuthentication,
			} {
				if other != tc.sentinel && errors.Is(tc.err, other) {
					t.Errorf("matches the unrelated %v", other)
				}
			}
		})
	}
}

func TestCapability_NamesAreDistinct(t *testing.T) {
	seen := map[Capability]bool{}
	for _, c := range []Capability{
		CapabilityBytes, CapabilityFreeze, CapabilitySign, CapabilityDecrypt, CapabilityAEAD,
		CapabilityDerive, CapabilityAttest, CapabilityImport, CapabilitySweep, CapabilityConfine,
	} {
		if c == "" || seen[c] {
			t.Errorf("capability %q is empty or named twice", c)
		}
		seen[c] = true
	}
}

func TestPurposeAndAlgorithm_NamesAreValid(t *testing.T) {
	seen := map[Purpose]bool{}
	for _, p := range []Purpose{PurposeMaterial, PurposeWrappingKey, PurposeDataKey} {
		if !validName(string(p)) || seen[p] {
			t.Errorf("purpose %q is invalid or named twice", p)
		}
		seen[p] = true
	}
	if !validName(string(AlgorithmAES256GCM)) {
		t.Errorf("algorithm %q is not a valid name", AlgorithmAES256GCM)
	}
}
