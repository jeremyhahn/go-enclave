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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeBackend is a backend with a chosen name.
type fakeBackend struct{ name string }

func (b *fakeBackend) Name() string { return b.name }

// wrappingBackend wraps another backend and exposes it through As.
type wrappingBackend struct{ inner Backend }

func (w *wrappingBackend) Name() string       { return w.inner.Name() }
func (w *wrappingBackend) As(target any) bool { return As(w.inner, target) }

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

func TestDefaultBackend_IsLockedMemoryAndAlwaysRegistered(t *testing.T) {
	if got := DefaultBackend().Name(); got != LockedMemoryBackendName {
		t.Fatalf("DefaultBackend().Name() = %q, want %q", got, LockedMemoryBackendName)
	}
	b, err := Lookup(LockedMemoryBackendName)
	if err != nil || b != DefaultBackend() {
		t.Fatalf("Lookup(%q) = %v, %v; want the default backend", LockedMemoryBackendName, b, err)
	}
	if !slices.Contains(BackendNames(), LockedMemoryBackendName) {
		t.Fatalf("BackendNames() = %q, want it to hold %q", BackendNames(), LockedMemoryBackendName)
	}
	err = Register(&fakeBackend{name: LockedMemoryBackendName})
	var exists *BackendExistsError
	if !errors.As(err, &exists) || exists.Name != LockedMemoryBackendName {
		t.Fatalf("Register over the default = %v, want a *BackendExistsError naming it", err)
	}
	if b, _ := Lookup(LockedMemoryBackendName); b != DefaultBackend() {
		t.Fatal("a refused Register rebound the default name")
	}
}

func TestMemory_BackendIsTheDefault(t *testing.T) {
	e, err := newMemoryCopy([]byte("material"))
	if err != nil {
		t.Fatal(err)
	}
	var h Handle = e
	if h.Backend() != DefaultBackend() {
		t.Errorf("Backend() = %v, want the default backend", h.Backend())
	}
	if err := e.Destroy(); err != nil {
		t.Fatal(err)
	}
	if h.Backend() != DefaultBackend() {
		t.Error("Backend() changed once destroyed")
	}
	var none *lockedRegion
	if none.Backend() != DefaultBackend() {
		t.Error("a nil *lockedRegion does not report the default backend")
	}
}

func TestRegister_LookupFindsTheRegisteredBackend(t *testing.T) {
	b := &fakeBackend{name: "test-register"}
	registerForTest(t, b)

	got, err := Lookup("test-register")
	if err != nil || got != b {
		t.Fatalf("Lookup = %v, %v; want the registered backend", got, err)
	}
	if names := BackendNames(); !slices.IsSorted(names) || !slices.Contains(names, "test-register") {
		t.Fatalf("BackendNames() = %q, want it sorted and holding the new name", names)
	}

	err = Register(&fakeBackend{name: "test-register"})
	if !errors.Is(err, ErrBackendExists) {
		t.Fatalf("second Register = %v, want ErrBackendExists", err)
	}
	if got, _ := Lookup("test-register"); got != b {
		t.Fatal("a refused Register rebound the name")
	}
}

func TestRegister_RefusesNilAndInvalidNames(t *testing.T) {
	var typedNil *fakeBackend
	for _, tc := range []struct {
		name string
		b    Backend
	}{
		{"nil", nil},
		{"typed nil", typedNil},
		{"empty", &fakeBackend{}},
		{"upper case", &fakeBackend{name: "TDX"}},
		{"leading dash", &fakeBackend{name: "-tdx"}},
		{"trailing dot", &fakeBackend{name: "tdx."}},
		{"space", &fakeBackend{name: "sev snp"}},
		{"slash", &fakeBackend{name: "nvidia/cc"}},
		{"too long", &fakeBackend{name: strings.Repeat("a", maxBackendName+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Register(tc.b); err != ErrInvalidBackend {
				t.Fatalf("Register = %v, want ErrInvalidBackend", err)
			}
		})
	}
	for _, name := range []string{"a", "tdx", "sev-snp", "go-enclave.tpm2", "x9", strings.Repeat("a", maxBackendName)} {
		if !validName(name) {
			t.Errorf("validBackendName(%q) = false, want true", name)
		}
	}
}

func TestLookup_UnknownNameIsTyped(t *testing.T) {
	b, err := Lookup("no-such-backend")
	var missing *BackendNotRegisteredError
	if b != nil || !errors.As(err, &missing) || missing.Name != "no-such-backend" {
		t.Fatalf("Lookup = %v, %v; want nil and a *BackendNotRegisteredError naming it", b, err)
	}
	if !errors.Is(err, ErrBackendNotRegistered) {
		t.Fatalf("%v does not match ErrBackendNotRegistered", err)
	}
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

func TestAs(t *testing.T) {
	inner := &fakeBackend{name: "test-as"}
	var wrapped Backend = &wrappingBackend{inner: inner}

	var concrete *fakeBackend
	if !As(inner, &concrete) || concrete != inner {
		t.Fatal("As did not match the dynamic type itself")
	}
	concrete = nil
	if !As(wrapped, &concrete) || concrete != inner {
		t.Fatal("As did not reach the wrapped backend through its As method")
	}
	var iface Backend
	if !As(inner, &iface) || iface != inner {
		t.Fatal("As did not match an interface target")
	}
	var w *wrappingBackend
	if !As(wrapped, &w) || w != wrapped {
		t.Fatal("As did not match the wrapper itself first")
	}

	var e *lockedRegion
	if As(inner, &e) || e != nil {
		t.Fatal("As matched an unrelated type")
	}
	if As(DefaultBackend(), &concrete) {
		t.Fatal("As matched a backend with no As method to an unrelated type")
	}

	// Never a panic, unlike errors.As. A typed-nil v is refused before
	// reflection, so neither a direct match nor a nil wrapper's As runs.
	var nilPtr *Backend
	var nilInner *fakeBackend
	var nilWrapper *wrappingBackend
	for _, tc := range []struct {
		name      string
		v, target any
	}{
		{"nil v", nil, &iface},
		{"typed-nil v, direct", nilInner, &concrete},
		{"typed-nil v, interface target", nilInner, &iface},
		{"typed-nil wrapper", nilWrapper, &concrete},
		{"typed-nil wrapper in an interface", Backend(nilWrapper), &concrete},
		{"nil target", inner, nil},
		{"non-pointer target", inner, "target"},
		{"nil pointer target", inner, nilPtr},
	} {
		if As(tc.v, tc.target) {
			t.Errorf("%s: As = true, want false", tc.name)
		}
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

func TestNewImportSpec(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []ImportOption
		want ImportSpec
	}{
		{"material", []ImportOption{WithPurpose(PurposeMaterial)},
			ImportSpec{Purpose: PurposeMaterial}},
		{"wrapping key", []ImportOption{WithPurpose(PurposeWrappingKey), WithAlgorithm(AlgorithmAES256GCM)},
			ImportSpec{Purpose: PurposeWrappingKey, Algorithm: AlgorithmAES256GCM}},
		{"data key, algorithm first", []ImportOption{WithAlgorithm(AlgorithmAES256GCM), WithPurpose(PurposeDataKey)},
			ImportSpec{Purpose: PurposeDataKey, Algorithm: AlgorithmAES256GCM}},
		{"a backend's own algorithm", []ImportOption{WithPurpose(PurposeDataKey), WithAlgorithm("chacha20-poly1305")},
			ImportSpec{Purpose: PurposeDataKey, Algorithm: "chacha20-poly1305"}},
		{"last option wins", []ImportOption{WithPurpose(PurposeDataKey), WithPurpose(PurposeMaterial)},
			ImportSpec{Purpose: PurposeMaterial}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewImportSpec(tc.opts...)
			if err != nil || got != tc.want {
				t.Fatalf("NewImportSpec = %+v, %v; want %+v, nil", got, err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		opts []ImportOption
	}{
		{"no options", nil},
		{"nil option", []ImportOption{WithPurpose(PurposeMaterial), nil}},
		{"no purpose", []ImportOption{WithAlgorithm(AlgorithmAES256GCM)}},
		{"unknown purpose", []ImportOption{WithPurpose("signing-key"), WithAlgorithm(AlgorithmAES256GCM)}},
		{"material with an algorithm", []ImportOption{WithPurpose(PurposeMaterial), WithAlgorithm(AlgorithmAES256GCM)}},
		{"wrapping key without an algorithm", []ImportOption{WithPurpose(PurposeWrappingKey)}},
		{"data key without an algorithm", []ImportOption{WithPurpose(PurposeDataKey)}},
		{"invalid algorithm", []ImportOption{WithPurpose(PurposeDataKey), WithAlgorithm("AES-256-GCM")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewImportSpec(tc.opts...)
			if !errors.Is(err, ErrInvalidImport) || got != (ImportSpec{}) {
				t.Fatalf("NewImportSpec = %+v, %v; want the zero spec, ErrInvalidImport", got, err)
			}
		})
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
