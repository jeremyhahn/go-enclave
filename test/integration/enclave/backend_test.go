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
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers backend.go: the default backend a real locked enclave reports, the
// registry, As, and the import spec, through the public package.

// backendSeq makes each test's backend names unique: the registry has no
// unregister, so a name registered once is taken for the process's life.
var backendSeq atomic.Uint64

// uniqueBackendName returns a valid backend name no earlier call returned.
func uniqueBackendName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, backendSeq.Add(1))
}

// fakeBackend is a minimal backend a test registers.
type fakeBackend struct{ name string }

func (b *fakeBackend) Name() string { return b.name }

// wrapperBackend wraps a fakeBackend and exposes it through As, as a backend
// that wraps another does.
type wrapperBackend struct {
	inner *fakeBackend
	calls int
}

func (w *wrapperBackend) Name() string { return "wrapper" }

func (w *wrapperBackend) As(target any) bool {
	w.calls++
	if p, ok := target.(**fakeBackend); ok {
		*p = w.inner
		return true
	}
	return false
}

// TestBackends_LockedEnclaveReportsTheDefaultBackend requires an enclave built
// on the real kernel's locked memory to report the registered default backend,
// before and after Destroy.
func TestBackends_LockedEnclaveReportsTheDefaultBackend(t *testing.T) {
	e := enclaveFromNeedle(t, newNeedle(t))

	def := enclave.DefaultBackend()
	if def.Name() != enclave.LockedMemoryBackendName {
		t.Fatalf("DefaultBackend().Name() = %q, want %q", def.Name(), enclave.LockedMemoryBackendName)
	}
	if got, err := enclave.Lookup(enclave.LockedMemoryBackendName); err != nil || got != def {
		t.Fatalf("Lookup(%q) = %v, %v; want the default backend", enclave.LockedMemoryBackendName, got, err)
	}
	if !slices.Contains(enclave.BackendNames(), enclave.LockedMemoryBackendName) {
		t.Fatalf("BackendNames() = %q, want it to hold %q", enclave.BackendNames(), enclave.LockedMemoryBackendName)
	}
	if e.Backend() != def {
		t.Errorf("Backend() = %v, want the default backend", e.Backend())
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if e.Backend() != def {
		t.Error("Backend() changed once destroyed")
	}
}

// TestBackends_RegisterThenLookup requires a valid backend to register, after
// which Lookup returns that instance and BackendNames lists its name.
func TestBackends_RegisterThenLookup(t *testing.T) {
	b := &fakeBackend{name: uniqueBackendName("reg")}
	if err := enclave.Register(b); err != nil {
		t.Fatalf("Register(%q): %v", b.name, err)
	}

	got, err := enclave.Lookup(b.name)
	if err != nil {
		t.Fatalf("Lookup(%q): %v", b.name, err)
	}
	if got != enclave.Backend(b) {
		t.Errorf("Lookup(%q) = %v, want the registered instance", b.name, got)
	}
	names := enclave.BackendNames()
	if !slices.Contains(names, b.name) || !slices.Contains(names, enclave.LockedMemoryBackendName) {
		t.Errorf("BackendNames() = %q, want it to hold %q and the default", names, b.name)
	}
	if !slices.IsSorted(names) {
		t.Errorf("BackendNames() = %q, want it sorted", names)
	}
}

// TestBackends_RegisterAcceptsBoundaryNames requires the longest valid name and
// the shortest to register, and names with interior '-' and '.' too.
func TestBackends_RegisterAcceptsBoundaryNames(t *testing.T) {
	longest := fmt.Sprint(backendSeq.Add(1))
	longest = strings.Repeat("x", 64-len(longest)) + longest
	for _, name := range []string{
		uniqueBackendName("bnd") + "-a.b-c",
		longest,
		fmt.Sprint(backendSeq.Add(1)),
	} {
		if err := enclave.Register(&fakeBackend{name: name}); err != nil {
			t.Errorf("Register(%q): %v", name, err)
		}
	}
}

// TestBackends_RegisterRefusesAnInvalidName requires a name that breaks the
// rule on Backend.Name to be refused with ErrInvalidBackend, registering
// nothing.
func TestBackends_RegisterRefusesAnInvalidName(t *testing.T) {
	before := enclave.BackendNames()
	for _, name := range []string{
		"",
		"Upper",
		"-lead",
		"trail-",
		".lead",
		"trail.",
		"under_score",
		"sp ace",
		"café",
		strings.Repeat("a", 65),
	} {
		err := enclave.Register(&fakeBackend{name: name})
		if !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Errorf("Register(%q) = %v, want ErrInvalidBackend", name, err)
		}
	}
	if after := enclave.BackendNames(); !slices.Equal(before, after) {
		t.Errorf("BackendNames() changed from %q to %q after refused registrations", before, after)
	}
}

// TestBackends_RegisterRefusesANilBackend requires a nil and a typed-nil
// backend to be refused with ErrInvalidBackend, without calling Name on the
// typed-nil value.
func TestBackends_RegisterRefusesANilBackend(t *testing.T) {
	if err := enclave.Register(nil); !errors.Is(err, enclave.ErrInvalidBackend) {
		t.Errorf("Register(nil) = %v, want ErrInvalidBackend", err)
	}
	var typedNil *fakeBackend
	if err := enclave.Register(typedNil); !errors.Is(err, enclave.ErrInvalidBackend) {
		t.Errorf("Register(typed nil) = %v, want ErrInvalidBackend", err)
	}
}

// TestBackends_RegisterRefusesADuplicate requires a taken name to be refused
// with a *BackendExistsError naming it, leaving the first backend bound.
func TestBackends_RegisterRefusesADuplicate(t *testing.T) {
	first := &fakeBackend{name: uniqueBackendName("dup")}
	if err := enclave.Register(first); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := enclave.Register(&fakeBackend{name: first.name})
	if !errors.Is(err, enclave.ErrBackendExists) {
		t.Fatalf("second Register = %v, want ErrBackendExists", err)
	}
	var exists *enclave.BackendExistsError
	if !errors.As(err, &exists) || exists.Name != first.name {
		t.Errorf("second Register = %v, want a *BackendExistsError for %q", err, first.name)
	}
	if got, err := enclave.Lookup(first.name); err != nil || got != enclave.Backend(first) {
		t.Errorf("Lookup(%q) = %v, %v; want the first instance, never rebound", first.name, got, err)
	}
}

// TestBackends_RegisterRefusesTheDefaultName requires the default backend's
// name to be taken from the start and to stay bound to the default.
func TestBackends_RegisterRefusesTheDefaultName(t *testing.T) {
	err := enclave.Register(&fakeBackend{name: enclave.LockedMemoryBackendName})
	var exists *enclave.BackendExistsError
	if !errors.Is(err, enclave.ErrBackendExists) || !errors.As(err, &exists) || exists.Name != enclave.LockedMemoryBackendName {
		t.Fatalf("Register(default name) = %v, want a *BackendExistsError for %q", err, enclave.LockedMemoryBackendName)
	}
	got, lerr := enclave.Lookup(enclave.LockedMemoryBackendName)
	if lerr != nil || got != enclave.DefaultBackend() {
		t.Errorf("Lookup(default) = %v, %v; want the default backend", got, lerr)
	}
}

// TestBackends_RegisterIsSafeForConcurrentUse requires racing registrations of
// one name to leave exactly one winner, the rest refused as duplicates.
func TestBackends_RegisterIsSafeForConcurrentUse(t *testing.T) {
	name := uniqueBackendName("race")
	const racers = 16
	errs := make(chan error, racers)
	backends := make([]*fakeBackend, racers)
	for i := range backends {
		backends[i] = &fakeBackend{name: name}
		go func(b *fakeBackend) { errs <- enclave.Register(b) }(backends[i])
	}
	won := 0
	for range racers {
		err := <-errs
		switch {
		case err == nil:
			won++
		case !errors.Is(err, enclave.ErrBackendExists):
			t.Errorf("Register = %v, want nil or ErrBackendExists", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d registrations won, want exactly 1", won)
	}
	got, err := enclave.Lookup(name)
	if err != nil || !slices.Contains(backends, got.(*fakeBackend)) {
		t.Errorf("Lookup(%q) = %v, %v; want one of the racers", name, got, err)
	}
}

// TestBackends_LookupUnknownName requires a name nothing is registered under to
// fail with a *BackendNotRegisteredError naming it and return no backend.
func TestBackends_LookupUnknownName(t *testing.T) {
	name := uniqueBackendName("unknown")
	got, err := enclave.Lookup(name)
	if got != nil {
		t.Errorf("Lookup(%q) returned %v, want nil", name, got)
	}
	if !errors.Is(err, enclave.ErrBackendNotRegistered) {
		t.Fatalf("Lookup(%q) = %v, want ErrBackendNotRegistered", name, err)
	}
	var missing *enclave.BackendNotRegisteredError
	if !errors.As(err, &missing) || missing.Name != name {
		t.Errorf("Lookup(%q) = %v, want a *BackendNotRegisteredError for it", name, err)
	}
	if _, err := enclave.Lookup(""); !errors.Is(err, enclave.ErrBackendNotRegistered) {
		t.Errorf("Lookup(\"\") = %v, want ErrBackendNotRegistered", err)
	}
}

// TestBackends_AsAssignable requires As to set a target whose type the value's
// dynamic type is assignable to, concrete or interface, and to leave a target
// of any other type untouched.
func TestBackends_AsAssignable(t *testing.T) {
	b := &fakeBackend{name: "assignable"}

	var concrete *fakeBackend
	if !enclave.As(b, &concrete) || concrete != b {
		t.Errorf("As(b, *fakeBackend) = %v, want the same instance", concrete)
	}
	var iface enclave.Backend
	if !enclave.As(b, &iface) || iface != enclave.Backend(b) {
		t.Errorf("As(b, *Backend) = %v, want the same instance", iface)
	}
	var wrong *wrapperBackend
	if enclave.As(b, &wrong) || wrong != nil {
		t.Errorf("As(b, *wrapperBackend) = %v, want false and an untouched target", wrong)
	}

	var def enclave.Backend
	if !enclave.As(enclave.DefaultBackend(), &def) || def.Name() != enclave.LockedMemoryBackendName {
		t.Errorf("As(DefaultBackend(), *Backend) = %v, want the default backend", def)
	}
}

// TestBackends_AsReachesCapabilitiesOfALockedEnclave requires As to find the
// capabilities a real locked enclave provides and the backend it reports.
func TestBackends_AsReachesCapabilitiesOfALockedEnclave(t *testing.T) {
	e := enclaveFromNeedle(t, newNeedle(t))
	t.Cleanup(func() { _ = e.Destroy() })
	var h enclave.Handle = e

	var access enclave.ByteAccess
	if !enclave.As(h, &access) {
		t.Error("As(enclave, *ByteAccess) = false, want true")
	}
	var freezer enclave.Freezer
	if !enclave.As(h, &freezer) {
		t.Error("As(enclave, *Freezer) = false, want true")
	}
	var aead enclave.AEAD
	if enclave.As(h, &aead) || aead != nil {
		t.Error("As(enclave, *AEAD) = true, want false: locked memory is not an AEAD")
	}
	var backend enclave.Backend
	if !enclave.As(h.Backend(), &backend) || backend != enclave.DefaultBackend() {
		t.Errorf("As(Backend(), *Backend) = %v, want the default backend", backend)
	}
}

// TestBackends_AsThroughAWrapper requires As to ask a value with an
// As(any) bool method when it is not assignable, and to report that method's
// answer; an assignable target never reaches the method.
func TestBackends_AsThroughAWrapper(t *testing.T) {
	inner := &fakeBackend{name: "inner"}
	w := &wrapperBackend{inner: inner}

	var got *fakeBackend
	if !enclave.As(w, &got) || got != inner {
		t.Errorf("As(wrapper, *fakeBackend) = %v, want the wrapped backend", got)
	}
	if w.calls != 1 {
		t.Errorf("wrapper's As ran %d times, want 1", w.calls)
	}

	var other *strings.Builder
	if enclave.As(w, &other) || other != nil {
		t.Errorf("As(wrapper, *strings.Builder) = %v, want false", other)
	}

	var self *wrapperBackend
	if !enclave.As(w, &self) || self != w {
		t.Errorf("As(wrapper, *wrapperBackend) = %v, want the wrapper itself", self)
	}
	if w.calls != 2 {
		t.Errorf("wrapper's As ran %d times, want 2: an assignable target must not reach it", w.calls)
	}
}

// TestBackends_AsRefusesNilValues requires a nil or typed-nil value to report
// false without panicking, and without running a typed-nil value's As method.
func TestBackends_AsRefusesNilValues(t *testing.T) {
	var target *fakeBackend
	if enclave.As(nil, &target) || target != nil {
		t.Errorf("As(nil, ...) = true or set %v, want false", target)
	}

	var typedNil *fakeBackend
	if enclave.As(typedNil, &target) || target != nil {
		t.Errorf("As(typed nil, *fakeBackend) = true or set %v, want false", target)
	}

	var nilWrapper *wrapperBackend
	if enclave.As(nilWrapper, &target) || target != nil {
		t.Errorf("As(typed-nil wrapper, ...) = true or set %v, want false", target)
	}
}

// TestBackends_AsRefusesABadTarget requires a target that is not a non-nil
// pointer to report false without panicking, and without asking a wrapper.
func TestBackends_AsRefusesABadTarget(t *testing.T) {
	b := &fakeBackend{name: "bad-target"}
	w := &wrapperBackend{inner: b}

	for name, target := range map[string]any{
		"nil":                     nil,
		"struct value":            fakeBackend{},
		"string":                  "target",
		"typed-nil *Backend":      (*enclave.Backend)(nil),
		"typed-nil **fakeBackend": (**fakeBackend)(nil),
	} {
		if enclave.As(b, target) {
			t.Errorf("As(backend, %s target) = true, want false", name)
		}
		if enclave.As(w, target) {
			t.Errorf("As(wrapper, %s target) = true, want false", name)
		}
	}
	if w.calls != 0 {
		t.Errorf("wrapper's As ran %d times, want 0: a bad target is refused before it", w.calls)
	}

	// A valid pointer of a type nothing matches reaches the wrapper, which
	// declines it.
	var mismatched int
	if enclave.As(w, &mismatched) || mismatched != 0 {
		t.Errorf("As(wrapper, *int) = true or set %d, want false", mismatched)
	}
	if w.calls != 1 {
		t.Errorf("wrapper's As ran %d times, want 1", w.calls)
	}
}

// TestBackends_ImportSpecValid requires NewImportSpec to resolve every valid
// purpose and algorithm combination, applying options in order.
func TestBackends_ImportSpecValid(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []enclave.ImportOption
		want enclave.ImportSpec
	}{
		{
			name: "material",
			opts: []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			want: enclave.ImportSpec{Purpose: enclave.PurposeMaterial},
		},
		{
			name: "wrapping key",
			opts: []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)},
			want: enclave.ImportSpec{Purpose: enclave.PurposeWrappingKey, Algorithm: enclave.AlgorithmAES256GCM},
		},
		{
			name: "data key, options in the other order",
			opts: []enclave.ImportOption{enclave.WithAlgorithm(enclave.AlgorithmAES256GCM), enclave.WithPurpose(enclave.PurposeDataKey)},
			want: enclave.ImportSpec{Purpose: enclave.PurposeDataKey, Algorithm: enclave.AlgorithmAES256GCM},
		},
		{
			name: "a backend's own algorithm",
			opts: []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm("chacha20-poly1305.v2")},
			want: enclave.ImportSpec{Purpose: enclave.PurposeDataKey, Algorithm: "chacha20-poly1305.v2"},
		},
		{
			name: "the last purpose wins",
			opts: []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial), enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)},
			want: enclave.ImportSpec{Purpose: enclave.PurposeDataKey, Algorithm: enclave.AlgorithmAES256GCM},
		},
		{
			name: "an algorithm of the longest valid name",
			opts: []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.Algorithm(strings.Repeat("a", 64)))},
			want: enclave.ImportSpec{Purpose: enclave.PurposeWrappingKey, Algorithm: enclave.Algorithm(strings.Repeat("a", 64))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enclave.NewImportSpec(tc.opts...)
			if err != nil {
				t.Fatalf("NewImportSpec: %v", err)
			}
			if got != tc.want {
				t.Errorf("NewImportSpec = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestBackends_ImportSpecInvalid requires NewImportSpec to refuse a nil option,
// a missing or unknown purpose, an algorithm on PurposeMaterial, and a key
// purpose without a valid algorithm, each with ErrInvalidImport and a zero spec.
func TestBackends_ImportSpecInvalid(t *testing.T) {
	key := enclave.WithPurpose(enclave.PurposeWrappingKey)
	for _, tc := range []struct {
		name string
		opts []enclave.ImportOption
	}{
		{"no options", nil},
		{"a nil option", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial), nil}},
		{"only a nil option", []enclave.ImportOption{nil}},
		{"an algorithm without a purpose", []enclave.ImportOption{enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}},
		{"an unknown purpose", []enclave.ImportOption{enclave.WithPurpose("signing-key"), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}},
		{"an empty purpose", []enclave.ImportOption{enclave.WithPurpose("")}},
		{"an algorithm on material", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}},
		{"a wrapping key without an algorithm", []enclave.ImportOption{key}},
		{"a data key without an algorithm", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeDataKey)}},
		{"an upper-case algorithm", []enclave.ImportOption{key, enclave.WithAlgorithm("AES-256-GCM")}},
		{"an algorithm with a leading dash", []enclave.ImportOption{key, enclave.WithAlgorithm("-aes")}},
		{"an algorithm with a trailing dot", []enclave.ImportOption{key, enclave.WithAlgorithm("aes.")}},
		{"an algorithm with a space", []enclave.ImportOption{key, enclave.WithAlgorithm("aes 256")}},
		{"an algorithm over 64 bytes", []enclave.ImportOption{key, enclave.WithAlgorithm(enclave.Algorithm(strings.Repeat("a", 65)))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enclave.NewImportSpec(tc.opts...)
			if !errors.Is(err, enclave.ErrInvalidImport) {
				t.Fatalf("NewImportSpec = %+v, %v; want ErrInvalidImport", got, err)
			}
			if got != (enclave.ImportSpec{}) {
				t.Errorf("NewImportSpec returned %+v with its error, want the zero spec", got)
			}
		})
	}
}
