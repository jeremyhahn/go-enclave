// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

// shallowCopy returns a new *T holding a copy of *p, made through reflect so
// go vet's copylocks check, which the noCopy field arms, does not refuse the
// test itself. It is what a caller's `c := *p` does.
func shallowCopy[T any](p *T) *T {
	c := new(T)
	reflect.ValueOf(c).Elem().Set(reflect.ValueOf(p).Elem())
	return c
}

// TestMemory_DestroyThroughACopyReachesEveryCopy pins B3: a copied lockedRegion is
// the same enclave, so one Destroy releases it for every copy and settles its
// one ledger entry.
func TestMemory_DestroyThroughACopyReachesEveryCopy(t *testing.T) {
	e, err := newMemory([]byte("shared by every copy"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	c := shallowCopy(e)
	if c == e {
		t.Fatal("shallowCopy returned the same pointer; the test copies nothing")
	}

	if err := c.Destroy(); err != nil {
		t.Fatalf("Destroy through the copy: %v", err)
	}
	if e.IsAlive() {
		t.Error("the original is alive after Destroy through a copy: the copy held its own state")
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes on the original = %v, want ErrEnclaveDestroyed", err)
	}
	if isRegistered(e) || isRegistered(c) {
		t.Error("the enclave is still on the shutdown ledger after Destroy through a copy")
	}
	if err := e.Destroy(); err != nil {
		t.Errorf("a second Destroy through the original = %v, want nil", err)
	}
}

// TestAllocator_CopySharesTheBudget pins B3 for the budget: a copied Allocator
// is the same budget, so the copy cannot admit what the original already
// spent, and a release through either is seen by both.
func TestAllocator_CopySharesTheBudget(t *testing.T) {
	page := LockedSize(1)
	a, err := newBudgetAllocator(page)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	c := shallowCopy(a)

	e, err := a.admitSized(1)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	if extra, err := c.admitSized(1); !errors.Is(err, ErrBudgetExhausted) {
		if err == nil {
			_ = extra.Destroy()
		}
		t.Fatalf("the copy admitted past the shared budget: err = %v, want ErrBudgetExhausted", err)
	}
	if got := c.InUse(); got != page {
		t.Errorf("copy InUse = %d, want %d", got, page)
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := c.Available(); got != page {
		t.Errorf("copy Available after the release = %d, want %d", got, page)
	}
	if err := a.TransferTo(c, 1); !errors.Is(err, ErrInvalidTransfer) {
		t.Errorf("TransferTo a copy = %v, want ErrInvalidTransfer", err)
	}
}

// TestAllocator_ZeroValueIsNotConstructed pins L2: every function that takes
// an *budgetAllocator refuses the zero value with ErrAllocatorNotConstructed, changes
// nothing, and still wipes the data it was handed.
func TestAllocator_ZeroValueIsNotConstructed(t *testing.T) {
	var zero budgetAllocator
	z := &zero
	a, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	data := []byte("wiped even when refused")
	material := []byte("wiped even when refused")
	calls := map[string]func() error{
		"New": func() error {
			_, err := z.New(data)
			return err
		},
		"NewSized": func() error {
			_, err := z.NewSized(1)
			return err
		},
		"Import": func() error {
			_, err := z.Import(t.Context(), material, WithPurpose(PurposeMaterial))
			return err
		},
		"SetLimit": func() error { return z.SetLimit(1) },
		"ForceLimit": func() error {
			_, err := z.ForceLimit(1)
			return err
		},
		"TransferTo from zero": func() error { return z.TransferTo(a, 1) },
		"TransferTo to zero":   func() error { return a.TransferTo(z, 1) },
		"SetAllocator":         func() error { return SetAllocator(z) },
		"Sealed.OpenIn": func() error {
			e, err := sealForBudgetTest(t).OpenIn(t.Context(), z)
			if err == nil {
				_ = e.Destroy()
			}
			return err
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrAllocatorNotConstructed) {
			t.Errorf("%s = %v, want ErrAllocatorNotConstructed", name, err)
		}
	}

	if !bytes.Equal(data, make([]byte, len(data))) || !bytes.Equal(material, make([]byte, len(material))) {
		t.Error("a refused New or Import left its data unwiped")
	}
	if z.InUse() != 0 || z.Limit() != 0 || z.Available() != 0 {
		t.Errorf("zero Allocator reports InUse=%d Limit=%d Available=%d, want all 0", z.InUse(), z.Limit(), z.Available())
	}
	if got := a.Limit(); got != LockedSize(1) {
		t.Errorf("a refused transfer changed the constructed side's limit to %d", got)
	}
	if got := z.Name(); got != LockedMemoryBackendName {
		t.Errorf("zero Allocator Name = %q, want %q", got, LockedMemoryBackendName)
	}
}

// TestMemory_WithBytesRefusesANilFunc pins L6: a nil callback is a typed error
// on a live enclave, and a nil or zero receiver stays ErrEnclaveDestroyed.
func TestMemory_WithBytesRefusesANilFunc(t *testing.T) {
	e, err := newMemory([]byte("unchanged by a nil func"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = e.Destroy() })

	if err := e.WithBytes(nil); !errors.Is(err, ErrNilFunc) {
		t.Errorf("WithBytes(nil) = %v, want ErrNilFunc", err)
	}
	if !e.IsAlive() {
		t.Error("WithBytes(nil) destroyed the enclave")
	}

	var nilMemory *lockedRegion
	var zero lockedRegion
	for name, m := range map[string]*lockedRegion{"nil": nilMemory, "zero": &zero} {
		if err := m.WithBytes(nil); !errors.Is(err, ErrEnclaveDestroyed) {
			t.Errorf("%s receiver WithBytes(nil) = %v, want ErrEnclaveDestroyed", name, err)
		}
		if err := m.Destroy(); err != nil {
			t.Errorf("%s receiver Destroy = %v, want nil", name, err)
		}
		if m.IsAlive() || m.Size() != 0 {
			t.Errorf("%s receiver reports a live enclave", name)
		}
	}
}

// TestMemory_BackendIsTheAdmittingAllocator pins the backend seam: a budgeted
// enclave reports the *budgetAllocator that admitted it, an unbudgeted or nil one
// the default, and no *budgetAllocator ever takes the default's registry name.
func TestMemory_BackendIsTheAdmittingAllocator(t *testing.T) {
	a, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	budgeted, err := a.admitSized(1)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	t.Cleanup(func() { _ = budgeted.Destroy() })
	if got, ok := budgeted.Backend().(*budgetAllocator); !ok || got != a {
		t.Errorf("budgeted Backend() = %#v, want the admitting *budgetAllocator", budgeted.Backend())
	}

	plain, err := newMemorySized(1)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	t.Cleanup(func() { _ = plain.Destroy() })
	var nilMemory *lockedRegion
	for name, m := range map[string]*lockedRegion{"unbudgeted": plain, "nil": nilMemory} {
		if got := m.Backend(); got != DefaultBackend() {
			t.Errorf("%s Backend() = %#v, want DefaultBackend()", name, got)
		}
	}

	if got := a.Name(); got != LockedMemoryBackendName {
		t.Errorf("Allocator Name = %q, want %q", got, LockedMemoryBackendName)
	}
	if err := Register(a); !errors.Is(err, ErrBackendExists) {
		t.Errorf("Register(*budgetAllocator) = %v, want ErrBackendExists", err)
	}
	if got, err := Lookup(LockedMemoryBackendName); err != nil || got != DefaultBackend() {
		t.Errorf("Lookup(%q) = (%#v, %v), want the unbudgeted default", LockedMemoryBackendName, got, err)
	}
}

// TestAllocator_Import pins the Importer contract for locked memory: it
// resolves options with NewImportSpec, charges the budget, and wipes material
// on every path.
func TestAllocator_Import(t *testing.T) {
	key := func() []byte { return bytes.Repeat([]byte{0x5a}, aes256KeyBytes) }
	cases := map[string]struct {
		ctx      context.Context
		material []byte
		opts     []ImportOption
		want     error
	}{
		"material":           {t.Context(), []byte("arbitrary"), []ImportOption{WithPurpose(PurposeMaterial)}, nil},
		"wrapping key":       {t.Context(), key(), []ImportOption{WithPurpose(PurposeWrappingKey), WithAlgorithm(AlgorithmAES256GCM)}, nil},
		"data key":           {t.Context(), key(), []ImportOption{WithPurpose(PurposeDataKey), WithAlgorithm(AlgorithmAES256GCM)}, nil},
		"nil ctx":            {nil, []byte("arbitrary"), []ImportOption{WithPurpose(PurposeMaterial)}, nil},
		"no purpose":         {t.Context(), []byte("arbitrary"), nil, ErrInvalidImport},
		"nil option":         {t.Context(), []byte("arbitrary"), []ImportOption{nil}, ErrInvalidImport},
		"short AES key":      {t.Context(), key()[:16], []ImportOption{WithPurpose(PurposeDataKey), WithAlgorithm(AlgorithmAES256GCM)}, ErrInvalidImport},
		"empty material":     {t.Context(), []byte{}, []ImportOption{WithPurpose(PurposeMaterial)}, ErrEmptyEnclave},
		"algorithm on bytes": {t.Context(), []byte("arbitrary"), []ImportOption{WithPurpose(PurposeMaterial), WithAlgorithm(AlgorithmAES256GCM)}, ErrInvalidImport},
	}
	for name, ended := range endedContexts(t) {
		cases["ended ctx "+name] = struct {
			ctx      context.Context
			material []byte
			opts     []ImportOption
			want     error
		}{ended.ctx, []byte("arbitrary"), []ImportOption{WithPurpose(PurposeMaterial)}, ended.want}
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := newBudgetAllocator(LockedSize(len(tc.material) + 1))
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}
			want := append([]byte(nil), tc.material...)

			h, err := a.Import(tc.ctx, tc.material, tc.opts...)
			if !bytes.Equal(tc.material, make([]byte, len(tc.material))) {
				t.Error("Import left material unwiped")
			}
			if tc.want != nil {
				if !errors.Is(err, tc.want) || h != nil {
					t.Fatalf("Import = (%v, %v), want (nil, %v)", h, err, tc.want)
				}
				if got := a.InUse(); got != 0 {
					t.Errorf("a refused Import left %d bytes charged", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			t.Cleanup(func() { _ = h.Destroy() })

			e, ok := h.(*lockedRegion)
			if !ok {
				t.Fatalf("Import returned a %T, want *lockedRegion", h)
			}
			if got := e.Backend(); got != Backend(a) {
				t.Errorf("imported Backend() = %#v, want the importing *budgetAllocator", got)
			}
			if got := a.InUse(); got != LockedSize(len(want)) {
				t.Errorf("InUse after Import = %d, want %d", got, LockedSize(len(want)))
			}
			if err := e.WithBytes(func(b []byte) error {
				if !bytes.Equal(b, want) {
					t.Error("the imported enclave does not hold the material")
				}
				return nil
			}); err != nil {
				t.Fatalf("WithBytes: %v", err)
			}
		})
	}

	var nilAllocator *budgetAllocator
	if _, err := nilAllocator.Import(t.Context(), []byte("x"), WithPurpose(PurposeMaterial)); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("nil Allocator Import = %v, want ErrNilAllocator", err)
	}
}
