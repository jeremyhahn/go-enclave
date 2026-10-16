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
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// An Allocator as a backend: it names the default, reports itself as the
// backend of what it admits and imports key material into its budget.

func TestBackends_AnAllocatorNamesTheDefaultBackendAndOwnsWhatItAdmits(t *testing.T) {
	a, err := enclave.NewAllocator(4 * enclave.LockedSize(enclave.RootKeyBytes))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if got := a.Name(); got != enclave.LockedMemoryBackendName {
		t.Errorf("allocator: Name = %q, want %q", got, enclave.LockedMemoryBackendName)
	}
	var importer enclave.Importer
	if !enclave.As(a, &importer) {
		t.Fatalf("As(allocator, *Importer) = false: an allocator imports")
	}

	m, err := a.New(heapBytes(enclave.RootKeyBytes))
	if err != nil {
		t.Fatalf("Allocator.New: %v", err)
	}
	if got := m.Backend(); got != enclave.Backend(a) {
		t.Fatalf("Backend of an admitted enclave = %v, want the allocator that admitted it", got)
	}
	if err := m.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := m.Backend(); got != enclave.Backend(a) {
		t.Fatalf("Backend of a destroyed enclave = %v, want the allocator that admitted it", got)
	}

	plain, err := enclave.NewMemory(heapBytes(enclave.RootKeyBytes))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	defer plain.Destroy()
	if got := plain.Backend(); got.Name() != enclave.LockedMemoryBackendName {
		t.Fatalf("Backend of an unbudgeted enclave = %q, want the default", got.Name())
	}
}

func TestBackends_AnAllocatorImportsKeysAndMaterialIntoItsBudget(t *testing.T) {
	ctx := context.Background()
	unit := enclave.LockedSize(enclave.RootKeyBytes)
	a, err := enclave.NewAllocator(4 * unit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts []enclave.ImportOption
	}{
		{"WrappingKey", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}},
		{"DataKey", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}},
		{"Material", []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := heapBytes(enclave.RootKeyBytes)
			for i := range buf {
				buf[i] = byte(i + 1)
			}
			want := bytes.Clone(buf)
			base := a.InUse()

			h, err := a.Import(ctx, buf, tc.opts...)
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			defer h.Destroy()
			if !memscan.AllZero(buf) {
				t.Errorf("Import left the caller's slice unwiped")
			}
			if h.Backend() != enclave.Backend(a) || h.Size() != enclave.RootKeyBytes || !h.IsAlive() {
				t.Errorf("handle: backend %v, size %d, alive %t; want the allocator, %d bytes, alive", h.Backend(), h.Size(), h.IsAlive(), enclave.RootKeyBytes)
			}
			if got := a.InUse() - base; got != unit {
				t.Errorf("the import charged %d bytes of budget, want %d", got, unit)
			}
			ba, ok := h.(enclave.ByteAccess)
			if !ok {
				t.Fatalf("Import returned a %T, want one with byte access", h)
			}
			if same, err := ba.EqualTo(want); err != nil || !same {
				t.Errorf("imported bytes: match %t, err %v", same, err)
			}
			if err := h.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			if got := a.InUse(); got != base {
				t.Errorf("InUse = %d after Destroy, want %d", got, base)
			}
		})
	}
}

func TestBackends_AnAllocatorRefusesAnImportItCannotHonour(t *testing.T) {
	ctx := context.Background()
	unit := enclave.LockedSize(enclave.RootKeyBytes)
	a, err := enclave.NewAllocator(unit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	key := func(opts ...enclave.ImportOption) []enclave.ImportOption {
		return append([]enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}, opts...)
	}
	ended, cancel := context.WithCancel(ctx)
	cancel()

	fill := func(size int) []byte {
		b := heapBytes(size)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		with enclave.Allocator
		ctx  context.Context
		size int
		opts []enclave.ImportOption
		want error
	}{
		{"NoPurpose", a, ctx, enclave.RootKeyBytes, nil, enclave.ErrInvalidImport},
		{"NilOption", a, ctx, enclave.RootKeyBytes, []enclave.ImportOption{nil}, enclave.ErrInvalidImport},
		{"AlgorithmOnMaterial", a, ctx, enclave.RootKeyBytes, []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM)}, enclave.ErrInvalidImport},
		{"ShortKey", a, ctx, 16, key(), enclave.ErrInvalidImport},
		{"LongKey", a, ctx, 48, key(), enclave.ErrInvalidImport},
		{"EndedContext", a, ended, enclave.RootKeyBytes, key(), context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := fill(tc.size)
			h, err := tc.with.Import(tc.ctx, buf, tc.opts...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Import: %v, want %v", err, tc.want)
			}
			if h != nil {
				t.Errorf("Import returned a handle %v with its error", h)
			}
			if !memscan.AllZero(buf) {
				t.Errorf("a refused Import left the caller's slice unwiped")
			}
		})
	}

	t.Run("BudgetExhausted", func(t *testing.T) {
		first, err := a.Import(ctx, fill(enclave.RootKeyBytes), key()...)
		if err != nil {
			t.Fatalf("Import within the budget: %v", err)
		}
		defer first.Destroy()
		buf := fill(enclave.RootKeyBytes)
		if h, err := a.Import(ctx, buf, key()...); !errors.Is(err, enclave.ErrBudgetExhausted) || h != nil {
			t.Fatalf("Import past the budget: %v, %v; want ErrBudgetExhausted and no handle", h, err)
		}
		if !memscan.AllZero(buf) {
			t.Errorf("an import refused for budget left the caller's slice unwiped")
		}
	})
}
