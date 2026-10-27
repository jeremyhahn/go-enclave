// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux || !(386 || amd64 || arm64 || loong64 || riscv64 || s390x)

package enclave

import (
	"errors"
	"testing"
)

func TestLinuxSecretmem_StubRefusesConstruction(t *testing.T) {
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator = %v", err)
	}
	if b, err := NewSecretMemory(a); b != nil || !errors.Is(err, ErrMemfdSecretUnavailable) {
		t.Fatalf("NewSecretMemory = %v, %v; want ErrMemfdSecretUnavailable", b, err)
	}
}

// The stub's pages refuse too, so an OpenIn into a backend built past the
// constructor fails typed, refunds its reservation and imports nothing.
func TestLinuxSecretmem_StubOpenInRefuses(t *testing.T) {
	freshProcessSealer(t)
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator = %v", err)
	}
	ba, err := budgetOf(a)
	if err != nil {
		t.Fatalf("budgetOf = %v", err)
	}
	s, err := newSealed(t.Context(), []byte("material"))
	if err != nil {
		t.Fatalf("NewSealed = %v", err)
	}
	defer s.Destroy()

	h, err := s.OpenIn(t.Context(), &secretMemory{allocator: ba})
	if h != nil || !errors.Is(err, ErrMemfdSecretUnavailable) {
		t.Fatalf("OpenIn(stub) = %v, %v; want ErrMemfdSecretUnavailable", h, err)
	}
	if a.InUse() != 0 || !s.IsAlive() {
		t.Fatalf("after a refused open: InUse() = %d, value alive %t", a.InUse(), s.IsAlive())
	}
}
