// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux && (386 || amd64 || arm64 || loong64 || riscv64 || s390x)

package enclave

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// importSpy is the secretmem backend with Import counted: OpenIn into it must
// decrypt into its pages and never import.
type importSpy struct {
	*secretMemory
	imports atomic.Int32
}

func (s *importSpy) Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error) {
	s.imports.Add(1)
	return s.secretMemory.Import(ctx, material, opts...)
}

// sealForSecretmem seals a copy of material, which newSealed wipes.
func sealForSecretmem(t *testing.T, material string) *sealedValue {
	t.Helper()
	s, err := newSealed(t.Context(), []byte(material))
	if err != nil {
		t.Fatalf("NewSealed = %v", err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	return s
}

func TestLinuxSecretmem_OpenInDecryptsIntoSecretPages(t *testing.T) {
	freshProcessSealer(t)
	memfdStandIn(t, 0)
	b, a := newSecretMemoryForTest(t, 1<<20)
	spy := &importSpy{secretMemory: b}

	// Generated into locked memory and sealed from a locked transfer enclave,
	// so the only copies a sweep can find are the needle and what OpenIn makes.
	needle, err := newMemorySized(64)
	if err != nil {
		t.Fatalf("newMemorySized = %v", err)
	}
	defer needle.Destroy()
	var home uintptr
	if err := needle.WithBytes(func(p []byte) error {
		if _, rerr := io.ReadFull(rand.Reader, p); rerr != nil {
			return rerr
		}
		var aerr error
		home, aerr = memscan.Addr(p)
		return aerr
	}); err != nil {
		t.Fatalf("generating the needle: %v", err)
	}
	s := sealFromEnclave(t, needle)
	defer s.Destroy()

	h, err := s.OpenIn(t.Context(), spy)
	if err != nil {
		t.Fatalf("OpenIn(secretmem) = %v", err)
	}
	defer h.Destroy()
	if n := spy.imports.Load(); n != 0 {
		t.Fatalf("OpenIn imported %d times; it must decrypt into the backend's pages", n)
	}
	if _, ok := h.(*secretRegion); !ok || h.Backend() != Backend(b) {
		t.Fatalf("OpenIn returned %T naming %v, want a secretmem handle", h, h.Backend())
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse() = %d, want the one page OpenIn admitted", a.InUse())
	}
	var eq bool
	if err := needle.WithBytes(func(p []byte) error {
		var eerr error
		eq, eerr = h.(ByteAccess).EqualTo(p)
		return eerr
	}); err != nil || !eq {
		t.Fatalf("opened handle EqualTo(needle) = %t, %v", eq, err)
	}

	// The plaintext lives in the needle and in the memfd pages, nowhere else:
	// no scratch enclave or heap buffer kept a copy.
	hits, err := findNeedle(needle, home)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if len(hits) != 1 || !strings.Contains(hits[0], "/memfd:secretmem-stand-in") {
		t.Fatalf("plaintext found in %q, want only the secretmem handle's pages", hits)
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if a.InUse() != 0 {
		t.Fatalf("InUse() = %d after Destroy, want 0", a.InUse())
	}
	if hits, err := findNeedle(needle, home); err != nil || len(hits) != 0 {
		t.Fatalf("after Destroy the plaintext is in %q (%v)", hits, err)
	}
}

func TestLinuxSecretmem_OpenInRefusesTamperedAndForgedValues(t *testing.T) {
	freshProcessSealer(t)
	memfdStandIn(t, 0)
	b, a := newSecretMemoryForTest(t, 1<<20)

	tampered := sealForSecretmem(t, "tampered material")
	tampered.sealed[len(tampered.sealed)-1] ^= 1
	// Two authentic halves never sealed together.
	forged := sealForSecretmem(t, "forged material A")
	other := sealForSecretmem(t, "forged material B")
	forged.blob = other.blob

	for name, s := range map[string]*sealedValue{"tampered": tampered, "forged": forged} {
		h, err := s.OpenIn(t.Context(), b)
		if !errors.Is(err, ErrSealedAuthentication) || h != nil {
			t.Fatalf("OpenIn(%s) = %v, %v; want ErrSealedAuthentication", name, h, err)
		}
		if a.InUse() != 0 {
			t.Fatalf("InUse() = %d after a refused %s open, want 0", a.InUse(), name)
		}
	}
}

func TestLinuxSecretmem_OpenInHonoursCancellation(t *testing.T) {
	freshProcessSealer(t)
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	b, a := newSecretMemoryForTest(t, 1<<20)
	s := sealForSecretmem(t, "material")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h, err := s.OpenIn(ctx, b)
	if !errors.Is(err, ErrOpenFailed) || !errors.Is(err, context.Canceled) || h != nil {
		t.Fatalf("OpenIn(canceled) = %v, %v; want ErrOpenFailed carrying context.Canceled", h, err)
	}
	if calls.Load() != 0 || a.InUse() != 0 {
		t.Fatalf("a canceled open called memfd_secret %d times, InUse() = %d", calls.Load(), a.InUse())
	}
	if !s.IsAlive() {
		t.Fatal("a canceled open destroyed the value")
	}
}

func TestLinuxSecretmem_OpenInRefusalIsTypedAndFallsBackToNothing(t *testing.T) {
	freshProcessSealer(t)
	refuseMemfdSecret(t, unix.ENOSYS)
	b, a := newSecretMemoryForTest(t, 1<<20)
	spy := &importSpy{secretMemory: b}
	s := sealForSecretmem(t, "material")

	h, err := s.OpenIn(t.Context(), spy)
	if h != nil || !errors.Is(err, ErrOpenFailed) {
		t.Fatalf("OpenIn on a refused memfd_secret = %v, %v; want ErrOpenFailed", h, err)
	}
	assertMemfdSecretRefusal(t, err, "memfd_secret", unix.ENOSYS)
	if spy.imports.Load() != 0 || a.InUse() != 0 {
		t.Fatalf("a refused open imported %d times, InUse() = %d", spy.imports.Load(), a.InUse())
	}
	// The value is intact: the memory enclave still opens it.
	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after a refused OpenIn = %v", err)
	}
	defer e.Destroy()
	if eq, err := e.EqualTo([]byte("material")); !eq || err != nil {
		t.Fatalf("EqualTo = %t, %v", eq, err)
	}
}

func TestLinuxSecretmem_OpenInBudgetRefusal(t *testing.T) {
	freshProcessSealer(t)
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	b, _ := newSecretMemoryForTest(t, pageSize)
	s := sealForSecretmem(t, string(bytes.Repeat([]byte{'x'}, int(2*pageSize))))

	_, err := s.OpenIn(t.Context(), b)
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("OpenIn past the budget = %v, want a *BudgetError", err)
	}
	if calls.Load() != 0 {
		t.Fatal("an open the budget refused called memfd_secret")
	}
}

func TestLinuxSecretmem_OpenInRealMemfdSecret(t *testing.T) {
	freshProcessSealer(t)
	b, a := newSecretMemoryForTest(t, 1<<20)
	requireMemfdSecret(t, b)
	s := sealForSecretmem(t, "opened into memfd_secret pages")

	h, err := s.OpenIn(t.Context(), b)
	if err != nil {
		t.Fatalf("OpenIn = %v", err)
	}
	if eq, err := h.(ByteAccess).EqualTo([]byte("opened into memfd_secret pages")); !eq || err != nil {
		t.Fatalf("EqualTo = %t, %v", eq, err)
	}
	if err := h.Destroy(); err != nil || a.InUse() != 0 {
		t.Fatalf("Destroy = %v, InUse() = %d", err, a.InUse())
	}
}
