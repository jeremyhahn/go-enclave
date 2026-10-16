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
	"os"
	"strings"
	"testing"
)

const (
	sealCleanupMarker = "ENCLAVE_TEST_SEAL_CLEANUP_CHILD"
	cleanupOpenDEK    = "SEAL-CLEANUP: Open's refused DEK returned its locked memory"
	cleanupSealKEK    = "SEAL-CLEANUP: Seal's refused KEK returned its locked memory"
	cleanupLoadFrozen = "SEAL-CLEANUP: loadFrozen's refused freeze returned its locked memory"
)

// TestSealer_RefusedAllocationsReturnLockedMemory drives the cleanup paths
// that run once part of an operation's locked memory exists: Open refused its
// DEK after allocating the destination, Seal refused a rotation's KEK after
// allocating the DEK, and loadFrozen refused the freeze after mapping. Each
// must return locked memory to its baseline. The ceiling is process-wide, so
// it runs in a child.
func TestSealer_RefusedAllocationsReturnLockedMemory(t *testing.T) {
	if os.Getenv(sealCleanupMarker) == "1" {
		sealCleanupChild(t)
		return
	}

	out, err := runTestChild(t, "TestSealer_RefusedAllocationsReturnLockedMemory", sealCleanupMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	for _, want := range []string{cleanupOpenDEK, cleanupSealKEK, cleanupLoadFrozen} {
		if !strings.Contains(out, want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func sealCleanupChild(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	material := []byte("cleanup-material") // one key's pages, as a DEK's

	setCeiling, original := injectMemlockCeiling(t)
	defer setCeiling(original.Cur)

	locked := func() int64 {
		t.Helper()
		n, err := vmLckBytes()
		if err != nil {
			t.Fatalf("VmLck: %v", err)
		}
		return n
	}

	// One key's locked footprint, which every allocation below shares.
	base := locked()
	k, err := newMemorySized(dekBytes)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	perKey := locked() - base
	_ = k.Destroy()
	if perKey <= 0 {
		t.Fatal("a key enclave moved VmLck by 0 bytes: the kernel is not accounting mlock, so every " +
			"baseline below would hold vacuously")
	}
	// allow lets exactly n more key-sized allocations lock their pages.
	allow := func(n int64) int64 {
		t.Helper()
		cur := locked()
		setCeiling(uint64(cur + n*perKey))
		return cur
	}
	requireBaseline := func(what string, before int64) {
		t.Helper()
		if after := locked(); after != before {
			t.Fatalf("%s left VmLck %d bytes from its baseline, want 0", what, after-before)
		}
	}

	// Open: the destination fits and the DEK does not.
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()
	v, err := s.sealData(ctx, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	before := allow(1)
	if e, err := v.Open(ctx); !errors.Is(err, ErrLockedMemoryUnavailable) {
		_ = e.Destroy()
		t.Fatalf("Open with room for one page set = %v, want ErrLockedMemoryUnavailable", err)
	}
	requireBaseline("Open's refused DEK", before)
	allow(2)
	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open with room for the destination and the DEK: %v (so the refusal above was not the DEK's)", err)
	}
	if !holds(e, material) {
		t.Fatal("the value opened to the wrong material after the refusal")
	}
	_ = e.Destroy()
	t.Log(cleanupOpenDEK)

	// Seal: the DEK fits and the rotation's KEK does not.
	setCeiling(original.Cur)
	r, err := newEnvelopeSealer(WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer r.Destroy()
	first, err := r.sealData(ctx, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer first.Destroy()

	before = allow(1)
	data := append([]byte(nil), material...)
	if w, err := r.sealData(ctx, data); !errors.Is(err, ErrLockedMemoryUnavailable) {
		_ = w.Destroy()
		t.Fatalf("a rotating Seal with room for one page set = %v, want ErrLockedMemoryUnavailable", err)
	}
	requireBaseline("Seal's refused KEK", before)
	allow(2)
	w, err := r.sealData(ctx, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("a rotating Seal with room for the DEK and the KEK: %v (so the refusal above was not the KEK's)", err)
	}
	_ = w.Destroy()
	t.Log(cleanupSealKEK)

	// loadFrozen: the mapping fits and the freeze is refused.
	before = allow(1)
	lift := denyProtect(t)
	m, err := newMemory(append([]byte(nil), material...))
	lift()
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		_ = m.Destroy()
		t.Fatalf("NewMemory with its freeze refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	requireBaseline("loadFrozen's refused freeze", before)
	m, err = newMemory(append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewMemory with room for one page set: %v (so the refusal above was not the freeze's)", err)
	}
	_ = m.Destroy()
	t.Log(cleanupLoadFrozen)
}
