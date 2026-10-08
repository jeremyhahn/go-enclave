// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

const (
	// sealLimitMarker selects the child half of the exhaustion test.
	sealLimitMarker = "GO_ENCLAVE_SEAL_LIMIT"

	// sealKeyRefused is logged once the child has seen NewSealed refuse with
	// a typed error because the sealer's keys could not be locked.
	sealKeyRefused = "NewSealed reported a typed error when its keys could not be locked"

	// sealOpenRefused is logged once the child has seen Open refuse with a
	// typed error because a locked destination could not be allocated.
	sealOpenRefused = "Open reported a typed error when the destination could not be locked"

	// sealSurvivedRefusal is logged once the child has confirmed the sealed
	// value is intact after both refusals and opens correctly when the
	// ceiling is lifted.
	sealSurvivedRefusal = "the sealed value survived the refusals and opened once the ceiling lifted"
)

// TestSealedEnclave_LockedMemoryExhausted pins that a sealed round trip under
// a low RLIMIT_MEMLOCK reports ErrLockedMemoryUnavailable rather than aborting,
// wherever locked memory is needed (root, KEK, transient DEK, destination),
// and that the sealed value survives a failed Open intact.
//
// It runs in a subprocess because the fault is injected process-wide.
func TestSealedEnclave_LockedMemoryExhausted(t *testing.T) {
	if os.Getenv(sealLimitMarker) == "1" {
		sealLimitChild(t)
		return
	}

	out, err := runTestChild(t, "TestSealedEnclave_LockedMemoryExhausted", sealLimitMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed (an abort here is the behavior this test forbids): %v\n%s", err, out)
	}
	for _, want := range []string{sealKeyRefused, sealOpenRefused, sealSurvivedRefusal} {
		if !strings.Contains(out, want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func sealLimitChild(t *testing.T) {
	t.Helper()

	material := append([]byte(nil), sealedMaterial...)

	setCeiling, original := injectMemlockCeiling(t)

	// Zero locked bytes allowed, so no key enclave can be created. This runs
	// first, before any of them exists.
	setCeiling(0)

	s, err := NewSealed(t.Context(), append([]byte(nil), material...))
	if err == nil {
		s.Destroy()
		t.Fatal("NewSealed succeeded under a zero RLIMIT_MEMLOCK: the ceiling did not bind, no fault " +
			"was injected, and everything below would be vacuous")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("NewSealed err = %v, want ErrLockedMemoryUnavailable", err)
	}
	t.Log(sealKeyRefused)

	// Lift the ceiling and seal for real; the failed first seal must not have
	// latched the failure.
	setCeiling(original.Cur)
	s, err = NewSealed(t.Context(), append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewSealed with the ceiling restored: %v (the failed first seal must not have latched "+
			"its failure)", err)
	}

	// Drop it again. The hierarchy's pages stay locked (lowering the soft limit
	// does not unlock them), so what fails is Open's allocation of the DEK and
	// the destination.
	setCeiling(uint64(os.Getpagesize()))

	var openErr error
	for i := 0; i < 64; i++ {
		e, oerr := s.Open(t.Context())
		if oerr != nil {
			openErr = oerr
			break
		}
		// Deliberately not destroyed: each surviving open holds a locked page,
		// so the ceiling is reached even if the first attempts squeeze under it.
		_ = e
	}
	if openErr == nil {
		t.Fatal("64 Opens succeeded under a one-page RLIMIT_MEMLOCK: the ceiling did not bind and no " +
			"fault was injected")
	}
	if !errors.Is(openErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("Open err = %v, want ErrLockedMemoryUnavailable", openErr)
	}
	t.Log(sealOpenRefused)

	// The refusals must have cost the sealed value nothing.
	if !s.IsAlive() {
		t.Fatal("the sealed value was destroyed by a failed Open")
	}
	setCeiling(original.Cur)
	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after the ceiling lifted: %v", err)
	}
	if !holds(e, material) {
		t.Fatal("the sealed value did not open to its original material after the refusals")
	}
	e.Destroy()
	t.Log(sealSurvivedRefusal)
}

// TestSealedEnclave_OpenedPlaintextIsLocked pins, using the kernel's VmLck,
// that Open's destination is genuinely mlock'd, and that the transient DEK is
// released before Open returns, so an open value costs exactly the
// plaintext's page.
func TestSealedEnclave_OpenedPlaintextIsLocked(t *testing.T) {
	freshProcessSealer(t)

	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	before, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	after, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	locked := after - before
	if want := LockedSize(len(sealedMaterial)); locked != want {
		t.Errorf("opening locked %d bytes, want %d (the page the plaintext should occupy; more means "+
			"a per-open key enclave outlived the Open)", locked, want)
	}
	if !holds(e, sealedMaterial) {
		t.Error("the opened enclave does not hold the material")
	}

	e.Destroy()

	final, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	if final != before {
		t.Errorf("VmLck = %d after destroying the opened enclave, want the pre-Open %d", final, before)
	}
}

// TestSealedEnclave_NoPlaintextInProcessMemory pins that no copy of the
// material survives anywhere in process memory once nothing is open.
//
// Every anonymous mapping is swept, named or not (the Go runtime names its heap
// "[anon: Go: heap]"); file-backed mappings are excluded. The needle is
// generated into locked memory and compared inside a borrow, so the test never
// matches a copy of its own making. The control must find a match outside the
// needle's own mapping, proving the sweep can see where a leak would be.
func TestSealedEnclave_NoPlaintextInProcessMemory(t *testing.T) {
	freshProcessSealer(t)
	// The needle is generated straight into locked memory. A []byte literal
	// would put a copy on the heap and the sweep would find the test's own
	// constant in every run.
	needleEnclave, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer needleEnclave.Destroy()
	if err := needleEnclave.WithBytes(func(b []byte) error {
		_, rerr := io.ReadFull(rand.Reader, b)
		return rerr
	}); err != nil {
		t.Fatalf("generating the needle: %v", err)
	}

	// The input is handed over from a locked transfer enclave, so the plaintext
	// never exists on the heap and the wipe NewSealed performs is part of what
	// the sweep checks.
	s := sealFromEnclave(t, needleEnclave)
	defer s.Destroy()

	// home is the mapping the needle itself lives in. Every legitimate match
	// is inside it; anything outside it is a copy that should not exist.
	var home uintptr
	if err := needleEnclave.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = memscan.Addr(b)
		return aerr
	}); err != nil {
		t.Fatalf("needle address: %v", err)
	}

	// Control first: with an enclave open there must be a match outside the
	// needle's own mapping, the opened plaintext.
	open, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	withOpen, err := findNeedle(needleEnclave, home)
	if err != nil {
		open.Destroy()
		t.Fatalf("cannot sweep process memory: %v (see memscan.Find for what the runner must allow)", err)
	}
	if len(withOpen) == 0 {
		open.Destroy()
		t.Fatalf("the sweep found no match outside the needle's own mapping even with an enclave open; it " +
			"cannot see the mappings a leak would live in and a negative result would be vacuous")
	}
	open.Destroy()

	// Nothing is open, so the only match may be the needle itself.
	closed, err := findNeedle(needleEnclave, home)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if len(closed) > 0 {
		t.Errorf("the material is present in %d mapping(s) outside the enclave holding it, with nothing open: "+
			"a copy survived sealing, opening or destroying. First at %s", len(closed), closed[0])
	}
}

// findNeedle sweeps process memory outside the mapping containing home for the
// material held in probe, comparing from inside a borrow so the needle never
// exists as a heap value.
func findNeedle(probe *MemoryEnclave, home uintptr) ([]string, error) {
	var hits []string
	var err error
	berr := probe.WithBytes(func(needle []byte) error {
		hits, err = memscan.Find(needle, home)
		return err
	})
	if berr != nil {
		return nil, berr
	}
	return hits, err
}

// TestSealedEnclave_FailedOpenLeaksNoLockedMemory pins the cleanup on Open's
// failure path. Open allocates its DEK and destination before it knows whether
// the envelope authenticates, and a MemoryEnclave has no finalizer, so a
// dropped Destroy would leak locked pages on every retried open. VmLck is the
// yardstick, so it measures what the kernel charged.
func TestSealedEnclave_FailedOpenLeaksNoLockedMemory(t *testing.T) {
	freshProcessSealer(t)

	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	// A successful open must move VmLck first; otherwise the assertion below
	// passes on any host where mlock is not accounted.
	base, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	openDelta, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	e.Destroy()
	if openDelta-base == 0 {
		t.Fatal("a successful Open moved VmLck by 0 bytes: the kernel is not accounting mlock, so the " +
			"no-growth assertion below would pass vacuously. The runner must be a real Linux kernel " +
			"that reports VmLck in /proc/self/status (see vmLckBytes)")
	}

	// Now make Open fail AFTER it has allocated: tamper with the sealed
	// bytes so the destination exists and the authentication does not.
	s.sealed[len(s.sealed)-1] ^= 0xFF

	before, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	const attempts = 32
	for i := 0; i < attempts; i++ {
		out, oerr := s.Open(t.Context())
		if oerr == nil {
			out.Destroy()
			t.Fatal("Open succeeded on tampered material")
		}
		if !errors.Is(oerr, ErrSealedAuthentication) {
			t.Fatalf("Open err = %v, want ErrSealedAuthentication", oerr)
		}
	}

	after, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	if after != before {
		t.Errorf("VmLck grew by %d bytes over %d failed Opens, want 0: each failure leaked locked pages, "+
			"and nothing reclaims them", after-before, attempts)
	}

	s.sealed[len(s.sealed)-1] ^= 0xFF // restore so the deferred Destroy is clean
}

// TestSealedEnclave_SizeMismatchDoesNotDecryptOntoTheHeap is the residency
// half of TestSealedEnclave_SizeMismatchIsRejected. A recorded length smaller
// than the real plaintext would make the AEAD's append reallocate and write
// the plaintext to the heap while Open still returned an error. Only a memory
// sweep can show that it does not.
func TestSealedEnclave_SizeMismatchDoesNotDecryptOntoTheHeap(t *testing.T) {
	freshProcessSealer(t)
	// Generated into locked memory: a literal would put the test's own constant
	// on the heap.
	needleEnclave, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer needleEnclave.Destroy()
	if err := needleEnclave.WithBytes(func(b []byte) error {
		_, rerr := io.ReadFull(rand.Reader, b)
		return rerr
	}); err != nil {
		t.Fatalf("generating the needle: %v", err)
	}

	s := sealFromEnclave(t, needleEnclave)
	defer s.Destroy()

	var home uintptr
	if err := needleEnclave.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = memscan.Addr(b)
		return aerr
	}); err != nil {
		t.Fatalf("needle address: %v", err)
	}

	// Control first: with an enclave open the sweep must find a match
	// outside the needle's own mapping. Without this, a negative result
	// below would prove only that the sweep cannot see anything.
	open, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	withOpen, err := findNeedle(needleEnclave, home)
	if err != nil {
		open.Destroy()
		t.Fatalf("cannot sweep process memory: %v (see memscan.Find for what the runner must allow)", err)
	}
	if len(withOpen) == 0 {
		open.Destroy()
		t.Fatalf("the sweep found no match outside the needle's own mapping even with an enclave open; " +
			"a negative result would be vacuous")
	}
	open.Destroy()

	// The recorded length is one byte short, the direction that would force the
	// reallocation; a longer one is refused without writing anything.
	s.mu.Lock()
	s.size--
	s.mu.Unlock()

	e, oerr := s.Open(t.Context())
	if !errors.Is(oerr, ErrSealedAuthentication) {
		t.Errorf("Open with a short recorded size = %v, want ErrSealedAuthentication", oerr)
	}
	if e != nil {
		e.Destroy()
		t.Error("Open returned an enclave despite a size mismatch")
	}

	// Restore before the sweep so the deferred Destroy wipes the whole
	// envelope rather than one byte less of it.
	s.mu.Lock()
	s.size++
	s.mu.Unlock()

	runtime.GC()

	closed, err := findNeedle(needleEnclave, home)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if len(closed) > 0 {
		t.Errorf("the material is present in %d mapping(s) outside the enclave holding it after a REFUSED "+
			"Open: the AEAD decrypted onto the heap before the mismatch was noticed, so the refusal is "+
			"cosmetic and the plaintext is in unlocked memory. First at %s", len(closed), closed[0])
	}
}

// sealFromEnclave seals a copy of src's material without the plaintext
// touching the ordinary heap: NewSealed is called on a borrow of a locked
// transfer enclave, so the input it wipes is locked memory.
func sealFromEnclave(t *testing.T, src *MemoryEnclave) *SealedEnclave {
	t.Helper()
	transfer, err := NewMemoryEnclaveSized(src.Size())
	if err != nil {
		t.Fatalf("allocating the transfer enclave: %v", err)
	}
	defer func() { _ = transfer.Destroy() }()
	var sealed *SealedEnclave
	if err := transfer.WithBytes(func(dst []byte) error {
		if err := src.WithBytes(func(b []byte) error { copy(dst, b); return nil }); err != nil {
			return err
		}
		var serr error
		sealed, serr = NewSealed(t.Context(), dst)
		if serr != nil {
			return serr
		}
		// NewSealed must wipe its input. Checked inside the borrow, because
		// destroying the transfer enclave below would erase the evidence.
		for _, c := range dst {
			if c != 0 {
				return errors.New("NewSealed left its input unwiped")
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("sealing from a locked transfer enclave: %v", err)
	}
	return sealed
}
