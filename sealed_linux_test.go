// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	// sealLimitMarker selects the child half of the exhaustion test.
	sealLimitMarker = "GO_ENCLAVE_SEAL_LIMIT"

	// sealKeyRefused is logged once the child has seen NewSealed refuse with
	// a typed error because the sealer's keys could not be locked.
	sealKeyRefused = "NewSealed reported a typed error when its keys could not be locked"

	// sealOpenRefused is logged once the child has seen Open refuse with a
	// typed error because a locked destination could not be allocated. This
	// is the half the original issue names: the round trip must fail as an
	// error, not as an abort.
	sealOpenRefused = "Open reported a typed error when the destination could not be locked"

	// sealSurvivedRefusal is logged once the child has confirmed the sealed
	// value is intact after both refusals and opens correctly when the
	// ceiling is lifted.
	sealSurvivedRefusal = "the sealed value survived the refusals and opened once the ceiling lifted"
)

// TestSealedEnclave_LockedMemoryExhausted is the evidence #15 asked for and
// #22 inherits: a sealed round trip under a deliberately low RLIMIT_MEMLOCK
// reports ErrLockedMemoryUnavailable rather than aborting the process.
//
// Sealing needs locked memory in more places under the #22 envelope than it
// did before — the hierarchy's root and KEK at first seal, a transient DEK
// enclave per operation, and the plaintext destination per Open — and all of
// them are covered by the same contract: the kernel refusing pages is a typed
// error, never an abort.
//
// The last part is the one that matters most to a consumer holding a
// credential: the sealed value must SURVIVE a failed Open intact, so a
// transient ceiling is a retryable condition and not a lost credential.
//
// It runs in a subprocess because the fault is injected process-wide.
func TestSealedEnclave_LockedMemoryExhausted(t *testing.T) {
	if os.Getenv(sealLimitMarker) == "1" {
		sealLimitChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSealedEnclave_LockedMemoryExhausted$", "-test.v")
	cmd.Env = append(os.Environ(), sealLimitMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed (an abort here is the behavior this test forbids): %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	for _, want := range []string{sealKeyRefused, sealOpenRefused, sealSurvivedRefusal} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func sealLimitChild(t *testing.T) {
	t.Helper()

	material := append([]byte(nil), sealedMaterial...)

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	lower := func(cur uint64) error {
		return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: cur, Max: original.Max})
	}

	// Zero locked bytes allowed, so no key enclave — not the provider root,
	// not the hierarchy, not a DEK — can be created at all. This runs FIRST,
	// before anything has caused any of them to exist.
	if err := lower(0); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

	s, err := NewSealed(append([]byte(nil), material...))
	if err == nil {
		s.Destroy()
		t.Skip("NewSealed unexpectedly succeeded under a zero ceiling; no fault was injected")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("NewSealed err = %v, want ErrLockedMemoryUnavailable", err)
	}
	t.Log(sealKeyRefused)

	// Lift the ceiling far enough to seal, then seal for real. This also
	// exercises the retry-not-memoize contract on the hierarchy: the failed
	// first seal must not have latched the failure.
	if err := lower(original.Cur); err != nil {
		t.Skipf("cannot restore RLIMIT_MEMLOCK: %v", err)
	}
	s, err = NewSealed(append([]byte(nil), material...))
	if err != nil {
		t.Skipf("could not seal with the ceiling restored: %v", err)
	}

	// Now drop it again. The hierarchy's keys are already locked and stay
	// locked — lowering the soft limit does not unlock existing pages — so
	// what fails is Open's attempt to allocate fresh pages for the DEK and
	// the destination.
	if err := lower(uint64(os.Getpagesize())); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

	var openErr error
	for i := 0; i < 64; i++ {
		e, oerr := s.Open()
		if oerr != nil {
			openErr = oerr
			break
		}
		// Deliberately NOT destroyed: each surviving open holds a locked
		// page, which is how the ceiling is reached if the first attempts
		// squeeze under it.
		_ = e
	}
	if openErr == nil {
		t.Skip("Open never failed under a one-page ceiling; no fault was injected")
	}
	if !errors.Is(openErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("Open err = %v, want ErrLockedMemoryUnavailable", openErr)
	}
	t.Log(sealOpenRefused)

	// The refusals must have cost the sealed value nothing. This is what
	// makes a transient ceiling retryable rather than a lost credential.
	if !s.IsAlive() {
		t.Fatal("the sealed value was destroyed by a failed Open")
	}
	if err := lower(original.Cur); err != nil {
		t.Skipf("cannot restore RLIMIT_MEMLOCK: %v", err)
	}
	e, err := s.Open()
	if err != nil {
		t.Fatalf("Open after the ceiling lifted: %v", err)
	}
	if !e.EqualTo(material) {
		t.Fatal("the sealed value did not open to its original material after the refusals")
	}
	e.Destroy()
	t.Log(sealSurvivedRefusal)
}

// TestSealedEnclave_OpenedPlaintextIsLocked closes the loop on the claim that
// Open decrypts into locked memory and nowhere else.
//
// The round-trip tests prove the plaintext ends up in the enclave, and the
// production check in openWithKeyInto proves the AEAD wrote it there in place
// rather than allocating. What neither shows is that those pages are
// genuinely mlock'd — so this asks the kernel, using VmLck as the yardstick
// rather than anything this package computes.
//
// The measurement is taken across a completed Open, which also pins a #22
// property in passing: the transient DEK enclave every Open creates is
// destroyed before Open returns, so the steady-state cost of an open value is
// exactly the plaintext's page, not the DEK's too.
func TestSealedEnclave_OpenedPlaintextIsLocked(t *testing.T) {
	freshProcessSealer(t)
	if _, err := vmLckBytes(); err != nil {
		t.Skipf("cannot read VmLck: %v", err)
	}

	s, err := NewSealed(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	before, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	e, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	after, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	locked := after - before
	if locked == 0 {
		t.Skip("opening moved VmLck by 0 bytes; mlock is not accounted in this environment")
	}
	if want := LockedSize(len(sealedMaterial)); locked != want {
		t.Errorf("opening locked %d bytes, want %d (the page the plaintext should occupy; more means "+
			"a per-open key enclave outlived the Open)", locked, want)
	}
	if !e.EqualTo(sealedMaterial) {
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

// TestSealedEnclave_NoPlaintextInProcessMemory is the residency claim taken
// past the envelope itself: no copy of the material survives anywhere in the
// process's memory once nothing is open.
//
// # The first version of this test was VACUOUS, and the way it failed is the
// # reason it is written like this now
//
// It skipped every NAMED mapping to avoid matching the test binary's own
// rodata. But the Go runtime NAMES its heap: `[anon: Go: heap]`. Measured,
// that left 1 unnamed-anonymous mapping swept and 30 kernel-named ones
// skipped — so the sweep read the locked enclave and essentially nothing
// else. A mutant retaining the plaintext on the heap forever survived it
// (reviewer-enclave-9, phase 1 on PR #16).
//
// The non-vacuity control did not save it, and that is the instructive part:
// the control proved the needle was findable SOMEWHERE, and it was — in the
// locked enclave. It never proved the sweep could see the place a leak would
// actually be. A control has to exercise the path the assertion depends on,
// not merely return the answer the assertion wants.
//
// So: file-backed mappings are excluded (the binary's rodata), every
// anonymous mapping is swept whether the kernel named it or not, the needle
// is generated into locked memory and never exists as a heap value, and the
// comparison runs INSIDE a borrow so the test cannot match a copy of its own
// making.
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

	// A transient heap copy is unavoidable to hand the material to NewSealed,
	// which takes ownership and wipes it. That wipe is part of what this test
	// checks: if it did not happen, the sweep finds the remains.
	tmp := make([]byte, 64)
	if err := needleEnclave.WithBytes(func(b []byte) error {
		copy(tmp, b)
		return nil
	}); err != nil {
		t.Fatalf("copying the needle: %v", err)
	}
	s, err := NewSealed(tmp)
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	// home is the mapping the needle itself lives in. Every legitimate match
	// is inside it; anything outside it is a copy that should not exist.
	var home uintptr
	if err := needleEnclave.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = sliceAddr(b)
		return aerr
	}); err != nil {
		t.Fatalf("needle address: %v", err)
	}

	// Control FIRST, and a real one: with an enclave open there must be a
	// match OUTSIDE the needle's own mapping — the opened plaintext. That
	// proves the sweep can see a second place, which is exactly what the old
	// version never established.
	open, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	withOpen, err := findNeedle(needleEnclave)
	if err != nil {
		open.Destroy()
		t.Skipf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(withOpen, home); len(outside) == 0 {
		open.Destroy()
		t.Skipf("the sweep found no match outside the needle's own mapping even with an enclave open "+
			"(%d matches total); it cannot see the mappings a leak would live in and a negative result "+
			"would be vacuous", len(withOpen))
	}
	open.Destroy()

	// The assertion: nothing open, so the only match may be the needle
	// itself.
	closed, err := findNeedle(needleEnclave)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(closed, home); len(outside) > 0 {
		t.Errorf("the material is present in %d mapping(s) outside the enclave holding it, with nothing open: "+
			"a copy survived sealing, opening or destroying. First at %s", len(outside), outside[0])
	}
}

// findNeedle sweeps process memory for the material held in probe, comparing
// from inside a borrow so the needle never exists as a heap value.
func findNeedle(probe *MemoryEnclave) ([]string, error) {
	var hits []string
	var err error
	berr := probe.WithBytes(func(needle []byte) error {
		hits, err = processMemoryFind(needle)
		return err
	})
	if berr != nil {
		return nil, berr
	}
	return hits, err
}

// TestSealedEnclave_FailedOpenLeaksNoLockedMemory pins the cleanup on Open's
// failure path (reviewer-enclave-9, phase 1 on PR #16, mutant SM8 — inherited
// here with a second allocation to cover).
//
// Open allocates its DEK enclave and its destination BEFORE it can know
// whether the envelope authenticates, so every failed Open has locked pages
// to give back. Dropping either Destroy leaks them permanently: a
// MemoryEnclave has no finalizer, so nothing reclaims it, and a caller
// retrying a failing Open in a loop — which is what a service does when a
// credential looks corrupt — walks straight into RLIMIT_MEMLOCK and takes
// every other allocation in the process down with it.
//
// The yardstick is VmLck, so it measures what the kernel charged rather than
// what this package believes it released.
func TestSealedEnclave_FailedOpenLeaksNoLockedMemory(t *testing.T) {
	freshProcessSealer(t)
	if _, err := vmLckBytes(); err != nil {
		t.Skipf("cannot read VmLck: %v", err)
	}

	s, err := NewSealed(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	// Prove the measurement can see a page at all before trusting it to show
	// none: a SUCCESSFUL open must move VmLck. Without this the assertion
	// below passes on any host where mlock is not accounted.
	base, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	e, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	openDelta, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	e.Destroy()
	if openDelta-base == 0 {
		t.Skip("a successful Open moved VmLck by 0 bytes; mlock is not accounted here and this test would be vacuous")
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
		out, oerr := s.Open()
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
// half of TestSealedEnclave_SizeMismatchIsRejected, and it is the half that
// matters.
//
// Open sizes its locked destination from the recorded plaintext length, and
// the destination's capacity is EXACT. So a recorded length SMALLER than the
// real plaintext would make the AEAD's append reallocate, and crypto/cipher
// would write the whole opened plaintext into an ordinary heap buffer. Open
// would then return an error and the caller would see a clean refusal, while
// the material it was refusing to hand over sat in unlocked, swappable,
// dumpable memory.
//
// Returning the right error is therefore not the property to test. The
// property is that the plaintext never exists outside locked memory, which is
// what this type is for, and only a sweep can show it. (The pre-#22 code had
// exactly this defect before the length check moved ahead of the decryption;
// the sweep below is what caught it.)
func TestSealedEnclave_SizeMismatchDoesNotDecryptOntoTheHeap(t *testing.T) {
	freshProcessSealer(t)
	// Generated straight into locked memory: a literal would put the test's
	// own constant on the heap and the sweep would match it every run.
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

	tmp := make([]byte, 64)
	if err := needleEnclave.WithBytes(func(b []byte) error {
		copy(tmp, b)
		return nil
	}); err != nil {
		t.Fatalf("copying the needle: %v", err)
	}
	s, err := NewSealed(tmp)
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	var home uintptr
	if err := needleEnclave.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = sliceAddr(b)
		return aerr
	}); err != nil {
		t.Fatalf("needle address: %v", err)
	}

	// Control first: with an enclave open the sweep must find a match
	// outside the needle's own mapping. Without this, a negative result
	// below would prove only that the sweep cannot see anything.
	open, err := s.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	withOpen, err := findNeedle(needleEnclave)
	if err != nil {
		open.Destroy()
		t.Skipf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(withOpen, home); len(outside) == 0 {
		open.Destroy()
		t.Skipf("the sweep found no match outside the needle's own mapping even with an enclave open "+
			"(%d matches total); a negative result would be vacuous", len(withOpen))
	}
	open.Destroy()

	// Now the corruption: the recorded length is one byte SHORT of the real
	// plaintext, which is the direction that forces the reallocation. A
	// longer recorded length makes the destination too big, which is refused
	// without putting anything anywhere.
	s.mu.Lock()
	s.size--
	s.mu.Unlock()

	e, oerr := s.Open()
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

	closed, err := findNeedle(needleEnclave)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(closed, home); len(outside) > 0 {
		t.Errorf("the material is present in %d mapping(s) outside the enclave holding it after a REFUSED "+
			"Open: the AEAD decrypted onto the heap before the mismatch was noticed, so the refusal is "+
			"cosmetic and the plaintext is in unlocked memory. First at %s", len(outside), outside[0])
	}
}
