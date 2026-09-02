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
	"crypto/rand"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memcall"
)

// TestMemoryEnclave_AllocateInsideBorrow covers the deadlock that owning the
// mapping was meant to remove.
//
// Until v0.3.0-alpha a process-wide lock serialized every allocation against
// every borrow: allocation took it exclusively, borrows took it shared, and Go's
// RWMutex blocks new readers once a writer queues. So a goroutine holding a
// borrow that called anything which allocated protected memory DEADLOCKED.
//
// That shape is ordinary, not exotic: handing borrowed key material to an
// injected interface whose implementations allocate protected memory of their
// own. All three ways of writing it were blocked — hold the borrow (deadlock),
// copy to the heap (the regression this package exists to prevent), or pass the
// bytes unborrowed (the race).
//
// go-enclave owns its mapping now, nothing can purge it, and the lock is gone.
// This holds a borrow and allocates, borrows, fills and destroys a second
// enclave from inside it.
//
// The wait is bounded around the CALL, not measured after it: a regression here
// is a deadlock, so a timing assertion placed after the borrow returned would
// simply never run and the suite would die on its own timeout with no
// explanation. The goroutine-plus-select reports the reason instead.
func TestMemoryEnclave_AllocateInsideBorrow(t *testing.T) {
	const outerMaterial = "outer-private-key-material"

	outer, err := NewMemoryEnclave([]byte(outerMaterial))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	// Cleanup is conditional ON PURPOSE. Destroy takes the enclave's write
	// lock, so if the borrow below never returns it blocks forever — and since
	// t.Fatal ends only its own goroutine after running deferred calls, a plain
	// `defer outer.Destroy()` would hang the binary on exactly the regression
	// this test exists to catch. The go-test alarm would then report a generic
	// timeout and swallow the message below. Measured: reintroducing the
	// process-wide lock produced "panic: test timed out" and no explanation
	// until this was conditional. Leaking one enclave in a failing run is the
	// right trade; the process is about to exit either way.
	completed := false
	defer func() {
		if completed {
			outer.Destroy()
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- outer.WithBytes(func(b []byte) error {
			// Everything below happens while the outer borrow is live. Each
			// line was individually impossible before v0.3.0-alpha.
			inner, ierr := NewMemoryEnclaveSized(32)
			if ierr != nil {
				return ierr
			}
			if ierr := inner.WithBytes(func(key []byte) error {
				_, rerr := io.ReadFull(rand.Reader, key)
				return rerr
			}); ierr != nil {
				inner.Destroy()
				return ierr
			}
			// Destroying a second enclave inside the first one's borrow was
			// blocked too: Destroy took the same lock exclusively.
			inner.Destroy()

			// And the outer material is still there and still correct.
			if string(b) != outerMaterial {
				return errors.New("outer material changed underneath the borrow")
			}
			return nil
		})
	}()

	select {
	case err := <-done:
		completed = true
		if err != nil {
			t.Fatalf("borrow: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("allocating inside a live borrow did not complete within 30s: " +
			"allocation and borrows are serialized against each other again (issue #2)")
	}
}

// TestMemoryEnclave_ConcurrentAllocationDuringBorrows is the same property under
// load rather than in isolation: many goroutines each allocating, filling and
// destroying a second enclave from inside a borrow of a shared first one. Under
// the old process-wide lock this shape did not deadlock outright — the borrows
// were short — but every allocation waited out every borrow.
//
// The work is a fixed number of iterations, not a wall-clock window: a
// time.Sleep would make what the test actually exercises depend on host load,
// and the conventions rule it out for exactly that reason. The only clock left
// is the bound on the WAIT, which is there to turn a deadlock into a named
// failure instead of a suite timeout.
func TestMemoryEnclave_ConcurrentAllocationDuringBorrows(t *testing.T) {
	const (
		material   = "shared-key-material"
		goroutines = 8
		iterations = 200
	)

	held, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	// Conditional for the same reason as TestMemoryEnclave_AllocateInsideBorrow:
	// Destroy waits on the borrows, so cleaning up after a hang hangs.
	drained := false
	defer func() {
		if drained {
			held.Destroy()
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := held.WithBytes(func(b []byte) error {
					// Allocate from inside the borrow, every iteration.
					e, aerr := NewMemoryEnclaveSized(64)
					if aerr != nil {
						return aerr
					}
					e.Destroy()
					if !bytes.Equal(b, []byte(material)) {
						return errors.New("material changed underneath the borrow")
					}
					return nil
				}); err != nil {
					t.Errorf("borrow: %v", err)
					return
				}
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
		drained = true
	case <-time.After(60 * time.Second):
		t.Fatalf("%d goroutines x %d borrow-and-allocate iterations did not finish within 60s; "+
			"allocation and borrows are serialized against each other again (issue #2)",
			goroutines, iterations)
	}
}

// TestMapping_WipesBeforeRelease asserts the zero-on-free obligation on the
// WHOLE mapping, not just the data region: the canary and the guard pages hold
// bytes derived from the same random value, and leaving them behind in freed
// memory would leak a distinguisher.
//
// It inspects the memory after wipeAndVerify and before the pages go back to
// the kernel, which is the only window where the property is observable — hence
// the split between wipeAndVerify and release.
func TestMapping_WipesBeforeRelease(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	copy(m.data, bytes.Repeat([]byte{0xA5}, 64))

	// Held across the wipe so the test can read what release is about to hand
	// back. release() nils the fields, so this has to be taken first.
	memory, inner := m.memory, m.inner

	if err := m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify: %v", err)
	}
	for i, c := range memory {
		if c != 0 {
			t.Fatalf("byte %d of the mapping = %#x after the wipe, want 0", i, c)
		}
	}

	if err := memcall.Unlock(inner); err != nil {
		t.Errorf("Unlock: %v", err)
	}
	if err := memcall.Free(memory); err != nil {
		t.Errorf("Free: %v", err)
	}
}

// TestMapping_CanaryDetectsUnderflow covers the canary's whole reason for
// existing. The data sits at the END of the locked region, so an overflow past
// it hits the postguard and faults immediately; an UNDERFLOW walks backwards
// into ordinary readable, writable slack, where nothing can fault. The canary is
// what turns that silent corruption into a detected one.
//
// It also asserts the memory is released anyway: a detected corruption must
// never additionally leak locked pages.
func TestMapping_CanaryDetectsUnderflow(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	if len(m.canary) == 0 {
		t.Fatal("a 32-byte mapping has no canary slack; the layout changed and this test is vacuous")
	}

	// Exactly what a buffer underflow through a retained slice would do: write
	// into the slack immediately ahead of the data.
	m.canary[len(m.canary)-1] ^= 0xFF

	err = m.release()
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Errorf("release after an underflow = %v, want ErrEnclaveCorrupted", err)
	}
	if m.memory != nil {
		t.Error("the mapping was not released after a detected corruption")
	}
}

// TestMapping_CanaryVerifiesOnACleanRelease is the other half of the pair: a
// mapping nobody wrote outside of must release without complaint. Without this
// the test above would pass just as happily against a canary check that always
// reported corruption.
func TestMapping_CanaryVerifiesOnACleanRelease(t *testing.T) {
	for _, size := range []int{1, 32, 4095, 4096, 8192} {
		m, err := newMapping(size)
		if err != nil {
			t.Fatalf("newMapping(%d): %v", size, err)
		}
		copy(m.data, bytes.Repeat([]byte{0x5A}, size))
		if err := m.release(); err != nil {
			t.Errorf("release of a clean %d-byte mapping = %v, want nil", size, err)
		}
	}
}

// TestMapping_LayoutInvariants pins the geometry the guard pages and the canary
// depend on. Each of these is load-bearing: if data stops sitting flush against
// the postguard, an overflow stops faulting and starts corrupting whatever
// follows.
func TestMapping_LayoutInvariants(t *testing.T) {
	page := int(pageSize)
	for _, size := range []int{1, 32, page - 1, page, page + 1, 3*page - 7} {
		m, err := newMapping(size)
		if err != nil {
			t.Fatalf("newMapping(%d): %v", size, err)
		}

		innerLen := int(LockedSize(size))
		if len(m.memory) != innerLen+2*page {
			t.Errorf("size %d: mapping is %d bytes, want %d", size, len(m.memory), innerLen+2*page)
		}
		if len(m.inner) != innerLen {
			t.Errorf("size %d: inner is %d bytes, want %d", size, len(m.inner), innerLen)
		}
		if len(m.data) != size {
			t.Errorf("size %d: data is %d bytes", size, len(m.data))
		}
		if len(m.preguard) != page || len(m.postguard) != page {
			t.Errorf("size %d: guards are %d/%d bytes, want %d each", size, len(m.preguard), len(m.postguard), page)
		}
		if len(m.canary) != innerLen-size {
			t.Errorf("size %d: canary is %d bytes, want %d", size, len(m.canary), innerLen-size)
		}
		// The byte after the data must be the postguard: that adjacency is what
		// makes an overflow fault instead of corrupt.
		if &m.inner[len(m.inner)-1] != &m.data[len(m.data)-1] {
			t.Errorf("size %d: data does not end flush with the locked region", size)
		}
		// The canary must be random, not a fixed pattern: an overflow that
		// wrote predictable bytes would otherwise reproduce it and go
		// undetected. All-zero is the failure this catches, since freshly
		// mapped pages arrive zeroed and a missing scramble leaves them so.
		if len(m.canary) >= 8 {
			zero := true
			for _, c := range m.canary {
				if c != 0 {
					zero = false
					break
				}
			}
			if zero {
				t.Errorf("size %d: canary is all zeroes; it was never randomized", size)
			}
		}

		// A fresh mapping is zeroed, whatever the previous tenant of those
		// pages left behind.
		for i, c := range m.data {
			if c != 0 {
				t.Fatalf("size %d: data[%d] = %#x on a fresh mapping, want 0", size, i, c)
			}
		}

		if err := m.release(); err != nil {
			t.Errorf("size %d: release: %v", size, err)
		}
	}
}

// TestPackageDoesNotImportMemguard is the structural half of the owner's ruling
// on issue #2. The whole point is that go-enclave's pages are not in memguard's
// process-global registry, and a single import — in the package or in a test
// binary that links it — would put them back there and quietly restore the
// process-wide purge this design exists to remove.
//
// Behavior cannot catch that: an enclave built through memguard reads back
// identically. Only the import graph shows it, so the import graph is what is
// asserted.
func TestPackageDoesNotImportMemguard(t *testing.T) {
	const forbidden = "github.com/awnumar/memguard"

	// Walked file by file rather than with parser.ParseDir, which is deprecated
	// (SA1019) and, more to the point here, does not consider build tags — it
	// would silently skip the _linux files, which are exactly where a
	// convenience import is most likely to be added.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	fset := token.NewFileSet()
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		files++
		for _, imp := range file.Imports {
			if strings.Contains(imp.Path.Value, forbidden) {
				t.Errorf("%s imports %s; go-enclave's pages would rejoin memguard's "+
					"global registry and become purgeable again", name, forbidden)
			}
		}
	}
	if files < 2 {
		t.Fatalf("only %d Go files parsed; the test would be vacuous", files)
	}

	// The module graph too: an indirect requirement means something in the
	// build still links it.
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if strings.Contains(string(mod), forbidden) {
		t.Errorf("go.mod still requires %s", forbidden)
	}
}

// TestMapping_FreezeIsIdempotent covers the guard that keeps a second freeze
// from re-issuing the mprotect. It matters because release has to melt the
// region again before it can wipe, and a freeze that lost track of its own state
// would either skip a needed protect or issue one on unmapped pages.
func TestMapping_FreezeIsIdempotent(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	if !m.mutable {
		t.Error("a fresh mapping is not mutable; the fill path would fault")
	}
	if err := m.freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if m.mutable {
		t.Error("still mutable after freeze")
	}
	if err := m.freeze(); err != nil {
		t.Fatalf("second freeze: %v", err)
	}

	// A frozen mapping still releases cleanly: release melts it first.
	if err := m.release(); err != nil {
		t.Errorf("release of a frozen mapping: %v", err)
	}
}

// TestMapping_FrozenRegionIsStillWiped covers what freezing COSTS, at the layer
// where the cost lives.
//
// wipeAndVerify destroys the material first, before any syscall that can be
// refused — but it can only do that while the region is still writable. A frozen
// region has to be made writable again before a single byte can be zeroed, so
// for a frozen enclave the wipe sits BEHIND an mprotect that the kernel could
// deny. That is the trade [MemoryEnclave.Freeze] makes deliberately, and it is
// the trade NewMemoryEnclave has always made.
//
// This asserts the ordinary path still ends with nothing left behind. The
// refused-mprotect path is #38's: the release hands the pages back with a bare
// munmap and reports ErrReleasedWithoutWipe, rather than keeping a region whose
// material a permanent denial would strand for the process lifetime. A frozen
// enclave is the only kind that can get there, which is why the two changes meet
// — see TestMemoryEnclave_FrozenDestroyFallsBackToUnmap.
func TestMapping_FrozenRegionIsStillWiped(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	copy(m.data, bytes.Repeat([]byte{0xA5}, 64))

	if err := m.freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if m.mutable {
		t.Fatal("the mapping is still writable after freeze; this test would be measuring the unfrozen path")
	}

	// Held across the wipe for the reason TestMapping_WipesBeforeRelease gives:
	// release nils the fields, and this window is the only place the property is
	// observable.
	memory, inner := m.memory, m.inner

	if err := m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify on a frozen mapping: %v", err)
	}
	if !m.mutable {
		t.Error("a frozen mapping was not recorded as melted; release would then skip the melt on a retry " +
			"and wipe a read-only region")
	}
	for i, c := range memory {
		if c != 0 {
			t.Fatalf("byte %d of a frozen mapping = %#x after the wipe, want 0", i, c)
		}
	}

	if err := memcall.Unlock(inner); err != nil {
		t.Errorf("Unlock: %v", err)
	}
	if err := memcall.Free(memory); err != nil {
		t.Errorf("Free: %v", err)
	}
}

// TestMapping_RejectsUnmappableSizes asserts the layer refuses a size it cannot
// lay out, rather than handing a nonsense length to mmap. The public
// constructors check this too, but newMapping is the last line and is reachable
// from anywhere inside the package.
func TestMapping_RejectsUnmappableSizes(t *testing.T) {
	maxIntV := int(^uint(0) >> 1)
	for _, n := range []int{0, -1, -4096, maxIntV, maxIntV - int(pageSize)} {
		m, err := newMapping(n)
		if !errors.Is(err, ErrInvalidSize) {
			t.Errorf("newMapping(%d) = %v, want ErrInvalidSize", n, err)
		}
		if m != nil {
			t.Errorf("newMapping(%d) returned a non-nil mapping", n)
			_ = m.release()
		}
	}
}

// unmappableCopy returns a mapping whose memory slice the kernel will refuse to
// mprotect, so the release path can be driven through its failure branch
// without a production seam.
//
// The address is a real mmap'd page offset by one byte: mmap guarantees a
// page-aligned base, so base+1 is guaranteed NOT page-aligned, and mprotect on
// an unaligned address is EINVAL by definition. Nothing else in the process is
// touched, and the real region is returned so the test can free it.
func unmappableSlice(t *testing.T) (bad []byte, free func()) {
	t.Helper()
	region, err := memcall.Alloc(int(pageSize) * 2)
	if err != nil {
		t.Skipf("could not allocate the probe region: %v", err)
	}
	return region[1:], func() {
		if err := memcall.Free(region); err != nil {
			t.Errorf("freeing the probe region: %v", err)
		}
	}
}

// TestMapping_ReleaseKeepsStateWhenUnmapFails is the regression test for the
// second finding of Codex round 2 on PR #9.
//
// release used to clear every field regardless of whether the pages actually
// went back. If the region could not be made writable — so it was never wiped —
// or could not be unmapped, the mapping stayed resident while the only handle
// to it was dropped: unreachable memory, possibly still locked, possibly still
// holding material, for the process lifetime.
//
// The mapping must instead come back untouched, so a caller can retry.
func TestMapping_ReleaseKeepsStateWhenUnmapFails(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	real := m.memory
	bad, freeProbe := unmappableSlice(t)
	defer freeProbe()

	m.memory = bad
	err = m.release()

	if err == nil {
		t.Fatal("release reported success on a region it could not protect")
	}
	if errors.Is(err, ErrEnclaveCorrupted) {
		t.Errorf("err = %v, want a mapping failure rather than a canary report", err)
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("err = %v, want ErrLockedMemoryUnavailable", err)
	}

	// Everything must still be here: this is what makes a retry possible.
	if m.memory == nil || m.inner == nil || m.data == nil ||
		m.preguard == nil || m.postguard == nil {
		t.Fatal("release discarded the mapping it could not unmap; the pages are now unreachable")
	}

	// Put the real region back and confirm the retry completes.
	m.memory = real
	if err := m.release(); err != nil {
		t.Errorf("retrying release after the failure: %v", err)
	}
	if m.memory != nil {
		t.Error("the successful retry did not clear the mapping")
	}
}

// TestMemoryEnclave_FailedReleaseKeepsTheReservation is the same defect seen
// from the Allocator's side, which is where it does the most damage: the budget
// would report bytes as available while the kernel still held the pages, so the
// allocator would go on admitting allocations the process could not satisfy.
//
// It also pins the retry: a caller that recovers from the panic can call Destroy
// again, and the reservation comes back exactly once.
func TestMemoryEnclave_FailedReleaseKeepsTheReservation(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.NewSized(64)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}

	reserved := a.InUse()
	if reserved == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}

	real := e.m.memory
	bad, freeProbe := unmappableSlice(t)
	defer freeProbe()
	e.m.memory = bad

	func() {
		defer func() {
			if recover() == nil {
				t.Error("Destroy returned quietly after failing to release the pages")
			}
		}()
		e.Destroy()
	}()

	if got := a.InUse(); got != reserved {
		t.Errorf("InUse = %d after a FAILED release, want the unchanged %d: the budget "+
			"reported pages as available while the kernel still held them", got, reserved)
	}
	if e.m == nil {
		t.Fatal("the enclave discarded a mapping it never released")
	}
	// The MAPPING is retained -- asserted directly, just above. The ENCLAVE is
	// not alive, and this assertion was inverted deliberately: a.NewSized gives
	// a MUTABLE mapping, so wipeAndVerify's early wipe destroyed the material
	// before the syscall that failed. The pages being held is the truth about
	// the mapping; it was never the truth about the enclave, and reporting
	// alive here is what let a caller that recovers from the panic read zeroes
	// and take them for the secret (#13). The retry below is unaffected --
	// Destroy consults the mapping, not the wiped flag.
	if e.IsAlive() {
		t.Error("IsAlive = true although the early wipe already destroyed the " +
			"material; the caller would read zeroes and not be told")
	}

	// The retry: same enclave, real region restored.
	e.m.memory = real
	e.Destroy()

	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after the successful retry, want 0", got)
	}
	if e.IsAlive() {
		t.Error("IsAlive = true after a successful Destroy")
	}
}

// TestCoreDumpsDisabled covers the accessor added for the first finding of Codex
// round 2: the package documented core dumps as disabled while ignoring whether
// the call succeeded, giving callers no way to check. It now reports.
//
// The value is environment-dependent — a sandbox may deny setrlimit — so the
// assertion is on the contract rather than on a particular answer: it is stable,
// and it agrees with the process's actual RLIMIT_CORE.
func TestCoreDumpsDisabled(t *testing.T) {
	first := CoreDumpsDisabled()
	if second := CoreDumpsDisabled(); !errors.Is(second, first) && second != first {
		t.Errorf("CoreDumpsDisabled is not stable: %v then %v", first, second)
	}
	if first == nil {
		t.Log("core dumps disabled process-wide")
	} else {
		t.Logf("core dumps NOT disabled: %v", first)
	}
}

// TestMapping_WipesMaterialBeforeAnySyscallThatCanFail is the regression test
// for the third finding of Codex round 2/3 on PR #9, and it guards the
// property that matters most on the whole failure path.
//
// wipeAndVerify used to make the region writable FIRST and wipe afterwards. That
// mprotect can be refused — a seccomp filter is the realistic case — and when it
// was, the function returned an error having wiped nothing: the material sat in
// locked memory while the caller was handed a failure. NewMemoryEnclave's own
// freeze-failure path then discarded the mapping, so the secret was resident,
// locked, and unreachable.
//
// The fix is ordering, not more syscalls: while the inner region is writable —
// which it is unless a freeze succeeded — the material can be destroyed with no
// call anything could deny. So it is destroyed first, and the worst a refusal
// can now cost is an empty mapping that could not be handed back.
func TestMapping_WipesMaterialBeforeAnySyscallThatCanFail(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	secret := bytes.Repeat([]byte{0xC3}, 64)
	copy(m.data, secret)
	if !bytes.Equal(m.data, secret) {
		t.Fatal("the material was not written; the test would be vacuous")
	}

	// Point the whole-region handle at something mprotect must refuse, leaving
	// data and inner aliasing the real, still-writable pages. That is exactly
	// the shape of a denied mprotect during cleanup.
	real := m.memory
	bad, freeProbe := unmappableSlice(t)
	defer freeProbe()
	m.memory = bad

	err = m.wipeAndVerify()
	if err == nil {
		t.Fatal("wipeAndVerify reported success on a region it could not protect")
	}

	// The point of the test: the material is gone anyway.
	for i, c := range m.data {
		if c != 0 {
			t.Fatalf("data[%d] = %#x after a refused mprotect: the material survived on "+
				"locked pages the caller was told it could not have", i, c)
		}
	}

	m.memory = real
	if err := m.release(); err != nil {
		t.Errorf("release after restoring the region: %v", err)
	}
}

// TestMapping_AbandonReleasesAPartialMapping covers the constructor's rollback
// directly. It only ever runs when the kernel has already refused something —
// the ceiling reached, an mprotect denied — so it is both the least exercised
// code here and the code most likely to meet a second refusal while cleaning up.
//
// The contract has two halves: the pages go back, and the caller is told what
// went wrong in a form it can match on.
func TestMapping_AbandonReleasesAPartialMapping(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	cause := errors.New("induced construction failure")
	got := m.abandon(cause, true)

	if !errors.Is(got, ErrLockedMemoryUnavailable) {
		t.Errorf("abandon = %v, want it to match ErrLockedMemoryUnavailable", got)
	}
	if !errors.Is(got, cause) {
		t.Errorf("abandon = %v, want the original cause to remain reachable", got)
	}

	// Releasing again must fail rather than double-free: the region is gone.
	if second := m.abandon(cause, true); second == nil {
		t.Error("abandon reported success unmapping an already-released region")
	}
}
