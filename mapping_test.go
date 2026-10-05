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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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
			if !bytes.Equal(b, []byte(outerMaterial)) {
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

	if err := sysUnlock(inner); err != nil {
		t.Errorf("munlock: %v", err)
	}
	if err := sysUnmap(memory); err != nil {
		t.Errorf("munmap: %v", err)
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

	if err := sysUnlock(inner); err != nil {
		t.Errorf("munlock: %v", err)
	}
	if err := sysUnmap(memory); err != nil {
		t.Errorf("munmap: %v", err)
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

	lift := denyProtectAndUnmap(t)
	err = m.release()

	if err == nil {
		t.Fatal("release reported success on a region it could not protect")
	}
	if !pagesHeld(err) {
		t.Errorf("pagesHeld(%v) = false, want true: nothing could return the pages", err)
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

	// Lift the refusals and confirm the retry completes.
	lift()
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
// It also pins the retry: the failure is RETURNED, not panicked (#83 — it
// panicked until then, and this test asserted that it did), the caller can call
// Destroy again, and the reservation comes back exactly once.
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

	lift := denyProtectAndUnmap(t)

	var derr error
	if r := panicValue(func() { derr = e.Destroy() }); r != nil {
		t.Fatalf("Destroy panicked with %v; it never panics", r)
	}
	if !errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Errorf("Destroy = %v after failing to release the pages, want ErrLockedMemoryUnavailable", derr)
	}

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
	// alive here is what let a caller whose Destroy failed read zeroes and take
	// them for the secret (#13). The retry below is unaffected --
	// Destroy consults the mapping, not the wiped flag.
	if e.IsAlive() {
		t.Error("IsAlive = true although the early wipe already destroyed the " +
			"material; the caller would read zeroes and not be told")
	}

	// The retry: same enclave, refusals lifted.
	lift()
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

	// A denied mprotect during cleanup, with every slice still aliasing the
	// real pages.
	lift := denyProtect(t)

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

	lift()
	if err := m.release(); err != nil {
		t.Errorf("release after the refusal lifted: %v", err)
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

// TestMapping_CorruptionIsStickyAcrossAFailedRelease is the regression for the
// lost-corruption finding in #83, at the layer that lost it.
//
// wipeAndVerify detects the bad canary and then wipes the guards AND the canary.
// If the munlock or munmap after it is refused, release kept the mapping and
// returned only the LockedMemoryError — and the retry re-verified, compared an
// all-zero guard with an all-zero canary, found them equal, and reported a clean
// release. The detection existed for one failed attempt and then nowhere.
//
// Each attempt is asserted: the first reports BOTH facts, an intermediate one
// still does, the final one that actually releases reports the corruption — and
// the predicate the callers share classifies the held attempts as NOT released,
// so joining the corruption in cannot make Destroy drop the handle or an
// Allocator refund pages the kernel still holds.
func TestMapping_CorruptionIsStickyAcrossAFailedRelease(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	if len(m.canary) == 0 {
		t.Fatal("a 32-byte mapping has no canary slack; the layout changed and this test is vacuous")
	}
	m.canary[len(m.canary)-1] ^= 0xFF

	denied := errors.New("munlock: cannot allocate memory")
	prev := unlockMemory
	t.Cleanup(func() {
		unlockMemory = prev
		if m.memory != nil {
			_ = m.release()
		}
	})
	unlockMemory = func([]byte) error { return denied }

	for attempt := 1; attempt <= 2; attempt++ {
		err = m.release()
		if !errors.Is(err, ErrEnclaveCorrupted) {
			t.Fatalf("held attempt %d = %v, want ErrEnclaveCorrupted: the detection must not be lost "+
				"because the release after it was refused", attempt, err)
		}
		if !errors.Is(err, denied) || !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Errorf("held attempt %d = %v, want the refused munlock reported alongside the corruption", attempt, err)
		}
		if releasedPages(err) {
			t.Fatalf("releasedPages(%v) = true on held attempt %d; the pages are still mapped", err, attempt)
		}
		if m.memory == nil {
			t.Fatalf("held attempt %d dropped the mapping; there is no handle left to retry through", attempt)
		}
	}

	unlockMemory = prev
	err = m.release()
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Fatalf("the release that returned the pages = %v, want ErrEnclaveCorrupted: the retry "+
			"re-verified a canary its own first attempt had wiped", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("the release that returned the pages = %v still reports a refusal", err)
	}
	if !releasedPages(err) {
		t.Errorf("releasedPages(%v) = false although the pages went back", err)
	}
	if m.memory != nil {
		t.Error("the mapping was not released by the successful retry")
	}
}

// TestMapping_RetryDoesNotReverify pins the other half of the stickiness: a
// CLEAN mapping whose first release was refused after the wipe must not be
// re-verified on the retry either. The guards and canary are zero by then, so a
// second verification compares zeroes with zeroes; it happens to pass for a
// clean mapping, which is exactly why a re-verify would be invisible here — the
// assertion is therefore on the protection syscall the re-verify needs.
func TestMapping_RetryDoesNotReverify(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	prevUnlock, prevProtect := unlockMemory, protectMemory
	t.Cleanup(func() {
		unlockMemory, protectMemory = prevUnlock, prevProtect
		if m.memory != nil {
			_ = m.release()
		}
	})
	unlockMemory = func([]byte) error { return errors.New("munlock refused") }

	if err := m.release(); err == nil || releasedPages(err) {
		t.Fatalf("release with a refused munlock = %v, want a held failure", err)
	}

	unlockMemory = prevUnlock
	protects := 0
	protectMemory = func(b []byte, p protection) error {
		protects++
		return prevProtect(b, p)
	}
	if err := m.release(); err != nil {
		t.Fatalf("retry = %v, want nil for a clean mapping", err)
	}
	if protects != 0 {
		t.Errorf("the retry re-opened the region %d times to verify a canary it had already wiped", protects)
	}
}

// TestMapping_AbandonReportsWhetherLockedPagesWereLeft pins the predicate a
// failed constructor's refund rests on (#83). Admission refunds a charge only
// when the failure left no LOCKED pages behind; abandon is the only place that
// knows, so its error has to say.
//
// It has to say two things, not one. Pages left MAPPED but unlocked cost no
// locked memory, so the charge goes back — but they are still mapped, so the
// error must still be marked held and still hand the mapping over for the
// orphan ledger to retry. An earlier revision marked only the locked case,
// and a cleanup that unlocked and then could unmap nothing reported the pages
// as gone.
func TestMapping_AbandonReportsWhetherLockedPagesWereLeft(t *testing.T) {
	cause := errors.New("the step that failed")
	refused := func([]byte) error { return errors.New("refused") }

	for _, tc := range []struct {
		name                 string
		unlock, unmap        bool // whether each step is refused
		wantHeld, wantLocked bool
	}{
		{"clean rollback", false, false, false, false},
		{"munlock refused, munmap took the lock with it", true, false, false, false},
		{"unlocked, but the munmap was refused", false, true, true, false},
		{"munlock and munmap refused", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newMapping(64)
			if err != nil {
				t.Fatalf("newMapping: %v", err)
			}
			memory := m.memory

			prevUnlock, prevUnmap := unlockMemory, unmapMemory
			restore := func() { unlockMemory, unmapMemory = prevUnlock, prevUnmap }
			t.Cleanup(restore)
			if tc.unlock {
				unlockMemory = refused
			}
			unmaps := 0
			unmapMemory = func(b []byte) error {
				unmaps++
				if tc.unmap {
					return errors.New("refused")
				}
				return prevUnmap(b)
			}

			err = m.abandon(cause, true)
			restore()

			if !errors.Is(err, cause) || !errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Errorf("abandon = %v, want the original cause as ErrLockedMemoryUnavailable", err)
			}
			if got := pagesHeld(err); got != tc.wantHeld {
				t.Errorf("pagesHeld(%v) = %v, want %v", err, got, tc.wantHeld)
			}
			if got := lockedPagesHeld(err); got != tc.wantLocked {
				t.Errorf("lockedPagesHeld(%v) = %v, want %v", err, got, tc.wantLocked)
			}
			var held *pagesHeldError
			if errors.As(err, &held) && held.orphan != m {
				t.Errorf("abandon left pages held without handing over the mapping that holds them")
			}
			// Exactly one unmap in every row: a refused munlock must not stop
			// the rollback short of it, and nothing may retry it behind the
			// caller's back.
			if unmaps != 1 {
				t.Errorf("abandon unmapped %d times, want exactly 1", unmaps)
			}

			// Whatever the row left mapped is handed back here, so a refused
			// cleanup does not leak a locked page into every later test.
			if tc.unmap {
				if err := sysUnmap(memory); err != nil {
					t.Errorf("cleanup munmap: %v", err)
				}
			}
		})
	}
}

// TestMapping_ReleaseIsExactlyItsExplicitSteps pins #86's requirement on the
// release path: it is the steps written in release and nothing else — make the
// mapping writable, wipe and verify, munlock, munmap — with no step hidden
// inside a primitive. It records every call through the seams, in order, and
// reads the whole mapping at the unlock and at the unmap, so a wipe that moved
// after either, or a primitive that started re-protecting or unmapping on its
// own, shows up as a different sequence or as live bytes.
//
// The denied row is the one path allowed to unmap without the wipe, and it
// must get there without an unlock: munmap drops the lock with the mapping,
// and an unlock on that path is the ordinary teardown running as though the
// wipe had happened.
func TestMapping_ReleaseIsExactlyItsExplicitSteps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		freeze    bool
		deny      bool
		wantSteps []string
		wantErr   error
	}{
		{"writable", false, false, []string{"protect rw memory", "unlock inner", "unmap memory"}, nil},
		{"frozen", true, false, []string{"protect rw memory", "unlock inner", "unmap memory"}, nil},
		{"frozen, mprotect denied", true, true, []string{"protect rw memory", "unmap memory"}, ErrReleasedWithoutWipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newMapping(64)
			if err != nil {
				t.Fatalf("newMapping: %v", err)
			}
			copy(m.data, bytes.Repeat([]byte{0xE7}, 64))
			if tc.freeze {
				if err := m.freeze(); err != nil {
					t.Fatalf("freeze: %v", err)
				}
			}
			memory, inner := m.memory, m.inner

			region := func(b []byte) string {
				switch {
				case &b[0] == &memory[0] && len(b) == len(memory):
					return "memory"
				case &b[0] == &inner[0] && len(b) == len(inner):
					return "inner"
				default:
					return "other"
				}
			}
			names := map[protection]string{protNoAccess: "none", protReadOnly: "ro", protReadWrite: "rw"}
			wipedAt := map[string]bool{}

			var steps []string
			prevProtect, prevUnlock, prevUnmap := protectMemory, unlockMemory, unmapMemory
			t.Cleanup(func() { protectMemory, unlockMemory, unmapMemory = prevProtect, prevUnlock, prevUnmap })
			protectMemory = func(b []byte, p protection) error {
				steps = append(steps, "protect "+names[p]+" "+region(b))
				if tc.deny {
					return errors.New("mprotect denied by policy")
				}
				return prevProtect(b, p)
			}
			unlockMemory = func(b []byte) error {
				steps = append(steps, "unlock "+region(b))
				wipedAt["unlock"] = bytes.Equal(memory, make([]byte, len(memory)))
				return prevUnlock(b)
			}
			unmapMemory = func(b []byte) error {
				steps = append(steps, "unmap "+region(b))
				// Readable in every row: the region was made writable, or it is
				// frozen read-only — only the guards are inaccessible, and they
				// are left alone when the mprotect is denied.
				if !tc.deny {
					wipedAt["unmap"] = bytes.Equal(memory, make([]byte, len(memory)))
				}
				return prevUnmap(b)
			}

			err = m.release()
			if tc.wantErr == nil && err != nil {
				t.Fatalf("release = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("release = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(steps, tc.wantSteps) {
				t.Errorf("release made %q, want exactly %q", steps, tc.wantSteps)
			}
			for step, wiped := range wipedAt {
				if !wiped {
					t.Errorf("the mapping still held non-zero bytes at the %s: the wipe did not precede it", step)
				}
			}
			if m.memory != nil {
				t.Error("the mapping kept its handle after the pages went back")
			}
		})
	}
}

// errNotLocked is what installStrictUnlock returns for a second unlock of the
// same region: Windows' VirtualUnlock fails with ERROR_NOT_LOCKED on pages that
// are not locked, where Linux's munlock succeeds.
var errNotLocked = errors.New("VirtualUnlock: ERROR_NOT_LOCKED")

// installStrictUnlock replaces unlockMemory with one that has VirtualUnlock's
// semantics: the first unlock of a region goes through to the real call, and
// any later unlock of a region already unlocked is REFUSED with errNotLocked.
//
// Linux tolerates a repeated munlock, so without this a release path that
// unlocks again on every retry passes here and fails on Windows (#83). The
// seam is restored by t.Cleanup; register any cleanup that must run with the
// real unlock BEFORE calling this, since cleanups run last-in first-out.
func installStrictUnlock(t *testing.T) {
	t.Helper()
	prev := unlockMemory
	t.Cleanup(func() { unlockMemory = prev })

	var mu sync.Mutex
	unlocked := make(map[*byte]struct{})
	unlockMemory = func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if _, done := unlocked[&b[0]]; done {
			return errNotLocked
		}
		if err := prev(b); err != nil {
			return err
		}
		unlocked[&b[0]] = struct{}{}
		return nil
	}
}

// TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain is the regression for
// the repeated-unlock finding in #83.
//
// release unlocked the pages on EVERY attempt. When the first attempt's munlock
// succeeded and its munmap was refused, the retry unlocked again — harmless on
// Linux, but on Windows VirtualUnlock refuses pages that are not locked, so
// every retry returned at the unlock and never reached the unmap again. The
// mapping, and any Allocator reservation behind it, was then held for the
// process lifetime however often DestroyErr or WipeAll retried.
//
// The held attempt must also report the pages as NOT locked, since the unlock
// that did succeed is the state the retry now trusts.
func TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	prevUnmap := unmapMemory
	t.Cleanup(func() {
		unmapMemory = prevUnmap
		if m.memory != nil {
			_ = m.release()
		}
	})
	installStrictUnlock(t)

	unmaps := 0
	unmapMemory = func(b []byte) error {
		unmaps++
		if unmaps == 1 {
			return errors.New("munmap: cannot allocate memory")
		}
		return prevUnmap(b)
	}

	err = m.release()
	if !pagesHeld(err) {
		t.Fatalf("release with a refused munmap = %v, want a held failure", err)
	}
	if lockedPagesHeld(err) {
		t.Errorf("lockedPagesHeld(%v) = true, want false: the munlock succeeded", err)
	}

	err = m.release()
	if errors.Is(err, errNotLocked) {
		t.Fatalf("the retry unlocked the region a second time and was refused (%v); on Windows the "+
			"mapping can then never be released", err)
	}
	if err != nil {
		t.Fatalf("retry = %v, want nil once the munmap is allowed", err)
	}
	if unmaps != 2 {
		t.Errorf("munmap attempted %d times, want 2: the retry never reached it", unmaps)
	}
	if m.memory != nil {
		t.Error("the mapping is still held after the retry released the pages")
	}
}

// TestNewMapping_EveryConstructionStepRollsBack fails each step of newMapping
// in turn, through the public constructor, and asserts the rollback: the
// region is unlocked if it had been locked, unmapped once, reported as held
// only when the unmap was refused, and a held region is adopted as an orphan
// that a later WipeAll reclaims.
func TestNewMapping_EveryConstructionStepRollsBack(t *testing.T) {
	type seams struct {
		lock, unlock, unmap func([]byte) error
		protect             func([]byte, protection) error
		core, fork, canary  func([]byte) error
	}
	saved := seams{lockMemory, unlockMemory, unmapMemory, protectMemory, excludeCoreDump, excludeFork, fillCanary}
	restore := func() {
		lockMemory, unlockMemory, unmapMemory, protectMemory = saved.lock, saved.unlock, saved.unmap, saved.protect
		excludeCoreDump, excludeFork, fillCanary = saved.core, saved.fork, saved.canary
	}
	t.Cleanup(restore)

	cause := errors.New("the step that failed")
	fail := func([]byte) error { return cause }
	// guardFailure fails the nth guard-page mprotect (1 = preguard).
	guardFailure := func(nth int) func() {
		return func() {
			calls := 0
			protectMemory = func(b []byte, p protection) error {
				if p == protNoAccess {
					calls++
					if calls == nth {
						return cause
					}
				}
				return saved.protect(b, p)
			}
		}
	}

	steps := []struct {
		name   string
		inject func()
		locked bool
	}{
		{"mlock", func() { lockMemory = fail }, false},
		{"core-dump exclusion", func() { excludeCoreDump = fail }, true},
		{"fork exclusion", func() { excludeFork = fail }, true},
		{"canary fill", func() { fillCanary = fail }, true},
		{"preguard mprotect", guardFailure(1), true},
		{"postguard mprotect", guardFailure(2), true},
	}
	cleanups := []struct {
		name                        string
		unlockRefused, unmapRefused bool
	}{
		{"clean rollback", false, false},
		{"munmap refused", false, true},
		{"munlock and munmap refused", true, true},
	}

	for _, step := range steps {
		for _, cl := range cleanups {
			t.Run(step.name+"/"+cl.name, func(t *testing.T) {
				requireCleanLedger(t)
				t.Cleanup(restore)
				step.inject()

				unlocks, unmaps := 0, 0
				unlockMemory = func(b []byte) error {
					unlocks++
					if cl.unlockRefused {
						return errors.New("munlock refused")
					}
					return saved.unlock(b)
				}
				unmapMemory = func(b []byte) error {
					unmaps++
					if cl.unmapRefused {
						return errors.New("munmap refused")
					}
					return saved.unmap(b)
				}

				e, err := NewMemoryEnclaveSized(64)
				restore()

				if e != nil {
					t.Fatalf("NewMemoryEnclaveSized returned an enclave although %s failed", step.name)
				}
				if !errors.Is(err, cause) || !errors.Is(err, ErrLockedMemoryUnavailable) {
					t.Errorf("err = %v, want the failed step as ErrLockedMemoryUnavailable", err)
				}
				wantUnlocks := 0
				if step.locked {
					wantUnlocks = 1
				}
				if unlocks != wantUnlocks {
					t.Errorf("munlock called %d times, want %d", unlocks, wantUnlocks)
				}
				if unmaps != 1 {
					t.Errorf("munmap called %d times, want 1", unmaps)
				}
				if got := pagesHeld(err); got != cl.unmapRefused {
					t.Errorf("pagesHeld(%v) = %v, want %v", err, got, cl.unmapRefused)
				}
				wantLocked := step.locked && cl.unlockRefused && cl.unmapRefused
				if got := lockedPagesHeld(err); got != wantLocked {
					t.Errorf("lockedPagesHeld(%v) = %v, want %v", err, got, wantLocked)
				}

				wantOrphans := 0
				if cl.unmapRefused {
					wantOrphans = 1
				}
				if got := orphanCount(); got != wantOrphans {
					t.Errorf("orphan ledger holds %d, want %d", got, wantOrphans)
				}
				if remaining := sweep(t); remaining != 0 {
					t.Errorf("WipeAll left %d entries once the refusals lifted, want 0", remaining)
				}
			})
		}
	}
}
