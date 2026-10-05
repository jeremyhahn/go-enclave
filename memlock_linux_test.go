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
	"errors"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRlimInfinityMatchesTheKernelConstant backs the claim made where
// rlimInfinity is declared. The constant is spelled out there because
// unix.RLIM_INFINITY is untyped and generated per architecture and the
// comparison needs a uint64; if that spelling ever stops matching the ABI, the
// unlimited case silently becomes "some enormous finite ceiling" and every
// budget passes for the wrong reason.
func TestRlimInfinityMatchesTheKernelConstant(t *testing.T) {
	if rlimInfinity != uint64(unix.RLIM_INFINITY) {
		t.Fatalf("rlimInfinity = %#x, but unix.RLIM_INFINITY = %#x", rlimInfinity, uint64(unix.RLIM_INFINITY))
	}
}

// TestDiscoverLockedMemoryLimit_LinuxAlwaysLooks pins the claim that
// LimitUnsupported means "this package did not look", not "this host has no
// ceiling" — Linux always has one to read, so reporting it here would be a
// silent instrument: a discovery that answers without looking reads exactly
// like one that looked and found nothing, and the constructor then accepts
// every budget while appearing to check.
//
// It is separate from the subprocess contract test on purpose, and the reason
// is measured. Replacing the Linux discovery body with
// `LockedMemoryLimit{Source: LimitUnsupported}` was caught ONLY by that
// subprocess test — and that test asserts the privileged contract instead
// whenever the runner holds CAP_IPC_LOCK and cannot drop it, so on a privileged
// CI the mutant survived the entire suite. This assertion needs no privilege,
// no injection and no subprocess, so it holds on every runner.
func TestDiscoverLockedMemoryLimit_LinuxAlwaysLooks(t *testing.T) {
	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Source == LimitUnsupported {
		t.Fatal("Linux reported LimitUnsupported; RLIMIT_MEMLOCK is always readable here, so this says the check did not run")
	}
	if limit.Source == LimitUnknown {
		t.Fatal("a successful discovery must name its source")
	}
}

const (
	// memlockContractMarker selects the child half of the startup-contract test.
	memlockContractMarker = "GO_ENCLAVE_MEMLOCK_CONTRACT"

	// limitDiscovered is logged once the child has read back the ceiling it
	// injected. Without it a discovery that returned some unrelated figure
	// would still let the refusal below look correct.
	limitDiscovered = "the discovered ceiling matches the injected RLIMIT_MEMLOCK"

	// withinLimitAccepted is the CONTROL. An implementation that refused every
	// budget would satisfy overLimitRefused and fail this, which is the whole
	// reason it is a required line and not an incidental assertion.
	withinLimitAccepted = "a budget equal to the discovered ceiling was accepted and allocates"

	// overLimitRefused is logged once a budget one byte above the ceiling has
	// been refused with the typed error carrying both figures.
	overLimitRefused = "a budget above the discovered ceiling was refused with both figures named"

	// notEnforcedConfirmed replaces the three lines above when the child holds
	// CAP_IPC_LOCK and could not drop it. It is not a skip: it asserts the
	// documented privileged contract instead — an unenforced limit refuses
	// nothing — and the parent reports which of the two contracts ran.
	notEnforcedConfirmed = "an unenforced RLIMIT_MEMLOCK refused nothing"

	// constructorReturned is logged last, and its presence is the assertion
	// that the refusal came back as a value. A library must never end its
	// host's process over a resource limit, and a child that had exited or
	// panicked could not print this.
	constructorReturned = "the refusal returned to its caller; the process was not aborted"
)

// TestNewAllocatorWithinRLimit_StartupContract injects an RLIMIT_MEMLOCK
// ceiling and asserts the whole startup contract against it: the ceiling is
// discovered, a budget within it is accepted AND usable, a budget above it is
// refused with a typed error naming both figures, and the refusal arrives as a
// return value rather than as a dead process.
//
// It runs in a subprocess because the fault is process-wide — setrlimit here
// would bind every other test in the package — through runTestChild in
// enclave_linux_test.go, including the rule that the child must log a
// confirmation line so a child that verified nothing cannot be mistaken for one
// that did.
func TestNewAllocatorWithinRLimit_StartupContract(t *testing.T) {
	if os.Getenv(memlockContractMarker) == "1" {
		memlockContractChild(t)
		return
	}

	// There is no legitimate skip in the child: lowering one's own soft limit
	// needs no privilege, and the privileged case has a contract of its own to
	// assert rather than to duck. runTestChild fails a child that skipped.
	out, err := runTestChild(t, "TestNewAllocatorWithinRLimit_StartupContract", memlockContractMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, constructorReturned) {
		t.Fatalf("subprocess did not confirm the constructor returned:\n%s", out)
	}

	switch {
	case strings.Contains(out, notEnforcedConfirmed):
		// The child proved — with its OWN capability read, not the package's —
		// that it holds CAP_IPC_LOCK and could not drop it. Say so loudly: this
		// run did NOT exercise the refusal, and a reader of a green log needs to
		// know which of the two contracts was measured.
		t.Logf("ran the unenforced-limit contract (CAP_IPC_LOCK held and not droppable); the refusal path was not exercised here")
	default:
		for _, want := range []string{limitDiscovered, withinLimitAccepted, overLimitRefused} {
			if !strings.Contains(out, want) {
				t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
			}
		}
	}
}

func memlockContractChild(t *testing.T) {
	t.Helper()

	// Capabilities are PER-THREAD on Linux, and the Go runtime moves goroutines
	// between threads. Pin this goroutine before touching them, and leave it
	// pinned, or the capability state asserted below belongs to one thread while
	// the mlock happens on another. Never unlocked: the test ends with the
	// process.
	runtime.LockOSThread()

	// Inject the ceiling. Lowering one's own soft limit requires no privilege,
	// and raising it towards the hard limit does not either. 64 pages is far
	// below any plausible real budget and still several times what the control
	// allocation needs.
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	target := uint64(64 * pageSize)
	if original.Max != rlimInfinity && original.Max < target {
		target = original.Max
	}
	if target < uint64(4*pageSize) {
		t.Fatalf("the hard RLIMIT_MEMLOCK (%d) is too small to inject a usable ceiling", original.Max)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: target, Max: original.Max}); err != nil {
		t.Fatalf("cannot set RLIMIT_MEMLOCK to %d: %v", target, err)
	}

	// WHICH CONTRACT TO ASSERT IS DECIDED BY AN ORACLE THIS PACKAGE DOES NOT
	// OWN. Asking memlockRLimitEnforced() instead would let the test follow the
	// implementation wherever it went: invert the capability sense in that
	// function and an unprivileged run would quietly assert the PRIVILEGED
	// contract — which it satisfies — and stay green while the refusal it
	// exists to guard had been disabled for every ordinary process. Measured:
	// that mutant survives when the branch is chosen by the production
	// function, and dies when it is chosen here.
	if testHoldsIPCLock(t) {
		// Running privileged. Give the capability up so the mainstream contract
		// can be measured; if that is refused, assert the privileged contract
		// rather than pretending to have measured the other one.
		if err := dropIPCLock(); err != nil {
			t.Logf("could not drop CAP_IPC_LOCK (%v); asserting the unenforced contract", err)
		}
	}

	if testHoldsIPCLock(t) {
		unenforcedContract(t, target)
		t.Log(constructorReturned)
		return
	}

	enforcedContract(t, target)
	// Reaching this line is the assertion. A constructor that called
	// log.Fatal, os.Exit or panic on a host resource limit would have taken the
	// process out above, and the parent requires this line.
	t.Log(constructorReturned)
}

// enforcedContract asserts the mainstream case: RLIMIT_MEMLOCK binds, so the
// ceiling is a ceiling.
func enforcedContract(t *testing.T, target uint64) {
	t.Helper()

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if !limit.Bounded || limit.Bytes != int64(target) || limit.Source != LimitRLimit {
		t.Fatalf("discovered %+v, want the injected %d bytes as a bounded LimitRLimit", limit, target)
	}
	t.Log(limitDiscovered)

	// CONTROL. A budget EQUAL to the ceiling is within it and must be accepted,
	// and the allocator it returns must work — an implementation that refused
	// everything, or that returned a broken allocator, dies here rather than
	// passing the refusal test below.
	a, err := NewAllocatorWithinRLimit(int64(target))
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit(%d) refused a budget equal to the ceiling: %v", target, err)
	}
	if a.Limit() != int64(target) {
		t.Fatalf("Limit = %d, want the budget asked for (%d)", a.Limit(), target)
	}
	const material = "material-under-an-injected-ceiling"
	e, err := a.New([]byte(material))
	if err != nil {
		t.Fatalf("allocating through the accepted allocator: %v", err)
	}
	if !holds(e, []byte(material)) {
		t.Fatal("material did not survive into an enclave from the accepted allocator")
	}
	e.Destroy()
	t.Log(withinLimitAccepted)

	// ONE BYTE over. Paired with the control above this pins the comparison at
	// the exact discovered figure, in bytes: a `>=` refuses the control, a
	// reversed comparison refuses nothing here, and a comparison against any
	// other quantity lands on neither boundary.
	for _, over := range []int64{int64(target) + 1, int64(target) * 2} {
		bad, err := NewAllocatorWithinRLimit(over)
		if bad != nil {
			t.Fatalf("NewAllocatorWithinRLimit(%d) returned an allocator despite a %d-byte ceiling", over, target)
		}
		if !errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Fatalf("NewAllocatorWithinRLimit(%d) err = %v, want ErrBudgetExceedsRLimit", over, err)
		}
		// Distinguishable from its neighbors ON THE REAL PATH, not only in the
		// hand-built error of the portable test.
		if errors.Is(err, ErrInvalidBudget) || errors.Is(err, ErrLockedMemoryUnavailable) || errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("the refusal also matched a neighboring sentinel: %v", err)
		}

		var typed *RLimitError
		if !errors.As(err, &typed) {
			t.Fatalf("errors.As could not reach *RLimitError from %v", err)
		}
		if typed.Requested != over || typed.Limit.Bytes != int64(target) || !typed.Limit.Bounded {
			t.Fatalf("RLimitError = %+v, want Requested=%d and the bounded ceiling %d", typed, over, target)
		}
		// The discovered figure has to be IN THE MESSAGE. An operator reading a
		// startup failure needs the number to change, not a statement that some
		// number was too big.
		if !strings.Contains(err.Error(), strconv.FormatUint(target, 10)) {
			t.Fatalf("error message %q does not name the discovered limit %d", err.Error(), target)
		}
	}
	t.Log(overLimitRefused)
}

// unenforcedContract asserts the privileged case: the process holds
// CAP_IPC_LOCK, mlock may exceed RLIMIT_MEMLOCK, and so a budget above it is
// NOT refused — the figure is reported for diagnostics only.
func unenforcedContract(t *testing.T, target uint64) {
	t.Helper()

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Bounded || limit.Source != LimitNotEnforced || limit.Bytes != int64(target) {
		t.Fatalf("discovered %+v, want the injected %d bytes as an unenforced, unbounded limit", limit, target)
	}

	a, err := NewAllocatorWithinRLimit(int64(target) * 2)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit refused a budget against a limit the kernel will not enforce: %v", err)
	}
	if a.Limit() != int64(target)*2 {
		t.Fatalf("Limit = %d, want %d", a.Limit(), int64(target)*2)
	}
	t.Log(notEnforcedConfirmed)
}

// ipcLockBit is CAP_IPC_LOCK's place in the capability bitmap, which is split
// into 32-bit words. It is 14, so the low word; the indices are derived rather
// than written as 0 so this stays correct if copied for a higher capability.
const (
	ipcLockWord = unix.CAP_IPC_LOCK / 32
	ipcLockBit  = uint32(1) << (unix.CAP_IPC_LOCK % 32)
)

// testHoldsIPCLock reports whether this THREAD holds CAP_IPC_LOCK, read
// independently of the package code under test so that the choice of which
// contract to assert is never made by the thing being asserted.
func testHoldsIPCLock(t *testing.T) bool {
	t.Helper()

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		// Not a skip and not a guess: a host where the capability cannot be read
		// cannot tell the two contracts apart, and running the wrong one would
		// report a verification that did not happen.
		t.Fatalf("capget: %v", err)
	}
	return data[ipcLockWord].Effective&ipcLockBit != 0
}

// dropIPCLock removes CAP_IPC_LOCK from this thread's effective and permitted
// sets, so RLIMIT_MEMLOCK starts binding. Permitted goes too: leaving it would
// let anything raise the capability back into the effective set, and then the
// state the test asserted is not the state the mlock runs under.
//
// The caller must already hold the OS thread, since capset is per-thread.
func dropIPCLock() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	data[ipcLockWord].Effective &^= ipcLockBit
	data[ipcLockWord].Permitted &^= ipcLockBit
	data[ipcLockWord].Inheritable &^= ipcLockBit
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	return unix.Capset(&hdr, &data[0])
}

const (
	retuneContractMarker = "GO_ENCLAVE_RETUNE_RLIMIT_CHILD"

	retuneWithinCeilingAccepted = "a raise within the ceiling was accepted"
	retuneOverCeilingRefused    = "a raise above the ceiling was refused with the figures"
	retuneLoweringUnchecked     = "a lowering above the ceiling was not refused"
	retuneFreshCeilingHonored   = "the ceiling was re-read, not remembered, in both directions"
	retuneForceOverrode         = "ForceLimit raised above the ceiling and the allocator stayed bound"
	retuneTransferJudged        = "a transfer was judged on the destination's ceiling"
	retunePlainUnaffected       = "a plain NewAllocator allocator was not judged at all"
	retuneUnenforcedConfirmed   = "the ceiling does not bind this process; nothing was refused"
	retuneChildFinished         = "the retune contract child returned normally"
)

// TestAllocator_RLimitContract_UnderAnInjectedCeiling asserts the sticky
// ceiling contract against a ceiling this test controls, which is the only way
// to reach the figures and the only way to demonstrate the property the whole
// issue turns on: that the ceiling is re-read on every raise rather than
// remembered from construction.
//
// It runs in a subprocess because setrlimit is process-wide and would bind every
// other test in the package — through runTestChild in enclave_linux_test.go,
// including the rule that the child logs a confirmation line for each
// contract it verified, so a child that verified nothing cannot be mistaken
// for one that did.
func TestAllocator_RLimitContract_UnderAnInjectedCeiling(t *testing.T) {
	if os.Getenv(retuneContractMarker) == "1" {
		retuneContractChild(t)
		return
	}

	// A skip here would be a contract nobody checked: lowering one's own soft
	// limit needs no privilege, and the privileged case has its own contract to
	// assert rather than to duck. runTestChild fails a child that skipped.
	out, err := runTestChild(t, "TestAllocator_RLimitContract_UnderAnInjectedCeiling", retuneContractMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, retuneChildFinished) {
		t.Fatalf("subprocess did not run to the end:\n%s", out)
	}

	switch {
	case strings.Contains(out, retuneUnenforcedConfirmed):
		// Say so loudly. This run did NOT exercise a single refusal, and a
		// reader of a green log has to know which contract was measured.
		t.Logf("ran the unenforced-limit contract (CAP_IPC_LOCK held and not droppable); no refusal was exercised here")
	default:
		for _, want := range []string{
			retuneWithinCeilingAccepted,
			retuneOverCeilingRefused,
			retuneLoweringUnchecked,
			retuneFreshCeilingHonored,
			retuneForceOverrode,
			retuneTransferJudged,
			retunePlainUnaffected,
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
			}
		}
	}
}

func retuneContractChild(t *testing.T) {
	t.Helper()

	// Capabilities are per-thread and the runtime moves goroutines between
	// threads; pin before touching them and stay pinned, or the capability
	// state asserted is not the one the checks run under.
	runtime.LockOSThread()

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	high := uint64(64 * pageSize)
	if original.Max != rlimInfinity && original.Max < high {
		high = original.Max
	}
	if high < uint64(16*pageSize) {
		t.Fatalf("the hard RLIMIT_MEMLOCK (%d) is too small to inject a usable ceiling", original.Max)
	}
	low := high / 4
	setCeiling := func(to uint64) {
		t.Helper()
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: to, Max: original.Max}); err != nil {
			t.Fatalf("cannot set RLIMIT_MEMLOCK to %d: %v", to, err)
		}
	}
	setCeiling(high)

	// WHICH CONTRACT TO ASSERT IS DECIDED BY AN ORACLE THIS PACKAGE DOES NOT
	// OWN — testHoldsIPCLock reads the capability itself rather than asking the
	// production code, for the reason spelled out in memlock_linux_test.go: a
	// test that asks the implementation which contract applies follows the
	// implementation wherever it goes, including into a bug.
	if testHoldsIPCLock(t) {
		if err := dropIPCLock(); err != nil {
			t.Logf("could not drop CAP_IPC_LOCK (%v); asserting the unenforced contract", err)
		}
	}
	if testHoldsIPCLock(t) {
		retuneUnenforcedContract(t, high)
		t.Log(retuneChildFinished)
		return
	}

	retuneEnforcedContract(t, high, low, setCeiling)
	t.Log(retuneChildFinished)
}

// retuneEnforcedContract asserts the mainstream case, where RLIMIT_MEMLOCK
// binds and the ceiling is therefore a ceiling.
func retuneEnforcedContract(t *testing.T, high, low uint64, setCeiling func(uint64)) {
	t.Helper()

	hi := int64(high)
	lo := int64(low)

	a, err := NewAllocatorWithinRLimit(hi / 2)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit(%d) under a %d-byte ceiling: %v", hi/2, hi, err)
	}

	// CONTROL FIRST. A raise that fits must be accepted, and the allocator must
	// still work afterwards — an implementation that refused every raise, or
	// that returned success without raising, dies here rather than passing the
	// refusal below.
	if err := a.SetLimit(hi - pageSize); err != nil {
		t.Fatalf("SetLimit(%d) under a %d-byte ceiling was refused: %v", hi-pageSize, hi, err)
	}
	if a.Limit() != hi-pageSize {
		t.Fatalf("Limit = %d, want the raised %d", a.Limit(), hi-pageSize)
	}
	const material = "material-under-a-retuned-ceiling"
	e, err := a.New([]byte(material))
	if err != nil {
		t.Fatalf("allocating after an accepted raise: %v", err)
	}
	if !holds(e, []byte(material)) {
		t.Fatal("material did not survive into an enclave after an accepted raise")
	}
	e.Destroy()
	t.Log(retuneWithinCeilingAccepted)

	// ONE BYTE over. Paired with the control this pins the comparison at the
	// exact discovered figure: a `>=` refuses the control, a reversed comparison
	// refuses nothing here.
	for _, over := range []int64{hi + 1, hi * 2} {
		before := a.Limit()
		err := a.SetLimit(over)
		if !errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Fatalf("SetLimit(%d) under a %d-byte ceiling err = %v, want ErrBudgetExceedsRLimit", over, hi, err)
		}
		if errors.Is(err, ErrInvalidBudget) || errors.Is(err, ErrBudgetInUse) || errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Fatalf("the refusal also matched a neighboring sentinel: %v", err)
		}
		var typed *RLimitError
		if !errors.As(err, &typed) {
			t.Fatalf("errors.As could not reach *RLimitError from %v", err)
		}
		if typed.Requested != over || typed.Limit.Bytes != hi || !typed.Limit.Bounded {
			t.Fatalf("RLimitError = %+v, want Requested=%d and the bounded ceiling %d", typed, over, hi)
		}
		if !strings.Contains(err.Error(), strconv.FormatInt(hi, 10)) {
			t.Fatalf("error message %q does not name the ceiling %d", err.Error(), hi)
		}
		// A refused retune changes nothing.
		if a.Limit() != before {
			t.Fatalf("Limit = %d after a refused raise, want the unchanged %d", a.Limit(), before)
		}
	}
	t.Log(retuneOverCeilingRefused)

	// FRESHNESS, DOWNWARD. Lower the ceiling under the running allocator. A
	// budget that was comfortably legal a moment ago must now be refused, and
	// the error must name the NEW figure. An implementation that cached the
	// ceiling at construction still sees the old one and admits this raise,
	// which is the mutation this whole subprocess exists to kill.
	setCeiling(low)
	target := hi - pageSize/2 // above lo, below hi: legal before, illegal now
	err = a.SetLimit(target)
	if !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Fatalf("after the ceiling dropped to %d, SetLimit(%d) err = %v, want ErrBudgetExceedsRLimit "+
			"(the ceiling was remembered from construction instead of re-read)", lo, target, err)
	}
	var typed *RLimitError
	if !errors.As(err, &typed) {
		t.Fatalf("errors.As could not reach *RLimitError from %v", err)
	}
	if typed.Limit.Bytes != lo {
		t.Fatalf("the refusal named %d as the ceiling, want the CURRENT %d", typed.Limit.Bytes, lo)
	}

	// Only raises are checked. The budget is above the ceiling right now, and a
	// LOWERING must still be allowed, or an over-ceiling allocator could never
	// move back towards compliance.
	if err := a.SetLimit(lo * 2); err != nil {
		t.Fatalf("SetLimit(%d) as a lowering under a %d-byte ceiling was refused: %v", lo*2, lo, err)
	}
	if a.Limit() != lo*2 {
		t.Fatalf("Limit = %d, want the lowered %d", a.Limit(), lo*2)
	}
	t.Log(retuneLoweringUnchecked)

	// FRESHNESS, UPWARD. Put the ceiling back. The same raise that was just
	// refused must now be accepted — a ceiling cached at the FIRST check, rather
	// than at construction, would still refuse it.
	setCeiling(high)
	if err := a.SetLimit(target); err != nil {
		t.Fatalf("after the ceiling returned to %d, SetLimit(%d) was still refused: %v "+
			"(the ceiling was remembered from the earlier check)", hi, target, err)
	}
	if a.Limit() != target {
		t.Fatalf("Limit = %d, want %d", a.Limit(), target)
	}
	t.Log(retuneFreshCeilingHonored)

	// ForceLimit is the documented override: it raises above the ceiling without
	// reading it. The allocator must remain bound afterwards — an override is
	// not an opt-out.
	excess, err := a.ForceLimit(hi * 4)
	if err != nil {
		t.Fatalf("ForceLimit(%d) under a %d-byte ceiling: %v (the override picked up the check)", hi*4, hi, err)
	}
	if excess != 0 {
		t.Fatalf("ForceLimit excess = %d, want 0", excess)
	}
	if a.Limit() != hi*4 {
		t.Fatalf("Limit = %d, want the forced %d", a.Limit(), hi*4)
	}
	if err := a.SetLimit(hi * 8); !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Fatalf("after a ForceLimit override, SetLimit err = %v, want the allocator still bound", err)
	}
	t.Log(retuneForceOverrode)

	// A transfer is a raise on the receiving side and is judged the same way.
	dst, err := NewAllocatorWithinRLimit(hi / 8)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit(%d): %v", hi/8, err)
	}
	src, err := NewAllocator(hi * 8)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	srcBefore, dstBefore := src.Limit(), dst.Limit()
	err = src.TransferTo(dst, hi)
	if !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Fatalf("TransferTo taking dst to %d under a %d-byte ceiling err = %v, want ErrBudgetExceedsRLimit",
			dstBefore+hi, hi, err)
	}
	if src.Limit() != srcBefore || dst.Limit() != dstBefore {
		t.Fatalf("a refused transfer moved something: src %d->%d, dst %d->%d",
			srcBefore, src.Limit(), dstBefore, dst.Limit())
	}
	// CONTROL: a transfer that leaves dst within the ceiling must succeed, or
	// "refuses over the ceiling" would be indistinguishable from "refuses every
	// transfer into a bound allocator".
	if err := src.TransferTo(dst, hi/8); err != nil {
		t.Fatalf("a transfer leaving dst within the ceiling was refused: %v", err)
	}
	if dst.Limit() != hi/4 {
		t.Fatalf("dst.Limit = %d, want %d", dst.Limit(), hi/4)
	}
	t.Log(retuneTransferJudged)

	// And the opt-in half, under the very same ceiling: an allocator that never
	// asked for the contract is never judged by it.
	plain, err := NewAllocator(hi / 8)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := plain.SetLimit(math.MaxInt64); err != nil {
		t.Fatalf("SetLimit(MaxInt64) on a plain allocator under a %d-byte ceiling: %v", hi, err)
	}
	if plain.Limit() != math.MaxInt64 {
		t.Fatalf("plain.Limit = %d, want %d", plain.Limit(), int64(math.MaxInt64))
	}
	plainDst, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := plain.TransferTo(plainDst, hi*4); err != nil {
		t.Fatalf("TransferTo into a plain allocator under a %d-byte ceiling: %v", hi, err)
	}
	t.Log(retunePlainUnaffected)
}

// retuneUnenforcedContract asserts the privileged case: the process holds
// CAP_IPC_LOCK, so mlock may exceed RLIMIT_MEMLOCK and the figure is not a
// ceiling. Nothing is refused, on any path.
func retuneUnenforcedContract(t *testing.T, high uint64) {
	t.Helper()

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Bounded || limit.Source != LimitNotEnforced {
		t.Fatalf("discovered %+v, want an unenforced, unbounded limit", limit)
	}

	a, err := NewAllocatorWithinRLimit(int64(high))
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit under an unenforced limit: %v", err)
	}
	if err := a.SetLimit(int64(high) * 8); err != nil {
		t.Fatalf("SetLimit above an unenforced limit was refused: %v", err)
	}
	if a.Limit() != int64(high)*8 {
		t.Fatalf("Limit = %d, want %d", a.Limit(), int64(high)*8)
	}
	t.Log(retuneUnenforcedConfirmed)
}

// testMemlockHardLimit reports whether the hard RLIMIT_MEMLOCK reaches the
// suite's requirement — what a fault-injection test can raise the soft limit
// to after dropping CAP_IPC_LOCK — and the hard limit itself.
func testMemlockHardLimit() (uint64, bool) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return 0, false
	}
	return rl.Max, rl.Max == rlimInfinity || rl.Max >= testMemlockRequirement
}

func TestIsInitialUIDMap(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    string
		want bool
	}{
		{"initial namespace", "         0          0 4294967295\n", true},
		{"unshare -Ur", "         0       1000          1\n", false},
		{"rootless container range", "0 1000 1\n1 100000 65536\n", false},
		{"offset full range", "0 1 4294967295\n", false},
		{"short range", "0 0 4294967294\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInitialUIDMap([]byte(tc.m)); got != tc.want {
				t.Errorf("isInitialUIDMap(%q) = %v, want %v", tc.m, got, tc.want)
			}
		})
	}
}

// TestMemlockRLimitEnforced_TrustsTheCapabilityOnlyInTheInitialNamespace
// presents uid maps through the seam. Outside the initial namespace, or when
// the map cannot be read, the limit is enforced whatever capget says; inside
// it, the answer is the capability's.
func TestMemlockRLimitEnforced_TrustsTheCapabilityOnlyInTheInitialNamespace(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	prev := readUIDMap
	t.Cleanup(func() { readUIDMap = prev })

	readUIDMap = func() ([]byte, error) { return []byte("0 1000 1\n"), nil }
	if !memlockRLimitEnforced() {
		t.Error("memlockRLimitEnforced() = false in a child user namespace, want true")
	}
	readUIDMap = func() ([]byte, error) { return nil, os.ErrPermission }
	if !memlockRLimitEnforced() {
		t.Error("memlockRLimitEnforced() = false with an unreadable uid_map, want true")
	}
	readUIDMap = func() ([]byte, error) { return []byte("0 0 4294967295\n"), nil }
	if got, want := memlockRLimitEnforced(), !testHoldsIPCLock(t); got != want {
		t.Errorf("memlockRLimitEnforced() = %v in the initial namespace, want %v (the capability's answer)", got, want)
	}
}

const (
	userNamespaceMarker        = "GO_ENCLAVE_USERNS_CHILD"
	userNamespaceNoCapability  = "userns child: no CAP_IPC_LOCK in the namespace"
	userNamespaceLimitEnforced = "userns child: the limit was reported and found enforced"
)

// TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace re-executes the
// test binary as root of a new user namespace, the equivalent of unshare -Ur:
// it holds CAP_IPC_LOCK there, and the kernel still applies RLIMIT_MEMLOCK
// because the capability is checked in the initial namespace. The child
// asserts both: this package reports the limit enforced, and mlock past it
// really fails.
//
// It skips only when the host refuses unprivileged user namespaces, or grants
// one without capabilities (an AppArmor userns restriction).
func TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace(t *testing.T) {
	if os.Getenv(userNamespaceMarker) == "1" {
		userNamespaceChild(t)
		return
	}

	attr := &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	probe := exec.Command(os.Args[0], "-test.run=^$")
	probe.SysProcAttr = attr
	if err := probe.Run(); err != nil {
		for _, denied := range []error{unix.EPERM, unix.EACCES, unix.ENOSPC, unix.EINVAL, unix.ENOSYS} {
			if errors.Is(err, denied) {
				t.Skipf("unprivileged user namespaces are unavailable here: %v", err)
			}
		}
		t.Fatalf("starting a child in a new user namespace: %v", err)
	}

	out, err := runTestChildWith(t, "TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace",
		userNamespaceMarker, "1", attr)
	if strings.Contains(out, userNamespaceNoCapability) {
		t.Skipf("the user namespace carries no capabilities here:\n%s", out)
	}
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, userNamespaceLimitEnforced) {
		t.Fatalf("subprocess did not confirm the enforced limit:\n%s", out)
	}
}

func userNamespaceChild(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()

	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatalf("read uid_map: %v", err)
	}
	if fields := strings.Fields(string(raw)); len(fields) == 3 && fields[1] == "0" && fields[2] == "4294967295" {
		t.Fatalf("the child is in the initial user namespace (uid_map %q); nothing is under test", raw)
	}
	if !testHoldsIPCLock(t) {
		t.Log(userNamespaceNoCapability)
		return
	}

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	ceiling := uint64(4 * pageSize)
	if original.Max != rlimInfinity && original.Max < ceiling {
		ceiling = original.Max
	}
	// Past the ceiling by at least one whole page, whatever its size.
	over := int((ceiling/uint64(pageSize) + 1) * uint64(pageSize))
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: ceiling, Max: original.Max}); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Source != LimitRLimit || !limit.Bounded || limit.Bytes != int64(ceiling) {
		t.Fatalf("DiscoverLockedMemoryLimit = %+v, want a bounded LimitRLimit of %d: CAP_IPC_LOCK in a "+
			"child namespace does not lift the limit", limit, ceiling)
	}
	if _, err := NewAllocatorWithinRLimit(int64(over)); !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Fatalf("NewAllocatorWithinRLimit over the ceiling = %v, want ErrBudgetExceedsRLimit", err)
	}

	// The kernel agrees: a region larger than the ceiling cannot be locked.
	region, err := sysMap(over)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() { _ = sysUnmap(region) }()
	if err := unix.Mlock(region); !errors.Is(err, unix.ENOMEM) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("mlock past the ceiling = %v, want ENOMEM: the kernel did not enforce the limit, so "+
			"this host does not reproduce the case under test", err)
	}
	t.Log(userNamespaceLimitEnforced)
}
