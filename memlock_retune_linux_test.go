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
	"testing"

	"golang.org/x/sys/unix"
)

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
// other test in the package — the harness in memlock_linux_test.go and
// enclave_lockfail_linux_test.go, including its rule that the child logs a
// confirmation line for each contract it verified, so a child that verified
// nothing cannot be mistaken for one that did.
func TestAllocator_RLimitContract_UnderAnInjectedCeiling(t *testing.T) {
	if os.Getenv(retuneContractMarker) == "1" {
		retuneContractChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAllocator_RLimitContract_UnderAnInjectedCeiling$", "-test.v")
	cmd.Env = append(os.Environ(), retuneContractMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	// A skip here would be a contract nobody checked: lowering one's own soft
	// limit needs no privilege, and the privileged case has its own contract to
	// assert rather than to duck.
	if strings.Contains(string(out), "--- SKIP") {
		t.Fatalf("the child skipped instead of verifying a contract:\n%s", out)
	}
	if !strings.Contains(string(out), retuneChildFinished) {
		t.Fatalf("subprocess did not run to the end:\n%s", out)
	}

	switch {
	case strings.Contains(string(out), retuneUnenforcedConfirmed):
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
			if !strings.Contains(string(out), want) {
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
	if !e.EqualTo([]byte(material)) {
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
