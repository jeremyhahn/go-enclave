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
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers admission.go, memlock.go and process_allocator.go against a REAL
// RLIMIT_MEMLOCK: each test runs in a child process whose ceiling was lowered
// (soft and hard) before any test code ran, in a container holding no
// CAP_IPC_LOCK, so the kernel enforces it and the process cannot lift it.
// Every figure the allocator reports is checked against the kernel's own
// VmLck, and every kernel refusal is a real mlock failure, not a simulation.

// admissionPages is the child's ceiling, in pages, for the ceiling tests.
const admissionPages = 32

// requireCeiling verifies the child really runs under the ceiling it asked
// for, that the kernel enforces it, and that nothing is locked yet.
func requireCeiling(t *testing.T, want int64) {
	t.Helper()
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_MEMLOCK): %v", err)
	}
	if rl.Cur != uint64(want) || rl.Max != uint64(want) {
		t.Fatalf("RLIMIT_MEMLOCK = %d/%d, want %d/%d", rl.Cur, rl.Max, want, want)
	}
	// The ceiling is the hard limit too, and this process cannot raise it.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: uint64(want) + 4096, Max: uint64(want) + 4096}); !errors.Is(err, unix.EPERM) {
		t.Fatalf("raising RLIMIT_MEMLOCK: err = %v, want EPERM — the ceiling must be one the process cannot lift", err)
	}
	lim, err := enclave.DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if lim != (enclave.LockedMemoryLimit{Bytes: want, Bounded: true, Source: enclave.LimitRLimit}) {
		t.Fatalf("DiscoverLockedMemoryLimit = %+v, want {Bytes:%d Bounded:true Source:%v}", lim, want, enclave.LimitRLimit)
	}
	if got := vmLck(t); got != 0 {
		t.Fatalf("VmLck = %d before anything was allocated, want 0", got)
	}
}

// requireBudgetError asserts err is a refusal by the BUDGET (before any
// syscall) with exactly the given figures.
func requireBudgetError(t *testing.T, what string, err error, requested, inUse, limit int64) {
	t.Helper()
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("%s: err = %v, want ErrBudgetExhausted", what, err)
	}
	var be *enclave.BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("%s: err = %T %v, want a *BudgetError", what, err, err)
	}
	if be.Requested != requested || be.InUse != inUse || be.Limit != limit {
		t.Fatalf("%s: BudgetError = %+v, want {Requested:%d InUse:%d Limit:%d}", what, *be, requested, inUse, limit)
	}
	if errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
		t.Fatalf("%s: a budget refusal also matches ErrLockedMemoryUnavailable: %v", what, err)
	}
}

// TestAdmissionUnderRealMemlockCeiling drives one allocator through the whole
// admission lifecycle against a 32-page kernel ceiling: construction checks,
// filling to the ceiling (VmLck agreeing) with the next refused by budget, an
// unadmitted allocation refused by the kernel, release and re-admission,
// SetLimit/ForceLimit/TransferTo at the ceiling, and nothing held at the end.
func TestAdmissionUnderRealMemlockCeiling(t *testing.T) {
	page := enclave.LockedSize(1)
	ceiling := admissionPages * page
	isolated(t, childOpts{memlock: ceiling}, func(t *testing.T) {
		requireCeiling(t, ceiling)

		// Construction is checked against the ceiling.
		_, err := enclave.NewAllocatorWithinRLimit(ceiling + page)
		var rle *enclave.RLimitError
		if !errors.Is(err, enclave.ErrBudgetExceedsRLimit) || !errors.As(err, &rle) {
			t.Fatalf("NewAllocatorWithinRLimit(ceiling+page): err = %v, want an RLimitError matching ErrBudgetExceedsRLimit", err)
		}
		if rle.Requested != ceiling+page || rle.Limit.Bytes != ceiling || !rle.Limit.Bounded {
			t.Fatalf("RLimitError = %+v, want Requested %d against a bounded %d", *rle, ceiling+page, ceiling)
		}
		a, err := enclave.NewAllocatorWithinRLimit(ceiling)
		if err != nil {
			t.Fatalf("NewAllocatorWithinRLimit(ceiling): %v", err)
		}

		// Fill to the ceiling, through the allocator.
		var live []*enclave.MemoryEnclave
		for i := int64(0); i < admissionPages; i++ {
			e, err := a.NewSized(1)
			if err != nil {
				t.Fatalf("admission %d of %d: %v (InUse %d, VmLck %d)", i+1, admissionPages, err, a.InUse(), vmLck(t))
			}
			live = append(live, e)
		}
		if a.InUse() != ceiling || a.Available() != 0 || vmLck(t) != ceiling {
			t.Fatalf("at the ceiling: InUse %d, Available %d, VmLck %d; want %d, 0, %d", a.InUse(), a.Available(), vmLck(t), ceiling, ceiling)
		}
		_, err = a.NewSized(1)
		requireBudgetError(t, "allocation past the budget", err, page, ceiling, ceiling)
		_, err = a.New([]byte("past the budget"))
		requireBudgetError(t, "Allocator.New past the budget", err, page, ceiling, ceiling)

		// The ceiling is the kernel's, not only the allocator's.
		_, err = enclave.NewMemoryEnclaveSized(1)
		var lme *enclave.LockedMemoryError
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) || !errors.As(err, &lme) {
			t.Fatalf("unadmitted allocation at RLIMIT_MEMLOCK: err = %v, want a LockedMemoryError matching ErrLockedMemoryUnavailable", err)
		}
		if !errors.Is(err, unix.ENOMEM) && !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("kernel refusal at the ceiling: err = %v, want the mlock/mmap ENOMEM or EAGAIN reachable through it", err)
		}
		if got := vmLck(t); got != ceiling {
			t.Fatalf("after the kernel refused an allocation VmLck = %d, want %d: the failed construction leaked locked pages", got, ceiling)
		}

		// Destroy returns the reservation and the page; admission resumes.
		if err := live[0].Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if a.InUse() != ceiling-page || vmLck(t) != ceiling-page {
			t.Fatalf("after one Destroy: InUse %d, VmLck %d, want %d", a.InUse(), vmLck(t), ceiling-page)
		}
		e, err := a.NewSized(1)
		if err != nil {
			t.Fatalf("allocation after a Destroy freed a page: %v", err)
		}
		live[0] = e

		// SetLimit: never below live reservations, never above the ceiling.
		err = a.SetLimit(ceiling - page)
		var le *enclave.BudgetInUseError
		if !errors.Is(err, enclave.ErrBudgetInUse) || !errors.As(err, &le) {
			t.Fatalf("SetLimit below InUse: err = %v, want a BudgetInUseError matching ErrBudgetInUse", err)
		}
		if *le != (enclave.BudgetInUseError{Requested: ceiling - page, InUse: ceiling, Limit: ceiling}) || a.Limit() != ceiling {
			t.Fatalf("BudgetInUseError = %+v, Limit() = %d; want {Requested:%d InUse:%d Limit:%d} and the budget unchanged", *le, a.Limit(), ceiling-page, ceiling, ceiling)
		}
		if err := a.SetLimit(ceiling + page); !errors.Is(err, enclave.ErrBudgetExceedsRLimit) {
			t.Fatalf("SetLimit above RLIMIT_MEMLOCK on a WithinRLimit allocator: err = %v, want ErrBudgetExceedsRLimit", err)
		}

		// ForceLimit: the ceiling moved underneath live enclaves.
		half := ceiling / 2
		excess, err := a.ForceLimit(half)
		if err != nil || excess != ceiling-half {
			t.Fatalf("ForceLimit(half) = (%d, %v), want (%d, nil)", excess, err, ceiling-half)
		}
		if a.Available() != 0 || a.InUse() != ceiling {
			t.Fatalf("over-subscribed: Available %d, InUse %d; want 0, %d", a.Available(), a.InUse(), ceiling)
		}
		_, err = a.NewSized(1)
		requireBudgetError(t, "allocation while over-subscribed", err, page, ceiling, half)
		for len(live) > 0 && a.InUse() > half-page {
			if err := live[len(live)-1].Destroy(); err != nil {
				t.Fatalf("Destroy while draining: %v", err)
			}
			live = live[:len(live)-1]
		}
		e, err = a.NewSized(1)
		if err != nil {
			t.Fatalf("allocation once usage drained below the forced limit: %v", err)
		}
		live = append(live, e)
		if a.InUse() != half || vmLck(t) != half {
			t.Fatalf("after draining: InUse %d, VmLck %d; want %d", a.InUse(), vmLck(t), half)
		}

		// TransferTo: headroom moves in one step, and only headroom that exists.
		if err := a.SetLimit(half + 4*page); err != nil {
			t.Fatalf("SetLimit raise within the ceiling: %v", err)
		}
		b, err := enclave.NewAllocator(page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if err := a.TransferTo(b, 2*page); err != nil {
			t.Fatalf("TransferTo(2 pages of headroom): %v", err)
		}
		if a.Limit() != half+2*page || b.Limit() != 3*page {
			t.Fatalf("after TransferTo: limits %d and %d, want %d and %d", a.Limit(), b.Limit(), half+2*page, 3*page)
		}
		if err := a.TransferTo(b, 3*page); !errors.Is(err, enclave.ErrBudgetInUse) {
			t.Fatalf("TransferTo more than the headroom: err = %v, want ErrBudgetInUse", err)
		}
		if err := a.TransferTo(a, page); !errors.Is(err, enclave.ErrInvalidTransfer) {
			t.Fatalf("TransferTo self: err = %v, want ErrInvalidTransfer", err)
		}
		c, err := enclave.NewAllocatorWithinRLimit(page)
		if err != nil {
			t.Fatalf("NewAllocatorWithinRLimit(page): %v", err)
		}
		if err := a.TransferTo(c, 2*page); err != nil {
			t.Fatalf("TransferTo into a WithinRLimit allocator, staying under the ceiling: %v", err)
		}
		bulk, err := enclave.NewAllocator(2 * ceiling)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if err := bulk.TransferTo(c, ceiling); !errors.Is(err, enclave.ErrBudgetExceedsRLimit) {
			t.Fatalf("TransferTo taking a WithinRLimit destination past RLIMIT_MEMLOCK: err = %v, want ErrBudgetExceedsRLimit", err)
		}
		for i := 0; i < 3; i++ {
			e, err := b.NewSized(1)
			if err != nil {
				t.Fatalf("allocation %d through the transferred headroom: %v", i+1, err)
			}
			live = append(live, e)
		}
		_, err = b.NewSized(1)
		requireBudgetError(t, "allocation past the transferred headroom", err, page, 3*page, 3*page)

		for _, e := range live {
			if err := e.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
		}
		if a.InUse() != 0 || b.InUse() != 0 || vmLck(t) != 0 {
			t.Fatalf("after destroying everything: InUse %d and %d, VmLck %d; want all 0", a.InUse(), b.InUse(), vmLck(t))
		}
		n, err := enclave.WipeAll(context.Background())
		if n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestAdmissionHoldsTheKernelCeilingUnderContention admits and releases from
// many goroutines while another retunes a budget whose maximum is exactly the
// kernel ceiling, so any over-admission becomes a real mlock failure. Refusals
// and sampled figures stay in range, and everything is returned at the end.
func TestAdmissionHoldsTheKernelCeilingUnderContention(t *testing.T) {
	page := enclave.LockedSize(1)
	ceiling := admissionPages * page
	isolated(t, childOpts{memlock: ceiling}, func(t *testing.T) {
		requireCeiling(t, ceiling)
		a, err := enclave.NewAllocatorWithinRLimit(ceiling)
		if err != nil {
			t.Fatalf("NewAllocatorWithinRLimit: %v", err)
		}

		const workers, iterations = 8, 400
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			failures []string
			admitted int
			refused  int
		)
		fail := func(msg string) {
			mu.Lock()
			defer mu.Unlock()
			if len(failures) < 10 {
				failures = append(failures, msg)
			}
		}
		stop := make(chan struct{})
		retuned := make(chan int)
		go func() {
			// Flip the budget between the ceiling and half of it. Lowering
			// refused because reservations are live is the expected answer half
			// the time; anything else is not.
			n := 0
			for {
				select {
				case <-stop:
					retuned <- n
					return
				default:
				}
				target := ceiling
				if n%2 == 0 {
					target = ceiling / 2
				}
				if err := a.SetLimit(target); err != nil && !errors.Is(err, enclave.ErrBudgetInUse) {
					fail("SetLimit: " + err.Error())
				}
				n++
			}
		}()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var held []*enclave.MemoryEnclave
				for i := 0; i < iterations; i++ {
					e, err := a.NewSized(1)
					var be *enclave.BudgetError
					switch {
					case err == nil:
						held = append(held, e)
						mu.Lock()
						admitted++
						mu.Unlock()
					case errors.As(err, &be):
						if be.InUse < 0 || be.Requested != page || be.Limit < 0 || be.Limit > ceiling {
							fail("impossible BudgetError: " + err.Error())
						}
						mu.Lock()
						refused++
						mu.Unlock()
					default:
						// Including ErrLockedMemoryUnavailable: the budget never
						// exceeds the kernel ceiling, so the kernel refusing means
						// the allocator admitted bytes it did not have.
						fail("allocation failed other than by the budget (over-admission reached the kernel): " + err.Error())
					}
					if inUse, avail := a.InUse(), a.Available(); inUse < 0 || avail < 0 || inUse > ceiling {
						fail("InUse/Available out of range")
					}
					// Release half the time, keeping the budget contended.
					if len(held) > 0 && i%2 == 1 {
						if err := held[0].Destroy(); err != nil {
							fail("Destroy: " + err.Error())
						}
						held = held[1:]
					}
				}
				for _, e := range held {
					if err := e.Destroy(); err != nil {
						fail("Destroy: " + err.Error())
					}
				}
			}()
		}
		wg.Wait()
		close(stop)
		retunes := <-retuned

		for _, f := range failures {
			t.Error(f)
		}
		if admitted == 0 || refused == 0 {
			t.Errorf("admitted %d, refused %d: the budget was never contended, so this measured nothing", admitted, refused)
		}
		if a.InUse() != 0 || vmLck(t) != 0 {
			t.Errorf("after every enclave was destroyed: InUse %d, VmLck %d; want 0 and 0", a.InUse(), vmLck(t))
		}
		t.Logf("%d workers x %d iterations: %d admitted, %d refused by the budget, %d retunes, no kernel refusal", workers, iterations, admitted, refused, retunes)
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestProcessAllocatorDefaultsToTheKernelCeiling is the library path: the lazy
// default's budget is the discovered ceiling, kept for life, and installation
// is one-shot.
func TestProcessAllocatorDefaultsToTheKernelCeiling(t *testing.T) {
	page := enclave.LockedSize(1)
	const pages = 8
	ceiling := pages * page
	isolated(t, childOpts{memlock: ceiling}, func(t *testing.T) {
		requireCeiling(t, ceiling)
		a, err := enclave.ProcessAllocator()
		if err != nil {
			t.Fatalf("ProcessAllocator: %v", err)
		}
		if again, err := enclave.ProcessAllocator(); err != nil || again != a {
			t.Fatalf("second ProcessAllocator = (%p, %v), want the same allocator", again, err)
		}
		if a.Limit() != ceiling {
			t.Fatalf("default budget %d, want the discovered ceiling %d", a.Limit(), ceiling)
		}
		var live []*enclave.MemoryEnclave
		for i := 0; i < pages; i++ {
			e, err := a.NewSized(1)
			if err != nil {
				t.Fatalf("admission %d of %d: %v", i+1, pages, err)
			}
			live = append(live, e)
		}
		if vmLck(t) != ceiling {
			t.Fatalf("VmLck %d at the default budget, want %d", vmLck(t), ceiling)
		}
		_, err = a.NewSized(1)
		requireBudgetError(t, "default allocator past the ceiling", err, page, ceiling, ceiling)
		if err := a.SetLimit(ceiling + page); !errors.Is(err, enclave.ErrBudgetExceedsRLimit) {
			t.Fatalf("raising the default past the ceiling: err = %v, want ErrBudgetExceedsRLimit", err)
		}
		other, err := enclave.NewAllocator(page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if err := enclave.SetAllocator(other); !errors.Is(err, enclave.ErrAllocatorInstalled) {
			t.Fatalf("SetAllocator after the default was installed: err = %v, want ErrAllocatorInstalled", err)
		}
		for _, e := range live {
			if err := e.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil || vmLck(t) != 0 {
			t.Fatalf("WipeAll = (%d, %v), VmLck %d; want (0, nil), 0", n, err, vmLck(t))
		}
	})
}

// TestSetAllocatorIsTheBinarysOneShotDecision is the binary path: the budget
// installed once is what every ProcessAllocator caller admits against; nil and a
// second installation are refused.
func TestSetAllocatorIsTheBinarysOneShotDecision(t *testing.T) {
	page := enclave.LockedSize(1)
	ceiling := admissionPages * page
	isolated(t, childOpts{memlock: ceiling}, func(t *testing.T) {
		requireCeiling(t, ceiling)
		if err := enclave.SetAllocator(nil); !errors.Is(err, enclave.ErrNilAllocator) {
			t.Fatalf("SetAllocator(nil): err = %v, want ErrNilAllocator", err)
		}
		budget, err := enclave.NewAllocatorWithinRLimit(4 * page)
		if err != nil {
			t.Fatalf("NewAllocatorWithinRLimit: %v", err)
		}
		if err := enclave.SetAllocator(budget); err != nil {
			t.Fatalf("SetAllocator: %v", err)
		}
		if err := enclave.SetAllocator(budget); !errors.Is(err, enclave.ErrAllocatorInstalled) {
			t.Fatalf("second SetAllocator: err = %v, want ErrAllocatorInstalled", err)
		}
		lib, err := enclave.ProcessAllocator()
		if err != nil || lib != budget {
			t.Fatalf("ProcessAllocator = (%p, %v), want the installed allocator %p", lib, err, budget)
		}
		var live []*enclave.MemoryEnclave
		for i := 0; i < 4; i++ {
			e, err := lib.NewSized(1)
			if err != nil {
				t.Fatalf("library admission %d: %v", i+1, err)
			}
			live = append(live, e)
		}
		_, err = lib.NewSized(1)
		requireBudgetError(t, "library allocation past the binary's budget", err, page, 4*page, 4*page)
		for _, e := range live {
			if err := e.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestZeroMemlockCeilingFailsClosedEverywhere pins that under a zero
// RLIMIT_MEMLOCK every route to locked memory refuses with a typed error: the
// default allocator by budget, direct construction and sealing by the kernel.
func TestZeroMemlockCeilingFailsClosedEverywhere(t *testing.T) {
	isolated(t, childOpts{memlockZero: true}, func(t *testing.T) {
		lim, err := enclave.DiscoverLockedMemoryLimit()
		if err != nil {
			t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
		}
		if lim != (enclave.LockedMemoryLimit{Bytes: 0, Bounded: true, Source: enclave.LimitRLimit}) {
			t.Fatalf("DiscoverLockedMemoryLimit = %+v, want a bounded zero ceiling", lim)
		}
		if _, err := enclave.NewAllocatorWithinRLimit(enclave.LockedSize(1)); !errors.Is(err, enclave.ErrBudgetExceedsRLimit) {
			t.Fatalf("NewAllocatorWithinRLimit under a zero ceiling: err = %v, want ErrBudgetExceedsRLimit", err)
		}
		a, err := enclave.ProcessAllocator()
		if err != nil {
			t.Fatalf("ProcessAllocator: %v", err)
		}
		if a.Limit() != 0 {
			t.Fatalf("default budget under a zero ceiling = %d, want 0", a.Limit())
		}
		_, err = a.NewSized(1)
		requireBudgetError(t, "default allocator under a zero ceiling", err, enclave.LockedSize(1), 0, 0)

		for name, construct := range map[string]func() error{
			"NewMemoryEnclaveSized": func() error { _, err := enclave.NewMemoryEnclaveSized(1); return err },
			"NewMemoryEnclave":      func() error { _, err := enclave.NewMemoryEnclave([]byte{1}); return err },
			"NewSealed": func() error {
				_, err := enclave.NewSealed(context.Background(), []byte{1})
				return err
			},
		} {
			if err := construct(); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
				t.Errorf("%s under a zero ceiling: err = %v, want ErrLockedMemoryUnavailable", name, err)
			}
		}
		if got := vmLck(t); got != 0 {
			t.Fatalf("VmLck = %d under a zero ceiling", got)
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil): a refused construction left pages held", n, err)
		}
	})
}

// TestForceLimitReportsTheExcessItCreates pins ForceLimit's excess on raise,
// no-op and lowering, and that the excess refuses admission until repaid.
func TestForceLimitReportsTheExcessItCreates(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		page := enclave.LockedSize(1)
		a, err := enclave.NewAllocator(2 * page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		held, err := a.NewSized(1)
		if err != nil {
			t.Fatalf("NewSized: %v", err)
		}
		if excess, err := a.ForceLimit(4 * page); excess != 0 || err != nil || a.Limit() != 4*page {
			t.Fatalf("raising ForceLimit = (%d, %v), limit %d; want (0, nil), %d", excess, err, a.Limit(), 4*page)
		}
		if excess, err := a.ForceLimit(4 * page); excess != 0 || err != nil {
			t.Fatalf("ForceLimit to the same limit = (%d, %v), want (0, nil)", excess, err)
		}
		if excess, err := a.ForceLimit(0); excess != page || err != nil {
			t.Fatalf("ForceLimit(0) under one live page = (%d, %v), want (%d, nil)", excess, err, page)
		}
		if _, err := a.NewSized(1); !errors.Is(err, enclave.ErrBudgetExhausted) {
			t.Errorf("admission while over the forced limit = %v, want ErrBudgetExhausted", err)
		}
		if err := held.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if a.InUse() != 0 || a.Available() != 0 {
			t.Errorf("after the release: InUse %d, Available %d; want 0 and 0", a.InUse(), a.Available())
		}
	})
}

// TestAdmissionErrorsDescribeThemselves drives each admission and rlimit
// error from a real refusal and checks what an operator reads: the message
// names the condition, errors.As reaches the figures, and the sentinel still
// matches; LimitDiscoveryError renders and unwraps its cause.
func TestAdmissionErrorsDescribeThemselves(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		page := enclave.LockedSize(1)

		// BudgetError: an admission refusal, with the figures it was decided on.
		a, err := enclave.NewAllocator(page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		held, err := a.NewSized(1)
		if err != nil {
			t.Fatalf("NewSized: %v", err)
		}
		_, err = a.NewSized(1)
		var be *enclave.BudgetError
		if !errors.As(err, &be) || !errors.Is(err, enclave.ErrBudgetExhausted) {
			t.Fatalf("a refusal past the budget = %v, want a *BudgetError matching ErrBudgetExhausted", err)
		}
		if be.Requested != page || be.InUse != page || be.Limit != page {
			t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", *be, page)
		}
		if msg := err.Error(); !strings.Contains(msg, "budget") {
			t.Errorf("BudgetError message %q does not name the budget", msg)
		}
		if err := held.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}

		// SetLimit below what is reserved, and a negative budget.
		held, err = a.NewSized(1)
		if err != nil {
			t.Fatalf("NewSized: %v", err)
		}
		if err := a.SetLimit(0); err == nil || err.Error() == "" {
			t.Errorf("SetLimit below the bytes in use = %v, want a refusal that describes itself", err)
		}
		if _, err := enclave.NewAllocator(-1); err == nil || err.Error() == "" {
			t.Errorf("NewAllocator(-1) = %v, want a refusal that describes itself", err)
		}
		if err := held.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}

		// A budget above the kernel ceiling, refused by the rlimit-checked
		// constructor with the figures it compared.
		lim, err := enclave.DiscoverLockedMemoryLimit()
		if err != nil {
			t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
		}
		if !lim.Bounded {
			t.Fatalf("the devcontainer's RLIMIT_MEMLOCK is not bounded (%+v); compose.yaml sets it", lim)
		}
		_, err = enclave.NewAllocatorWithinRLimit(lim.Bytes + page)
		if !errors.Is(err, enclave.ErrBudgetExceedsRLimit) {
			t.Fatalf("NewAllocatorWithinRLimit above the ceiling = %v, want ErrBudgetExceedsRLimit", err)
		}
		if msg := err.Error(); !strings.Contains(msg, "limit") {
			t.Errorf("the rlimit refusal %q does not name the limit", msg)
		}

		if s := lim.Source.String(); s == "" || strings.Contains(s, "%") {
			t.Errorf("LimitSource.String() = %q", s)
		}
		if msg := (&enclave.LimitDiscoveryError{}).Error(); !strings.HasPrefix(msg, "enclave: ") {
			t.Errorf("LimitDiscoveryError{}.Error() = %q, want a message in the package's voice", msg)
		}
		cause := errors.New("prlimit: permission denied")
		lde := &enclave.LimitDiscoveryError{Cause: cause}
		if !errors.Is(lde, enclave.ErrLimitDiscoveryFailed) || !errors.Is(lde, cause) || !strings.Contains(lde.Error(), cause.Error()) {
			t.Errorf("LimitDiscoveryError = %v: want it to match ErrLimitDiscoveryFailed, reach and print its cause", lde)
		}
	})
}

// TestAllocatorRefusesInvalidArguments drives every argument check of the
// budget API against real locked memory: each is refused with its documented
// sentinel and leaves no locked memory or charge behind.
func TestAllocatorRefusesInvalidArguments(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		before := vmLck(t)
		a, err := enclave.NewAllocator(4 * enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if _, err := a.NewSized(0); !errors.Is(err, enclave.ErrInvalidSize) {
			t.Errorf("Allocator.NewSized(0) = %v, want ErrInvalidSize", err)
		}
		if _, err := a.New(nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("Allocator.New(nil) = %v, want ErrEmptyEnclave", err)
		}
		if err := a.SetLimit(-1); !errors.Is(err, enclave.ErrInvalidBudget) {
			t.Errorf("SetLimit(-1) = %v, want ErrInvalidBudget", err)
		}
		if _, err := a.ForceLimit(-1); !errors.Is(err, enclave.ErrInvalidBudget) {
			t.Errorf("ForceLimit(-1) = %v, want ErrInvalidBudget", err)
		}
		if _, err := enclave.NewAllocatorWithinRLimit(0); !errors.Is(err, enclave.ErrInvalidBudget) {
			t.Errorf("NewAllocatorWithinRLimit(0) = %v, want ErrInvalidBudget", err)
		}
		huge, err := enclave.NewAllocator(math.MaxInt64)
		if err != nil {
			t.Fatalf("NewAllocator(MaxInt64): %v", err)
		}
		if err := a.TransferTo(huge, 1); err == nil {
			t.Error("TransferTo a budget it would overflow succeeded")
		}

		if after := vmLck(t); after != before {
			t.Errorf("VmLck = %d after only refusals, want %d: a refusal locked memory", after, before)
		}
		if a.InUse() != 0 {
			t.Errorf("InUse = %d after only refusals, want 0", a.InUse())
		}
	})
}

// TestNilAllocatorRefusesEverywhere: a nil *Allocator is a lost configuration
// step, so every method that can fail refuses with ErrNilAllocator, New still
// wipes the data it took, nothing is locked, and the observers report zero.
func TestNilAllocatorRefusesEverywhere(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		before := vmLck(t)
		var a *enclave.Allocator

		data := []byte("handed to a nil allocator")
		if e, err := a.New(data); e != nil || !errors.Is(err, enclave.ErrNilAllocator) {
			t.Errorf("New = (%v, %v), want (nil, ErrNilAllocator)", e, err)
		}
		if !allZero(data) {
			t.Error("New on a nil Allocator left the caller's data unwiped")
		}
		if e, err := a.NewSized(32); e != nil || !errors.Is(err, enclave.ErrNilAllocator) {
			t.Errorf("NewSized = (%v, %v), want (nil, ErrNilAllocator)", e, err)
		}
		if err := a.SetLimit(1); !errors.Is(err, enclave.ErrNilAllocator) {
			t.Errorf("SetLimit = %v, want ErrNilAllocator", err)
		}
		if excess, err := a.ForceLimit(1); excess != 0 || !errors.Is(err, enclave.ErrNilAllocator) {
			t.Errorf("ForceLimit = (%d, %v), want (0, ErrNilAllocator)", excess, err)
		}
		dst, err := enclave.NewAllocator(enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if err := a.TransferTo(dst, 1); !errors.Is(err, enclave.ErrNilAllocator) {
			t.Errorf("TransferTo = %v, want ErrNilAllocator", err)
		}
		if a.InUse() != 0 || a.Limit() != 0 || a.Available() != 0 {
			t.Errorf("InUse, Limit, Available = %d, %d, %d; want 0, 0, 0", a.InUse(), a.Limit(), a.Available())
		}
		if after := vmLck(t); after != before {
			t.Errorf("VmLck = %d after only refusals, want %d", after, before)
		}
	})
}
