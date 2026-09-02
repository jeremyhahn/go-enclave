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
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestLimitSource_String(t *testing.T) {
	cases := []struct {
		source LimitSource
		want   string
	}{
		{LimitRLimit, "RLIMIT_MEMLOCK"},
		{LimitUnlimited, "RLIMIT_MEMLOCK unlimited"},
		{LimitNotEnforced, "RLIMIT_MEMLOCK not enforced (CAP_IPC_LOCK)"},
		{LimitUnsupported, "no locked-memory limit on this platform"},
		{LimitUnknown, "unknown"},
		{LimitSource(200), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.source.String(); got != tc.want {
			t.Errorf("LimitSource(%d).String() = %q, want %q", tc.source, got, tc.want)
		}
	}
	// Every named source must render differently: the whole point of the type
	// is that an operator can tell "unlimited" from "we did not look", and two
	// sources sharing a string would erase exactly that distinction in the one
	// place it gets read — a log line.
	seen := make(map[string]LimitSource, len(cases))
	for _, tc := range cases[:4] {
		if prev, dup := seen[tc.want]; dup {
			t.Errorf("LimitSource %d and %d render identically as %q", prev, tc.source, tc.want)
		}
		seen[tc.want] = tc.source
	}
}

// TestRLimitError_Distinguishable pins the property the issue asks for by name:
// the refusal must be tellable apart from the three errors it neighbors. A
// caller that cannot separate "this budget was never satisfiable" from "the
// kernel refused a lock just now" cannot act on either.
func TestRLimitError_Distinguishable(t *testing.T) {
	err := error(&RLimitError{
		Requested: 1 << 20,
		Limit:     LockedMemoryLimit{Bytes: 65536, Bounded: true, Source: LimitRLimit},
	})

	if !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Errorf("errors.Is(err, ErrBudgetExceedsRLimit) = false, want true")
	}
	for _, other := range []struct {
		name string
		err  error
	}{
		{"ErrInvalidBudget", ErrInvalidBudget},
		{"ErrBudgetExhausted", ErrBudgetExhausted},
		{"ErrLockedMemoryUnavailable", ErrLockedMemoryUnavailable},
		{"ErrInvalidSize", ErrInvalidSize},
	} {
		if errors.Is(err, other.err) {
			t.Errorf("errors.Is(RLimitError, %s) = true, want false", other.name)
		}
	}

	// And the reverse direction: the neighbors must not match this sentinel
	// either, or a caller switching on it would swallow unrelated failures.
	for _, other := range []error{ErrInvalidBudget, ErrBudgetExhausted, ErrLockedMemoryUnavailable} {
		if errors.Is(other, ErrBudgetExceedsRLimit) {
			t.Errorf("errors.Is(%v, ErrBudgetExceedsRLimit) = true, want false", other)
		}
	}

	// Both figures must survive into the message. The reason to fail at startup
	// is to tell an operator what to change, and a refusal that names neither
	// the budget nor the ceiling does not.
	msg := err.Error()
	for _, want := range []string{strconv.Itoa(1 << 20), "65536", "RLIMIT_MEMLOCK"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}

	var target *RLimitError
	if !errors.As(err, &target) {
		t.Fatal("errors.As could not reach *RLimitError")
	}
	if target.Requested != 1<<20 || target.Limit.Bytes != 65536 {
		t.Errorf("As gave Requested=%d Limit.Bytes=%d, want %d and 65536", target.Requested, target.Limit.Bytes, 1<<20)
	}
}

// linuxRlimInfinity and bsdRlimInfinity are the two RLIM_INFINITY values in the
// portfolio's target platforms, written out here so the classifier can be
// tested against BOTH from a Linux runner. The BSD path has no CI of its own —
// that is exactly why its classification is exercised here rather than left to
// a host nobody runs the suite on.
const (
	linuxRlimInfinity = ^uint64(0)        // all bits set
	bsdRlimInfinity   = uint64(1)<<63 - 1 // the largest positive int64
)

// TestClassifyRlimit exercises every reading of a raw RLIMIT_MEMLOCK value,
// including the ones no unprivileged test process can make a kernel produce:
// RLIM_INFINITY cannot be set when the hard limit is finite, and CAP_IPC_LOCK
// cannot be acquired at all. Those readings are the ones most likely to be
// wrong, so they are tested here rather than left to a host that happens to be
// configured for them.
//
// Each case runs against both platforms' infinity sentinels, which pins the
// property that made the sentinel an argument in the first place: a BSD value
// read against the Linux sentinel classifies as a bounded ceiling of about nine
// exabytes, and the Linux value read against the BSD sentinel as a bounded
// ceiling of -1 — one refusing nothing, the other refusing everything.
//
// Measured while mutation-checking this table: removing the explicit
// RLIM_INFINITY branch ALONE does not turn it red, because the representability
// check below it catches all-bits-set too. Both have to be broken for the Linux
// infinity case to fail, and the mutation run does exactly that. The redundancy
// is deliberate — see classifyRlimit — but it is recorded here so the next
// reader does not mistake this table for proof that the first branch is
// load-bearing on its own. The BSD sentinel is a different matter: it is below
// math.MaxInt64+1, so nothing else catches it, and disabling that branch alone
// does turn the BSD half red.
func TestClassifyRlimit(t *testing.T) {
	page := uint64(pageSize)

	for _, platform := range []struct {
		name     string
		infinity uint64
	}{
		{"linux", linuxRlimInfinity},
		{"bsd", bsdRlimInfinity},
	} {
		t.Run(platform.name, func(t *testing.T) {
			inf := platform.infinity

			cases := []struct {
				name     string
				cur      uint64
				enforced bool
				want     LockedMemoryLimit
			}{
				{
					// The case the issue calls out: the sentinel must not read
					// as a number. The Linux one as an int64 is -1, which is
					// BELOW every budget and would refuse them all.
					name:     "infinity is unlimited, not -1 and not zero",
					cur:      inf,
					enforced: true,
					want:     LockedMemoryLimit{Bytes: 0, Bounded: false, Source: LimitUnlimited},
				},
				{
					name:     "infinity stays unlimited when the limit is unenforced",
					cur:      inf,
					enforced: false,
					want:     LockedMemoryLimit{Bytes: 0, Bounded: false, Source: LimitUnlimited},
				},
				{
					// Finite, but not representable as the int64 a budget is.
					// Nothing to compare against, and truncating would invent a
					// small ceiling out of an enormous one. This is also where a
					// negative value from a BSD's signed rlimit field lands.
					name:     "past int64 is unlimited",
					cur:      uint64(math.MaxInt64) + 1,
					enforced: true,
					want:     LockedMemoryLimit{Bytes: 0, Bounded: false, Source: LimitUnlimited},
				},
				{
					// Zero is a real answer — a process allowed to lock nothing
					// — and must not be confused with the zero Bytes reported
					// for unlimited.
					name:     "zero is a bounded ceiling of zero",
					cur:      0,
					enforced: true,
					want:     LockedMemoryLimit{Bytes: 0, Bounded: true, Source: LimitRLimit},
				},
				{
					name:     "an ordinary finite limit",
					cur:      page,
					enforced: true,
					want:     LockedMemoryLimit{Bytes: int64(page), Bounded: true, Source: LimitRLimit},
				},
				{
					// CAP_IPC_LOCK: the figure is real but the kernel will not
					// hold the process to it, so it is reported and not
					// enforced.
					name:     "unenforced keeps the figure but is not a ceiling",
					cur:      page,
					enforced: false,
					want:     LockedMemoryLimit{Bytes: int64(page), Bounded: false, Source: LimitNotEnforced},
				},
			}
			if inf != uint64(math.MaxInt64) {
				// Only meaningful where the sentinel is not itself int64's
				// maximum: on the BSDs that value IS infinity, tested above.
				cases = append(cases, struct {
					name     string
					cur      uint64
					enforced bool
					want     LockedMemoryLimit
				}{
					name:     "exactly int64 max is still a ceiling",
					cur:      uint64(math.MaxInt64),
					enforced: true,
					want:     LockedMemoryLimit{Bytes: math.MaxInt64, Bounded: true, Source: LimitRLimit},
				})
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got := classifyRlimit(tc.cur, inf, tc.enforced)
					if got != tc.want {
						t.Errorf("classifyRlimit(%#x, %#x, %v) = %+v, want %+v", tc.cur, inf, tc.enforced, got, tc.want)
					}
				})
			}
		})
	}
}

// TestClassifyRlimit_WrongSentinelIsCaught states the failure the sentinel
// argument exists to prevent, so that a future refactor collapsing it back into
// a package constant has to delete an assertion that says why.
func TestClassifyRlimit_WrongSentinelIsCaught(t *testing.T) {
	// A BSD-unlimited value read with the Linux sentinel: a bounded ceiling of
	// nine exabytes, which refuses nothing and reports a number that is not a
	// ceiling.
	if got := classifyRlimit(bsdRlimInfinity, linuxRlimInfinity, true); !got.Bounded || got.Source != LimitRLimit {
		t.Fatalf("expected the mismatched read to produce a bogus bounded ceiling, got %+v", got)
	}
	// And correctly, with its own sentinel.
	if got := classifyRlimit(bsdRlimInfinity, bsdRlimInfinity, true); got.Bounded || got.Source != LimitUnlimited {
		t.Fatalf("classifyRlimit with the BSD sentinel = %+v, want unlimited", got)
	}
}

// TestClassifyRlimit_UnboundedRefusesNothing joins the classification to the
// decision it drives. Reporting "unlimited" correctly is worth nothing if the
// constructor then refuses against it anyway, and the two halves live in
// different functions, so the join needs asserting somewhere.
func TestClassifyRlimit_UnboundedRefusesNothing(t *testing.T) {
	for _, tc := range []struct{ cur, inf uint64 }{
		{linuxRlimInfinity, linuxRlimInfinity},
		{bsdRlimInfinity, bsdRlimInfinity},
		{uint64(math.MaxInt64) + 1, linuxRlimInfinity},
	} {
		limit := classifyRlimit(tc.cur, tc.inf, true)
		if limit.Bounded {
			t.Fatalf("classifyRlimit(%#x, %#x) reported a ceiling to compare against", tc.cur, tc.inf)
		}
		if err := limit.refuse(math.MaxInt64); err != nil {
			t.Fatalf("an unbounded ceiling refused the largest budget expressible: %v", err)
		}
	}
}

// TestLimitDiscoveryError_Distinguishable covers the error returned when the
// ceiling cannot be READ. Nothing was compared, so it must not read as a
// verdict on the budget or as a shortage of locked memory.
func TestLimitDiscoveryError_Distinguishable(t *testing.T) {
	cause := errors.New("getrlimit: operation not permitted")
	err := error(&LimitDiscoveryError{Cause: cause})

	if !errors.Is(err, ErrLimitDiscoveryFailed) {
		t.Error("errors.Is(err, ErrLimitDiscoveryFailed) = false, want true")
	}
	for _, other := range []error{ErrBudgetExceedsRLimit, ErrInvalidBudget, ErrBudgetExhausted, ErrLockedMemoryUnavailable} {
		if errors.Is(err, other) {
			t.Errorf("a discovery failure also matched %v", other)
		}
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is could not reach the wrapped syscall failure")
	}
	if !strings.Contains(err.Error(), "operation not permitted") {
		t.Errorf("Error() = %q, want it to carry the cause", err.Error())
	}
	// A nil cause must still render, since an error that panics while being
	// logged is worse than the failure it reports.
	if got := (&LimitDiscoveryError{}).Error(); got != ErrLimitDiscoveryFailed.Error() {
		t.Errorf("Error() with no cause = %q, want %q", got, ErrLimitDiscoveryFailed.Error())
	}
	if (&LimitDiscoveryError{}).Unwrap() != nil {
		t.Error("Unwrap with no cause should be nil")
	}
}

// TestLockedMemoryLimit_Refuse exercises the decision NewAllocatorWithinRLimit
// makes, against every kind of ceiling, on any host and with nothing injected.
//
// It exists because of what the subprocess test in memlock_linux_test.go cannot
// promise. That test reaches the refusal through the real constructor, which
// discovers its own ceiling — so on a host holding CAP_IPC_LOCK, where there is
// no ceiling to inject, it asserts the privileged contract instead and the
// refusal path goes unmeasured. Codex raised exactly that on this branch: a
// privileged CI would not catch a regression in the primary path. This test
// closes it. Measured: the mutants that break the comparison (removing it,
// `>` to `>=`, inverting Bounded) die here as well as there, so the coverage
// no longer depends on the runner's privileges.
func TestLockedMemoryLimit_Refuse(t *testing.T) {
	bounded := LockedMemoryLimit{Bytes: 65536, Bounded: true, Source: LimitRLimit}

	cases := []struct {
		name    string
		limit   LockedMemoryLimit
		budget  int64
		wantErr bool
	}{
		{"well within a bounded ceiling", bounded, 4096, false},
		// The boundary, from both sides. A `>=` refuses the first of these and
		// a reversed comparison accepts the second.
		{"exactly at a bounded ceiling", bounded, 65536, false},
		{"one byte above a bounded ceiling", bounded, 65537, true},
		{"far above a bounded ceiling", bounded, 1 << 40, true},
		// A ceiling of zero bytes is a real ceiling: a process allowed to lock
		// nothing refuses everything.
		{"any budget against a zero ceiling", LockedMemoryLimit{Bounded: true, Source: LimitRLimit}, 1, true},
		// None of these bound anything, so none of them refuse anything — not
		// even the largest budget expressible.
		{"unlimited refuses nothing", LockedMemoryLimit{Source: LimitUnlimited}, math.MaxInt64, false},
		{"unenforced refuses nothing", LockedMemoryLimit{Bytes: 4096, Source: LimitNotEnforced}, math.MaxInt64, false},
		{"unsupported refuses nothing", LockedMemoryLimit{Source: LimitUnsupported}, math.MaxInt64, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.limit.refuse(tc.budget)
			if tc.wantErr != (err != nil) {
				t.Fatalf("refuse(%d) against %+v = %v, wantErr = %v", tc.budget, tc.limit, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrBudgetExceedsRLimit) {
				t.Fatalf("refuse(%d) err = %v, want ErrBudgetExceedsRLimit", tc.budget, err)
			}
			var typed *RLimitError
			if !errors.As(err, &typed) {
				t.Fatalf("errors.As could not reach *RLimitError from %v", err)
			}
			if typed.Requested != tc.budget || typed.Limit != tc.limit {
				t.Fatalf("RLimitError = %+v, want Requested=%d and Limit=%+v", typed, tc.budget, tc.limit)
			}
		})
	}
}

// TestNewAllocatorWithinRLimit_InvalidBudget checks that a nonsense budget is
// reported as a caller mistake and never as a host-configuration problem, on
// any platform and whatever the ceiling happens to be.
func TestNewAllocatorWithinRLimit_InvalidBudget(t *testing.T) {
	for _, n := range []int64{0, -1, -4096, math.MinInt64} {
		a, err := NewAllocatorWithinRLimit(n)
		if !errors.Is(err, ErrInvalidBudget) {
			t.Errorf("NewAllocatorWithinRLimit(%d) err = %v, want ErrInvalidBudget", n, err)
		}
		if errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Errorf("NewAllocatorWithinRLimit(%d) reported a bad budget as an rlimit refusal", n)
		}
		if a != nil {
			t.Errorf("NewAllocatorWithinRLimit(%d) returned a non-nil allocator on error", n)
		}
	}
}

// TestNewAllocatorWithinRLimit_AcceptsModestBudget is the CONTROL for the
// refusal tests: an implementation that refused every budget, or that never
// returned a working allocator, would pass those and fail this one.
//
// It runs against whatever ceiling the host actually has, with nothing injected
// — a single page is below any RLIMIT_MEMLOCK a host running this suite can
// have, since the rest of the suite locks pages too.
func TestNewAllocatorWithinRLimit_AcceptsModestBudget(t *testing.T) {
	a, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit(%d): %v", pageSize, err)
	}
	if a.Limit() != pageSize {
		t.Errorf("Limit = %d, want %d — the budget must be the one asked for, not a clamped figure", a.Limit(), pageSize)
	}

	// The allocator has to be usable, not merely non-nil: this is the assertion
	// that fails if the checked constructor ever returns a half-built one.
	material := []byte("checked-allocator-material")
	e, err := a.New(material)
	if err != nil {
		t.Fatalf("New through a checked allocator: %v", err)
	}
	defer e.Destroy()
	if !e.EqualTo([]byte("checked-allocator-material")) {
		t.Error("material did not survive into an enclave from a checked allocator")
	}
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
}

// TestDiscoverLockedMemoryLimit_SelfConsistent asserts the invariants the type's
// documentation promises, against the real host. It cannot assert a particular
// figure — that is the host's business — but it can assert that the figure and
// the flags never disagree, which is what a caller reads.
func TestDiscoverLockedMemoryLimit_SelfConsistent(t *testing.T) {
	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}

	if limit.Source == LimitUnknown {
		t.Error("Source = LimitUnknown after a successful discovery; a successful discovery always names one")
	}
	if limit.Bounded != (limit.Source == LimitRLimit) {
		t.Errorf("Bounded = %v with Source = %v; only LimitRLimit is a ceiling to rely on", limit.Bounded, limit.Source)
	}
	if limit.Bytes < 0 {
		t.Errorf("Bytes = %d, want a non-negative figure", limit.Bytes)
	}
	if !limit.Bounded && limit.Source == LimitUnlimited && limit.Bytes != 0 {
		t.Errorf("Bytes = %d with an unlimited ceiling, want 0 — there is no figure to report", limit.Bytes)
	}

	t.Logf("host locked-memory ceiling: bytes=%d bounded=%v source=%s", limit.Bytes, limit.Bounded, limit.Source)
}
