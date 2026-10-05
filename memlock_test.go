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
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// testMemlockRequirement is the locked memory the unit suite needs at once:
// 1 MiB measured, doubled for headroom under -cpu=8. TestMain checks it once so
// a short environment fails with one actionable message. CAP_IPC_LOCK satisfies
// it only if the hard limit also reaches it, because the fault-injection tests
// drop the capability and raise the soft limit to at most the hard.
const testMemlockRequirement = 2 << 20

func TestMain(m *testing.M) {
	lim, err := DiscoverLockedMemoryLimit()
	if err != nil {
		// The requirement cannot be checked, so it is not assumed met.
		fmt.Fprintf(os.Stderr, "cannot read RLIMIT_MEMLOCK to check the suite's %d-byte requirement: %v\n", testMemlockRequirement, err)
		os.Exit(2)
	}
	if lim.Source == LimitNotEnforced {
		// The fault-injection tests drop CAP_IPC_LOCK and then raise the soft
		// limit to at most the hard one, so the hard limit must meet the
		// requirement too.
		if hard, ok := testMemlockHardLimit(); !ok {
			fmt.Fprintf(os.Stderr, "go-enclave unit tests hold CAP_IPC_LOCK with a hard RLIMIT_MEMLOCK of %d bytes; the "+
				"fault-injection tests drop the capability and then need at least %d. Raise the hard limit.\n",
				hard, testMemlockRequirement)
			os.Exit(2)
		}
	}
	if lim.Bounded && lim.Bytes < testMemlockRequirement {
		fmt.Fprintf(os.Stderr, "go-enclave unit tests need RLIMIT_MEMLOCK >= %d bytes (soft); this process has %d. "+
			"Raise it (ulimit -l %d, or the CI runner's --ulimit memlock) — the suite allocates real locked memory.\n",
			testMemlockRequirement, lim.Bytes, testMemlockRequirement/1024)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

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
	// Every named source must render differently, so a log line tells
	// "unlimited" from "we did not look".
	seen := make(map[string]LimitSource, len(cases))
	for _, tc := range cases[:4] {
		if prev, dup := seen[tc.want]; dup {
			t.Errorf("LimitSource %d and %d render identically as %q", prev, tc.source, tc.want)
		}
		seen[tc.want] = tc.source
	}
}

// TestRLimitError_Distinguishable pins that the refusal is distinct from the
// three errors it neighbors, in both directions.
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

	// The neighbors must not match this sentinel either.
	for _, other := range []error{ErrInvalidBudget, ErrBudgetExhausted, ErrLockedMemoryUnavailable} {
		if errors.Is(other, ErrBudgetExceedsRLimit) {
			t.Errorf("errors.Is(%v, ErrBudgetExceedsRLimit) = true, want false", other)
		}
	}

	// Both figures must survive into the message.
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

// linuxRlimInfinity and bsdRlimInfinity are the two RLIM_INFINITY values,
// written out so the classifier is tested against both on a Linux runner.
const (
	linuxRlimInfinity = ^uint64(0)        // all bits set
	bsdRlimInfinity   = uint64(1)<<63 - 1 // the largest positive int64
)

// TestClassifyRlimit covers every reading of a raw RLIMIT_MEMLOCK value,
// including ones an unprivileged process cannot make a kernel produce, against
// both platforms' infinity sentinels. Removing the explicit RLIM_INFINITY branch
// alone does not fail the Linux half (the MaxInt64 check also catches
// all-bits-set); it does fail the BSD half.
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
					// The Linux sentinel as an int64 is -1, below every budget.
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
					// Finite but not representable as an int64 budget; also where a
					// negative BSD rlimit lands.
					name:     "past int64 is unlimited",
					cur:      uint64(math.MaxInt64) + 1,
					enforced: true,
					want:     LockedMemoryLimit{Bytes: 0, Bounded: false, Source: LimitUnlimited},
				},
				{
					// Zero is a real ceiling, distinct from the zero Bytes of unlimited.
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
					// CAP_IPC_LOCK: reported, not enforced.
					name:     "unenforced keeps the figure but is not a ceiling",
					cur:      page,
					enforced: false,
					want:     LockedMemoryLimit{Bytes: int64(page), Bounded: false, Source: LimitNotEnforced},
				},
			}
			if inf != uint64(math.MaxInt64) {
				// On the BSDs MaxInt64 is infinity, tested above.
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

// TestClassifyRlimit_WrongSentinelIsCaught pins why the sentinel is an
// argument: the BSD value read with the Linux sentinel is not a ceiling.
func TestClassifyRlimit_WrongSentinelIsCaught(t *testing.T) {
	// A BSD-unlimited value read with the Linux sentinel: a bounded ceiling
	// of nine exabytes.
	if got := classifyRlimit(bsdRlimInfinity, linuxRlimInfinity, true); !got.Bounded || got.Source != LimitRLimit {
		t.Fatalf("expected the mismatched read to produce a bogus bounded ceiling, got %+v", got)
	}
	// And correctly, with its own sentinel.
	if got := classifyRlimit(bsdRlimInfinity, bsdRlimInfinity, true); got.Bounded || got.Source != LimitUnlimited {
		t.Fatalf("classifyRlimit with the BSD sentinel = %+v, want unlimited", got)
	}
}

// TestClassifyRlimit_UnboundedRefusesNothing pins that an unbounded
// classification is never refused by the constructor's decision.
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

// TestLimitDiscoveryError_Distinguishable pins that a failure to read the
// ceiling matches neither a budget verdict nor a locked-memory shortage.
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
	// A nil cause must still render.
	if got := (&LimitDiscoveryError{}).Error(); got != ErrLimitDiscoveryFailed.Error() {
		t.Errorf("Error() with no cause = %q, want %q", got, ErrLimitDiscoveryFailed.Error())
	}
	if (&LimitDiscoveryError{}).Unwrap() != nil {
		t.Error("Unwrap with no cause should be nil")
	}
}

// TestLockedMemoryLimit_Refuse covers the decision NewAllocatorWithinRLimit
// makes against every kind of ceiling, on any host with nothing injected, so
// the refusal path is measured even on a runner holding CAP_IPC_LOCK.
func TestLockedMemoryLimit_Refuse(t *testing.T) {
	bounded := LockedMemoryLimit{Bytes: 65536, Bounded: true, Source: LimitRLimit}

	cases := []struct {
		name    string
		limit   LockedMemoryLimit
		budget  int64
		wantErr bool
	}{
		{"well within a bounded ceiling", bounded, 4096, false},
		// The boundary, from both sides.
		{"exactly at a bounded ceiling", bounded, 65536, false},
		{"one byte above a bounded ceiling", bounded, 65537, true},
		{"far above a bounded ceiling", bounded, 1 << 40, true},
		// A ceiling of zero bytes refuses everything.
		{"any budget against a zero ceiling", LockedMemoryLimit{Bounded: true, Source: LimitRLimit}, 1, true},
		// Unbounded ceilings refuse nothing, not even MaxInt64.
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

// TestNewAllocatorWithinRLimit_InvalidBudget pins that a non-positive budget
// is ErrInvalidBudget, never a host-configuration error.
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

// TestNewAllocatorWithinRLimit_AcceptsModestBudget is the control for the
// refusal tests: a single page passes on any host that can run this suite, and
// the allocator returned is usable.
func TestNewAllocatorWithinRLimit_AcceptsModestBudget(t *testing.T) {
	a, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit(%d): %v", pageSize, err)
	}
	if a.Limit() != pageSize {
		t.Errorf("Limit = %d, want %d — the budget must be the one asked for, not a clamped figure", a.Limit(), pageSize)
	}

	material := []byte("checked-allocator-material")
	e, err := a.New(material)
	if err != nil {
		t.Fatalf("New through a checked allocator: %v", err)
	}
	defer e.Destroy()
	if !holds(e, []byte("checked-allocator-material")) {
		t.Error("material did not survive into an enclave from a checked allocator")
	}
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
}

// TestDiscoverLockedMemoryLimit_SelfConsistent pins that the figure and
// flags of the host's real ceiling never disagree.
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

// hostCeiling reports what this host's ceiling does to a very large budget,
// so a test can assert two entry points agree without knowing the verdict. It
// holds on bounded, unlimited, privileged and discovery-failing hosts; the
// subprocess test in memlock_linux_test.go asserts the figures.
func hostCeiling(t *testing.T) (LockedMemoryLimit, error) {
	t.Helper()
	limit, err := DiscoverLockedMemoryLimit()
	switch {
	case err != nil:
		t.Logf("this host's ceiling could not be read (%v); asserting the discovery-failure contract", err)
	case limit.Bounded:
		t.Logf("this host has a bounded ceiling of %d bytes (%s); the refusal path is exercised here", limit.Bytes, limit.Source)
	default:
		t.Logf("this host has no binding ceiling (%s); nothing is refused here and the tests assert that instead", limit.Source)
	}
	return limit, err
}

// TestAllocator_RLimitContract_OptInIsRecorded pins that the rlimit contract
// is recorded on the allocator by NewAllocatorWithinRLimit and not by
// NewAllocator.
func TestAllocator_RLimitContract_OptInIsRecorded(t *testing.T) {
	plain, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if plain.rlimitBound {
		t.Error("NewAllocator produced an allocator carrying the RLIMIT contract; the unchecked constructor must stay unchecked")
	}
	// An allocator that never opted in must not look at a ceiling.
	ceiling, err := plain.ceilingForRaise()
	if err != nil {
		t.Errorf("ceilingForRaise on an unbound allocator returned %v, want nil without consulting anything", err)
	}
	if ceiling.Bounded || ceiling.Source != LimitUnknown {
		t.Errorf("ceilingForRaise on an unbound allocator = %+v, want the zero limit", ceiling)
	}

	bound, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		// Ceiling under one page, or discovery failed: no allocator to inspect.
		t.Logf("NewAllocatorWithinRLimit(%d) refused on this host (%v); the flag assertion below cannot run", pageSize, err)
		return
	}
	if !bound.rlimitBound {
		t.Error("NewAllocatorWithinRLimit produced an allocator NOT carrying the contract; the check would not outlive construction")
	}
}

// TestAllocator_RLimitContract_UnboundIsNeverChecked pins that an allocator
// from NewAllocator never consults a ceiling: raising to MaxInt64 succeeds on
// any host.
func TestAllocator_RLimitContract_UnboundIsNeverChecked(t *testing.T) {
	hostCeiling(t)

	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := a.SetLimit(math.MaxInt64); err != nil {
		t.Fatalf("SetLimit(MaxInt64) on an unbound allocator: %v (a ceiling was applied to an allocator that never opted in)", err)
	}
	if a.Limit() != math.MaxInt64 {
		t.Errorf("Limit = %d, want %d", a.Limit(), int64(math.MaxInt64))
	}

	// The same for the receiving side of a transfer.
	src, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := src.TransferTo(dst, 4*pageSize); err != nil {
		t.Fatalf("TransferTo into an unbound allocator: %v", err)
	}
	if dst.Limit() != 5*pageSize {
		t.Errorf("dst.Limit = %d, want %d", dst.Limit(), 5*pageSize)
	}
}

// TestAllocator_RLimitContract_EntryPointsAgree pins that, for one budget, a
// raise on a bound allocator and the constructor reach the same verdict. On a
// bounded host both refuse; on an unlimited or privileged host both accept.
func TestAllocator_RLimitContract_EntryPointsAgree(t *testing.T) {
	hostCeiling(t)

	a, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		// Whatever refused the small budget must refuse the large one too.
		if _, big := NewAllocatorWithinRLimit(math.MaxInt64); !sameVerdictClass(err, big) {
			t.Fatalf("constructor refused %d with %v but MaxInt64 with %v; the two disagree", pageSize, err, big)
		}
		t.Logf("this host refuses even a one-page checked budget (%v); the retune comparison cannot run", err)
		return
	}

	_, ctorErr := NewAllocatorWithinRLimit(math.MaxInt64)
	setErr := a.SetLimit(math.MaxInt64)

	if !sameVerdictClass(ctorErr, setErr) {
		t.Fatalf("the constructor said %v for a MaxInt64 budget and SetLimit said %v; "+
			"two entry points to the same allocator must not disagree about the ceiling", ctorErr, setErr)
	}

	if setErr == nil {
		// Accepted: the raise must actually have happened.
		if a.Limit() != math.MaxInt64 {
			t.Errorf("SetLimit reported success but Limit = %d, want %d", a.Limit(), int64(math.MaxInt64))
		}
		return
	}
	// Refused: nothing may have moved.
	if a.Limit() != pageSize {
		t.Errorf("Limit = %d after a refused raise, want the unchanged %d", a.Limit(), pageSize)
	}
	if a.Available() != pageSize {
		t.Errorf("Available = %d after a refused raise, want the unchanged %d", a.Available(), pageSize)
	}
}

// TestAllocator_RLimitContract_TransferAgreesWithSetLimit pins that a
// transfer into a bound allocator reaches the verdict SetLimit would for the
// same resulting budget.
func TestAllocator_RLimitContract_TransferAgreesWithSetLimit(t *testing.T) {
	host, _ := hostCeiling(t)

	dst, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Logf("this host refuses a one-page checked budget (%v); the transfer comparison cannot run", err)
		return
	}
	// A plain source contributes no verdict of its own.
	src, err := NewAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// The reference verdict for this exact resulting budget.
	reference, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit: %v", err)
	}
	want := reference.SetLimit(math.MaxInt64 - pageSize)

	got := src.TransferTo(dst, math.MaxInt64-2*pageSize)
	if !sameVerdictClass(want, got) {
		t.Fatalf("SetLimit said %v and TransferTo said %v for the same resulting budget; "+
			"a transfer is a raise on the receiving side and must be judged the same way", want, got)
	}

	if got != nil {
		// Refused: neither side may have moved.
		if dst.Limit() != pageSize {
			t.Errorf("dst.Limit = %d after a refused transfer, want the unchanged %d", dst.Limit(), pageSize)
		}
		if src.Limit() != math.MaxInt64 {
			t.Errorf("src.Limit = %d after a refused transfer, want the unchanged %d", src.Limit(), int64(math.MaxInt64))
		}
	}

	// Control: a transfer that leaves the destination within the ceiling
	// must succeed. Figures come from the discovered ceiling, since a
	// one-page host would correctly refuse a two-page transfer.
	small, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Logf("this host refuses a one-page checked budget (%v); the control cannot run", err)
		return
	}
	feeder, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	if host.Bounded && host.Bytes < 2*pageSize {
		// No positive transfer fits this ceiling, so assert the refusal and
		// its reason instead.
		t.Logf("this host's ceiling is %d bytes, under two pages; asserting the refusal instead of an accepted control", host.Bytes)
		if err := feeder.TransferTo(small, pageSize); !errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Errorf("TransferTo err = %v, want ErrBudgetExceedsRLimit on a sub-two-page ceiling", err)
		}
		if small.Limit() != pageSize {
			t.Errorf("small.Limit = %d after a refused transfer, want the unchanged %d", small.Limit(), pageSize)
		}
		return
	}

	if err := feeder.TransferTo(small, pageSize); err != nil {
		t.Fatalf("a transfer leaving the destination at two pages was refused: %v", err)
	}
	if small.Limit() != 2*pageSize {
		t.Errorf("small.Limit = %d, want %d", small.Limit(), 2*pageSize)
	}
}

// TestAllocator_RLimitContract_ForceLimitOverrides pins that ForceLimit
// accepts MaxInt64 on a bound allocator on every host, since it reads no
// ceiling, while SetLimit still judges raises.
func TestAllocator_RLimitContract_ForceLimitOverrides(t *testing.T) {
	hostCeiling(t)

	a, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Logf("this host refuses a one-page checked budget (%v); the override cannot be demonstrated", err)
		return
	}

	excess, err := a.ForceLimit(math.MaxInt64)
	if err != nil {
		t.Fatalf("ForceLimit(MaxInt64) on a bound allocator: %v (the override picked up the ceiling check)", err)
	}
	if excess != 0 {
		t.Errorf("excess = %d, want 0: raising cannot over-subscribe anything", excess)
	}
	if a.Limit() != math.MaxInt64 {
		t.Fatalf("Limit = %d, want the forced %d", a.Limit(), int64(math.MaxInt64))
	}

	// A lowering that is still above any ceiling must succeed.
	if err := a.SetLimit(math.MaxInt64 - pageSize); err != nil {
		t.Fatalf("SetLimit lowering from MaxInt64: %v (a lowering was checked against the ceiling)", err)
	}
	if a.Limit() != math.MaxInt64-pageSize {
		t.Errorf("Limit = %d, want %d", a.Limit(), int64(math.MaxInt64)-pageSize)
	}

	// Control: the allocator is still bound, so a raise is still judged.
	_, ctorErr := NewAllocatorWithinRLimit(math.MaxInt64)
	setErr := a.SetLimit(math.MaxInt64)
	if !sameVerdictClass(ctorErr, setErr) {
		t.Errorf("after a ForceLimit override the allocator stopped being bound: constructor says %v, SetLimit says %v", ctorErr, setErr)
	}
}

// sameVerdictClass reports whether two outcomes are the same answer (both
// accepted, both refused for the ceiling, or both discovery failures), since the
// figures inside a refusal legitimately differ.
func sameVerdictClass(a, b error) bool {
	switch {
	case a == nil || b == nil:
		return a == nil && b == nil
	case errors.Is(a, ErrBudgetExceedsRLimit) || errors.Is(b, ErrBudgetExceedsRLimit):
		return errors.Is(a, ErrBudgetExceedsRLimit) && errors.Is(b, ErrBudgetExceedsRLimit)
	case errors.Is(a, ErrLimitDiscoveryFailed) || errors.Is(b, ErrLimitDiscoveryFailed):
		return errors.Is(a, ErrLimitDiscoveryFailed) && errors.Is(b, ErrLimitDiscoveryFailed)
	default:
		return false
	}
}

// TestCheckRaise tests the sticky contract's decision directly, including a
// discovery failure after construction, which cannot be produced in-process.
func TestCheckRaise(t *testing.T) {
	bounded := LockedMemoryLimit{Bytes: 8 * pageSize, Bounded: true, Source: LimitRLimit}
	unbounded := LockedMemoryLimit{Bytes: 8 * pageSize, Source: LimitNotEnforced}
	boom := errors.New("getrlimit refused by policy")

	t.Run("within a bounded ceiling", func(t *testing.T) {
		if err := checkRaise(bounded, nil, 8*pageSize); err != nil {
			t.Errorf("a budget equal to the ceiling was refused: %v", err)
		}
	})
	t.Run("above a bounded ceiling", func(t *testing.T) {
		err := checkRaise(bounded, nil, 8*pageSize+1)
		if !errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Errorf("err = %v, want ErrBudgetExceedsRLimit", err)
		}
	})
	t.Run("no ceiling refuses nothing", func(t *testing.T) {
		if err := checkRaise(unbounded, nil, math.MaxInt64); err != nil {
			t.Errorf("an unbounded ceiling refused a budget: %v", err)
		}
	})
	t.Run("a never-opted-in allocator's zero ceiling refuses nothing", func(t *testing.T) {
		if err := checkRaise(LockedMemoryLimit{}, nil, math.MaxInt64); err != nil {
			t.Errorf("the zero ceiling refused a budget: %v", err)
		}
	})
	t.Run("a failed reading refuses the raise", func(t *testing.T) {
		// Even a budget the ceiling would have allowed: nothing was compared.
		err := checkRaise(LockedMemoryLimit{}, boom, pageSize)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the discovery failure", err)
		}
		if errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Error("a failed reading reported as a budget verdict; nothing was compared")
		}
	})
}

// TestAllocator_RLimitContract_FailedDiscoveryStillLowers pins that a failed
// ceiling read refuses raises but never a lowering, so an over-ceiling
// allocator can always shrink. It uses the unexported entry point because a
// failed read cannot be produced in a healthy process.
func TestAllocator_RLimitContract_FailedDiscoveryStillLowers(t *testing.T) {
	boom := errors.New("getrlimit refused by policy")

	a, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// A lowering must go through: the reading is irrelevant to it.
	if err := a.setLimit(2*pageSize, LockedMemoryLimit{}, boom); err != nil {
		t.Fatalf("a lowering was refused because the ceiling could not be read: %v", err)
	}
	if a.Limit() != 2*pageSize {
		t.Errorf("Limit = %d, want the lowered %d", a.Limit(), 2*pageSize)
	}

	// Control: a raise with the same failed reading is refused, and reports
	// the discovery failure.
	err = a.setLimit(4*pageSize, LockedMemoryLimit{}, boom)
	if !errors.Is(err, boom) {
		t.Fatalf("a raise err = %v, want the discovery failure", err)
	}
	if a.Limit() != 2*pageSize {
		t.Errorf("Limit = %d after a refused raise, want the unchanged %d", a.Limit(), 2*pageSize)
	}

	// Setting the same budget is neither, and must not be refused.
	if err := a.setLimit(2*pageSize, LockedMemoryLimit{}, boom); err != nil {
		t.Errorf("a no-op SetLimit was refused because the ceiling could not be read: %v", err)
	}

	// A transfer is always a raise on the receiving side, so the failed
	// reading always refuses it.
	src, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := src.transferTo(a, pageSize, LockedMemoryLimit{}, boom); !errors.Is(err, boom) {
		t.Errorf("transfer err = %v, want the discovery failure", err)
	}
	if a.Limit() != 2*pageSize || src.Limit() != 8*pageSize {
		t.Errorf("a refused transfer moved something: dst %d, src %d", a.Limit(), src.Limit())
	}
}
