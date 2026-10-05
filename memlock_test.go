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
// measured at 1 MiB for this package (the suite fails at 512 KiB, passes at
// 1 MiB, #90), doubled for headroom under the -cpu=8 run. Skip guards used to
// hide a smaller ceiling as a run of quiet skips; it is now a stated
// requirement, checked once here so a short environment fails with one
// actionable message instead of dozens of allocation failures. An unbounded
// limit (RLIMIT_MEMLOCK unlimited) satisfies it; so does CAP_IPC_LOCK, provided
// the HARD limit also reaches the requirement, because the fault-injection
// tests drop the capability and then raise the soft limit to at most the hard.
const testMemlockRequirement = 2 << 20

func TestMain(m *testing.M) {
	lim, err := DiscoverLockedMemoryLimit()
	if err != nil {
		// The requirement cannot be checked, so it is not assumed met.
		fmt.Fprintf(os.Stderr, "cannot read RLIMIT_MEMLOCK to check the suite's %d-byte requirement: %v\n", testMemlockRequirement, err)
		os.Exit(2)
	}
	if lim.Source == LimitNotEnforced {
		// CAP_IPC_LOCK exempts the process from the soft limit — but the
		// fault-injection tests DROP that capability to make RLIMIT_MEMLOCK
		// bind, and then the hard limit is the ceiling they can raise the
		// soft one to. The requirement therefore has a second half that only
		// this case exposes; checking it here keeps the promise of one
		// startup diagnostic instead of a failure deep inside a child test.
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
	if !holds(e, []byte("checked-allocator-material")) {
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

// hostCeiling reports what this host's locked-memory ceiling does to a very
// large budget, so a test can assert the CONSISTENCY of two entry points
// without knowing which verdict the host will produce.
//
// This is the portable half of the split #43 established: the subprocess test in
// memlock_linux_test.go injects a known ceiling and asserts the figures,
// and everything here has to hold on a bounded host, an unlimited one, a
// privileged one holding CAP_IPC_LOCK, and one where discovery does not answer
// at all. Nothing skips — a host that cannot exercise a refusal still has a
// contract, and it is asserted rather than ducked.
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

// TestAllocator_RLimitContract_OptInIsRecorded is the flag's own test: the
// contract has to be a property of the ALLOCATOR, because that is the only
// thing that can outlive the constructor call.
//
// Dropping the flag on the way through NewAllocatorWithinRLimit, or setting it
// for plain NewAllocator, is caught here before any of the behavioral tests
// have to work out which host they are on.
func TestAllocator_RLimitContract_OptInIsRecorded(t *testing.T) {
	plain, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if plain.rlimitBound {
		t.Error("NewAllocator produced an allocator carrying the RLIMIT contract; the unchecked constructor must stay unchecked")
	}
	// An allocator that never opted in must not even LOOK at a ceiling.
	ceiling, err := plain.ceilingForRaise()
	if err != nil {
		t.Errorf("ceilingForRaise on an unbound allocator returned %v, want nil without consulting anything", err)
	}
	if ceiling.Bounded || ceiling.Source != LimitUnknown {
		t.Errorf("ceilingForRaise on an unbound allocator = %+v, want the zero limit", ceiling)
	}

	bound, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		// A host whose ceiling is under one page, or whose discovery failed.
		// Either way there is no allocator to inspect, and the constructor's own
		// contract is #43's to assert.
		t.Logf("NewAllocatorWithinRLimit(%d) refused on this host (%v); the flag assertion below cannot run", pageSize, err)
		return
	}
	if !bound.rlimitBound {
		t.Error("NewAllocatorWithinRLimit produced an allocator NOT carrying the contract; the check would not outlive construction")
	}
}

// TestAllocator_RLimitContract_UnboundIsNeverChecked pins the opt-in half of the
// contract, and it holds on every host precisely because an unbound allocator
// never consults a ceiling: raising to the largest budget an int64 can express
// must succeed even on a host whose real ceiling is a few pages.
//
// This is the test that fails if the check is ever applied to every allocator
// rather than to the ones that asked for it — the alternative #46 rejected,
// which would break callers who deliberately chose the unchecked constructor.
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

// TestAllocator_RLimitContract_EntryPointsAgree is the property #46 was filed
// about, stated so it can be checked on any host: for one budget, a RAISE on a
// bound allocator and the CONSTRUCTOR must reach the same verdict. Two entry
// points to the same allocator disagreeing about whether the kernel ceiling
// binds is the defect, whichever way the host happens to answer.
//
// It is a conditional, and that is why hostCeiling logs which branch ran. On a
// bounded host both refuse and the refusal is compared; on an unlimited or
// privileged host both accept, and the test asserts that agreement instead. The
// figures and the exact boundary are the subprocess test's job, since only that
// one knows what the ceiling is.
func TestAllocator_RLimitContract_EntryPointsAgree(t *testing.T) {
	hostCeiling(t)

	a, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		// Whatever refused the small budget must refuse the large one too; that
		// is the same agreement property, asserted from the other side.
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
		// Accepted: the raise must actually have happened, or "agreement" could
		// be satisfied by a SetLimit that silently did nothing.
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

// TestAllocator_RLimitContract_TransferAgreesWithSetLimit extends the same
// agreement to the third entry point. A transfer is a raise on the receiving
// side, so a destination that opted in must reach the same verdict a SetLimit to
// the same figure would.
//
// Without this, a transfer is a door into exactly the state #46 is about: a
// bound allocator holding a budget above the ceiling, arrived at through a
// sibling instead of a setter.
func TestAllocator_RLimitContract_TransferAgreesWithSetLimit(t *testing.T) {
	host, _ := hostCeiling(t)

	dst, err := NewAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Logf("this host refuses a one-page checked budget (%v); the transfer comparison cannot run", err)
		return
	}
	// A plain source, so the source side contributes no verdict of its own.
	src, err := NewAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// The reference verdict: what a bound allocator would be told for this exact
	// resulting budget.
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

	// CONTROL: a transfer that leaves the destination WITHIN the ceiling must
	// succeed, or "refuses a destination over the ceiling" would be
	// indistinguishable from "refuses every transfer into a bound allocator".
	//
	// The figures are taken from the DISCOVERED ceiling rather than assumed. Two
	// pages looks like a safe constant and is not: a host whose ceiling is a
	// single page would refuse this transfer entirely correctly, and the failure
	// would read as a defect in the contract rather than as the contract
	// working. Codex caught that assumption in review.
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
		// No positive transfer can leave the destination within this ceiling, so
		// there is no accepted control to demonstrate. Assert the contract's
		// other half instead of skipping: the transfer must be refused, and for
		// the ceiling rather than for anything else.
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

// TestAllocator_RLimitContract_ForceLimitOverrides pins the override, and it is
// host-independent in the direction that matters: ForceLimit must accept a
// budget of MaxInt64 on a bound allocator on EVERY host, because it does not
// read a ceiling at all. On a bounded host that is a budget the ceiling would
// have refused, which is the whole point.
//
// The override is deliberate and documented; this is what stops it from being
// quietly removed, and equally what would catch it being extended to SetLimit.
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

	// And now the other half of "only raises are checked": from a budget above
	// any ceiling, a LOWERING that is still above it must succeed. An allocator
	// must always be able to move back towards compliance.
	if err := a.SetLimit(math.MaxInt64 - pageSize); err != nil {
		t.Fatalf("SetLimit lowering from MaxInt64: %v (a lowering was checked against the ceiling)", err)
	}
	if a.Limit() != math.MaxInt64-pageSize {
		t.Errorf("Limit = %d, want %d", a.Limit(), int64(math.MaxInt64)-pageSize)
	}

	// CONTROL: the allocator is still bound, so a RAISE from here is still
	// judged. Without this the two assertions above would also pass on an
	// implementation that simply cleared the flag on the first ForceLimit.
	_, ctorErr := NewAllocatorWithinRLimit(math.MaxInt64)
	setErr := a.SetLimit(math.MaxInt64)
	if !sameVerdictClass(ctorErr, setErr) {
		t.Errorf("after a ForceLimit override the allocator stopped being bound: constructor says %v, SetLimit says %v", ctorErr, setErr)
	}
}

// sameVerdictClass reports whether two outcomes are the same ANSWER, rather than
// the same error value: both accepted, both refused for the ceiling, or both
// unable to read the ceiling. The figures inside a refusal differ legitimately
// between two calls about different budgets, so comparing errors directly would
// fail on hosts where the contract is being honored perfectly.
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

// TestCheckRaise is the sticky contract's decision, tested directly. The
// discovery-failure row is why this exists: getrlimit does not fail on a healthy
// host, and the case that matters — a sandbox installed after construction, so
// an allocator that opted in can no longer read the ceiling it opted into —
// cannot be produced from inside the process. Reached here on any host, with no
// privilege and nothing injected, exactly as #43 reached refuse.
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

// TestAllocator_RLimitContract_FailedDiscoveryStillLowers is the property Codex
// caught this branch getting wrong: the discovery failure was being returned
// before the method knew whether it was looking at a raise, so a host that
// stopped answering getrlimit could STRAND an over-ceiling allocator above the
// ceiling — refusing the shrink that was the only way back to compliance, in the
// name of a contract about raises.
//
// Reached through the unexported entry point, since a failed reading cannot be
// produced from inside a healthy process; the exported method differs only in
// taking the reading itself.
func TestAllocator_RLimitContract_FailedDiscoveryStillLowers(t *testing.T) {
	boom := errors.New("getrlimit refused by policy")

	a, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// A LOWERING must go through: the reading is irrelevant to it.
	if err := a.setLimit(2*pageSize, LockedMemoryLimit{}, boom); err != nil {
		t.Fatalf("a lowering was refused because the ceiling could not be read: %v", err)
	}
	if a.Limit() != 2*pageSize {
		t.Errorf("Limit = %d, want the lowered %d", a.Limit(), 2*pageSize)
	}

	// CONTROL, and it is what stops the assertion above from being satisfied by
	// an implementation that simply ignores cerr: a RAISE with the same failed
	// reading must be refused, and must report the discovery failure rather
	// than a budget verdict.
	err = a.setLimit(4*pageSize, LockedMemoryLimit{}, boom)
	if !errors.Is(err, boom) {
		t.Fatalf("a raise err = %v, want the discovery failure", err)
	}
	if a.Limit() != 2*pageSize {
		t.Errorf("Limit = %d after a refused raise, want the unchanged %d", a.Limit(), 2*pageSize)
	}

	// Setting the same budget is neither, and must not be refused either.
	if err := a.setLimit(2*pageSize, LockedMemoryLimit{}, boom); err != nil {
		t.Errorf("a no-op SetLimit was refused because the ceiling could not be read: %v", err)
	}

	// A transfer IS always a raise on the receiving side, so there the failed
	// reading always bites — the asymmetry is deliberate and is asserted, not
	// assumed.
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
