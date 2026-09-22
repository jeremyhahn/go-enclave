package enclave

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

// freshProcessAllocator makes a test hermetic against the package-level process
// allocator, for the same reason freshProcessSealer exists: installation is
// one-shot, so without a reset the first test to touch it decides the outcome
// of every later one, and -shuffle or -count>1 would turn that into order
// dependence rather than a finding.
func freshProcessAllocator(t *testing.T) {
	t.Helper()
	resetProcessAllocatorForTest()
	t.Cleanup(resetProcessAllocatorForTest)
}

// withDiscovery replaces the lazy default's ceiling discovery for one test.
func withDiscovery(t *testing.T, fn func() (LockedMemoryLimit, error)) {
	t.Helper()
	prev := discoverProcessLimit
	discoverProcessLimit = fn
	t.Cleanup(func() { discoverProcessLimit = prev })
}

func TestSetAllocator_InstalledAllocatorIsWhatLibrariesGet(t *testing.T) {
	freshProcessAllocator(t)

	a, err := NewAllocator(4 * LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator: %v", err)
	}

	got, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	if got != a {
		t.Fatal("ProcessAllocator returned a different allocator from the one installed")
	}
}

func TestSetAllocator_SecondInstallFailsClosed(t *testing.T) {
	freshProcessAllocator(t)

	first, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	second, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(first); err != nil {
		t.Fatalf("first SetAllocator: %v", err)
	}

	if err := SetAllocator(second); !errors.Is(err, ErrAllocatorInstalled) {
		t.Fatalf("second SetAllocator = %v, want ErrAllocatorInstalled", err)
	}
	// Failing closed means the FIRST one is still the answer, not merely that
	// an error was returned.
	got, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	if got != first {
		t.Fatal("a refused install replaced the installed allocator")
	}
}

func TestSetAllocator_NilIsRefusedAndLocksNothing(t *testing.T) {
	freshProcessAllocator(t)

	if err := SetAllocator(nil); !errors.Is(err, ErrNilAllocator) {
		t.Fatalf("SetAllocator(nil) = %v, want ErrNilAllocator", err)
	}

	// The refusal must not have consumed the one-shot: a real install after a
	// lost configuration step still succeeds.
	a, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator after a nil refusal: %v", err)
	}
}

func TestProcessAllocator_LazyDefaultLocksTheConfiguration(t *testing.T) {
	freshProcessAllocator(t)
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{Source: LimitUnlimited}, nil
	})

	def, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	again, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("second ProcessAllocator: %v", err)
	}
	if again != def {
		t.Fatal("the lazy default was installed twice")
	}

	late, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(late); !errors.Is(err, ErrAllocatorInstalled) {
		t.Fatalf("SetAllocator after a lazy default = %v, want ErrAllocatorInstalled", err)
	}
}

func TestProcessAllocator_DiscoveryFailureInstallsNothing(t *testing.T) {
	freshProcessAllocator(t)

	cause := errors.New("getrlimit refused")
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: cause}
	})

	a, err := ProcessAllocator()
	if !errors.Is(err, ErrLimitDiscoveryFailed) || !errors.Is(err, cause) {
		t.Fatalf("ProcessAllocator = %v, want ErrLimitDiscoveryFailed wrapping the cause", err)
	}
	if a != nil {
		t.Fatal("a failed discovery returned an allocator")
	}

	// Nothing was installed, so the binary can still install its own — the
	// failure must not have defaulted to an unbounded allocator behind the
	// error.
	mine, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(mine); err != nil {
		t.Fatalf("SetAllocator after a failed discovery: %v", err)
	}
}

func TestProcessAllocator_RetriesDiscoveryAfterAFailure(t *testing.T) {
	freshProcessAllocator(t)

	calls := 0
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		calls++
		if calls == 1 {
			return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: errors.New("transient")}
		}
		return LockedMemoryLimit{Bytes: 8 * LockedSize(1), Bounded: true, Source: LimitRLimit}, nil
	})

	if _, err := ProcessAllocator(); err == nil {
		t.Fatal("first ProcessAllocator succeeded; the injected failure was not reached")
	}
	a, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("second ProcessAllocator: %v", err)
	}
	if got, want := a.Limit(), 8*LockedSize(1); got != want {
		t.Fatalf("default budget = %d, want the discovered %d", got, want)
	}
}

func TestDefaultProcessAllocator_EveryCeilingShape(t *testing.T) {
	page := LockedSize(1)
	tests := []struct {
		name        string
		limit       LockedMemoryLimit
		wantBudget  int64
		wantSticky  bool
		admitsAPage bool
	}{
		{
			name:        "bounded ceiling becomes the budget, and sticks",
			limit:       LockedMemoryLimit{Bytes: 16 * page, Bounded: true, Source: LimitRLimit},
			wantBudget:  16 * page,
			wantSticky:  true,
			admitsAPage: true,
		},
		{
			name:        "a zero ceiling admits nothing",
			limit:       LockedMemoryLimit{Bytes: 0, Bounded: true, Source: LimitRLimit},
			wantBudget:  0,
			wantSticky:  true,
			admitsAPage: false,
		},
		{
			name:        "RLIM_INFINITY has no figure to admit against",
			limit:       LockedMemoryLimit{Source: LimitUnlimited},
			wantBudget:  math.MaxInt64,
			admitsAPage: true,
		},
		{
			name:        "an unenforced limit is a diagnostic, not a ceiling",
			limit:       LockedMemoryLimit{Bytes: page, Source: LimitNotEnforced},
			wantBudget:  math.MaxInt64,
			admitsAPage: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := defaultProcessAllocator(tt.limit)
			if got := a.Limit(); got != tt.wantBudget {
				t.Fatalf("budget = %d, want %d", got, tt.wantBudget)
			}
			if a.rlimitBound != tt.wantSticky {
				t.Fatalf("rlimitBound = %v, want %v", a.rlimitBound, tt.wantSticky)
			}
			if a.InUse() != 0 {
				t.Fatalf("a fresh default reports %d bytes in use", a.InUse())
			}

			e, err := a.NewSized(1)
			if !tt.admitsAPage {
				if !errors.Is(err, ErrBudgetExhausted) {
					t.Fatalf("NewSized on a zero budget = %v, want ErrBudgetExhausted", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSized: %v", err)
			}
			e.Destroy()
			if a.InUse() != 0 {
				t.Fatalf("Destroy left %d bytes charged to the default", a.InUse())
			}
		})
	}
}

// TestProcessAllocator_DefaultMatchesThisHost checks the real discovery path,
// unseamed, on whatever ceiling the test host has: the default's budget is the
// discovered figure when it binds and unbounded when it does not.
func TestProcessAllocator_DefaultMatchesThisHost(t *testing.T) {
	freshProcessAllocator(t)

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	a, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}

	want := int64(math.MaxInt64)
	if limit.Bounded {
		want = limit.Bytes
	}
	if got := a.Limit(); got != want {
		t.Fatalf("default budget = %d, want %d (discovered %+v)", got, want, limit)
	}
	t.Logf("host ceiling %+v -> default budget %d", limit, a.Limit())
}

// TestProcessAllocator_ConcurrentFirstUseInstallsOne races the lazy default:
// every caller must see the SAME allocator, or two libraries would admit
// against two budgets — the defect the process allocator exists to remove.
func TestProcessAllocator_ConcurrentFirstUseInstallsOne(t *testing.T) {
	freshProcessAllocator(t)
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{Source: LimitUnlimited}, nil
	})

	const callers = 32
	got := make([]*Allocator, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got[i], errs[i] = ProcessAllocator()
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent ProcessAllocator calls did not return; the install lock is stuck")
	}

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if got[i] != got[0] {
			t.Fatalf("caller %d got a different allocator; the default was installed more than once", i)
		}
	}
}

// TestProcessAllocator_OneBudgetAcrossCallers is the property that matters to
// consumers: two independent callers drawing from the process allocator share
// ONE budget, so the second is refused with the typed error before any locked
// memory is requested, and a release returns the room.
func TestProcessAllocator_OneBudgetAcrossCallers(t *testing.T) {
	freshProcessAllocator(t)

	a, err := NewAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator: %v", err)
	}

	libraryA, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	held, err := libraryA.NewSized(32)
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}

	libraryB, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	_, err = libraryB.NewSized(32)
	var be *BudgetError
	if !errors.Is(err, ErrBudgetExhausted) || !errors.As(err, &be) {
		t.Fatalf("second library's admission = %v, want a BudgetError matching ErrBudgetExhausted", err)
	}

	held.Destroy()
	again, err := libraryB.NewSized(32)
	if err != nil {
		t.Fatalf("admission after the first holder released: %v", err)
	}
	again.Destroy()
}
