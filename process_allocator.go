package enclave

import (
	"errors"
	"math"
	"sync"
)

// ErrAllocatorInstalled is returned by [SetAllocator] when the process
// allocator is already set — by an earlier SetAllocator, or by the first
// [ProcessAllocator] call lazily installing the default. Two allocators in one
// process would each admit against its own budget while together exceeding the
// one RLIMIT_MEMLOCK they share, which is the failure a process allocator
// exists to prevent, so installation is one-shot and fails closed. Install
// before anything can allocate.
var ErrAllocatorInstalled = errors.New("enclave: a process allocator is already installed")

// The process allocator: the ONE budget every library in the process admits
// its locked memory against, so that the binary sizes the process's locked
// memory once instead of finding and wiring an allocator per dependency.
var (
	processAllocatorMu sync.Mutex
	// processAllocatorInstance is nil until [SetAllocator] installs one or the
	// first [ProcessAllocator] call lazily installs the default. It is never
	// cleared outside the package's own tests: replacing it under live
	// enclaves would strand their reservations on an allocator nothing admits
	// against any more.
	processAllocatorInstance *Allocator

	// discoverProcessLimit is how the lazy default reads the ceiling. It is a
	// variable only so a test can make discovery FAIL, which no host does on
	// demand; nothing else assigns it. It sits on the one-time installation
	// path, never on admission.
	discoverProcessLimit = DiscoverLockedMemoryLimit
)

// SetAllocator installs a as the process allocator — the one
// [ProcessAllocator] returns to every library in the process.
//
// It belongs to the BINARY. RLIMIT_MEMLOCK is a process-wide resource, so the
// only code that can size a budget against it is the code that owns the
// process: a main function, before it constructs anything that allocates
// locked memory. A library calling SetAllocator is making that decision for
// every other library in its host, exactly as a library calling [WipeAll]
// destroys enclaves it does not own; libraries call [ProcessAllocator] and
// nothing else.
//
// It is ONE-SHOT and fails closed with [ErrAllocatorInstalled] once any
// process allocator exists, including the default that the first
// ProcessAllocator call installs lazily. An allocator that could be replaced
// would leave every live reservation charged to the old one while the new one
// admitted against a fresh budget, and the two would together exceed the
// ceiling both were sized against. So the order is a startup obligation:
// install before anything can allocate. A stray early ProcessAllocator call
// is safe — it gets the default — but it locks the configuration, which is
// stated here because it is surprising to discover.
//
// Building a with [NewAllocatorWithinRLimit] is the usual choice, since a
// budget that exceeds the process's ceiling then fails here at startup rather
// than at the first allocation under load. Leave headroom below that ceiling
// for locked memory taken outside the allocator: the unbudgeted constructors,
// [SealedEnclave.Open], and any other library that locks memory itself.
//
// It returns [ErrNilAllocator] for a nil allocator.
func SetAllocator(a *Allocator) error {
	if a == nil {
		return ErrNilAllocator
	}

	processAllocatorMu.Lock()
	defer processAllocatorMu.Unlock()

	if processAllocatorInstance != nil {
		return ErrAllocatorInstalled
	}
	processAllocatorInstance = a
	return nil
}

// ProcessAllocator returns the process allocator: the one [SetAllocator]
// installed or, when nothing was, a default installed on this first call.
//
// It is how a LIBRARY admits locked memory. Allocate through the returned
// allocator's [Allocator.New] and [Allocator.NewSized] (and pass it to
// [SealedEnclave.OpenWith]) instead of constructing an allocator of your own:
// a per-library allocator stays inside its own budget while the process's
// allocators together exceed the one ceiling they share. A refusal arrives as
// [ErrBudgetExhausted] before any locked memory is requested, which is what
// lets an unauthenticated path fail one request instead of the process.
//
// # The default
//
// The default admits exactly what the kernel would. Its budget is the
// process's discovered RLIMIT_MEMLOCK ceiling when that ceiling binds
// ([LockedMemoryLimit.Bounded]), and like [NewAllocatorWithinRLimit] it keeps
// that ceiling for life, so a later [Allocator.SetLimit] cannot raise it
// past the kernel's figure. A ceiling of zero yields a budget of zero, which
// admits nothing: that is the kernel's answer, not a misconfiguration to be
// corrected. When no ceiling binds — RLIM_INFINITY, CAP_IPC_LOCK, or a
// platform that exposes none — the budget is unbounded (math.MaxInt64),
// because there is no figure to admit against, and [ErrLockedMemoryUnavailable]
// remains the authority on what the process may actually lock.
//
// The default leaves no headroom, deliberately: headroom is a sizing policy,
// and sizing is the binary's decision, made through SetAllocator. What the
// default guarantees is that a library using it never admits past the
// process's ceiling; it does not reserve room for anything else.
//
// It returns an error, and installs nothing, only when the ceiling could not
// be read: [ErrLimitDiscoveryFailed] (as a [LimitDiscoveryError]). A later
// call tries again. Once an allocator is installed it never fails.
func ProcessAllocator() (*Allocator, error) {
	processAllocatorMu.Lock()
	defer processAllocatorMu.Unlock()

	if processAllocatorInstance == nil {
		limit, err := discoverProcessLimit()
		if err != nil {
			// Returned rather than defaulted around: an unread ceiling is not
			// "no ceiling", and installing an unbounded allocator on a host
			// that has one would admit past it for the life of the process.
			return nil, err
		}
		processAllocatorInstance = defaultProcessAllocator(limit)
	}
	return processAllocatorInstance, nil
}

// defaultProcessAllocator derives the lazily installed process allocator from
// a discovered ceiling. It is separate from [ProcessAllocator] so the
// derivation can be tested against every shape of ceiling rather than only the
// one the test host happens to have.
func defaultProcessAllocator(limit LockedMemoryLimit) *Allocator {
	if !limit.Bounded {
		return buildAllocator(math.MaxInt64, false)
	}
	return buildAllocator(limit.Bytes, true)
}

// resetProcessAllocatorForTest clears the process allocator so the package's
// own tests can exercise installation and the lazy default. Production code has
// no path to it on purpose: un-installing the process allocator under live
// enclaves is exactly what [SetAllocator]'s one-shot contract exists to
// prevent.
func resetProcessAllocatorForTest() {
	processAllocatorMu.Lock()
	processAllocatorInstance = nil
	processAllocatorMu.Unlock()
}
