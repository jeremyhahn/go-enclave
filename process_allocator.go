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
	"sync"
)

// ErrAllocatorInstalled is returned by [SetAllocator] when the process
// allocator is already set, by an earlier SetAllocator or by the first
// [ProcessAllocator] call installing the default.
var ErrAllocatorInstalled = errors.New("enclave: a process allocator is already installed")

var (
	processAllocatorMu sync.Mutex
	// processAllocatorInstance is set once and cleared only by tests: replacing
	// it would strand live reservations on an allocator nothing admits against.
	processAllocatorInstance *Allocator

	// discoverProcessLimit is a variable so a test can make discovery fail.
	discoverProcessLimit = DiscoverLockedMemoryLimit
)

// SetAllocator installs a as the process allocator, the one [ProcessAllocator]
// returns to every library in the process.
//
// It belongs to the binary: call it from main before anything allocates
// locked memory. Libraries call [ProcessAllocator] instead. It is one-shot and
// returns [ErrAllocatorInstalled] once any process allocator exists, including
// the default installed by an earlier ProcessAllocator call, so even a stray
// early ProcessAllocator call locks the configuration.
//
// Build a with [NewAllocatorWithinRLimit] so a budget above the ceiling fails
// at startup, and leave headroom below the ceiling for locked memory taken
// outside the allocator, such as [SealedEnclave.Open]. It returns
// [ErrNilAllocator] for a nil allocator.
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
// installed or, if none was, a default installed on this first call. Libraries
// allocate through it ([Allocator.New], [Allocator.NewSized],
// [SealedEnclave.OpenWith]) rather than building their own, because separate
// allocators can together exceed the one ceiling they share.
//
// The default's budget is the discovered RLIMIT_MEMLOCK ceiling when it binds
// ([LockedMemoryLimit.Bounded]), kept for life as with
// [NewAllocatorWithinRLimit]; a zero ceiling gives a zero budget. When no
// ceiling binds the budget is math.MaxInt64. It leaves no headroom; sizing is
// the binary's decision through SetAllocator.
//
// If the ceiling cannot be read it returns [ErrLimitDiscoveryFailed] (as a
// [LimitDiscoveryError]), installs nothing, and a later call retries. Once an
// allocator is installed it never fails.
func ProcessAllocator() (*Allocator, error) {
	processAllocatorMu.Lock()
	defer processAllocatorMu.Unlock()

	if processAllocatorInstance == nil {
		limit, err := discoverProcessLimit()
		if err != nil {
			// An unread ceiling is not "no ceiling"; install nothing.
			return nil, err
		}
		processAllocatorInstance = defaultProcessAllocator(limit)
	}
	return processAllocatorInstance, nil
}

// defaultProcessAllocator is split out so every ceiling shape can be tested.
func defaultProcessAllocator(limit LockedMemoryLimit) *Allocator {
	if !limit.Bounded {
		return buildAllocator(math.MaxInt64, false)
	}
	return buildAllocator(limit.Bytes, true)
}
