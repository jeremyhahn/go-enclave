// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package enclave

// DiscoverLockedMemoryLimit reads the process's current locked-memory ceiling;
// the full contract is in memlock_unix.go. It reports [LimitUnsupported] with
// no bound on the platforms that have no locked-memory rlimit to read: Windows (which bounds a
// working-set size instead), AIX, Solaris and illumos. [NewAllocatorWithinRLimit]
// therefore accepts every positive budget here, as [NewAllocator] does; the
// kernel's refusal still arrives as [ErrLockedMemoryUnavailable] on the
// allocation that hits it. The build tag is the exact complement of
// memlock_unix.go's, so a platform added there cannot also match here.
func DiscoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	return LockedMemoryLimit{Source: LimitUnsupported}, nil
}
