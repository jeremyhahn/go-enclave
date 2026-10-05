// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package enclave

// discoverLockedMemoryLimit reports [LimitUnsupported] with no bound on the
// platforms that have no locked-memory rlimit to read: Windows (which bounds a
// working-set size instead), AIX, Solaris and illumos. [NewAllocatorWithinRLimit]
// therefore accepts every positive budget here, as [NewAllocator] does; the
// kernel's refusal still arrives as [ErrLockedMemoryUnavailable] on the
// allocation that hits it. The build tag is an explicit exclusion list so a
// platform added to memlock_bsd.go cannot also match here.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	return LockedMemoryLimit{Source: LimitUnsupported}, nil
}
