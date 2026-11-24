// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package enclave

// DiscoverLockedMemoryLimit reports [LimitUnsupported] on platforms without a locked-memory rlimit.
func DiscoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	return LockedMemoryLimit{Source: LimitUnsupported}, nil
}
