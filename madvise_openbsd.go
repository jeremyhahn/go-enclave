// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "golang.org/x/sys/unix"

// OpenBSD excludes at map time and has no advice to apply afterwards: the mmap
// in sysMap either creates a concealed mapping or fails the allocation.
// x/sys exposes no minherit, so there is no fork advice either.
const (
	// coreDumpMapFlags is MAP_CONCEAL, OpenBSD's per-mapping core-dump
	// exclusion (6.5 and later).
	coreDumpMapFlags = unix.MAP_CONCEAL
	coreDumpAdvice   = noAdvice
	forkAdvice       = noAdvice
)
