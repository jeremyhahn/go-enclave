// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "golang.org/x/sys/unix"

// coreDumpMapFlags is MAP_CONCEAL, OpenBSD's per-mapping core-dump exclusion
// (6.5 and later), set by the mmap that creates the mapping.
const coreDumpMapFlags = unix.MAP_CONCEAL

// excludeFromCoreDump has nothing left to do on OpenBSD: the mmap in sysMap
// either creates a concealed mapping or fails the allocation.
func excludeFromCoreDump([]byte) error { return nil }
