// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build openbsd

package enclave

import "golang.org/x/sys/unix"

// coreDumpMapFlags is MAP_CONCEAL, OpenBSD's per-mapping core-dump exclusion
// (OpenBSD 6.5 and later; every supported release has it). It is a property of
// the mapping, set by the same mmap that creates it.
const coreDumpMapFlags = unix.MAP_CONCEAL

// excludeFromCoreDump has nothing left to do on OpenBSD: the exclusion is
// MAP_CONCEAL on the mmap in [sysMap], and that call either creates a
// concealed mapping or fails the allocation. There is no separate step that
// could be refused on its own, so there is nothing further to verify — unlike
// Linux, FreeBSD and DragonFly, where the exclusion is a second system call.
func excludeFromCoreDump([]byte) error { return nil }
