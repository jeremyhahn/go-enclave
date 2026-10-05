// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build aix || darwin || netbsd || solaris

package enclave

// coreDumpMapFlags is empty: x/sys exposes no mapping-time exclusion here.
const coreDumpMapFlags = 0

// excludeFromCoreDump is a no-op where x/sys exposes no per-mapping core-dump
// exclusion (darwin, ios, NetBSD, AIX, Solaris, illumos). It reports success
// so the lock, guard pages and canary still apply; RLIMIT_CORE is the only
// dump control here, and [CoreDumpsDisabled] reports whether it took.
func excludeFromCoreDump([]byte) error { return nil }
