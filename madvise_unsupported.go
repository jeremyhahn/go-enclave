// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !dragonfly && !freebsd && !linux && !openbsd

package enclave

// This is every platform with no per-mapping dump or fork advice that x/sys
// exposes: darwin (and ios), NetBSD, AIX, Solaris (and illumos), Windows, and
// any GOOS the package does not support. Both hooks report success so the lock,
// guard pages and canary still apply; RLIMIT_CORE is the only dump control on
// the unix ones, and [CoreDumpsDisabled] reports whether it took. A child
// forked on them inherits a copy-on-write view of the enclave pages, and Windows
// has no fork.
//
// Windows excludes nothing from any dump, so dump exposure must be governed by
// host policy. See docs/memory-enclave/engineering.md, Platform contract, for
// why WerRegisterExcludedMemoryBlock is not used.

// coreDumpMapFlags is empty: there is no mapping-time exclusion here.
const coreDumpMapFlags = 0

// excludeFromCoreDump is a no-op; see the platforms above.
func excludeFromCoreDump([]byte) error { return nil }

// excludeFromFork is a no-op; see the platforms above.
func excludeFromFork([]byte) error { return nil }
