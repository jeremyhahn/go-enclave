// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build aix || darwin || netbsd || solaris

package enclave

// coreDumpMapFlags is empty: these platforms have no mapping-time exclusion
// that golang.org/x/sys exposes.
const coreDumpMapFlags = 0

// excludeFromCoreDump is a no-op on the unix platforms with no per-mapping
// core-dump exclusion this package can reach: darwin (and ios), NetBSD, AIX,
// Solaris and illumos. golang.org/x/sys v0.48.0 defines no MADV_DONTDUMP,
// MADV_NOCORE, MAP_NOCORE or MAP_CONCEAL for any of them — checked in its
// generated constants, not assumed. Linux, FreeBSD, DragonFly and OpenBSD have
// files of their own.
//
// It reports success rather than failure deliberately: refusing to build any
// enclave at all on such a platform would remove mlock, the guard pages and the
// canary as well, which is strictly worse than losing one of the four. On these
// platforms the process-wide RLIMIT_CORE hardening is all this package can
// apply — and it binds only the dumps the platform's dump mechanism counts
// against that limit — and [CoreDumpsDisabled] reports whether it took.
func excludeFromCoreDump([]byte) error { return nil }
