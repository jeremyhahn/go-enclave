// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "errors"

// This file and its platform siblings are the whole of go-enclave's contact
// with the operating system's virtual-memory interface. Each primitive does
// exactly ONE system call and nothing else — no wipe, no protection change, no
// advice the caller did not ask for — so that every step [mapping] takes is a
// step written in mapping.go, where the ordering and the failure policy live.
//
// That is the reason this layer exists (#86). Through v0.6.2-alpha the
// primitives came from github.com/awnumar/memcall, whose Free made the region
// writable, wiped it and only then unmapped it, and whose Lock issued a
// madvise and discarded the result. Those hidden steps were individually
// harmless and collectively the problem: a release path cannot reason about
// which refusal it is recovering from when one call makes three syscalls, so
// it had to carry a second, "direct" unmap for the case where Free's own
// mprotect was the one refused, and fallback logic choosing between the two.
// With one syscall per primitive there is one unmap, and nothing to choose.
//
// The platform files:
//
//   - osmem_unix.go — mmap, mlock, munlock, mprotect, munmap and setrlimit
//     through golang.org/x/sys/unix, on every GOOS where x/sys provides all of
//     them: aix, darwin (and ios), dragonfly, freebsd, illumos, linux (and
//     android), netbsd, openbsd and solaris.
//   - osmem_windows.go — VirtualAlloc, VirtualLock, VirtualUnlock,
//     VirtualProtect and VirtualFree through golang.org/x/sys/windows.
//   - osmem_unsupported.go — every other GOOS, where the package refuses to
//     compile with an error that names the reason, rather than failing inside
//     a dependency or building something that cannot lock memory.
//   - dontdump_*.go — the per-mapping core-dump exclusion, which differs per
//     kernel and is verified where it can be (see [excludeFromCoreDump]).

// protection is a page-protection state this package asks for. It is a closed
// set of three — the only states a mapping is ever moved between — and each
// platform file translates it to its own constants.
type protection uint8

const (
	// protNoAccess makes pages unreadable and unwritable. The guard pages
	// live in this state for the whole life of a mapping.
	protNoAccess protection = iota + 1
	// protReadOnly makes pages readable only. A frozen data region is here.
	protReadOnly
	// protReadWrite makes pages readable and writable. A fresh mapping is
	// here, and so is every region release is about to wipe.
	protReadWrite
)

// errInvalidProtection reports a [protection] outside the three defined
// values. Nothing in this package constructs one; it exists so the platform
// translation has an answer for the zero value other than a guess, and a
// guess here would be a page left more accessible than asked for.
var errInvalidProtection = errors.New("enclave: invalid page protection")
