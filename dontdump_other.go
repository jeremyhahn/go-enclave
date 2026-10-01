// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux && !freebsd

package enclave

// excludeFromCoreDump is a no-op on the platforms this package does not wire a
// per-mapping core-dump exclusion for: Linux (MADV_DONTDUMP) and FreeBSD
// (MADV_NOCORE) have their own files. It means "not verified here", not "the
// platform has no such mechanism": darwin, OpenBSD and NetBSD expose no
// per-mapping exclusion through golang.org/x/sys, but that is a statement about
// what is wired, not a survey of every kernel this could build for.
//
// It reports success rather than failure deliberately: refusing to build any
// enclave at all on such a platform would remove mlock, the guard pages and the
// canary as well, which is strictly worse than losing one of the four. On these
// platforms the process-wide RLIMIT_CORE hardening is the whole story, and
// [CoreDumpsDisabled] reports whether it took.
func excludeFromCoreDump([]byte) error { return nil }
