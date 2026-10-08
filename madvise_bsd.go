// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build dragonfly || freebsd

package enclave

import "golang.org/x/sys/unix"

// The BSDs that expose MAP_NOCORE and MADV_NOCORE are DragonFly and FreeBSD.
// darwin, NetBSD and OpenBSD are not among them; see madvise_unsupported.go and
// madvise_openbsd.go. x/sys exposes no minherit, so there is no fork advice.
const (
	// coreDumpMapFlags excludes the pages from the moment they are mapped,
	// before the madvise runs.
	coreDumpMapFlags = unix.MAP_NOCORE
	// coreDumpAdvice is the verified step: MAP_NOCORE could be ignored
	// silently, so a failing madvise fails the allocation.
	coreDumpAdvice = unix.MADV_NOCORE
	forkAdvice     = noAdvice
)
