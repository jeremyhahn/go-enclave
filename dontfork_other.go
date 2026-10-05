// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

// excludeFromFork is a no-op off Linux.
//
// FreeBSD and OpenBSD have minherit(2) with INHERIT_ZERO, but
// golang.org/x/sys v0.48.0 exposes no minherit wrapper for either, and OpenBSD
// rejects system calls made outside libc, so there is no supported way to
// issue it from here. darwin's minherit is not exposed either, and Windows has
// no fork. A child forked on these platforms inherits a copy-on-write view of
// the enclave pages.
func excludeFromFork([]byte) error { return nil }
