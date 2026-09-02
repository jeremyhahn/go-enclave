// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import "golang.org/x/sys/unix"

// unmapDirect returns b to the kernel with a bare munmap, with NO mprotect and
// NO wipe first.
//
// It exists because memcall.Free cannot be the fallback for a denied mprotect:
// Free itself begins with Protect(b, ReadWrite()), which is the very syscall
// that was refused. Calling it there would fail for the same reason and leave
// the material resident, which is the defect this bypass closes.
//
// Skipping the wipe is safe in the way that matters. The pages are anonymous and
// the kernel zeroes an anonymous page before handing it to any process, so the
// material cannot be read by anything afterwards; and they were mlock'd for
// their whole life, so no copy was ever written to swap. What is lost is the
// in-process overwrite, and that is unreachable anyway when mprotect is denied —
// the region is read-only and cannot be written by anyone, including us.
//
// Not for ordinary teardown: the wiping path is the contract, and this is only
// what release falls back to when that path is refused.
func unmapDirect(b []byte) error { return unix.Munmap(b) }
