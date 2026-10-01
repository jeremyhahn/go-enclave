// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package enclave

// This GOOS has no way to lock memory that golang.org/x/sys exposes — js and
// wasip1 have no virtual-memory interface at all, plan9 has no mlock — so
// there is nothing an enclave could be built from. The package therefore
// refuses to COMPILE here rather than compiling into something that fails at
// run time, or into something that hands out unlocked memory and calls it an
// enclave.
//
// The identifier on the last line is deliberately undefined: the compiler's
// error names it, and its name is the message. The build constraint is the
// complement of osmem_unix.go's and osmem_windows.go's, so exactly one of the
// three applies to any GOOS, and a GOOS added to Go in future lands here until
// someone has checked what x/sys provides for it.
//
// The variables declare the platform layer's names and nothing more — no
// bodies, no behavior, and this file can never compile anyway. They are here
// so that the deliberate error is the ONLY one: without them the type checker
// reports every call into the missing layer first, up to its error limit, and
// the line that explains why never makes it onto the screen (measured with
// GOOS=js, GOOS=wasip1 and GOOS=plan9).
var (
	sysMap                       func(n int) ([]byte, error)
	sysLock, sysUnlock, sysUnmap func(b []byte) error
	sysProtect                   func(b []byte, p protection) error
	sysDisableCoreDumps          func() error
	excludeFromCoreDump          func(b []byte) error
)

const _ = go_enclave_does_not_support_this_GOOS
