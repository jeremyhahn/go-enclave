// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package enclave

// This GOOS has no memory locking that x/sys exposes (js, wasip1, plan9), so
// the package refuses to compile: the undefined identifier on the last line is
// the error message. The variables declare osmem's names only so that this
// error is the one the compiler reports; the other concerns (madvise, memlock,
// harden) define their own names on every GOOS in their _unsupported files.
var (
	sysMap                       func(n int) ([]byte, error)
	sysLock, sysUnlock, sysUnmap func(b []byte) error
	sysProtect                   func(b []byte, p protection) error
	sysDisableCoreDumps          func() error
)

const _ = go_enclave_does_not_support_this_GOOS
