// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package enclave

// This GOOS has no memory locking x/sys exposes, so the undefined identifier on the last line fails the build.
var (
	sysMap                       func(n int) ([]byte, error)
	sysLock, sysUnlock, sysUnmap func(b []byte) error
	sysProtect                   func(b []byte, p protection) error
	sysDisableCoreDumps          func() error
	coreDumpsBeforeHardening     error
)

const _ = go_enclave_does_not_support_this_GOOS
