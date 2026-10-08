// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package enclave

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCoreDumpsDisabled_LowersBothLimitsToZero pins that RLIMIT_CORE is
// lowered to zero soft and hard, so an unprivileged process cannot raise it
// again. Success must be visible in the kernel's rlimit; failure must be the
// named setrlimit refusal.
func TestCoreDumpsDisabled_LowersBothLimitsToZero(t *testing.T) {
	err := CoreDumpsDisabled()
	if err != nil {
		var sys *os.SyscallError
		if !errors.As(err, &sys) || sys.Syscall != "setrlimit" {
			t.Fatalf("CoreDumpsDisabled() = %v, want nil or the refused setrlimit", err)
		}
		return
	}

	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Errorf("RLIMIT_CORE = {cur %d, max %d} with CoreDumpsDisabled() == nil, want {0, 0}", rl.Cur, rl.Max)
	}
}
