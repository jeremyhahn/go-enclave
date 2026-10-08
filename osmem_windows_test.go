// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"testing"
)

// TestCoreDumpsDisabled_IsTheSentinelOnWindows pins that Windows returns
// exactly ErrCoreDumpLimitUnsupported.
func TestCoreDumpsDisabled_IsTheSentinelOnWindows(t *testing.T) {
	if err := CoreDumpsDisabled(); !errors.Is(err, ErrCoreDumpLimitUnsupported) {
		t.Fatalf("CoreDumpsDisabled() = %v, want ErrCoreDumpLimitUnsupported", err)
	}
}

// TestSysUnlock_RefusesAnUnlockedRegion pins the VirtualUnlock behavior the
// release path is built around: a second unlock is refused. installStrictUnlock
// models this on Linux.
func TestSysUnlock_RefusesAnUnlockedRegion(t *testing.T) {
	b := mapPagesForTest(t, int(pageSize))
	if err := sysLock(b); err != nil {
		t.Fatalf("sysLock: %v", err)
	}
	if err := sysUnlock(b); err != nil {
		t.Fatalf("first sysUnlock: %v", err)
	}
	if err := sysUnlock(b); err == nil {
		t.Error("a second VirtualUnlock succeeded; the strict-unlock model the release tests use is wrong")
	}
}
