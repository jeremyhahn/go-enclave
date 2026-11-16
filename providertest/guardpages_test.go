// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"fmt"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// TestTheResidueSweepReportsSkippedGuardPages pins that the residue note
// carries the kernel guard pages each sweep skipped, so a run shows how much
// of the process the sweep could not read and why that was excused.
func TestTheResidueSweepReportsSkippedGuardPages(t *testing.T) {
	if !memscan.Supported {
		t.Fatalf("the residue sweep needs Linux: %s", memscan.UnsupportedReason)
	}
	orig := sweepProcess
	t.Cleanup(func() { sweepProcess = orig })
	sweepProcess = func(needle []byte, home uintptr) (memscan.Result, error) {
		r, err := memscan.Sweep(needle, home)
		r.GuardPages = 3
		return r, err
	}

	var notes []string
	cfg := Config{
		New:   func() (any, error) { return software(), nil },
		Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
		Logf:  func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) },
	}
	if err := TestProvider(t.Context(), cfg); err != nil {
		t.Fatalf("TestProvider = %v", err)
	}
	const want = "skipped 3 kernel guard page(s) while the destination was alive and 3 after"
	for _, n := range notes {
		if strings.Contains(n, "residue sweep ran") && strings.Contains(n, want) {
			return
		}
	}
	t.Fatalf("no residue note reports the skipped guard pages (%q): %q", want, notes)
}
