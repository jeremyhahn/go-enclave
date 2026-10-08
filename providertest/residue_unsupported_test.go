// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package providertest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// TestResidueSweepReportsItselfNotRunOffLinux pins that off Linux, where there
// is no residue sweep, a provider that retains a copy makes the suite return
// ErrNotMeasured and say so through Logf rather than return nil. The Linux
// counterpart is TestSuiteCatchesAProviderThatRetainsACopy in
// residue_linux_test.go.
func TestResidueSweepReportsItselfNotRunOffLinux(t *testing.T) {
	if memscan.Supported {
		t.Fatal("memscan.Supported is true in a !linux build; memscan_unsupported.go is not the file in effect")
	}
	var log strings.Builder
	cfg := perOp(func() (any, error) { return &retainingProtector{inner: software()}, nil })
	cfg.Logf = func(format string, args ...any) { fmt.Fprintf(&log, format+"\n", args...) }

	err := TestProvider(t.Context(), cfg)
	var nm *NotMeasuredError
	if !errors.Is(err, ErrNotMeasured) || !errors.As(err, &nm) || !strings.Contains(nm.Reason, memscan.UnsupportedReason) {
		t.Fatalf("TestProvider = %v; want only an error matching ErrNotMeasured naming %q", err, memscan.UnsupportedReason)
	}
	var pe *PropertyError
	if errors.As(err, &pe) {
		t.Fatalf("with no sweep available the retaining provider conforms in every measured way: %v", pe)
	}
	cfg.SkipResidueSweep = "no sweep on this platform; accepted for the test"
	if err := TestProvider(t.Context(), cfg); err != nil {
		t.Fatalf("with SkipResidueSweep set the unmeasured sweep is accepted, got %v", err)
	}
	if !strings.Contains(log.String(), "residue sweep not run") ||
		!strings.Contains(log.String(), memscan.UnsupportedReason) {
		t.Errorf("the unmeasured property was not reported; a reader of this green run would not know "+
			"retention by copy went unmeasured. Log was:\n%s", log.String())
	}
}
