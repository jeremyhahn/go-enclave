// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers memlock.go's descriptive surface. Its behavior under the real
// RLIMIT_MEMLOCK ceiling is exercised with the budget it bounds, in
// admission_test.go.

// TestLimitSourcesDescribeThemselves: every LimitSource an operator can see
// in a log renders as a description, not a number.
func TestLimitSourcesDescribeThemselves(t *testing.T) {
	for _, src := range []enclave.LimitSource{enclave.LimitUnknown, enclave.LimitRLimit, enclave.LimitUnlimited, enclave.LimitNotEnforced, enclave.LimitUnsupported} {
		if s := src.String(); s == "" || strings.Contains(s, "%") {
			t.Errorf("LimitSource(%d).String() = %q", int(src), s)
		}
	}
}
