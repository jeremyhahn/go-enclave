// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package memscan

import (
	"strings"
	"testing"
)

// TestFindRefusesOffLinux pins that, with no sweep available, Find refuses
// rather than report an empty, clean-looking sweep.
func TestFindRefusesOffLinux(t *testing.T) {
	if Supported {
		t.Fatal("Supported is true in a !linux build; memscan_unsupported.go is not the file in effect")
	}
	hits, err := Find([]byte("needle"), 0)
	if err == nil || hits != nil {
		t.Fatalf("Find = %v, %v off Linux; want nil and an error", hits, err)
	}
	if !strings.Contains(err.Error(), UnsupportedReason) {
		t.Errorf("Find's error %q does not give the reason %q", err, UnsupportedReason)
	}
}
