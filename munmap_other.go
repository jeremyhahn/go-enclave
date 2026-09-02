// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

import "errors"

// unmapDirect is unavailable off Linux, where this package does not depend on a
// raw munmap.
//
// It reports failure rather than success so that release keeps the mapping and
// says so. Claiming a release that did not happen would tell the [Allocator]
// those bytes are available while the kernel still holds them, and would drop
// the only handle for retrying — strictly worse than an honest refusal.
func unmapDirect([]byte) error {
	return errors.New("enclave: no direct unmap on this platform")
}
