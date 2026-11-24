// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !dragonfly && !freebsd && !linux && !openbsd

package enclave

// Platforms with no per-mapping dump or fork advice: the hooks report success; see docs/memory-enclave/engineering.md, Platform contract.

// coreDumpMapFlags is empty: there is no mapping-time exclusion here.
const coreDumpMapFlags = 0

// excludeFromCoreDump is a no-op; see the platforms above.
func excludeFromCoreDump([]byte) error { return nil }

// excludeFromFork is a no-op; see the platforms above.
func excludeFromFork([]byte) error { return nil }
