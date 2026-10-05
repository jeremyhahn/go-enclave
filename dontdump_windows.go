// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

// excludeFromCoreDump is a no-op on Windows: no enclave page is excluded from
// any dump, and dump exposure must be governed by host policy. See
// docs/locked-memory/engineering.md, Platform contract, for why
// WerRegisterExcludedMemoryBlock is not used.
func excludeFromCoreDump([]byte) error { return nil }
