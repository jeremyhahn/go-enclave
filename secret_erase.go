// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build goexperiment.runtimesecret && linux && !android && (amd64 || arm64)

package enclave

import "runtime/secret"

// keyScheduleErasure is true when the build erases the temporaries of every
// AES operation. Android satisfies the linux tag but secret.Do does not erase
// there, so it is excluded.
const keyScheduleErasure = true

// secretDo runs f under runtime/secret.Do: f's registers and stack are erased
// before it returns, and its heap allocations (the AES key schedule) are
// erased once unreachable. See docs/sealing/engineering.md.
func secretDo(f func()) { secret.Do(f) }
