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
// AES operation: built with GOEXPERIMENT=runtimesecret, on a platform where
// runtime/secret actually erases (linux/amd64 and linux/arm64 as of Go 1.27). Android satisfies the
// linux tag but secret.Do only calls f there, so it is excluded.
const keyScheduleErasure = true

// secretDo runs f under runtime/secret.Do (#98): the registers and stack f
// used are erased before secretDo returns, and every heap allocation f made —
// the AES key schedule crypto/aes expands from a DEK, KEK or root, the
// largest exposure this package documents — is erased as soon as the garbage
// collector finds it unreachable, instead of lingering until its memory is
// reused.
func secretDo(f func()) { secret.Do(f) }
