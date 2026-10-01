// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !(goexperiment.runtimesecret && linux && !android && (amd64 || arm64))

package enclave

// keyScheduleErasure is false: this build does not erase AES temporaries.
// Either it was not built with GOEXPERIMENT=runtimesecret, or it targets a
// platform where runtime/secret does not erase (it calls f directly there).
const keyScheduleErasure = false

// secretDo calls f directly; see secret_erase.go for the erasing build.
func secretDo(f func()) { f() }
