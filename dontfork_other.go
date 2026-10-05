// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

// excludeFromFork is a no-op off Linux: x/sys exposes no minherit, and Windows
// has no fork. A child forked on these platforms inherits a copy-on-write view
// of the enclave pages.
func excludeFromFork([]byte) error { return nil }
