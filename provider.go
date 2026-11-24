// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "context"

// RootKeyBytes is the length of every root key and of every key handed to a
// provider: 32 bytes, an AES-256 key. It is fixed so the destination can be
// allocated in locked memory before the provider is called.
const RootKeyBytes = 32

// KeyProtector protects short key material outside this process for [ModePerOperation]; Unprotect must authenticate and must not retain key or blob.
type KeyProtector interface {
	Protect(ctx context.Context, key []byte) (blob []byte, err error)
	Unprotect(ctx context.Context, blob []byte, key []byte) error
}

// RootUnsealer yields the process root key for [ModeRootKey]; UnsealRoot is called until one call succeeds, and ended contexts are refused without device work.
type RootUnsealer interface {
	UnsealRoot(ctx context.Context, dst []byte) error
}

// HealthReporter is an optional [KeyProtector] capability [Sealed.Openable] consults; Health must not block.
type HealthReporter interface {
	Health() error
}
