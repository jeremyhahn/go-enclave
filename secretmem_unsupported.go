// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux || !(386 || amd64 || arm64 || loong64 || riscv64 || s390x)

package enclave

// Platforms without memfd_secret: the stub of the platform contract; the build tag is the complement of secretmem_linux.go's.

// secretMemorySupported refuses: [NewSecretMemory] returns
// [ErrMemfdSecretUnavailable] here.
func secretMemorySupported() error { return ErrMemfdSecretUnavailable }

// probeSecret refuses, as [NewSecretMemory] does.
func probeSecret() error { return ErrMemfdSecretUnavailable }

// mapSecret refuses, as [NewSecretMemory] does.
func mapSecret([]byte) error { return ErrMemfdSecretUnavailable }
