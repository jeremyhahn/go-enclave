// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package enclave provides locked, zeroized memory for sensitive material such
// as private keys, credentials, passphrases and tokens.
//
// [Memory] holds plaintext on pages the package maps itself: locked out
// of swap, fenced by guard pages, checked by a canary, excluded from core dumps
// where the kernel allows, and wiped before release ([ErrReleasedWithoutWipe]
// reports the rare release that could not wipe). Failures are returned as
// errors; nothing in the package panics.
//
//	e, err := enclave.NewMemory(keyPEM) // keyPEM is wiped
//	if err != nil {
//		return err
//	}
//	defer e.Destroy()
//
//	err = e.WithBytes(func(key []byte) error {
//		_, err := tls.X509KeyPair(certPEM, key)
//		return err
//	})
//
// [Allocator] admits enclaves against a budget of locked bytes and refuses
// with [ErrBudgetExhausted] before requesting memory. The binary installs one
// with [SetAllocator]; libraries allocate through [ProcessAllocator].
//
// [Sealed] holds material encrypted at rest with AES-256-GCM and
// decrypts it into a new Memory on [Sealed.Open]. A [Sealer]
// protects the keys through a provider: the built-in [SoftwareProvider], or a
// TPM, HSM or KMS provider implementing [KeyProtector] or [RootUnsealer] and
// injected with [NewSealer] or [SetSealer]. Read [Mode] before choosing one.
//
// [WipeAll] destroys every enclave the package still holds, including
// in-process sealing keys. It belongs to the program that owns the process,
// never to a library.
//
// The package supports Linux, Android, the BSDs, darwin, iOS, illumos,
// Solaris, AIX and Windows; core-dump exclusion and other protections vary by
// platform, and other GOOS values fail to compile. Design, invariants, error semantics, the platform matrix and
// upgrade notes are in the [documentation index].
//
// [documentation index]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/README.md
package enclave
