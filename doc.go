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
// A memory enclave, from [NewMemory], [NewMemoryCopy] or [NewMemorySized],
// is a [ByteAccess] holding plaintext on pages the package maps itself: locked out
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
// decrypts it into a new memory enclave on [Sealed.Open]. A [Sealer]
// protects the keys through a provider: the built-in [SoftwareProvider], the
// TPM and TrustZone providers in the nested modules backends/tpm and
// backends/armtrustzone, or any other provider implementing [KeyProtector] or
// [RootUnsealer], injected with [NewSealer] or [SetSealer]. Read [Mode] before
// choosing one.
//
// A [Backend] makes and holds the material behind a [Handle]. Locked memory
// ([DefaultBackend]) is always registered; the program registers any other
// with [Register] and finds it by name with [Lookup]. [Detect] probes every
// registered backend that implements [Prober] and returns the highest-ranked
// one this host can run, with locked memory as the floor, together with one
// [ProbeResult] per backend saying why each other was passed over. Nothing
// registers or probes at import.
//
// [NewSecretMemory] returns the linux-secretmem backend: memory enclaves whose
// pages are memfd_secret(2) memory, which the kernel removes from its direct
// map and refuses to ptrace and /proc/<pid>/mem. It ranks above locked memory,
// and [Sealed.OpenIn] decrypts straight into it. Where memfd_secret is not
// available it returns [ErrMemfdSecretUnavailable].
//
// [WipeAll] destroys every enclave the package still holds, including
// in-process sealing keys. It belongs to the program that owns the process,
// never to a library.
//
// The package supports Linux, Android, the BSDs, darwin, iOS, illumos,
// Solaris, AIX and Windows; core-dump exclusion and other protections vary by
// platform, and other GOOS values fail to compile. Tests run on Linux only;
// the other platforms are build-only. Design, invariants, error semantics,
// the platform matrix and upgrade notes are in the [documentation index].
//
// [documentation index]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/README.md
package enclave
