// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package enclave provides locked, zeroized memory for sensitive material —
// private keys, credentials, passphrases and tokens.
//
// [MemoryEnclave] holds plaintext for its whole lifetime on pages this package
// maps itself: mlock'd so they are kept out of swap, fenced by inaccessible guard
// pages so an overflow faults, preceded by a random canary so an underflow is
// detected on release, excluded from core dumps where the kernel allows, and
// wiped before they go back to the kernel — unless the environment denies the
// mprotect that makes a frozen enclave writable, in which case the pages are
// unmapped unwiped and [ErrReleasedWithoutWipe] says so. Every mapping failure is a returned
// error, and no failure anywhere in the process can touch an enclave it does
// not own.
//
//	e, err := enclave.NewMemoryEnclave(keyPEM) // keyPEM is wiped
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
// Material that is about to be generated should go straight into locked pages
// with [NewMemoryEnclaveSized], filled inside [MemoryEnclave.WithBytes] and then
// made read-only with [MemoryEnclave.Freeze]. [MemoryEnclave.Open] returns a
// slice no lock protects; prefer WithBytes.
//
// # The one panic
//
// [MemoryEnclave.Destroy] returns what went wrong with a release, and panics
// with a value matching [ErrEnclaveCorrupted] only when the canary did not
// verify — after wiping the material and, unless the kernel refuses, releasing
// the pages. It is the
// package's single deliberate exception to returning errors: a process whose
// key memory was written by something that did not own it must not carry on,
// and an error returned to `defer e.Destroy()` would be silently dropped.
// [WipeAll] reports the same condition as a [SweepError] instead.
//
// # Budgets
//
// RLIMIT_MEMLOCK is one ceiling for the whole process. [Allocator] admits
// enclaves against a budget in locked bytes ([LockedSize]) and refuses with
// [ErrBudgetExhausted] before any memory is requested. The binary sizes one
// budget and installs it with [SetAllocator]; libraries allocate through
// [ProcessAllocator] and never install or construct their own.
//
// # Sealing
//
// [SealedEnclave] holds material encrypted at rest with AES-256-GCM and
// decrypts it into a new MemoryEnclave only when [SealedEnclave.Open] is
// called. The keys are protected by a [Sealer] through the [KeyProtector] or
// [RootUnsealer] provider seam; go-enclave ships only the pure-software
// [SoftwareProvider], and TPM, HSM or KMS providers are injected from above with
// [NewSealer] or [SetSealer]. Every call that can reach a provider takes a
// [context.Context], and no mutex of a Sealer's is held across a provider call.
// Plaintext is decrypted only into locked pages, but keys are not: with the
// software default a reader of this process's memory can recover the sealing
// keys, and in every mode each seal and open leaves that value's AES key
// schedule on the heap, unwiped. Read [Mode] before choosing. Sealing uses
// only a FIPS 140-3
// approved algorithm (AES-256-GCM), and its tests pass in strict mode
// (GODEBUG=fips140=only, a best-effort testing aid). That is compatibility
// evidence, not validation: a validated deployment builds with GOFIPS140 set
// to a certified module snapshot and runs as that module's security policy
// requires. GOEXPERIMENT=boringcrypto builds cannot seal, by design.
//
// # Shutdown
//
// [WipeAll] destroys the enclaves the package still holds — including in-process
// sealing keys — waiting for in-progress borrows for as long as its context
// allows; an enclave still borrowed when the context ends is left mapped and
// counted. It belongs to the program that owns the process, never to a library.
//
// # Documentation
//
// The design, invariants, error semantics, platform support and a guide to
// upgrading from v0.6 are in the repository's docs directory:
//
//   - [Locked-memory enclaves]
//   - [Budgets and admission control]
//   - [Sealing and the provider seam]
//   - [Shutdown sweep]
//   - [Provider conformance] (package providertest)
//   - [Upgrading from v0.6]
//
// [Locked-memory enclaves]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/locked-memory/user.md
// [Budgets and admission control]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/locked-memory-budget/user.md
// [Sealing and the provider seam]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/sealing/user.md
// [Shutdown sweep]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/shutdown-sweep/user.md
// [Provider conformance]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/provider-conformance/user.md
// [Upgrading from v0.6]: https://github.com/jeremyhahn/go-enclave/blob/main/docs/README.md
package enclave
