// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "context"

// SecretMemoryBackendName is the name of the secretmem backend
// ([NewSecretMemory]). Nothing registers it: main does, with [Register].
const SecretMemoryBackendName = "linux-secretmem"

// secretMemoryRank is the secretmem backend's [Prober.Rank]: above locked
// memory's 0 and below every hardware backend, each of which reports more.
const secretMemoryRank = 1

// secretMemory is the secretmem backend: memory enclaves whose material
// pages are memfd_secret(2) memory, admitted through one Allocator.
type secretMemory struct {
	allocator *budgetAllocator
}

// NewSecretMemory returns the secretmem backend: an [Importer] and [Prober]
// whose handles are memory enclaves, a [ByteAccess] and [Freezer] each, with
// their material pages in memfd_secret(2) memory, which is locked, out of core
// dumps and the kernel's direct map, and refused to /proc/<pid>/mem, ptrace
// and process_vm_readv. Each handle keeps the memory enclave's guard pages,
// canary, wipe, freeze and release rules, and [WipeAll] sweeps it.
//
// a admits every handle against its budget, so one budget covers this backend
// and locked memory; a nil or zero Allocator is [ErrNilAllocator] or
// [ErrAllocatorNotConstructed]. Construction makes no system call: whether the
// host allows memfd_secret is [Detect]'s question, through Probe, and an
// [Importer.Import] the host refuses returns a [*MemfdSecretError], never a
// memory enclave in its place. On a platform without memfd_secret it returns
// [ErrMemfdSecretUnavailable].
func NewSecretMemory(a Allocator) (Backend, error) {
	if err := secretMemorySupported(); err != nil {
		return nil, err
	}
	b, err := budgetOf(a)
	if err != nil {
		return nil, err
	}
	return &secretMemory{allocator: b}, nil
}

// Name is [SecretMemoryBackendName].
func (s *secretMemory) Name() string { return SecretMemoryBackendName }

// Rank is 1: above locked memory, below every hardware backend.
func (s *secretMemory) Rank() int { return secretMemoryRank }

// Probe checks ctx, then maps one page of memfd_secret memory, touches it and
// releases it, leaving nothing behind. A refusal is a [*MemfdSecretError]
// naming the call and its errno: ENOSYS (disabled or too old a kernel), EPERM
// (filtered), EAGAIN or ENOMEM (no memory or no lock headroom).
func (s *secretMemory) Probe(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return probeSecret()
}

// Import moves material into a new frozen handle in memfd_secret memory and
// wipes the caller's slice on every return path, as the Allocator's Import
// does.
func (s *secretMemory) Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error) {
	defer Wipe(material)
	if err := s.allocator.usable(); err != nil {
		return nil, err
	}
	spec, err := NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	if spec.Algorithm == AlgorithmAES256GCM && len(material) != aes256KeyBytes {
		return nil, ErrInvalidImport
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if len(material) == 0 {
		return nil, ErrEmptyEnclave
	}
	e, err := s.allocator.admit(int64(len(material)), func(locked int64) (*mapping, error) {
		m, err := mapBacked(len(material), locked, mapSecret)
		if err != nil {
			return nil, err
		}
		return m.loadFrozen(material)
	})
	if err != nil {
		// Never a typed nil inside the Handle.
		return nil, err
	}
	return &secretRegion{lockedRegion: e, backend: s}, nil
}

// secretRegion is a memory enclave the secretmem backend made: everything but
// Backend is the memory enclave's.
type secretRegion struct {
	*lockedRegion
	backend *secretMemory
}

// Backend returns the secretmem backend that made the handle.
func (e *secretRegion) Backend() Backend { return e.backend }
