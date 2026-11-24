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

// NewSecretMemory returns the secretmem backend, whose memory enclaves keep their material in memfd_secret(2) pages admitted against a.
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

// Probe maps, touches and releases one page of memfd_secret memory; a refusal is a [*MemfdSecretError].
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

// allocRegion implements regionTarget: a writable region of n bytes on
// memfd_secret pages, admitted as Import admits one, for [Sealed.OpenIn] to
// decrypt into.
func (s *secretMemory) allocRegion(n int) (*lockedRegion, error) {
	if err := s.allocator.usable(); err != nil {
		return nil, err
	}
	return s.allocator.admit(int64(n), func(locked int64) (*mapping, error) {
		return mapBacked(n, locked, mapSecret)
	})
}

// regionHandle implements regionTarget.
func (s *secretMemory) regionHandle(r *lockedRegion) Handle {
	return &secretRegion{lockedRegion: r, backend: s}
}

// secretRegion is a memory enclave the secretmem backend made: everything but
// Backend is the memory enclave's.
type secretRegion struct {
	*lockedRegion
	backend *secretMemory
}

// Backend returns the secretmem backend that made the handle.
func (e *secretRegion) Backend() Backend { return e.backend }
