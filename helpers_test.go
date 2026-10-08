// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"testing"
	"time"
)

// swapSeam replaces *seam with value for the rest of the test and returns the
// previous value, so a replacement can delegate to it.
func swapSeam[T any](t testing.TB, seam *T, value T) (prev T) {
	t.Helper()
	prev = *seam
	t.Cleanup(func() { *seam = prev })
	*seam = value
	return prev
}

// mapPagesForTest maps n bytes straight from the platform layer and unmaps
// them when the test ends.
func mapPagesForTest(t testing.TB, n int) []byte {
	t.Helper()
	b, err := sysMap(n)
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() {
		if err := sysUnmap(b); err != nil {
			t.Errorf("sysUnmap: %v", err)
		}
	})
	return b
}

// resetProcessAllocatorForTest clears the process allocator so tests can
// exercise installation and the lazy default.
func resetProcessAllocatorForTest() {
	processAllocatorSlot.reset()
}

// resetProcessSealerForTest clears the process sealer so tests can exercise
// installation, the lazy default and the post-sweep state.
func resetProcessSealerForTest() {
	processSealerSlot.reset()
}

// unpublishedCopy is NewMemoryEnclave without the WipeAll ledger, for a test
// that leaves the pages held on purpose: a ledger entry would leak into every
// WipeAll test. data is wiped.
func unpublishedCopy(data []byte) (*MemoryEnclave, error) {
	defer Wipe(data)
	return unpublished(newFrozenCopy(data))
}

// unpublishedSized is NewMemoryEnclaveSized without the ledger, as above.
func unpublishedSized(n int) (*MemoryEnclave, error) {
	return unpublished(newMapping(n))
}

func unpublished(m *mapping, err error) (*MemoryEnclave, error) {
	if err != nil {
		return nil, err
	}
	return &MemoryEnclave{m: m}, nil
}

// reset clears the slot; only tests may, because replacing a live value
// strands whatever it holds.
func (s *processSingleton[T]) reset() {
	s.mu.Lock()
	s.value = nil
	s.mu.Unlock()
}

// providerOption injects p in mode m, for tests that range over both modes.
func providerOption(p any, m Mode) SealerOption {
	if m == ModePerOperation {
		kp, _ := p.(KeyProtector)
		return WithKeyProtector(kp)
	}
	ru, _ := p.(RootUnsealer)
	return WithRootUnsealer(ru)
}

// endedContexts are the two ways a context ends, constructed already ended:
// a cancellation, and a deadline in the past (expired at construction, so no
// timer is involved).
func endedContexts(t *testing.T) map[string]struct {
	ctx  context.Context
	want error
} {
	t.Helper()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, release := context.WithDeadline(t.Context(), time.Unix(0, 0))
	t.Cleanup(release)
	return map[string]struct {
		ctx  context.Context
		want error
	}{
		"canceled": {canceled, context.Canceled},
		"expired":  {expired, context.DeadlineExceeded},
	}
}
