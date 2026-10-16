// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
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

// swapCoreDumpSeam replaces the RLIMIT_CORE step with step for the rest of the
// test, and restores what CoreDumpsDisabled reports when it ends, so a test
// can run HardenProcess without changing its own process or the next test's.
func swapCoreDumpSeam(t testing.TB, step func() error) {
	t.Helper()
	coreDumpLimit.mu.Lock()
	set, err := coreDumpLimit.set, coreDumpLimit.err
	coreDumpLimit.mu.Unlock()
	t.Cleanup(func() {
		coreDumpLimit.mu.Lock()
		coreDumpLimit.set, coreDumpLimit.err = set, err
		coreDumpLimit.mu.Unlock()
	})
	swapSeam(t, &disableCoreDumps, step)
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

// unpublishedCopy is NewMemory without the WipeAll ledger, for a test
// that leaves the pages held on purpose: a ledger entry would leak into every
// WipeAll test. data is wiped.
func unpublishedCopy(data []byte) (*lockedRegion, error) {
	defer Wipe(data)
	return unpublished(newFrozenCopy(data))
}

// unpublishedSized is NewMemorySized without the ledger, as above.
func unpublishedSized(n int) (*lockedRegion, error) {
	return unpublished(newMapping(n))
}

func unpublished(m *mapping, err error) (*lockedRegion, error) {
	if err != nil {
		return nil, err
	}
	return &lockedRegion{memoryState: &memoryState{m: m}}, nil
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

// fuzzUntouched fills the destination a fuzz target hands to a parser. After a
// refusal every byte is still fuzzUntouched or every byte is zero: a mix is a
// partly written destination.
const fuzzUntouched byte = 0xA5

// fuzzDestination returns n bytes of fuzzUntouched.
func fuzzDestination(n int) []byte {
	return bytes.Repeat([]byte{fuzzUntouched}, n)
}

// refusedCleanly reports whether a refused parser left dst untouched or wiped
// it whole.
func refusedCleanly(dst []byte) bool {
	untouched, wiped := true, true
	for _, b := range dst {
		untouched = untouched && b == fuzzUntouched
		wiped = wiped && b == 0
	}
	return untouched || wiped
}

// fuzzSeedMutations returns the truncated and tampered seeds of a parser fuzz
// target: every proper prefix of b, from empty up, so every frame boundary is
// among them, then b with one bit flipped in each byte in turn.
func fuzzSeedMutations(b []byte) [][]byte {
	out := make([][]byte, 0, 2*len(b))
	for i := range b {
		out = append(out, bytes.Clone(b[:i]))
	}
	for i := range b {
		c := bytes.Clone(b)
		c[i] ^= 1 << (i % 8)
		out = append(out, c)
	}
	return out
}
