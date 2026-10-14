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
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeProber is a registrable backend with a fixed rank and probe verdict.
type fakeProber struct {
	name   string
	rank   int
	err    error
	probes atomic.Int32
	sawKey atomic.Bool
}

func (p *fakeProber) Name() string { return p.name }
func (p *fakeProber) Rank() int    { return p.rank }

func (p *fakeProber) Probe(ctx context.Context) error {
	p.probes.Add(1)
	if ctx != nil && ctx.Value(probeKey{}) != nil {
		p.sawKey.Store(true)
	}
	return p.err
}

// probeKey marks the context a test hands Detect.
type probeKey struct{}

// errNoDevice is the fakes' own probe failure.
var errNoDevice = errors.New("fake: device absent")

// resultFor returns Detect's result for name, failing the test without one.
func resultFor(t *testing.T, results []ProbeResult, name string) ProbeResult {
	t.Helper()
	for _, r := range results {
		if r.Backend == name {
			return r
		}
	}
	t.Fatalf("no result for %q in %v", name, results)
	return ProbeResult{}
}

func TestDetect_SelectsLockedMemoryWhenNothingElseIsRegistered(t *testing.T) {
	got, results := Detect(context.Background())
	if got != DefaultBackend() {
		t.Fatalf("Detect selected %q, want the default", got.Name())
	}
	r := resultFor(t, results, LockedMemoryBackendName)
	if r.Rank != 0 || r.Err != nil {
		t.Fatalf("default result = %+v, want rank 0, usable", r)
	}
}

func TestDetect_SelectsTheHigherRankedUsableBackend(t *testing.T) {
	low := &fakeProber{name: "test-detect-low", rank: 10}
	high := &fakeProber{name: "test-detect-high", rank: 20}
	registerForTest(t, low)
	registerForTest(t, high)
	got, results := Detect(context.Background())
	if got != high {
		t.Fatalf("Detect selected %q, want %q", got.Name(), high.name)
	}
	if r := resultFor(t, results, low.name); r.Rank != 10 || r.Err != nil {
		t.Fatalf("outranked result = %+v, want rank 10, usable", r)
	}
}

func TestDetect_PassesOverAnUnusableHigherRankedBackend(t *testing.T) {
	usable := &fakeProber{name: "test-detect-usable", rank: 10}
	absent := &fakeProber{name: "test-detect-absent", rank: 50, err: errNoDevice}
	registerForTest(t, usable)
	registerForTest(t, absent)
	got, results := Detect(context.Background())
	if got != usable {
		t.Fatalf("Detect selected %q, want %q", got.Name(), usable.name)
	}
	r := resultFor(t, results, absent.name)
	if r.Rank != 50 || !errors.Is(r.Err, ErrBackendUnavailable) || !errors.Is(r.Err, errNoDevice) {
		t.Fatalf("passed-over result = %+v, want rank 50 and a probe error carrying the cause", r)
	}
	var pe *ProbeError
	if !errors.As(r.Err, &pe) || pe.Backend != absent.name || pe.Cause != errNoDevice {
		t.Fatalf("errors.As(%v, *ProbeError) = %+v", r.Err, pe)
	}
}

func TestDetect_FallsBackToLockedMemoryWhenNoOtherIsUsable(t *testing.T) {
	registerForTest(t, &fakeProber{name: "test-detect-gone", rank: 50, err: errNoDevice})
	registerForTest(t, &fakeProber{name: "test-detect-weaker", rank: -1})
	if got, _ := Detect(context.Background()); got != DefaultBackend() {
		t.Fatalf("Detect selected %q, want the default", got.Name())
	}
}

func TestDetect_ATieGoesToLockedMemory(t *testing.T) {
	// "a-..." sorts before "locked-memory": name order alone would pick it.
	registerForTest(t, &fakeProber{name: "a-test-detect-tie", rank: 0})
	if got, _ := Detect(context.Background()); got != DefaultBackend() {
		t.Fatalf("Detect selected %q, want the default", got.Name())
	}
}

func TestDetect_ATieGoesToTheFirstName(t *testing.T) {
	second := &fakeProber{name: "test-detect-tie-b", rank: 7}
	first := &fakeProber{name: "test-detect-tie-a", rank: 7}
	registerForTest(t, second)
	registerForTest(t, first)
	for range 8 {
		if got, _ := Detect(context.Background()); got != first {
			t.Fatalf("Detect selected %q, want %q", got.Name(), first.name)
		}
	}
}

func TestDetect_NeverSelectsABackendThatIsNoProber(t *testing.T) {
	b := &fakeBackend{name: "test-detect-plain"}
	registerForTest(t, b)
	got, results := Detect(context.Background())
	if got != DefaultBackend() {
		t.Fatalf("Detect selected %q, want the default", got.Name())
	}
	r := resultFor(t, results, b.name)
	var ce *CapabilityError
	if !errors.As(r.Err, &ce) || ce.Backend != b.name || ce.Capability != CapabilityProbe {
		t.Fatalf("result = %+v, want a CapabilityError for %q", r, CapabilityProbe)
	}
}

func TestDetect_ResultsAreInNameOrder(t *testing.T) {
	registerForTest(t, &fakeProber{name: "test-detect-order-b"})
	registerForTest(t, &fakeProber{name: "test-detect-order-a"})
	_, results := Detect(context.Background())
	if len(results) < 3 {
		t.Fatalf("Detect returned %d results, want every registered backend", len(results))
	}
	for i := 1; i < len(results); i++ {
		if strings.Compare(results[i-1].Backend, results[i].Backend) >= 0 {
			t.Fatalf("results out of name order: %q before %q", results[i-1].Backend, results[i].Backend)
		}
	}
}

func TestDetect_ProbesOnlyWhenCalledAndPassesCtx(t *testing.T) {
	p := &fakeProber{name: "test-detect-ctx", rank: 1}
	registerForTest(t, p)
	if n := p.probes.Load(); n != 0 {
		t.Fatalf("Register probed %d times, want 0", n)
	}
	Detect(context.WithValue(context.Background(), probeKey{}, true))
	if n := p.probes.Load(); n != 1 || !p.sawKey.Load() {
		t.Fatalf("Detect probed %d times (ctx passed: %v), want once with the caller's ctx", n, p.sawKey.Load())
	}
	// A nil ctx is in the Prober contract.
	if got, _ := Detect(nil); got != p {
		t.Fatalf("Detect(nil) selected %q, want %q", got.Name(), p.name)
	}
}

func TestDetect_IsSafeForConcurrentUse(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	for i := range n {
		b := &fakeProber{name: "test-detect-concurrent-" + strconv.Itoa(i), rank: i - n}
		t.Cleanup(func() {
			backendsMu.Lock()
			delete(backends, b.name)
			backendsMu.Unlock()
		})
		wg.Go(func() {
			if err := Register(b); err != nil {
				t.Errorf("Register(%q) = %v", b.name, err)
			}
		})
		wg.Go(func() {
			if got, _ := Detect(context.Background()); got != DefaultBackend() {
				t.Errorf("Detect selected %q, want the default", got.Name())
			}
		})
	}
	wg.Wait()
}

func TestProbeError_Text(t *testing.T) {
	bare := &ProbeError{Backend: "tdx"}
	if got, want := bare.Error(), ErrBackendUnavailable.Error()+`: "tdx"`; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if bare.Unwrap() != nil {
		t.Fatal("Unwrap() of a ProbeError without a cause is not nil")
	}
	withCause := &ProbeError{Backend: "tdx", Cause: errNoDevice}
	if got, want := withCause.Error(), ErrBackendUnavailable.Error()+`: "tdx": `+errNoDevice.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestLockedMemory_RanksAndProbesAsTheDefault(t *testing.T) {
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	for _, b := range []Backend{DefaultBackend(), a, (*budgetAllocator)(nil)} {
		p, ok := b.(Prober)
		if !ok {
			t.Fatalf("%T is no Prober", b)
		}
		if p.Rank() != 0 {
			t.Errorf("%T Rank() = %d, want 0", b, p.Rank())
		}
		if err := p.Probe(nil); err != nil { // A nil ctx is in the Prober contract.
			t.Errorf("%T Probe(nil) = %v", b, err)
		}
	}
}
