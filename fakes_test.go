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
	"fmt"
	"sync"
	"testing"
)

// The test-only KeyProtector and RootUnsealer fakes of the package, one
// declaration each.

// mapKeyProtector is a KeyProtector whose "device" is a map of locked
// mappings outside the package ledger. Its key store survives a WipeAll, as a
// device-held key does, and a test can mint alias blobs in it.
type mapKeyProtector struct {
	mu         sync.Mutex
	n          int
	keys       map[string]*mapping // a device's key store: locked, outside the ledger
	protects   int
	unprotects int
}

func newMapKeyProtector(t testing.TB) *mapKeyProtector {
	m := &mapKeyProtector{keys: make(map[string]*mapping)}
	t.Cleanup(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		releaseDeviceStore(t, m.keys)
	})
	return m
}

func (m *mapKeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	m.protects++
	blob := fmt.Appendf(nil, "map-key-protector-blob-%d", m.n)
	stored, err := deviceCopy(key)
	if err != nil {
		return nil, err
	}
	m.keys[string(blob)] = stored
	return blob, nil
}

func (m *mapKeyProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unprotects++
	k, ok := m.keys[string(blob)]
	if !ok || len(k.data) != len(key) {
		return ErrSealedAuthentication
	}
	copy(key, k.data)
	return nil
}

// protectCount reports how many Protects ran, so a test can prove WHICH
// provider a seal went through rather than inferring it.
func (m *mapKeyProtector) protectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.protects
}

// unprotectCount reports how many Unprotects ran, so a test can prove that an
// open refused by its budget never reached the key at all.
func (m *mapKeyProtector) unprotectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unprotects
}

// alias registers a second valid blob for the key filed under existing, so a
// test can build an envelope whose blob recovers the right DEK yet differs
// from the blob the value was sealed with.
func (m *mapKeyProtector) alias(existing, alias []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[string(existing)]
	if !ok {
		return false
	}
	m.keys[string(alias)] = k // the same stored key, filed under a second blob
	return true
}

// releaseDeviceStore releases every distinct mapping of a fake device's key
// store. WipeAll cannot reach these and the garbage collector never unmaps
// them; aliases share a mapping, so each is released once.
func releaseDeviceStore(t testing.TB, store map[string]*mapping) {
	t.Helper()
	seen := make(map[*mapping]struct{}, len(store))
	for blob, m := range store {
		delete(store, blob)
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		if err := m.release(); err != nil {
			t.Errorf("releasing a fake device's stored key: %v", err)
		}
	}
}

// deviceCopy files a copy of key in a raw locked mapping outside the package
// ledger, as a device would hold it, so a sweep cannot reach it.
func deviceCopy(key []byte) (*mapping, error) {
	m, err := newMapping(len(key))
	if err != nil {
		return nil, err
	}
	copy(m.data, key)
	return m, nil
}

// fixedRootUnsealer is a RootUnsealer and nothing else: it fills dst with a
// fixed byte. It exists for the capability-mismatch checks and for proving a
// provider-supplied root actually reaches the hierarchy.
type fixedRootUnsealer struct{ fill byte }

func (f *fixedRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	for i := range dst {
		dst[i] = f.fill
	}
	return nil
}

// erroringProvider fails every operation with its own error, standing in for
// a device that is present but unhealthy.
type erroringProvider struct{ err error }

func (e *erroringProvider) Protect(context.Context, []byte) ([]byte, error) { return nil, e.err }

func (e *erroringProvider) Unprotect(context.Context, []byte, []byte) error { return e.err }

func (e *erroringProvider) UnsealRoot(context.Context, []byte) error { return e.err }

// emptyBlobProtector violates the Protect contract by returning an empty
// blob, so the sealer's guard against sealing an unrecoverable value is
// reachable.
type emptyBlobProtector struct{}

func (emptyBlobProtector) Protect(context.Context, []byte) ([]byte, error) { return []byte{}, nil }

func (emptyBlobProtector) Unprotect(context.Context, []byte, []byte) error {
	return ErrSealedAuthentication
}

// manualContext is a context the test ends by hand, with the error of its
// choosing, and that REPORTS when somebody first waits on it.
//
// The second property is what makes the waiter tests exact: the only place a
// Sealer selects on ctx.Done() is the init slot, so a closed waiting channel
// means the caller has reached the slot and is queued on it — not merely that
// its goroutine was started.
type manualContext struct {
	context.Context

	done    chan struct{}
	waiting chan struct{}
	once    sync.Once

	mu  sync.Mutex
	err error
}

func newManualContext() *manualContext {
	return &manualContext{
		Context: context.Background(),
		done:    make(chan struct{}),
		waiting: make(chan struct{}),
	}
}

func (c *manualContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.done
}

func (c *manualContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// end ends the context with err — context.DeadlineExceeded to model a
// deadline passing, without a clock.
func (c *manualContext) end(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	close(c.done)
}

// blockingProvider is a provider whose every operation can be held open by the
// test. It implements both seam interfaces so one type serves both modes.
//
// entered receives once per call that reaches the provider, before it blocks;
// the call then waits for release (or, when honor is set, for its own
// context to end, returning ctx.Err() — the conforming behavior). A nil
// release channel means "do not block".
type blockingProvider struct {
	inner *SoftwareProvider

	entered chan struct{}
	release chan struct{}
	honor   bool

	// beforeReturn runs after the provider has done its work and before it
	// returns success — the seam for "the caller's context ended while the
	// device was working".
	beforeReturn func()

	mu     sync.Mutex
	calls  int
	gotCtx []context.Context
}

func newBlockingProvider() *blockingProvider {
	return &blockingProvider{
		inner:   NewSoftwareProvider(),
		entered: make(chan struct{}, 64),
	}
}

func (p *blockingProvider) arrive(ctx context.Context) error {
	p.mu.Lock()
	p.calls++
	p.gotCtx = append(p.gotCtx, ctx)
	release := p.release
	p.mu.Unlock()

	p.entered <- struct{}{}
	if release == nil {
		return nil
	}
	if p.honor {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-release
	return nil
}

func (p *blockingProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *blockingProvider) finish() {
	if p.beforeReturn != nil {
		p.beforeReturn()
	}
}

func (p *blockingProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := p.arrive(ctx); err != nil {
		return nil, err
	}
	blob, err := p.inner.Protect(context.WithoutCancel(ctx), key)
	p.finish()
	return blob, err
}

func (p *blockingProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.arrive(ctx); err != nil {
		return err
	}
	err := p.inner.Unprotect(context.WithoutCancel(ctx), blob, key)
	p.finish()
	return err
}

func (p *blockingProvider) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := p.arrive(ctx); err != nil {
		return err
	}
	err := p.inner.UnsealRoot(context.WithoutCancel(ctx), dst)
	p.finish()
	return err
}

// errorThenCancelProtector returns a chosen error from Protect or Unprotect,
// a sentinel normally passed through untouched, and ends the caller's
// context before returning. With only openErr set it refuses every Unprotect
// with that error and Protect delegates to the inner provider.
type errorThenCancelProtector struct {
	inner      *SoftwareProvider
	cancel     context.CancelFunc
	protectErr error
	openErr    error
}

func (p *errorThenCancelProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if p.protectErr == nil {
		return p.inner.Protect(ctx, key)
	}
	p.cancel()
	return nil, p.protectErr
}

func (p *errorThenCancelProtector) Unprotect(_ context.Context, _, _ []byte) error {
	p.cancel()
	return p.openErr
}

// parkingProtector parks every Unprotect until the test hands it a verdict on
// the gate it publishes: nil to proceed, or an error to return instead.
type parkingProtector struct {
	inner    *SoftwareProvider
	arrivals chan chan error
}

func (p *parkingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *parkingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	gate := make(chan error)
	p.arrivals <- gate
	if err := <-gate; err != nil {
		return err
	}
	return p.inner.Unprotect(ctx, blob, key)
}

// reusingProtector returns every blob in ONE buffer it owns and overwrites on
// the next Protect — legal under the KeyProtector contract.
type reusingProtector struct {
	inner *SoftwareProvider
	mu    sync.Mutex
	buf   []byte
}

func (r *reusingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	b, err := r.inner.Protect(ctx, key)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf[:0], b...)
	return r.buf, nil
}

func (r *reusingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return r.inner.Unprotect(ctx, blob, key)
}

// flakyRootUnsealer fails a set number of UnsealRoot calls before succeeding,
// so the retry-not-memoize contract on hierarchy initialization is testable:
// a transient provider failure (a busy TPM, a ceiling that lifts) must not be
// latched into a permanent one.
type flakyRootUnsealer struct {
	failures int
	calls    int
	inner    fixedRootUnsealer
}

func (f *flakyRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("transient: device busy")
	}
	return f.inner.UnsealRoot(ctx, dst)
}

// countingRootUnsealer counts UnsealRoot calls and runs an optional hook after
// a successful one, so a test can arrange for the step AFTER the unseal to fail.
type countingRootUnsealer struct {
	calls int
	after func()
	inner fixedRootUnsealer
}

func (c *countingRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	c.calls++
	if err := c.inner.UnsealRoot(ctx, dst); err != nil {
		return err
	}
	if c.after != nil {
		c.after()
	}
	return nil
}

// gatedRootUnsealer fills dst with a fixed byte once the test releases it.
// It allocates nothing, so an armed failNthLock is consumed by the sealer's
// own next mlock — the KEK mint — and not by the provider.
type gatedRootUnsealer struct {
	entered chan struct{}
	release chan struct{}
	after   func() // runs after a successful fill, before returning

	mu    sync.Mutex
	calls int
}

func (u *gatedRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	if u.entered != nil {
		u.entered <- struct{}{}
		<-u.release
	}
	for i := range dst {
		dst[i] = 0x7E
	}
	if u.after != nil {
		u.after()
	}
	return nil
}

func (u *gatedRootUnsealer) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// enclaveBackedProtector is a KeyProtector that keeps its key in this
// process's locked memory and does not implement [HealthReporter], standing in
// for a third-party provider that reports nothing.
type enclaveBackedProtector struct{ key *MemoryEnclave }

func newEnclaveBackedProtector(t *testing.T) *enclaveBackedProtector {
	t.Helper()
	k, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	return &enclaveBackedProtector{key: k}
}

func (p *enclaveBackedProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return sealWithKey(p.key, key, nil)
}

func (p *enclaveBackedProtector) Unprotect(ctx context.Context, blob []byte, key []byte) error {
	return openWithKeyInto(p.key, blob, nil, key)
}

// reportingProtector is enclaveBackedProtector opted in to [HealthReporter].
type reportingProtector struct{ *enclaveBackedProtector }

func (p reportingProtector) Health() error {
	if !p.key.IsAlive() {
		return ErrSealerWiped
	}
	return nil
}

// healthyProtector reports healthy unconditionally, standing in for a provider
// whose key lives outside this process.
type healthyProtector struct{ KeyProtector }

func (healthyProtector) Health() error { return nil }

// wipedReportingUnsealer is a RootUnsealer whose HealthReporter always
// reports wiped and records that it was asked.
type wipedReportingUnsealer struct {
	RootUnsealer
	called *bool
}

func (u wipedReportingUnsealer) Health() error {
	*u.called = true
	return ErrSealerWiped
}
