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
	"errors"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// These tests pin #87: every path that can reach a provider takes the
// caller's context and honors it, and no lock of a Sealer's or a
// SealedEnclave's is held across a provider call. Nothing here sleeps or
// races a clock. A provider that "takes a while" is one blocked on a channel
// the test closes, and a deadline that "expires" is a manualContext the test
// expires — so each test decides its interleaving instead of hoping for it.

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

// requireSealCanceled asserts the seal-side shape of an abandoned call.
func requireSealCanceled(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, ErrSealFailed) || !errors.Is(err, want) {
		t.Fatalf("Seal = %v, want an error matching BOTH ErrSealFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) || errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal = %v: an abandoned call must not read as a forgery or a sweep", err)
	}
}

// requireOpenCanceled asserts the open-side shape of an abandoned call.
func requireOpenCanceled(t *testing.T, e *MemoryEnclave, err, want error) {
	t.Helper()
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	if !errors.Is(err, ErrOpenFailed) || !errors.Is(err, want) {
		t.Fatalf("Open = %v, want an error matching BOTH ErrOpenFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Fatalf("Open = %v: a caller that gave up was reported as a forgery", err)
	}
}

// TestSealer_EndedContextIsRefusedBeforeAnyWork pins the entry half of the
// contract, for both modes and both ways a context ends: the call fails with
// the operation's sentinel AND the context's error, the provider is never
// reached, the ownership contract still wipes the caller's material, and the
// sealed value an abandoned Open was aimed at is intact.
func TestSealer_EndedContextIsRefusedBeforeAnyWork(t *testing.T) {
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		for name, ec := range endedContexts(t) {
			t.Run(m.String()+"/"+name, func(t *testing.T) {
				p := newBlockingProvider()
				s, err := NewSealer(WithProvider(p), WithMode(m))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}

				data := append([]byte(nil), sealedMaterial...)
				_, err = s.Seal(ec.ctx, data)
				requireSealCanceled(t, err, ec.want)
				if !bytes.Equal(data, make([]byte, len(data))) {
					t.Error("a refused Seal left the caller's material in place; the ownership contract wipes on every path")
				}
				if got := p.callCount(); got != 0 {
					t.Errorf("the provider was called %d times by a Seal whose context had already ended", got)
				}

				v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
				if err != nil {
					t.Fatalf("control Seal with a live context: %v", err)
				}
				defer v.Destroy()
				before := p.callCount()

				e, err := v.Open(ec.ctx)
				requireOpenCanceled(t, e, err, ec.want)

				a, err := NewAllocator(16 * LockedSize(1))
				if err != nil {
					t.Fatalf("NewAllocator: %v", err)
				}
				e, err = v.OpenWith(ec.ctx, a)
				requireOpenCanceled(t, e, err, ec.want)
				if a.InUse() != 0 {
					t.Errorf("an abandoned OpenWith charged %d bytes to the budget; it must cost nothing", a.InUse())
				}
				if got := p.callCount(); got != before {
					t.Errorf("the provider was called by an Open whose context had already ended")
				}

				// The value is intact: an abandoned open is retryable.
				e, err = v.Open(t.Context())
				if err != nil {
					t.Fatalf("Open with a live context after the refusals: %v", err)
				}
				defer e.Destroy()
				if !e.EqualTo(sealedMaterial) {
					t.Error("the value opened to the wrong material after an abandoned open")
				}
			})
		}
	}
}

// TestSealer_CancellationReachesTheProvider pins propagation: the context a
// provider receives is the caller's, so canceling the caller's context
// releases a provider that honors it — on each of the three provider
// operations — and the call fails as canceled.
func TestSealer_CancellationReachesTheProvider(t *testing.T) {
	type op struct {
		mode Mode
		// prepare returns the call to cancel; it runs with the provider not
		// yet blocking, so a value can be sealed first.
		prepare func(t *testing.T, s *Sealer) func(ctx context.Context) error
		isOpen  bool
	}
	seal := func(t *testing.T, s *Sealer) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			return err
		}
	}
	open := func(t *testing.T, s *Sealer) func(ctx context.Context) error {
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		t.Cleanup(v.Destroy)
		return func(ctx context.Context) error {
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
			}
			return err
		}
	}
	ops := map[string]op{
		"UnsealRoot via Seal": {mode: ModeRootKey, prepare: seal},
		"Protect via Seal":    {mode: ModePerOperation, prepare: seal},
		"Unprotect via Open":  {mode: ModePerOperation, prepare: open, isOpen: true},
	}

	for name, tc := range ops {
		t.Run(name, func(t *testing.T) {
			p := newBlockingProvider()
			p.honor = true
			s, err := NewSealer(WithProvider(p), WithMode(tc.mode))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			call := tc.prepare(t, s)

			// Block from here on; drain what preparation produced.
			p.mu.Lock()
			p.release = make(chan struct{})
			p.mu.Unlock()
			for len(p.entered) > 0 {
				<-p.entered
			}

			ctx, cancel := context.WithCancelCause(t.Context())
			why := errors.New("the request this seal served was abandoned")
			result := make(chan error, 1)
			go func() { result <- call(ctx) }()

			<-p.entered // inside the provider, blocked on the caller's context
			cancel(why)
			err = <-result

			sentinel := ErrSealFailed
			if tc.isOpen {
				sentinel = ErrOpenFailed
			}
			if !errors.Is(err, sentinel) || !errors.Is(err, context.Canceled) {
				t.Fatalf("%s = %v, want an error matching %v and context.Canceled", name, err, sentinel)
			}
			if !errors.Is(err, why) {
				t.Errorf("%s = %v, want the canceler's context.Cause reachable too", name, err)
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("%s = %v: cancellation reported as a forgery", name, err)
			}

			p.mu.Lock()
			got := p.gotCtx[len(p.gotCtx)-1]
			p.mu.Unlock()
			if got.Err() == nil {
				t.Error("the context the provider received did not end when the caller's did; it is not the caller's context")
			}
		})
	}
}

// TestSealer_ContextEndingDuringASuccessfulCallIsHonoured pins the AFTER half:
// a provider that completes its work while the caller's context ends must not
// turn into a success the caller stopped waiting for — and, for the root
// unseal, must not cost the root: the unseal succeeded, so it is published
// and never asked for again.
func TestSealer_ContextEndingDuringASuccessfulCallIsHonoured(t *testing.T) {
	t.Run("Protect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
	})

	t.Run("Unprotect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		e, err := v.Open(ctx)
		requireOpenCanceled(t, e, err, context.Canceled)
	})

	t.Run("UnsealRoot", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
		p.beforeReturn = nil

		if done, herr := s.publishedHierarchy(); !done || herr != nil {
			t.Fatalf("publishedHierarchy = (%t, %v) after a successful unseal whose caller gave up; "+
				"the root it delivered was discarded", done, herr)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("the next Seal: %v", err)
		}
		v.Destroy()
		if got := p.callCount(); got != 1 {
			t.Errorf("UnsealRoot was called %d times, want 1: a successful unseal was repeated because "+
				"the caller that triggered it had gone", got)
		}
	})
}

// TestSealer_BlockedUnsealDoesNotStallOthers is the headline of #87. A
// provider stuck inside UnsealRoot — one that IGNORES its context, the worst
// case — must stall only callers that need the hierarchy it is producing, and
// each of those only until its own context ends:
//
//   - another, initialized Sealer seals and opens normally;
//   - a second Seal on the SAME Sealer, queued for the init slot, returns
//     DeadlineExceeded when its deadline passes, instead of waiting out the
//     provider;
//   - the stuck caller completes once the provider does.
func TestSealer_BlockedUnsealDoesNotStallOthers(t *testing.T) {
	stuck := newBlockingProvider()
	stuck.release = make(chan struct{})
	s, err := NewSealer(WithProvider(stuck), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	other, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	warm, err := other.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("warm-up Seal: %v", err)
	}
	defer warm.Destroy()

	first := make(chan error, 1)
	go func() {
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if v != nil {
			v.Destroy()
		}
		first <- err
	}()
	<-stuck.entered // the first caller is inside UnsealRoot, holding the init slot

	// Another Sealer is untouched.
	v, err := other.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal on a different Sealer while a provider is stuck in UnsealRoot: %v", err)
	}
	v.Destroy()
	e, err := warm.Open(t.Context())
	if err != nil {
		t.Fatalf("Open on a different Sealer while a provider is stuck in UnsealRoot: %v", err)
	}
	e.Destroy()

	// The stuck Sealer's own state stays readable: nothing holds mu.
	if err := s.hierarchyOpenable(); err != nil {
		t.Fatalf("hierarchyOpenable during a stuck unseal = %v", err)
	}

	// A second Seal on the stuck Sealer queues for the slot and leaves when
	// its deadline passes.
	deadline := newManualContext()
	second := make(chan error, 1)
	go func() {
		_, err := s.Seal(deadline, append([]byte(nil), sealedMaterial...))
		second <- err
	}()
	<-deadline.waiting // queued on the init slot
	deadline.end(context.DeadlineExceeded)
	requireSealCanceled(t, <-second, context.DeadlineExceeded)
	if got := stuck.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: the queued caller reached the provider", got)
	}

	close(stuck.release)
	if err := <-first; err != nil {
		t.Fatalf("the stuck caller's Seal after the provider returned: %v", err)
	}
}

// TestSealer_UnsealRootAtMostOnceUnderConcurrentFirstUse pins the #83
// guarantee across the #87 restructuring: many callers arriving at a fresh
// Sealer together cause exactly ONE UnsealRoot, and all of them seal. Every
// caller is held at the init slot (observed, not assumed) before the one
// inside the provider is released, so the interleaving is the contended one.
func TestSealer_UnsealRootAtMostOnceUnderConcurrentFirstUse(t *testing.T) {
	const callers = 8
	p := newBlockingProvider()
	p.release = make(chan struct{})
	s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	ctxs := make([]*manualContext, callers)
	results := make(chan error, callers)
	for i := range ctxs {
		ctxs[i] = newManualContext()
		go func(ctx context.Context) {
			v, err := s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			if v != nil {
				v.Destroy()
			}
			results <- err
		}(ctxs[i])
	}
	for _, c := range ctxs {
		<-c.waiting // every caller has reached the slot
	}
	<-p.entered // and exactly one of them is inside the provider
	close(p.release)

	for range callers {
		if err := <-results; err != nil {
			t.Errorf("concurrent first Seal: %v", err)
		}
	}
	if got := p.callCount(); got != 1 {
		t.Fatalf("UnsealRoot was called %d times by %d concurrent first seals, want exactly 1", got, callers)
	}
}

// TestSealer_CanceledUnsealIsRetriedByTheNextCaller pins the other half of
// at-most-once: a call refused because its context ended is a FAILED call,
// so the next caller in the queue asks again — once — and succeeds.
func TestSealer_CanceledUnsealIsRetriedByTheNextCaller(t *testing.T) {
	p := newBlockingProvider()
	p.honor = true
	p.release = make(chan struct{})
	s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	holderCtx, cancelHolder := context.WithCancel(t.Context())
	holder := make(chan error, 1)
	go func() {
		_, err := s.Seal(holderCtx, append([]byte(nil), sealedMaterial...))
		holder <- err
	}()
	<-p.entered

	waiterCtx := newManualContext()
	waiter := make(chan error, 1)
	go func() {
		v, err := s.Seal(waiterCtx, append([]byte(nil), sealedMaterial...))
		if v != nil {
			v.Destroy()
		}
		waiter <- err
	}()
	<-waiterCtx.waiting

	cancelHolder()
	requireSealCanceled(t, <-holder, context.Canceled)

	<-p.entered // the waiter's retry reached the provider
	close(p.release)
	if err := <-waiter; err != nil {
		t.Fatalf("the queued Seal after the holder's unseal was canceled: %v", err)
	}
	if got := p.callCount(); got != 2 {
		t.Errorf("UnsealRoot was called %d times, want 2: one canceled, one retry", got)
	}
}

// sweepOnceWaiting arms sweepWaitingForTest for one test and returns a
// channel closed the first time a sweep is about to block on a borrow.
func sweepOnceWaiting(t *testing.T) <-chan struct{} {
	t.Helper()
	waiting := make(chan struct{})
	var once sync.Once
	prev := sweepWaitingForTest
	sweepWaitingForTest = func() { once.Do(func() { close(waiting) }) }
	t.Cleanup(func() { sweepWaitingForTest = prev })
	return waiting
}

// sweepAbandoningBorrow runs a sweep that reaches a borrowed enclave, waits
// on it, and then has its context ended by the test — the shutdown whose
// deadline passes while a provider still holds a borrow. It returns what the
// sweep left held, which includes the borrowed enclave.
func sweepAbandoningBorrow(t *testing.T) int {
	t.Helper()
	waiting := sweepOnceWaiting(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		n   int
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := WipeAll(ctx)
		out <- result{n, err}
	}()
	<-waiting
	cancel()
	r := <-out
	if r.err != nil {
		t.Fatalf("WipeAll: %v", r.err)
	}
	return r.n
}

// TestSealer_SweepDuringABlockedUnsealLeavesTheSealerWiped pins the overlap
// rule in initHierarchy against BOTH ways a sweep can meet a root the provider
// is still writing into:
//
//   - the sweep's deadline ends while it waits on the borrow, so the root
//     SURVIVES it — and publishing that root would leave the key that opens
//     everything live after the sweep that exists to remove it;
//   - the sweep waits the borrow out and destroys the root the moment the
//     provider lets go.
//
// Either way the sealer must report ErrSealerWiped, hold no live root, and
// never ask the provider again.
func TestSealer_SweepDuringABlockedUnsealLeavesTheSealerWiped(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sweep func(t *testing.T, release func())
	}{
		{"the sweep gives up on the borrow", func(t *testing.T, release func()) {
			if remaining := sweepAbandoningBorrow(t); remaining == 0 {
				t.Fatal("the sweep reclaimed the root UnsealRoot is writing into; the premise no longer holds")
			}
			release()
		}},
		{"the sweep waits the borrow out", func(t *testing.T, release func()) {
			waiting := sweepOnceWaiting(t)
			done := make(chan int, 1)
			go func() { done <- sweep(t) }()
			<-waiting // the sweep is blocked on the root's borrow
			release()
			<-done
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// gatedRootUnsealer, not blockingProvider: the provider must
			// allocate NOTHING once released. A provider that builds an
			// enclave of its own after release (SoftwareProvider's root) lets
			// that allocation's borrow wake the waiting sweep, which can then
			// destroy the provider's enclave before the provider borrows it —
			// an unseal failure decided by the scheduler, not by the sealer.
			p := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
			s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}

			first := make(chan error, 1)
			go func() {
				_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
				first <- err
			}()
			<-p.entered

			tc.sweep(t, func() { close(p.release) })

			if err := <-first; !errors.Is(err, ErrSealerWiped) {
				t.Fatalf("Seal whose unseal overlapped a sweep = %v, want ErrSealerWiped", err)
			}
			if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
				t.Error("the root delivered across the sweep is still alive; the sweep's purpose was defeated")
			}
			if done, _ := s.publishedHierarchy(); done {
				t.Error("a hierarchy was published from a root that overlapped a sweep")
			}
			if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
				t.Errorf("Seal after the overlapped init = %v, want ErrSealerWiped", err)
			}
			if got := p.callCount(); got != 1 {
				t.Errorf("UnsealRoot was called %d times, want 1: the sealer re-unsealed after a sweep", got)
			}
		})
	}
}

// TestSealer_InitSlotRefusesAnEndedContext drives initHierarchy directly with
// an ended context. select picks at random between a free slot and a closed
// Done channel, so both arms are taken across the iterations; neither may
// reach the provider, and both must report the cancellation.
func TestSealer_InitSlotRefusesAnEndedContext(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for range 64 {
		requireSealCanceled(t, s.initHierarchy(ctx), context.Canceled)
	}
	if got := p.callCount(); got != 0 {
		t.Errorf("UnsealRoot was called %d times for an ended context", got)
	}
}

// TestSealedEnclave_DestroyDoesNotWaitForABlockedOpen pins the SealedEnclave
// half of "no lock across a provider": Destroy has no context, so it must not
// wait for an Open stuck in Unprotect. The in-flight open completes against
// the envelope it pinned, the ciphertext is wiped by the last open out, and
// opens after the Destroy are refused.
func TestSealedEnclave_DestroyDoesNotWaitForABlockedOpen(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	<-p.entered // the Protect
	sealed, blob := v.sealed, v.blob

	p.mu.Lock()
	p.release = make(chan struct{})
	p.mu.Unlock()

	opened := make(chan *MemoryEnclave, 1)
	openErr := make(chan error, 1)
	go func() {
		e, err := v.Open(t.Context())
		opened <- e
		openErr <- err
	}()
	<-p.entered // the open is inside Unprotect

	v.Destroy() // must return while the open is still blocked
	if v.IsAlive() {
		t.Error("IsAlive after Destroy")
	}
	if _, err := v.Open(t.Context()); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if bytes.Equal(sealed, make([]byte, len(sealed))) {
		t.Fatal("Destroy wiped the ciphertext under an open still reading it")
	}

	close(p.release)
	e := <-opened
	if err := <-openErr; err != nil {
		t.Fatalf("the open in flight across Destroy: %v", err)
	}
	defer e.Destroy()
	if !e.EqualTo(sealedMaterial) {
		t.Error("the open in flight across Destroy recovered the wrong material")
	}
	if !bytes.Equal(sealed, make([]byte, len(sealed))) || !bytes.Equal(blob, make([]byte, len(blob))) {
		t.Error("the last open out did not wipe the envelope Destroy left to it")
	}
}

// TestSoftwareProvider_RefusesAnEndedContext pins the shipped provider's half
// of the contract directly: every method refuses an ended context with its
// error, a refused first call generates no root, and a refused Protect is not
// charged to the message budget.
func TestSoftwareProvider_RefusesAnEndedContext(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			p := NewSoftwareProvider()
			key := bytes.Repeat([]byte{0x3C}, RootKeyBytes)

			if _, err := p.Protect(ec.ctx, key); !errors.Is(err, ec.want) {
				t.Errorf("Protect = %v, want %v", err, ec.want)
			}
			dst := make([]byte, RootKeyBytes)
			if err := p.UnsealRoot(ec.ctx, dst); !errors.Is(err, ec.want) {
				t.Errorf("UnsealRoot = %v, want %v", err, ec.want)
			}
			p.mu.Lock()
			root, protects := p.root, p.protects
			p.mu.Unlock()
			if root != nil {
				t.Error("a refused call generated the provider root")
			}
			if protects != 0 {
				t.Errorf("a refused Protect was charged to the budget (%d)", protects)
			}

			blob, err := p.Protect(t.Context(), key)
			if err != nil {
				t.Fatalf("Protect: %v", err)
			}
			got := make([]byte, RootKeyBytes)
			if err := p.Unprotect(ec.ctx, blob, got); !errors.Is(err, ec.want) {
				t.Errorf("Unprotect = %v, want %v", err, ec.want)
			}
			if !bytes.Equal(got, make([]byte, RootKeyBytes)) {
				t.Error("a refused Unprotect wrote into the destination")
			}
			// The size contract is a programming mistake and is reported as
			// such whatever the context says.
			if err := p.UnsealRoot(ec.ctx, make([]byte, 1)); !errors.Is(err, ErrInvalidSize) {
				t.Errorf("UnsealRoot(short dst, ended ctx) = %v, want ErrInvalidSize", err)
			}
		})
	}
}

// TestContextFailure pins the shape of the cancellation error as a pure
// function: nil while live; otherwise the operation's sentinel AND the
// context's error, with a provider's own wrapping of that error preferred to
// the bare one, an unrelated provider error kept alongside, and a distinct
// cancellation cause kept too.
func TestContextFailure(t *testing.T) {
	if err := contextFailure(t.Context(), ErrSealFailed, nil); err != nil {
		t.Fatalf("contextFailure(live) = %v, want nil", err)
	}

	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("shutting down")
	cancel(why)

	wrapped := &providerWrapError{err: context.Canceled}
	unrelated := errors.New("tpm: resource manager busy")
	for name, tc := range map[string]struct {
		cause error
		want  []error
	}{
		"no provider error": {nil, []error{ErrOpenFailed, context.Canceled, why}},
		"provider wrapped":  {wrapped, []error{ErrOpenFailed, context.Canceled, why}},
		"provider other":    {unrelated, []error{ErrOpenFailed, context.Canceled, why, unrelated}},
	} {
		err := contextFailure(ctx, ErrOpenFailed, tc.cause)
		for _, w := range tc.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: contextFailure = %v, does not match %v", name, err, w)
			}
		}
		var pw *providerWrapError
		if tc.cause == wrapped && !errors.As(err, &pw) {
			t.Errorf("%s: the provider's own wrapping was dropped: %v", name, err)
		}
	}

	// A plain cancellation has no distinct cause to add.
	plain, cancelPlain := context.WithCancel(t.Context())
	cancelPlain()
	if got := contextFailure(plain, ErrSealFailed, nil).Error(); got != errors.Join(ErrSealFailed, context.Canceled).Error() {
		t.Errorf("contextFailure(plain cancel) = %q, want only the sentinel and context.Canceled", got)
	}
}

// providerWrapError is a provider's own wrapping of a context error.
type providerWrapError struct{ err error }

func (e *providerWrapError) Error() string { return "device: call aborted: " + e.err.Error() }
func (e *providerWrapError) Unwrap() error { return e.err }

// TestProviderOpenFailure pins the open-side shaping: a verdict on the blob
// and this package's own sentinels pass through untouched, and an
// infrastructure failure is joined under ErrOpenFailed — reachable, and never
// readable as a forgery.
func TestProviderOpenFailure(t *testing.T) {
	if providerOpenFailure(nil) != nil {
		t.Error("providerOpenFailure(nil) is not nil")
	}
	for _, sentinel := range []error{ErrSealedAuthentication, ErrSealerWiped, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed} {
		if got := providerOpenFailure(sentinel); got != sentinel {
			t.Errorf("providerOpenFailure(%v) = %v, want it untouched", sentinel, got)
		}
	}
	down := errors.New("hsm: no session available")
	got := providerOpenFailure(down)
	if !errors.Is(got, ErrOpenFailed) || !errors.Is(got, down) || errors.Is(got, ErrSealedAuthentication) {
		t.Errorf("providerOpenFailure(infrastructure) = %v, want ErrOpenFailed joined with the cause, and not ErrSealedAuthentication", got)
	}
}

// TestSealer_InitAfterASweepOfThePublishedHierarchyIsWiped pins the slot
// holder's re-read of the published state. protectRootKey normally sees a
// swept hierarchy itself, but a sweep can land between its read and the slot
// — and the slot holder must then refuse, not treat the dead hierarchy as
// absent and unseal again.
func TestSealer_InitAfterASweepOfThePublishedHierarchyIsWiped(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithProvider(p), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	sweep(t)

	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("initHierarchy after the published hierarchy was swept = %v, want ErrSealerWiped", err)
	}
	if got := p.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: a swept hierarchy was rebuilt", got)
	}
}

// gatedRootUnsealer fills dst with a fixed byte once the test releases it.
// It allocates nothing, so an armed failNextLock is consumed by the sealer's
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

// TestSealer_SweepOverlapIsCheckedBeforeTheMint is the regression for the
// first #87 review finding. A sweep completes while UnsealRoot holds the
// root's borrow, so the root survives it; the unseal then succeeds and the KEK
// mint FAILS. The overlap must be caught before the mint — not only at
// publication, which a failed mint never reaches — so the root is destroyed,
// the sealer is wiped, and continued allocation failures cannot keep it
// resident behind an allocation error.
func TestSealer_SweepOverlapIsCheckedBeforeTheMint(t *testing.T) {
	u := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s, err := NewSealer(WithProvider(u), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		first <- err
	}()
	<-u.entered
	if remaining := sweepAbandoningBorrow(t); remaining == 0 {
		t.Fatal("the sweep reclaimed the borrowed root; the premise of this test no longer holds")
	}
	failNextLock(t) // the KEK mint is refused, if it is ever attempted
	close(u.release)

	if err := <-first; !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal whose unseal overlapped a sweep, with the mint refused = %v, want ErrSealerWiped", err)
	}
	if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
		t.Fatal("the root delivered across the sweep is still alive")
	}
	// Later attempts while the mint would still be refused. They are driven
	// at the hierarchy directly: a whole Seal allocates its DEK first, and
	// that refusal would answer before the hierarchy was ever consulted.
	for range 2 {
		failNextLock(t)
		if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("a later initialization under continued allocation failure = %v, want ErrSealerWiped", err)
		}
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestSealer_SweepDuringAFailedMintIsWiped covers the mint's own exit: a sweep
// runs while the first KEK is being allocated — inside the refused mlock — and
// the mint fails. The attempt reports the sweep, not the allocation error.
func TestSealer_SweepDuringAFailedMintIsWiped(t *testing.T) {
	u := &gatedRootUnsealer{}
	u.after = func() {
		prev := lockMemory
		t.Cleanup(func() { lockMemory = prev })
		lockMemory = func([]byte) error {
			lockMemory = prev
			sweep(t)
			return errors.New("mlock: cannot allocate memory")
		}
	}
	s, err := NewSealer(WithProvider(u), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal whose mint failed across a sweep = %v, want ErrSealerWiped", err)
	}
	if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
		t.Error("the root survived a sweep that overlapped its mint")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestSealer_CancellationShapesAFailedMint is the regression for the third
// review finding: the caller's context ends during a SUCCESSFUL unseal and
// the mint after it fails. The root is kept (at-most-once), and the error
// carries the cancellation AND the mint failure, under ErrSealFailed.
func TestSealer_CancellationShapesAFailedMint(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("request abandoned")
	u := &gatedRootUnsealer{}
	u.after = func() {
		failNextLock(t)
		cancel(why)
	}
	s, err := NewSealer(WithProvider(u), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
	for _, want := range []error{ErrSealFailed, context.Canceled, why, ErrLockedMemoryUnavailable} {
		if !errors.Is(err, want) {
			t.Errorf("Seal = %v, does not match %v", err, want)
		}
	}
	if s.pendingRoot == nil || !s.pendingRoot.IsAlive() {
		t.Fatal("the delivered root was not retained across the failed mint")
	}

	u.after = nil
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal after the failed mint: %v", err)
	}
	v.Destroy()
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestNewSealed_EndedContextInstallsNothing is the regression for the second
// review finding: NewSealed with an ended context must not lazily install the
// software default on its way to refusing, because installation is one-shot
// and the deployment's own SetSealer would then fail with ErrSealerInstalled.
func TestNewSealed_EndedContextInstallsNothing(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			freshProcessSealer(t)

			data := append([]byte(nil), sealedMaterial...)
			_, err := NewSealed(ec.ctx, data)
			requireSealCanceled(t, err, ec.want)
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("a refused NewSealed left the caller's material in place")
			}

			own, err := NewSealer(WithProvider(newMapKeyProtector()), WithMode(ModePerOperation))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			if err := SetSealer(own); err != nil {
				t.Fatalf("SetSealer after a refused NewSealed = %v: the refusal installed the default", err)
			}
		})
	}
}

// authThenCancelProtector refuses every Unprotect as a forgery, and ends the
// caller's context before returning — the race the fifth review finding named.
type authThenCancelProtector struct {
	inner  *SoftwareProvider
	cancel context.CancelFunc
}

func (p *authThenCancelProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *authThenCancelProtector) Unprotect(context.Context, []byte, []byte) error {
	p.cancel()
	return ErrSealedAuthentication
}

// TestSealer_AuthenticationVerdictSurvivesCancellation pins the documented
// precedence: an authentication failure the PROVIDER reported is a security
// signal and stays visible even when the caller's context ended before the
// post-call check — the error matches ErrSealedAuthentication AND the
// cancellation. Only a refusal the provider attributed to the context alone is
// kept clear of ErrSealedAuthentication.
func TestSealer_AuthenticationVerdictSurvivesCancellation(t *testing.T) {
	p := &authThenCancelProtector{inner: NewSoftwareProvider()}
	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	ctx, cancel := context.WithCancel(t.Context())
	p.cancel = cancel
	e, err := v.Open(ctx)
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	for _, want := range []error{ErrSealedAuthentication, ErrOpenFailed, context.Canceled} {
		if !errors.Is(err, want) {
			t.Errorf("Open = %v, does not match %v", err, want)
		}
	}
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

// TestSealedEnclave_OnlyTheLastOpenOutWipes is the sixth review finding: with
// ONE open in flight, "the last open wipes" and "any open wipes" are the same
// observation. Two opens are parked here, Destroy runs, and they are released
// one at a time — the first succeeding, the second leaving through a
// cancellation. The envelope must survive the first exit, because the second
// open is still reading it, and be wiped by the second.
func TestSealedEnclave_OnlyTheLastOpenOutWipes(t *testing.T) {
	p := &parkingProtector{inner: NewSoftwareProvider(), arrivals: make(chan chan error)}
	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, blob := v.sealed, v.blob
	zero := func(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

	type result struct {
		e   *MemoryEnclave
		err error
	}
	firstOut, secondOut := make(chan result, 1), make(chan result, 1)
	secondCtx, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()

	go func() { e, err := v.Open(t.Context()); firstOut <- result{e, err} }()
	firstGate := <-p.arrivals
	go func() { e, err := v.Open(secondCtx); secondOut <- result{e, err} }()
	secondGate := <-p.arrivals

	v.Destroy()

	firstGate <- nil
	r := <-firstOut
	if r.err != nil {
		t.Fatalf("the first open in flight across Destroy: %v", r.err)
	}
	if !r.e.EqualTo(sealedMaterial) {
		t.Error("the first open recovered the wrong material")
	}
	r.e.Destroy()
	if zero(sealed) || zero(blob) {
		t.Fatal("the first open out wiped the envelope while the second was still reading it")
	}

	cancelSecond()
	secondGate <- secondCtx.Err()
	r = <-secondOut
	requireOpenCanceled(t, r.e, r.err, context.Canceled)
	if !zero(sealed) || !zero(blob) {
		t.Error("the last open out — leaving through a cancellation — did not wipe the envelope")
	}
}

// errorThenCancelProtector returns a chosen error from Protect or Unprotect —
// a sentinel this package normally passes through untouched — and ends the
// caller's context before returning: the window Codex N8 named.
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

// TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds pins the
// qualification on the pass-through rule (Codex N8): a sentinel the provider
// returns — ErrSealerWiped, ErrLockedMemoryUnavailable, ErrProviderMessageLimit
// — normally reaches the caller untouched, but when the caller's context has
// ended by the time the provider returns, the error is the CANCELLATION
// joined with that sentinel: it matches the operation's sentinel, the
// context's error and the provider's sentinel, all three.
func TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds(t *testing.T) {
	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable} {
		t.Run("open/"+sentinel.Error(), func(t *testing.T) {
			p := &errorThenCancelProtector{inner: NewSoftwareProvider()}
			s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			ctx, cancel := context.WithCancel(t.Context())
			p.cancel, p.openErr = cancel, sentinel
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
				t.Fatal("Open returned a destination alongside its error")
			}
			for _, want := range []error{sentinel, ErrOpenFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Open = %v, does not match %v", err, want)
				}
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open = %v reads as a forgery", err)
			}

			// Control: with a live context the same sentinel passes through
			// untouched — not joined under ErrOpenFailed.
			p.cancel = func() {}
			if _, err := v.Open(t.Context()); err != sentinel {
				t.Errorf("Open with a live context = %v, want %v untouched", err, sentinel)
			}
		})
	}

	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable, ErrProviderMessageLimit} {
		t.Run("seal/"+sentinel.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			p := &errorThenCancelProtector{inner: NewSoftwareProvider(), cancel: cancel, protectErr: sentinel}
			s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			for _, want := range []error{sentinel, ErrSealFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Seal = %v, does not match %v", err, want)
				}
			}

			p.cancel = func() {}
			if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); err != sentinel {
				t.Errorf("Seal with a live context = %v, want %v untouched", err, sentinel)
			}
		})
	}
}

// TestSealer_RefusedReleaseOfASweptRootIsReportedAndRetried pins discardIfSwept
// against a kernel that refuses to take the root's pages back. The mapping must
// not be dropped: the root stays on the WipeAll ledger, the refusal is reported
// alongside ErrSealerWiped rather than swallowed, and the next attempt — the
// state is wiped for good — retries the release.
func TestSealer_RefusedReleaseOfASweptRootIsReportedAndRetried(t *testing.T) {
	u := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s, err := NewSealer(WithProvider(u), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		first <- err
	}()
	<-u.entered
	if remaining := sweepAbandoningBorrow(t); remaining == 0 {
		t.Fatal("the sweep reclaimed the borrowed root; the premise of this test no longer holds")
	}

	prevUnmap := unmapMemory
	t.Cleanup(func() { unmapMemory = prevUnmap })
	unmapMemory = func([]byte) error { return errors.New("munmap: operation not permitted") }
	close(u.release)

	err = <-first
	if !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal = %v, want ErrSealerWiped", err)
	}
	if !pagesHeld(err) {
		t.Errorf("Seal = %v: the refused release of the swept root was not reported", err)
	}
	root := s.pendingRoot
	if root == nil || !isRegistered(root) {
		t.Fatal("the swept root whose release was refused fell off the WipeAll ledger")
	}

	unmapMemory = prevUnmap
	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) || pagesHeld(err) {
		t.Errorf("the next initialization = %v, want a clean ErrSealerWiped after the retried release", err)
	}
	if isRegistered(root) {
		t.Error("the next attempt did not retry the refused release of the swept root")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
	sweep(t) // reclaim the scratch DEK whose release was refused alongside
}

// regionContains reports whether region contains the byte at addr.
func regionContains(region []byte, addr uintptr) bool {
	if len(region) == 0 {
		return false
	}
	lo := uintptr(unsafe.Pointer(&region[0]))
	return addr >= lo && addr < lo+uintptr(len(region))
}

// TestSealer_RefusedReleaseOfADiscardedKEKIsRetried is Codex round 3 #1. A
// sweep overlaps the initialization AFTER the root is unsealed — so the
// pre-mint check passes — and the first KEK is minted; publication then sees
// the overlap and destroys both. The kernel refuses the KEK's unmap. The
// sealer must keep a reference to that KEK and retry its release on the next
// attempt, alongside the root's — not report a clean ErrSealerWiped while the
// KEK's mapping is still held.
//
// The overlap is placed deterministically. The KEK's own mlock — the first
// step of the mint — runs a sweep while the test holds a borrow on the root,
// and ends that sweep's context once it is waiting on the borrow: the
// sequence moves, the root survives, and the mint then completes under it.
func TestSealer_RefusedReleaseOfADiscardedKEKIsRetried(t *testing.T) {
	u := &gatedRootUnsealer{}
	s, err := NewSealer(WithProvider(u), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	prevLock, prevUnmap := lockMemory, unmapMemory
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })

	var kekAt uintptr
	u.after = func() {
		// Runs inside UnsealRoot; the next mlock in this goroutine is the
		// KEK's, so arm the hook for it.
		lockMemory = func(b []byte) error {
			lockMemory = prevLock
			kekAt = uintptr(unsafe.Pointer(&b[0]))

			held, letGo := make(chan struct{}), make(chan struct{})
			go func() {
				_ = s.pendingRoot.WithBytes(func([]byte) error {
					close(held)
					<-letGo
					return nil
				})
			}()
			<-held
			sweepAbandoningBorrow(t) // the root survives; the sequence moves
			close(letGo)

			// Refuse the KEK's unmap — and only the KEK's.
			unmapMemory = func(m []byte) error {
				if regionContains(m, kekAt) {
					return errors.New("munmap: operation not permitted")
				}
				return prevUnmap(m)
			}
			return prevLock(b)
		}
	}

	_, err = s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if !errors.Is(err, ErrSealerWiped) || !pagesHeld(err) {
		t.Fatalf("Seal = %v, want ErrSealerWiped with the KEK's refused release reported", err)
	}
	kek := s.pendingKEK
	if kek == nil {
		t.Fatal("the KEK whose release was refused is no longer referenced by the sealer; nothing will retry it")
	}
	if !isRegistered(kek) {
		t.Fatal("the KEK whose release was refused fell off the WipeAll ledger")
	}
	if isRegistered(s.pendingRoot) {
		t.Error("the root's release was not refused, so it should be off the ledger")
	}

	unmapMemory = prevUnmap
	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) || pagesHeld(err) {
		t.Errorf("the next initialization = %v, want a clean ErrSealerWiped after the retried releases", err)
	}
	if isRegistered(kek) {
		t.Error("the next attempt did not retry the refused release of the discarded KEK")
	}
	if s.pendingKEK != nil {
		t.Error("pendingKEK was not cleared after its release succeeded")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}
