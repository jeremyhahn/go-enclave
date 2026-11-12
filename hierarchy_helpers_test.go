package enclave

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// helperKey is a hierarchy handle for the helper tables: it reports the
// liveness it is given, and its Destroy kills it or returns refuse.
type helperKey struct {
	alive    bool
	refuse   error
	destroys int
}

func (k *helperKey) Size() int     { return 0 }
func (k *helperKey) IsAlive() bool { return k.alive }
func (k *helperKey) Backend() Backend {
	return nil
}

func (k *helperKey) Destroy() error {
	k.destroys++
	if k.refuse != nil {
		return k.refuse
	}
	k.alive = false
	return nil
}

func liveKey() *helperKey { return &helperKey{alive: true} }
func deadKey() *helperKey { return &helperKey{} }

func TestHierarchyFailure(t *testing.T) {
	t.Parallel()
	errOther := errors.New("test: unrelated failure")
	wrapped := fmt.Errorf("test: open: %w", ErrEnclaveDestroyed)
	var typedNil *helperKey
	tests := []struct {
		name string
		err  error
		keys []Handle
		want error
	}{
		{name: "nil err", err: nil, keys: []Handle{deadKey()}, want: nil},
		{name: "unrelated err with dead keys", err: errOther, keys: []Handle{deadKey(), deadKey()}, want: errOther},
		{name: "destroyed with all keys alive", err: ErrEnclaveDestroyed, keys: []Handle{liveKey(), liveKey()}, want: ErrEnclaveDestroyed},
		{name: "destroyed with one key dead", err: ErrEnclaveDestroyed, keys: []Handle{liveKey(), deadKey()}, want: ErrSealerWiped},
		{name: "destroyed skips nil and typed-nil keys", err: ErrEnclaveDestroyed, keys: []Handle{nil, typedNil, liveKey()}, want: ErrEnclaveDestroyed},
		{name: "destroyed skips nil keys before a dead one", err: ErrEnclaveDestroyed, keys: []Handle{nil, typedNil, deadKey()}, want: ErrSealerWiped},
		{name: "destroyed with no keys", err: ErrEnclaveDestroyed, keys: nil, want: ErrEnclaveDestroyed},
		{name: "wrapped destroyed with a dead key", err: wrapped, keys: []Handle{deadKey()}, want: ErrSealerWiped},
		{name: "wrapped destroyed with live keys", err: wrapped, keys: []Handle{liveKey()}, want: wrapped},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hierarchyFailure(tc.err, tc.keys...); got != tc.want { //nolint:errorlint // identity is the contract
				t.Fatalf("hierarchyFailure(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestDestroyKeys(t *testing.T) {
	t.Parallel()
	errRefusedA := errors.New("test: release A refused")
	errRefusedB := errors.New("test: release B refused")

	t.Run("no keys", func(t *testing.T) {
		t.Parallel()
		if err := destroyKeys(); err != nil {
			t.Fatalf("destroyKeys() = %v, want nil", err)
		}
	})

	t.Run("nil and typed-nil keys skipped", func(t *testing.T) {
		t.Parallel()
		var typedNil *helperKey
		k := liveKey()
		if err := destroyKeys(nil, typedNil, k); err != nil {
			t.Fatalf("destroyKeys = %v, want nil", err)
		}
		if k.alive || k.destroys != 1 {
			t.Fatalf("key alive=%v destroys=%d, want dead after one Destroy", k.alive, k.destroys)
		}
	})

	t.Run("all destroy cleanly", func(t *testing.T) {
		t.Parallel()
		keys := []*helperKey{liveKey(), liveKey(), deadKey()}
		if err := destroyKeys(keys[0], keys[1], keys[2]); err != nil {
			t.Fatalf("destroyKeys = %v, want nil", err)
		}
		for i, k := range keys {
			if k.alive || k.destroys != 1 {
				t.Fatalf("key %d alive=%v destroys=%d, want dead after one Destroy", i, k.alive, k.destroys)
			}
		}
	})

	t.Run("one refuses", func(t *testing.T) {
		t.Parallel()
		first, refusing, last := liveKey(), &helperKey{alive: true, refuse: errRefusedA}, liveKey()
		err := destroyKeys(first, refusing, last)
		// With one refusal and no failure, withCleanupFailure returns that
		// refusal unchanged.
		if err != errRefusedA { //nolint:errorlint // identity is the contract
			t.Fatalf("destroyKeys = %v, want the refusal as is", err)
		}
		if first.alive || last.alive || refusing.destroys != 1 {
			t.Fatalf("first alive=%v last alive=%v refused destroys=%d, want the others destroyed", first.alive, last.alive, refusing.destroys)
		}
	})

	t.Run("two refuse", func(t *testing.T) {
		t.Parallel()
		ok := liveKey()
		err := destroyKeys(&helperKey{alive: true, refuse: errRefusedA}, ok, &helperKey{alive: true, refuse: errRefusedB})
		var ce *CleanupError
		if !errors.As(err, &ce) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("destroyKeys = %v, want a *CleanupError matching ErrCleanupFailed", err)
		}
		if ce.Failure != nil {
			t.Fatalf("CleanupError.Failure = %v, want nil", ce.Failure)
		}
		if !slices.Equal(ce.Causes, []error{errRefusedA, errRefusedB}) {
			t.Fatalf("CleanupError.Causes = %v, want both refusals in order", ce.Causes)
		}
		if ok.alive {
			t.Fatal("the clean key is still alive")
		}
	})

	t.Run("a refused CleanupError is flattened", func(t *testing.T) {
		t.Parallel()
		inner := &CleanupError{Causes: []error{errRefusedA}}
		err := destroyKeys(&helperKey{alive: true, refuse: inner}, &helperKey{alive: true, refuse: errRefusedB})
		var ce *CleanupError
		if !errors.As(err, &ce) || !slices.Equal(ce.Causes, []error{errRefusedA, errRefusedB}) {
			t.Fatalf("destroyKeys = %v, want one flat *CleanupError with both refusals", err)
		}
	})
}

func TestInitFailure(t *testing.T) {
	t.Parallel()
	errHolder := errors.New("test: slot holder failed")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	t.Cleanup(cancelExpired)
	errWhy := errors.New("test: shutting down")
	caused, cancelCaused := context.WithCancelCause(context.Background())
	cancelCaused(errWhy)

	t.Run("nil err with an ended ctx", func(t *testing.T) {
		t.Parallel()
		if err := initFailure(cancelled, nil); err != nil {
			t.Fatalf("initFailure = %v, want nil", err)
		}
	})

	t.Run("err with a live ctx", func(t *testing.T) {
		t.Parallel()
		if err := initFailure(context.Background(), errHolder); err != errHolder { //nolint:errorlint // identity is the contract
			t.Fatalf("initFailure = %v, want the holder's err as is", err)
		}
	})

	t.Run("seal failure with a live ctx", func(t *testing.T) {
		t.Parallel()
		in := fmt.Errorf("%w: %w", ErrSealFailed, context.Canceled)
		if err := initFailure(context.Background(), in); err != in { //nolint:errorlint // identity is the contract
			t.Fatalf("initFailure = %v, want the err as is", err)
		}
	})

	ended := []struct {
		name  string
		ctx   context.Context //nolint:containedctx // table input
		ended error
	}{
		{name: "cancelled", ctx: cancelled, ended: context.Canceled},
		{name: "deadline exceeded", ctx: expired, ended: context.DeadlineExceeded},
	}
	for _, tc := range ended {
		t.Run("err with a "+tc.name+" ctx", func(t *testing.T) {
			t.Parallel()
			err := initFailure(tc.ctx, errHolder)
			for _, want := range []error{ErrSealFailed, tc.ended, errHolder} {
				if !errors.Is(err, want) {
					t.Fatalf("initFailure = %v, want it to match %v", err, want)
				}
			}
			var se *SealError
			if !errors.As(err, &se) {
				t.Fatalf("initFailure = %T, want a *SealError", err)
			}
		})

		t.Run("seal failure already carrying the "+tc.name+" ctx", func(t *testing.T) {
			t.Parallel()
			in := initFailure(tc.ctx, errHolder)
			if err := initFailure(tc.ctx, in); err != in { //nolint:errorlint // identity is the contract
				t.Fatalf("initFailure = %v, want the err as is, not wrapped again", err)
			}
			plain := fmt.Errorf("%w: %w", ErrSealFailed, tc.ended)
			if err := initFailure(tc.ctx, plain); err != plain { //nolint:errorlint // identity is the contract
				t.Fatalf("initFailure = %v, want the err as is, not wrapped again", err)
			}
		})
	}

	t.Run("seal failure without the ended ctx is wrapped", func(t *testing.T) {
		t.Parallel()
		in := fmt.Errorf("%w: test: no ctx", ErrSealFailed)
		err := initFailure(cancelled, in)
		if err == in || !errors.Is(err, context.Canceled) || !errors.Is(err, in) { //nolint:errorlint // identity is the contract
			t.Fatalf("initFailure = %v, want it wrapped with context.Canceled", err)
		}
	})

	t.Run("cancel cause is reachable", func(t *testing.T) {
		t.Parallel()
		err := initFailure(caused, errHolder)
		for _, want := range []error{ErrSealFailed, context.Canceled, errWhy, errHolder} {
			if !errors.Is(err, want) {
				t.Fatalf("initFailure = %v, want it to match %v", err, want)
			}
		}
	})
}
