//go:build linux

package armtrustzone

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestBackendClose covers Close over the fake TEE: it is idempotent, later
// calls are refused, it waits out a call in flight, and it leaves the device
// holding nothing.
func TestBackendClose(t *testing.T) {
	t.Run("second close", func(t *testing.T) {
		forEachDriver(t, func(t *testing.T, f *fakeTEE) {
			b, err := dialFake(t, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatalf("first Close: %v", err)
			}
			if err := b.Close(); !errors.Is(err, ErrBackendClosed) {
				t.Fatalf("second Close = %v, want ErrBackendClosed", err)
			}
		})
	})

	t.Run("calls after close", func(t *testing.T) {
		forEachDriver(t, func(t *testing.T, f *fakeTEE) {
			b, err := dialFake(t, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := b.Probe(ctx); !errors.Is(err, ErrBackendClosed) {
				t.Errorf("Probe after Close = %v, want ErrBackendClosed", err)
			}
			h, err := b.Random(ctx, 16)
			if !errors.Is(err, ErrBackendClosed) {
				t.Errorf("Random after Close = %v, want ErrBackendClosed", err)
			}
			if h != nil {
				t.Errorf("Random after Close returned a handle")
			}
		})
	})

	t.Run("waits for a call in flight", func(t *testing.T) {
		forEachDriver(t, func(t *testing.T, f *fakeTEE) {
			b, err := dialFake(t, f)
			if err != nil {
				t.Fatal(err)
			}
			entered := f.blockOn(taCmdGetRandom)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			randErr := make(chan error, 1)
			go func() {
				h, err := b.Random(ctx, 16)
				if h != nil {
					_ = h.Destroy()
				}
				randErr <- err
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("Random never reached GET_RANDOM")
			}
			closeErr := make(chan error, 1)
			go func() { closeErr <- b.Close() }()
			select {
			case err := <-closeErr:
				t.Fatalf("Close returned %v while a call was in flight", err)
			case <-time.After(100 * time.Millisecond):
			}
			cancel()
			select {
			case err := <-closeErr:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Close did not return after the call was canceled")
			}
			select {
			case err := <-randErr:
				if err == nil {
					t.Fatal("canceled Random returned no error")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Random did not return after cancel")
			}
		})
	})

	t.Run("releases the device", func(t *testing.T) {
		forEachDriver(t, func(t *testing.T, f *fakeTEE) {
			b, err := dialFake(t, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			if n := f.live(); n != 0 {
				t.Errorf("%d shared memories live after Close", n)
			}
			f.mu.Lock()
			devs, sessions := len(f.devs), len(f.sessions)
			f.mu.Unlock()
			if devs != 0 || sessions != 0 {
				t.Errorf("after Close: %d device fds and %d sessions open", devs, sessions)
			}
		})
	})
}
