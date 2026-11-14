//go:build linux

package armtrustzone

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
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

// TestBackendRandomSizes fills a handle of one chunk, an exact multiple of
// the chunk size and one byte over, and checks that each GET_RANDOM call
// asked for its chunk and that the chunk landed at its offset.
func TestBackendRandomSizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"one byte", 1},
		{"one chunk", taRandomMax},
		{"three chunks", 3 * taRandomMax},
		{"one byte over", taRandomMax + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachDriver(t, func(t *testing.T, f *fakeTEE) {
				b, err := dialFake(t, f)
				if err != nil {
					t.Fatal(err)
				}
				h, err := b.Random(context.Background(), tc.n)
				if err != nil {
					t.Fatalf("Random(%d): %v", tc.n, err)
				}
				defer func() { _ = h.Destroy() }()
				if h.Backend() != b {
					t.Errorf("handle reports backend %v, want %v", h.Backend(), b)
				}
				plan := chunkPlan(tc.n)
				calls := f.calls(taCmdGetRandom)
				if len(calls) != len(plan) {
					t.Fatalf("%d GET_RANDOM calls, want %d", len(calls), len(plan))
				}
				for i, ch := range plan {
					p := calls[i].params[0]
					if p.attr != teeParamAttrTypeMemrefOutput || p.size != uint64(ch.n) {
						t.Errorf("call %d: attr %d size %d, want output memref of %d", i, p.attr, p.size, ch.n)
					}
					if f.regMem && p.off != uint64(ch.off) {
						t.Errorf("call %d at offset %d, want %d", i, p.off, ch.off)
					}
				}
				ba, ok := h.(enclave.ByteAccess)
				if !ok {
					t.Fatalf("handle %T gives no byte access", h)
				}
				err = ba.WithBytes(func(got []byte) error {
					if len(got) != tc.n {
						return fmt.Errorf("handle holds %d bytes, want %d", len(got), tc.n)
					}
					for i, ch := range plan {
						want := byte(i + 1)
						for j, v := range got[ch.off : ch.off+ch.n] {
							if v != want {
								return fmt.Errorf("byte %d of chunk %d is %#x, want %#x", j, i, v, want)
							}
						}
					}
					return nil
				})
				if err != nil {
					t.Error(err)
				}
				if n := f.live(); n != 0 {
					t.Errorf("%d shared memories live after Random", n)
				}
			})
		})
	}
}

// TestBackendRandomFailures fails the first, a middle and the last chunk of
// a three-chunk Random with a TA error code, an INVOKE ioctl error and a
// cancel while the chunk is blocked: no handle comes back, no shared memory
// stays live, and no chunk after the failed one is asked for.
func TestBackendRandomFailures(t *testing.T) {
	const chunks = 3
	kinds := []struct {
		name  string
		setup func(f *fakeTEE, nth int) <-chan struct{}
		check func(t *testing.T, err error)
	}{
		{
			name: "TA error",
			setup: func(f *fakeTEE, nth int) <-chan struct{} {
				f.failNth(taCmdGetRandom, nth, fakeErrGeneric, nil)
				return nil
			},
			check: func(t *testing.T, err error) {
				var ce *CommandError
				if !errors.As(err, &ce) || ce.Command != taCmdGetRandom || ce.Code != fakeErrGeneric || ce.Origin != OriginTrustedApp {
					t.Errorf("err = %v, want a GET_RANDOM CommandError with code %#x from the TA", err, fakeErrGeneric)
				}
			},
		},
		{
			name: "ioctl error",
			setup: func(f *fakeTEE, nth int) <-chan struct{} {
				f.failNth(taCmdGetRandom, nth, 0, unix.EIO)
				return nil
			},
			check: func(t *testing.T, err error) {
				var de *DeviceError
				if !errors.As(err, &de) || de.Op != "invoke" || !errors.Is(err, unix.EIO) {
					t.Errorf("err = %v, want an invoke DeviceError wrapping EIO", err)
				}
			},
		},
		{
			name: "cancel",
			setup: func(f *fakeTEE, nth int) <-chan struct{} {
				return f.blockOnNth(taCmdGetRandom, nth)
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("err = %v, want context.Canceled", err)
				}
			},
		},
	}
	for _, kind := range kinds {
		for _, at := range []struct {
			name string
			nth  int
		}{{"first chunk", 1}, {"middle chunk", 2}, {"last chunk", chunks}} {
			t.Run(kind.name+"/"+at.name, func(t *testing.T) {
				forEachDriver(t, func(t *testing.T, f *fakeTEE) {
					b, err := dialFake(t, f)
					if err != nil {
						t.Fatal(err)
					}
					entered := kind.setup(f, at.nth)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					type result struct {
						h   enclave.Handle
						err error
					}
					done := make(chan result, 1)
					go func() {
						h, err := b.Random(ctx, chunks*taRandomMax)
						done <- result{h, err}
					}()
					if entered != nil {
						select {
						case <-entered:
						case <-time.After(10 * time.Second):
							t.Fatalf("Random never reached GET_RANDOM call %d", at.nth)
						}
						cancel()
					}
					var r result
					select {
					case r = <-done:
					case <-time.After(10 * time.Second):
						t.Fatal("Random did not return")
					}
					if r.h != nil {
						_ = r.h.Destroy()
						t.Fatal("Random returned a handle on failure")
					}
					kind.check(t, r.err)
					if n := len(f.calls(taCmdGetRandom)); n != at.nth {
						t.Errorf("%d GET_RANDOM calls, want %d", n, at.nth)
					}
					if n := f.live(); n != 0 {
						t.Errorf("%d shared memories live after a failed Random", n)
					}
				})
			})
		}
	}
}
