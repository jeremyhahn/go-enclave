package armtrustzone

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// benchSize is the length in bytes of the material each benchmark iteration
// draws: one GET_RANDOM, well under the TA's per-call limit.
const benchSize = 32

// benchOpenUseClose measures the short-lived pattern the backend is for:
// each iteration opens a session (Connect, which also runs GET_INFO), draws
// benchSize bytes into locked memory with one Random, destroys the handle
// and closes the session. It reports the cycles per second as ops/s and the
// time per cycle as ns/access.
func benchOpenUseClose(b *testing.B, connect func() (*Backend, error)) {
	b.Helper()
	ctx := context.Background()
	n := 0
	for b.Loop() {
		be, err := connect()
		if err != nil {
			b.Fatalf("open: %v", err)
		}
		h, err := be.Random(ctx, benchSize)
		if err != nil {
			_ = be.Close()
			b.Fatalf("use: Random(%d): %v", benchSize, err)
		}
		if err := h.Destroy(); err != nil {
			_ = be.Close()
			b.Fatalf("use: Destroy: %v", err)
		}
		if err := be.Close(); err != nil {
			b.Fatalf("close: %v", err)
		}
		n++
	}
	reportRate(b, n)
}

// benchAccess measures one access on an open session: each iteration is
// one GET_RANDOM of benchSize bytes into the same locked buffer. It reports
// the accesses per second as ops/s and the time per access as ns/access.
func benchAccess(b *testing.B, connect func() (*Backend, error)) {
	b.Helper()
	be, err := connect()
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer func() {
		if err := be.Close(); err != nil {
			b.Errorf("close: %v", err)
		}
	}()
	mem, err := enclave.NewMemorySized(benchSize)
	if err != nil {
		b.Fatalf("NewMemorySized(%d): %v", benchSize, err)
	}
	defer func() {
		if err := mem.Destroy(); err != nil {
			b.Errorf("Destroy: %v", err)
		}
	}()
	ctx := context.Background()
	plan := chunkPlan(benchSize)
	n := 0
	err = mem.WithBytes(func(dst []byte) error {
		for b.Loop() {
			if err := be.c.fillRandom(ctx, dst, plan); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		b.Fatalf("access: GET_RANDOM(%d): %v", benchSize, err)
	}
	reportRate(b, n)
}

// reportRate reports n operations over the benchmark's elapsed time as
// ops/s and ns/access.
func reportRate(b *testing.B, n int) {
	b.Helper()
	elapsed := b.Elapsed()
	if n == 0 || elapsed <= 0 {
		b.Fatalf("no operations measured (n=%d, elapsed=%v)", n, elapsed)
	}
	b.ReportMetric(float64(n)/elapsed.Seconds(), "ops/s")
	b.ReportMetric(float64(elapsed.Nanoseconds())/float64(n), "ns/access")
}
