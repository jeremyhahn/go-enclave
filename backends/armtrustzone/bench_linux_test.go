package armtrustzone

import (
	"context"
	"testing"
)

// connectOn opens a backend on drv the way Connect does on the kernel
// driver: a session on the pinned TA, then GET_INFO.
func connectOn(drv teeDriver) func() (*Backend, error) {
	return func() (*Backend, error) {
		uuid, err := parseUUID(taUUID)
		if err != nil {
			return nil, err
		}
		c, err := openClientOn(drv, fakeEndpoint, uuid)
		if err != nil {
			return nil, err
		}
		be := &Backend{c: c}
		if err := be.Probe(context.Background()); err != nil {
			_ = c.close()
			return nil, err
		}
		return be, nil
	}
}

// TestBenchHarness_Fake runs each benchmark body once against the fake TEE,
// with and without registered memory. It checks the harness, not the
// timings: every run completes iterations, reports both metrics, and the
// fake's cleanup fails the test on any device fd, session or shared-memory
// object left behind.
func TestBenchHarness_Fake(t *testing.T) {
	benches := []struct {
		name string
		fn   func(*testing.B, func() (*Backend, error))
	}{
		{"OpenUseClose", benchOpenUseClose},
		{"Access", benchAccess},
	}
	for _, regMem := range []bool{false, true} {
		for _, bench := range benches {
			name := bench.name + "/shm"
			if regMem {
				name = bench.name + "/regmem"
			}
			t.Run(name, func(t *testing.T) {
				f := newFakeTEE(t, regMem)
				r := testing.Benchmark(func(b *testing.B) { bench.fn(b, connectOn(f)) })
				if r.N < 1 {
					t.Fatalf("the benchmark failed or ran no iterations: %+v", r)
				}
				for _, unit := range []string{"ops/s", "ns/access"} {
					if v := r.Extra[unit]; v <= 0 {
						t.Errorf("metric %s = %v, want > 0", unit, v)
					}
				}
				if n := f.live(); n != 0 {
					t.Errorf("%d shared-memory objects outlive the benchmark", n)
				}
			})
		}
	}
}
