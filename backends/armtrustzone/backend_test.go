package armtrustzone

import (
	"context"
	"errors"
	"testing"
)

func TestChunkPlan(t *testing.T) {
	cases := []struct {
		n    int
		want []chunk
	}{
		{1, []chunk{{0, 1}}},
		{4096, []chunk{{0, 4096}}},
		{4097, []chunk{{0, 4096}, {4096, 1}}},
		{3*4096 + 1, []chunk{{0, 4096}, {4096, 4096}, {8192, 4096}, {12288, 1}}},
	}
	for _, c := range cases {
		got := chunkPlan(c.n)
		if len(got) != len(c.want) {
			t.Errorf("chunkPlan(%d) = %v, want %v", c.n, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("chunkPlan(%d) = %v, want %v", c.n, got, c.want)
				break
			}
		}
	}
}

// TestRandomRefusesNonPositiveSizes calls Random on a Backend with no session:
// the refusal must come before the TA would be called.
func TestRandomRefusesNonPositiveSizes(t *testing.T) {
	for _, n := range []int{0, -1} {
		h, err := (&Backend{}).Random(context.Background(), n)
		var se *SizeError
		if h != nil || !errors.Is(err, ErrRandomSize) || !errors.As(err, &se) || se.N != n {
			t.Errorf("Random(%d) = %v, %v; want a SizeError for %d", n, h, err, n)
		}
	}
}

func TestCheckInfo(t *testing.T) {
	if err := checkInfo(1, 0); err != nil {
		t.Fatalf("checkInfo(1, 0) = %v, want nil", err)
	}
	for _, c := range []struct{ version, flags uint64 }{
		{0, 0}, {2, 0}, {0xffffffff, 0},
		{1, 1}, {1, 0x80000000}, {1, 0xffffffff},
		{2, 1},
	} {
		err := checkInfo(c.version, c.flags)
		var ie *InterfaceError
		if !errors.Is(err, ErrInterfaceUnsupported) || !errors.As(err, &ie) || ie.Version != c.version || ie.Flags != c.flags {
			t.Errorf("checkInfo(%d, %#x) = %v, want an InterfaceError for it", c.version, c.flags, err)
		}
	}
}

func TestBackendIdentity(t *testing.T) {
	if got := (&Backend{}).Name(); got != "arm-trustzone" {
		t.Errorf("Backend.Name() = %q, want arm-trustzone", got)
	}
	if got := (Connector{}).Name(); got != Name {
		t.Errorf("Connector.Name() = %q, want %q", got, Name)
	}
	if got := (&Backend{}).Rank(); got <= 1 {
		t.Errorf("Rank() = %d, want above the secretmem backend's 1", got)
	}
}
