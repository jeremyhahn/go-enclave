package intelsgx

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The handle layer is plain Go over enclave.NewMemory, so these run on a
// Backend built directly: New refuses outside an SGX enclave.

func wiped(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestImportMaterial(t *testing.T) {
	b := newTestBackend()
	material := pattern(48)
	want := bytes.Clone(material)
	h, err := b.Import(context.Background(), material, enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	defer h.Destroy()
	if !wiped(material) {
		t.Fatal("material not wiped after a successful import")
	}
	ba, ok := h.(enclave.ByteAccess)
	if !ok {
		t.Fatal("handle is not ByteAccess")
	}
	if h.Size() != len(want) || !h.IsAlive() || h.Backend() != b {
		t.Fatalf("Size %d IsAlive %v Backend %v", h.Size(), h.IsAlive(), h.Backend())
	}
	eq, err := ba.EqualTo(want)
	if err != nil || !eq {
		t.Fatalf("EqualTo = %v, %v", eq, err)
	}
	if err := ba.WithBytes(func(v []byte) error {
		if !bytes.Equal(v, want) {
			return errors.New("view differs")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

func TestImportAESKey(t *testing.T) {
	b := newTestBackend()
	for _, p := range []enclave.Purpose{enclave.PurposeWrappingKey, enclave.PurposeDataKey} {
		key := pattern(32)
		h, err := b.Import(context.Background(), key,
			enclave.WithPurpose(p), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM))
		if err != nil {
			t.Fatalf("Import %s: %v", p, err)
		}
		if !wiped(key) || h.Size() != 32 {
			t.Fatalf("%s: wiped %v Size %d", p, wiped(key), h.Size())
		}
		if err := h.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
	}
}

func TestImportRefusals(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	aes := []enclave.ImportOption{
		enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM),
	}
	cases := []struct {
		name  string
		ctx   context.Context
		n     int
		opts  []enclave.ImportOption
		check func(error) bool
	}{
		{"wrong algorithm", context.Background(), 32,
			[]enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm("chacha20-poly1305")},
			func(err error) bool {
				var ce *enclave.CapabilityError
				return errors.As(err, &ce) && ce.Capability == enclave.CapabilityImport && ce.Backend == Name
			}},
		{"short key", context.Background(), 31, aes,
			func(err error) bool { return errors.Is(err, enclave.ErrInvalidImport) }},
		{"no purpose", context.Background(), 16, nil,
			func(err error) bool { return errors.Is(err, enclave.ErrInvalidImport) }},
		{"canceled", canceled, 32, aes,
			func(err error) bool { return errors.Is(err, context.Canceled) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newTestBackend()
			material := pattern(tc.n)
			h, err := b.Import(tc.ctx, material, tc.opts...)
			if h != nil || !tc.check(err) {
				t.Fatalf("Import = %v, %v", h, err)
			}
			if !wiped(material) {
				t.Fatal("material not wiped after a refusal")
			}
		})
	}
}

func TestFreezeMakesReadOnly(t *testing.T) {
	b := newTestBackend()
	h, err := b.Import(context.Background(), pattern(16), enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	defer h.Destroy()
	if err := h.(enclave.Freezer).Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	faulted := func() (f bool) {
		defer func() { f = recover() != nil }()
		_ = h.(enclave.ByteAccess).WithBytes(func(v []byte) error {
			v[0] = 0xff
			return nil
		})
		return false
	}()
	if !faulted {
		t.Fatal("write to a frozen handle did not fault")
	}
}

func TestDestroy(t *testing.T) {
	b := newTestBackend()
	h, err := b.Import(context.Background(), pattern(16), enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
	if h.IsAlive() || h.Size() != 0 || h.Backend() != b {
		t.Fatal("destroyed handle still alive, sized or unowned")
	}
	ba := h.(enclave.ByteAccess)
	if err := ba.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("WithBytes = %v", err)
	}
	if _, err := ba.EqualTo(nil); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("EqualTo = %v", err)
	}
	if err := h.(enclave.Freezer).Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("Freeze = %v", err)
	}
	if len(b.handles) != 0 {
		t.Fatal("destroyed handle left in the registry")
	}
}

func TestSweep(t *testing.T) {
	b := newTestBackend()
	var hs []enclave.Handle
	for range 3 {
		h, err := b.Import(context.Background(), pattern(8), enclave.WithPurpose(enclave.PurposeMaterial))
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		hs = append(hs, h)
	}
	if err := hs[0].Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// A nil ctx must not panic, per the Sweeper contract.
	held, err := b.Sweep(nil)
	if held != 0 || err != nil {
		t.Fatalf("Sweep = %d, %v", held, err)
	}
	for i, h := range hs {
		if h.IsAlive() {
			t.Fatalf("handle %d alive after Sweep", i)
		}
	}
	if held, err := b.Sweep(context.Background()); held != 0 || err != nil {
		t.Fatalf("second Sweep = %d, %v", held, err)
	}
}

// borrow holds h's bytes inside WithBytes until the returned release runs.
func borrow(t *testing.T, h enclave.Handle) (release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	go func() {
		_ = h.(*handle).WithBytes(func([]byte) error {
			close(in)
			<-out
			return nil
		})
	}()
	<-in
	var once sync.Once
	return func() { once.Do(func() { close(out) }) }
}

// TestSweepBorrowed checks the Sweeper contract around a borrowed handle:
// every unborrowed handle is wiped under a nil, canceled or expiring ctx, the
// borrowed one is counted as held without an error, and Sweep returns
// without waiting for the borrow to end.
func TestSweepBorrowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"nil", func() (context.Context, context.CancelFunc) { return nil, func() {} }},
		{"canceled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newTestBackend()
			var hs []enclave.Handle
			for range 4 {
				h, err := b.Import(context.Background(), pattern(8), enclave.WithPurpose(enclave.PurposeMaterial))
				if err != nil {
					t.Fatalf("Import: %v", err)
				}
				hs = append(hs, h)
			}
			release := borrow(t, hs[1])
			defer release()
			ctx, cancel := tc.ctx()
			defer cancel()

			var held int
			var err error
			done := make(chan struct{})
			go func() {
				held, err = b.Sweep(ctx)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				release()
				t.Fatal("Sweep waited on a borrowed handle")
			}
			if held != 1 || err != nil {
				t.Fatalf("Sweep = %d, %v; want 1, nil", held, err)
			}
			for i, h := range hs {
				if i != 1 && h.IsAlive() {
					t.Fatalf("unborrowed handle %d alive after Sweep", i)
				}
			}
			if !hs[1].IsAlive() {
				t.Fatal("borrowed handle released under its reader")
			}
			release()
			if held, err := b.Sweep(context.Background()); held != 0 || err != nil {
				t.Fatalf("Sweep after release = %d, %v", held, err)
			}
			if hs[1].IsAlive() {
				t.Fatal("borrowed handle alive after the borrow ended and Sweep ran")
			}
		})
	}
}

// failingWipe fails its first Destroy with ErrReleasedWithoutWipe after
// releasing the pages, as a denied release mprotect does; a later Destroy of
// the released pages returns nil.
type failingWipe struct {
	enclave.ByteAccess
	failed atomic.Bool
}

func (f *failingWipe) Destroy() error {
	err := f.ByteAccess.Destroy()
	if err == nil && f.failed.CompareAndSwap(false, true) {
		return enclave.ErrReleasedWithoutWipe
	}
	return err
}

// TestSweepLeavesNoWorkers pins that bounded sweeps of a handle whose borrow
// outlasts them leave no goroutine behind, and that the wipe failure of that
// handle, once the borrow ends, reaches a caller instead of an abandoned
// worker.
func TestSweepLeavesNoWorkers(t *testing.T) {
	for _, via := range []string{"Destroy", "Sweep"} {
		t.Run(via, func(t *testing.T) {
			b := newTestBackend()
			h, err := b.Import(context.Background(), pattern(8), enclave.WithPurpose(enclave.PurposeMaterial))
			if err != nil {
				t.Fatalf("Import: %v", err)
			}
			hh := h.(*handle)
			hh.mem = &failingWipe{ByteAccess: hh.mem}
			release := borrow(t, h)
			defer release()

			before := runtime.NumGoroutine()
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
				held, err := b.Sweep(ctx)
				cancel()
				if held != 1 || err != nil {
					t.Fatalf("Sweep = %d, %v; want 1, nil", held, err)
				}
			}
			if after := runtime.NumGoroutine(); after > before+2 {
				t.Fatalf("goroutines grew from %d to %d over bounded sweeps", before, after)
			}
			if !h.IsAlive() {
				t.Fatal("borrowed handle released under its reader")
			}
			release()
			// Give an abandoned worker, if any, the chance to swallow the error.
			time.Sleep(50 * time.Millisecond)

			switch via {
			case "Destroy":
				err = h.Destroy()
			case "Sweep":
				_, err = b.Sweep(context.Background())
			}
			if !errors.Is(err, enclave.ErrReleasedWithoutWipe) {
				t.Fatalf("%s after the borrow ended = %v, want ErrReleasedWithoutWipe", via, err)
			}
		})
	}
}

func TestCapabilities(t *testing.T) {
	var b enclave.Backend = newTestBackend()
	if _, ok := b.(enclave.Importer); !ok {
		t.Fatal("not an Importer")
	}
	if _, ok := b.(enclave.Sweeper); !ok {
		t.Fatal("not a Sweeper")
	}
	h, err := b.(enclave.Importer).Import(context.Background(), pattern(4), enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	defer h.Destroy()
	if _, ok := h.(enclave.ByteAccess); !ok {
		t.Fatal("handle not ByteAccess")
	}
	if _, ok := h.(enclave.Freezer); !ok {
		t.Fatal("handle not Freezer")
	}
}
