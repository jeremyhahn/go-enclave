package intelsgx

import (
	"context"
	"errors"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// promptly is how long a canceled call may take to return.
const promptly = 2 * time.Second

// newTestBackend returns a Backend built as New builds one, without the
// hardware probe.
func newTestBackend() *Backend { return newBackend() }

func TestUnconstructedBackendRefusesUse(t *testing.T) {
	var b Backend
	if b.ConfinesProcess() {
		t.Fatal("ConfinesProcess = true on a Backend New did not build")
	}
	h, err := b.Import(context.Background(), []byte("material"), enclave.WithPurpose(enclave.PurposeMaterial))
	if !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Import on an unconstructed Backend: err = %v, want ErrSGXUnavailable", err)
	}
	if h != nil {
		t.Fatalf("Import on an unconstructed Backend returned handle %v", h)
	}
	if !newTestBackend().ConfinesProcess() {
		t.Fatal("ConfinesProcess = false on a constructed Backend")
	}
}

// TestProbeRefusesUnconstructedBackend guards detection: a Backend that New
// did not build must not pass Probe on a usable host, or it would displace
// working backends while its Import always refuses. A canceled
// ctx tells the paths apart without hardware: the probe helper returns
// ctx.Err(), the refusal returns ErrSGXUnavailable before probing.
func TestProbeRefusesUnconstructedBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var zero Backend
	if err := zero.Probe(ctx); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Probe on the zero Backend: err = %v, want ErrSGXUnavailable", err)
	}
	var nilBackend *Backend
	if err := nilBackend.Probe(ctx); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Probe on a nil *Backend: err = %v, want ErrSGXUnavailable", err)
	}
	if err := newTestBackend().Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe on a constructed Backend: err = %v, want the probe's context.Canceled", err)
	}
}

func TestSweepHonoursContextWhileHandleBorrowed(t *testing.T) {
	b := newTestBackend()
	h, err := b.Import(context.Background(), []byte("material"), enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	ba, ok := h.(interface {
		WithBytes(func([]byte) error) error
	})
	if !ok {
		t.Fatal("handle has no WithBytes")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	borrowDone := make(chan struct{})
	go func() {
		defer close(borrowDone)
		_ = ba.WithBytes(func([]byte) error {
			close(entered)
			<-release
			return nil
		})
	}()
	t.Cleanup(func() { close(release); <-borrowDone })
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	type result struct {
		held int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		held, err := b.Sweep(ctx)
		done <- result{held, err}
	}()
	select {
	case r := <-done:
		// Per the Sweeper contract a ctx ending during the sweep is not
		// an error: the borrowed handle is counted as held.
		if r.err != nil {
			t.Fatalf("Sweep err = %v, want nil", r.err)
		}
		if r.held != 1 {
			t.Fatalf("Sweep held = %d, want 1", r.held)
		}
	case <-time.After(promptly):
		t.Fatal("Sweep did not return after its context ended while a handle was borrowed")
	}
}

// TestNewRefusesOutsideEnclave runs the real constructor on a host that is
// not in an SGX enclave (or not linux/amd64): it refuses with the typed
// unavailable error and builds no backend.
func TestNewRefusesOutsideEnclave(t *testing.T) {
	outsideEnclave(t)
	b, err := New(context.Background())
	if b != nil || !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("New = %v, %v; want nil, ErrSGXUnavailable", b, err)
	}
	var se *SGXEnclaveError
	if !errors.As(err, &se) || se.Op == "" {
		t.Fatalf("New = %v, want an SGXEnclaveError naming its step", err)
	}
	if _, err := New(nil); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("New(nil) = %v, want ErrSGXUnavailable", err)
	}
}

// TestBackendShape checks the fixed facts of a backend; the zero value is
// used because New refuses here.
func TestBackendShape(t *testing.T) {
	b := newTestBackend()
	if b.Name() != "intel-sgx" || b.Rank() != 2 || !b.ConfinesProcess() {
		t.Fatalf("Name, Rank, ConfinesProcess = %q, %d, %v; want intel-sgx, 2, true", b.Name(), b.Rank(), b.ConfinesProcess())
	}
	outsideEnclave(t)
	if err := b.Probe(context.Background()); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Probe = %v, want ErrSGXUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) = %v, want context.Canceled", err)
	}
}
