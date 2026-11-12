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
func newTestBackend() *Backend { return &Backend{} }

// holdAttestSlot takes the attestation slot until the test ends.
func holdAttestSlot(t *testing.T, b *Backend) {
	t.Helper()
	b.mu.Lock()
	t.Cleanup(b.mu.Unlock)
}

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
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("Sweep err = %v, want context.DeadlineExceeded", r.err)
		}
		if r.held != 1 {
			t.Fatalf("Sweep held = %d, want 1", r.held)
		}
	case <-time.After(promptly):
		t.Fatal("Sweep did not return after its context ended while a handle was borrowed")
	}
}

func TestAttestHonoursContextWhileSlotHeld(t *testing.T) {
	b := newTestBackend()
	holdAttestSlot(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := b.Attest(ctx, []byte{1})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Attest err = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(promptly):
		t.Fatal("Attest did not return after its context ended while another call held the slot")
	}
}

// TestNewRefusesOutsideEnclave runs the real constructor on a host that is
// not in an SGX enclave (or not linux/amd64): it refuses with the typed
// unavailable error and builds no backend.
func TestNewRefusesOutsideEnclave(t *testing.T) {
	skipInEnclave(t)
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
	var b Backend
	if b.Name() != "intel-sgx" || b.Rank() != 2 || !b.ConfinesProcess() {
		t.Fatalf("Name, Rank, ConfinesProcess = %q, %d, %v; want intel-sgx, 2, true", b.Name(), b.Rank(), b.ConfinesProcess())
	}
	skipInEnclave(t)
	if err := b.Probe(context.Background()); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Probe = %v, want ErrSGXUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) = %v, want context.Canceled", err)
	}
}
