package inteltdx

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

var _ enclave.Attester = (*Backend)(nil)

// A nonce of no bytes or of more than REPORTDATA holds is refused before any
// request, on every platform.
func TestAttestRefusesNonceLength(t *testing.T) {
	b := testBackend()
	for _, n := range []int{0, reportDataSize + 1} {
		ev, err := b.Attest(context.Background(), make([]byte, n))
		if !errors.Is(err, enclave.ErrInvalidNonce) {
			t.Errorf("Attest(%d-byte nonce) = %v, want ErrInvalidNonce", n, err)
		}
		if ev.Format != "" || ev.Data != nil {
			t.Errorf("Attest(%d-byte nonce) evidence = %+v, want zero", n, ev)
		}
	}
	if _, err := b.Attest(context.Background(), nil); !errors.Is(err, enclave.ErrInvalidNonce) {
		t.Errorf("Attest(nil) = %v, want ErrInvalidNonce", err)
	}
}

// Q4: the nonce occupies REPORTDATA from offset 0 and the rest is zero.
func TestReportDataLayout(t *testing.T) {
	for _, n := range []int{1, 32, reportDataSize} {
		nonce := make([]byte, n)
		for i := range nonce {
			nonce[i] = byte(0xA0 + i%16)
		}
		rd, err := reportData(nonce)
		if err != nil {
			t.Fatalf("reportData(%d bytes) = %v", n, err)
		}
		if len(rd) != reportDataSize {
			t.Fatalf("reportData is %d bytes, want %d", len(rd), reportDataSize)
		}
		if !bytes.Equal(rd[:n], nonce) {
			t.Errorf("reportData(%d bytes)[:%d] = %x, want %x", n, n, rd[:n], nonce)
		}
		if !bytes.Equal(rd[n:], make([]byte, reportDataSize-n)) {
			t.Errorf("reportData(%d bytes)[%d:] = %x, want zeros", n, n, rd[n:])
		}
	}
}

// Q4's stated consequence: a nonce and the same nonce with trailing zeros give
// one REPORTDATA, so a relying party that cares sends 64 bytes.
func TestReportDataTrailingZeros(t *testing.T) {
	short, err := reportData([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	long, err := reportData([]byte{1, 2, 3, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if short != long {
		t.Fatalf("reportData differs: %x vs %x", short, long)
	}
}

// The padding copies the nonce: the caller's slice is not retained.
func TestReportDataCopies(t *testing.T) {
	nonce := []byte{9, 9}
	rd, err := reportData(nonce)
	if err != nil {
		t.Fatal(err)
	}
	nonce[0] = 0
	if rd[0] != 9 {
		t.Fatalf("reportData shares the caller's nonce")
	}
}

func TestAttestEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testBackend().Attest(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest(canceled) = %v, want context.Canceled", err)
	}
}

// holdSlot takes b's Attest slot, as a call waiting on a slow quote does,
// until release is called.
func holdSlot(b *Backend) (release func()) {
	b.mu.Lock()
	return b.mu.Unlock
}

// TestAttestDeadlineWhileSlotHeld: a caller whose deadline ends while another
// call holds the slot returns its context's error at once, not after the
// other call's quote.
func TestAttestDeadlineWhileSlotHeld(t *testing.T) {
	b := testBackend()
	release := holdSlot(b)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := b.Attest(ctx, []byte{1})
		done <- err
	}()
	select {
	case err := <-done:
		release()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Attest(deadline, slot held) = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		release()
		<-done
		t.Fatal("Attest waited past its deadline behind a held slot")
	}
}
