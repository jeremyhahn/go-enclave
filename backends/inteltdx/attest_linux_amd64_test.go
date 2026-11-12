package inteltdx

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
)

// On a host that is not a TD, Attest stops at its first configfs-tsm step
// with a *TSMReportError naming the step and wrapping the real errno.
func TestAttestRefusesOffTD(t *testing.T) {
	skipInTD(t)
	if _, err := os.Stat(tsmReportRoot); err == nil {
		t.Skip(tsmReportRoot + " is present: the report paths are the integration target's")
	}
	ev, err := testBackend().Attest(context.Background(), []byte("nonce"))
	var te *TSMReportError
	if !errors.As(err, &te) || te.Op != "stat" {
		t.Fatalf("Attest() = %v, want a TSMReportError at stat", err)
	}
	if !errors.Is(err, ErrTSMReportUnavailable) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("Attest() = %v, want ErrTSMReportUnavailable wrapping ENOENT", err)
	}
	if ev.Format != "" || ev.Data != nil {
		t.Fatalf("Attest() evidence = %+v on error, want zero", ev)
	}
}

// Concurrent calls on one backend serialize; under -race this proves the
// lock covers the shared state. Off a TD every call refuses.
func TestAttestConcurrent(t *testing.T) {
	skipInTD(t)
	b := testBackend()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.Attest(context.Background(), []byte{byte(i + 1)}); err == nil {
				t.Errorf("Attest off a TD succeeded")
			}
		}()
	}
	wg.Wait()
}
