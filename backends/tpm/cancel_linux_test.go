//go:build linux

package tpm

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// silentTPM is a simulator socket that accepts commands and never answers.
type silentTPM struct {
	path string
	ln   net.Listener
	got  chan struct{} // a command arrived
	wg   sync.WaitGroup

	mu    sync.Mutex
	conns []net.Conn
}

func newSilentTPM(t *testing.T) *silentTPM {
	t.Helper()
	s := &silentTPM{path: filepath.Join(t.TempDir(), "tpm.sock"), got: make(chan struct{}, 1)}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", s.path)
	if err != nil {
		t.Skipf("no unix socket: %v", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				buf := make([]byte, maxResponseBytes)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					select {
					case s.got <- struct{}{}:
					default:
					}
				}
			}()
		}
	}()
	t.Cleanup(s.close)
	return s
}

// close stops the listener and drops every connection, so that a call the
// provider failed to interrupt sees EOF, and waits for the server.
func (s *silentTPM) close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	s.wg.Wait()
}

func newSilentProtector(t *testing.T, s *silentTPM) *KeyProtector {
	t.Helper()
	alloc := newAllocator()
	dev, err := openDevice("unix:"+s.path, alloc)
	if err != nil {
		t.Fatal(err)
	}
	return newKeyProtector(dev, alloc, config{attempts: defaultAttempts, backoff: time.Millisecond})
}

// within runs f and fails the test unless it returns within d.
func within(t *testing.T, d time.Duration, what string, f func() error) error {
	t.Helper()
	errc := make(chan error, 1)
	start := time.Now()
	go func() { errc <- f() }()
	select {
	case err := <-errc:
		return err
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (started %v ago)", what, d, time.Since(start).Round(time.Millisecond))
		return nil
	}
}

// settles fails the test unless the goroutine count falls back to base.
func settles(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("%d goroutines remain, %d before the test:\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKeyProtector_ContextEndsOnSilentTPM(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSilentTPM(t)
	p := newSilentProtector(t, s)
	const bound = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := within(t, bound, "Protect after its context ended", func() error {
		_, err := p.Protect(ctx, make([]byte, 32))
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Protect: %v, want %v", err, context.DeadlineExceeded)
	}

	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		<-s.got
		cancel()
	}()
	key := make([]byte, 32)
	err = within(t, bound, "Unprotect after its context was canceled", func() error {
		return p.Unprotect(ctx, testBlob(t), key)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Unprotect: %v, want %v", err, context.Canceled)
	}

	if err := within(t, bound, "Close", p.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s.close()
	settles(t, base)
}

func TestKeyProtector_CloseInterruptsStuckCall(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSilentTPM(t)
	p := newSilentProtector(t, s)

	errc := make(chan error, 1)
	go func() {
		_, err := p.Protect(context.Background(), make([]byte, 32))
		errc <- err
	}()
	<-s.got
	if err := within(t, 5*time.Second, "Close with a call stuck in the TPM", p.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the stuck Protect succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("the stuck Protect did not return after Close")
	}
	if _, err := p.Protect(context.Background(), make([]byte, 32)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Protect after Close: %v, want %v", err, ErrClosed)
	}
	s.close()
	settles(t, base)
}

// TestKeyProtector_CloseRefusesQueuedCall holds Close to its bound when a
// second call waits behind one stuck in the TPM: the waiting call returns
// ErrClosed without reaching the device, so it cannot take the provider
// after Close has spent its one interrupt.
func TestKeyProtector_CloseRefusesQueuedCall(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSilentTPM(t)
	p := newSilentProtector(t, s)

	stuck := make(chan error, 1)
	go func() {
		_, err := p.Protect(context.Background(), make([]byte, 32))
		stuck <- err
	}()
	<-s.got
	queued := make(chan error, 1)
	go func() {
		_, err := p.Protect(context.Background(), make([]byte, 32))
		queued <- err
	}()
	waitQueued(t)

	bound := defaultCloseWait + 2*cleanupTimeout + time.Second
	if err := within(t, bound, "Close with a call stuck in the TPM and one queued", p.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-queued:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("queued Protect: %v, want %v", err, ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("the queued Protect did not return after Close")
	}
	select {
	case err := <-stuck:
		var de *DeviceError
		if !errors.As(err, &de) {
			t.Fatalf("stuck Protect: %v, want a DeviceError", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the stuck Protect did not return after Close")
	}
	select {
	case <-s.got:
		t.Fatal("the TPM received a command after the stuck one")
	default:
	}
	if _, err := p.Protect(context.Background(), make([]byte, 32)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Protect after Close: %v, want %v", err, ErrClosed)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	s.close()
	settles(t, base)
}

// waitQueued returns once a goroutine is blocked in acquire, waiting for
// the provider.
func waitQueued(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			header, _, _ := strings.Cut(g, "\n")
			blocked := strings.Contains(header, "[select") || strings.Contains(header, "[chan send")
			if blocked && strings.Contains(g, "(*KeyProtector).acquire(") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no call queued for the provider")
}
