//go:build linux

package tpm

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// openDevice opens the TPM device file, or a simulator's command socket
// named "unix:<path>" or "tcp:<host:port>".
func openDevice(path string, alloc allocator) (device, error) {
	dial := func(ctx context.Context) (io.ReadWriteCloser, error) { return dialDevice(ctx, path) }
	rw, err := dial(context.Background())
	if err != nil {
		return nil, &DeviceError{Path: path, Op: "open", Err: err}
	}
	t, err := newStreamTransport(rw, path, alloc)
	if err != nil {
		_ = rw.Close()
		return nil, err
	}
	t.dial = dial
	return &tpmDevice{t: t}, nil
}

func dialDevice(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	var d net.Dialer
	switch {
	case strings.HasPrefix(path, "unix:"):
		return d.DialContext(ctx, "unix", strings.TrimPrefix(path, "unix:"))
	case strings.HasPrefix(path, "tcp:"):
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(path, "tcp:"))
	}
	return openCharDevice(path)
}

// openCharDevice opens path read-write only if it is absolute and names a
// character device, so that a TPM path never reaches a regular file.
func openCharDevice(path string) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, errors.New("the device path is not absolute")
	}
	f, err := os.OpenFile(clean, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		_ = f.Close()
		return nil, errors.New("the path is not a character device")
	}
	return f, nil
}

// lockedAllocator maps each transient on its own anonymous pages, locked
// in RAM and excluded from core dumps.
type lockedAllocator struct {
	mu   sync.Mutex
	maps map[*byte][]byte
}

func newAllocator() allocator { return &lockedAllocator{maps: make(map[*byte][]byte)} }

func (a *lockedAllocator) alloc(n int) ([]byte, error) {
	page := os.Getpagesize()
	size := (n + page - 1) / page * page
	m, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, errors.Join(ErrLockedMemory, err)
	}
	if err := unix.Mlock(m); err != nil {
		_ = unix.Munmap(m)
		return nil, errors.Join(ErrLockedMemory, err)
	}
	_ = unix.Madvise(m, unix.MADV_DONTDUMP)
	a.mu.Lock()
	a.maps[&m[0]] = m
	a.mu.Unlock()
	return m[:n:n], nil
}

func (a *lockedAllocator) free(b []byte) {
	if cap(b) == 0 {
		return
	}
	a.mu.Lock()
	m, ok := a.maps[&b[:1][0]]
	delete(a.maps, &b[:1][0])
	a.mu.Unlock()
	if ok {
		_ = unix.Munlock(m)
		_ = unix.Munmap(m)
	}
}
