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
	"syscall"
	"testing"
)

// TestOpenDevice_RefusesPath opens paths that exist and can be read and
// written but are not TPM devices: each is refused with a DeviceError
// naming the path.
func TestOpenDevice_RefusesPath(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "tpmrm0")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	for name, path := range map[string]string{
		"relative":        "tpmrm0",
		"relative_dot":    "./tpmrm0",
		"regular_file":    regular,
		"unclean_regular": dir + "/../" + filepath.Base(dir) + "/tpmrm0",
		"directory":       dir,
	} {
		t.Run(name, func(t *testing.T) {
			dev, err := openDevice(path, newFakeAllocator())
			if err == nil {
				_ = dev.close()
				t.Fatalf("openDevice(%q) succeeded, want a refusal", path)
			}
			var de *DeviceError
			if !errors.As(err, &de) || !errors.Is(err, ErrDeviceUnavailable) {
				t.Fatalf("got %v, want a DeviceError", err)
			}
			if de.Path != path || de.Op != "open" || !strings.Contains(err.Error(), path) {
				t.Fatalf("got %v (path %q, op %q), want the open of %q named", err, de.Path, de.Op, path)
			}
		})
	}
}

// TestOpenDevice_CharacterDevice opens a character device that is not a
// TPM: the path checks pass it, and the transport only opens it.
func TestOpenDevice_CharacterDevice(t *testing.T) {
	dev, err := openDevice("/dev/null", newFakeAllocator())
	if err != nil {
		t.Fatalf("openDevice(/dev/null): %v", err)
	}
	if err := dev.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestResourceManaged decides from the path, or from the link target when
// the path resolves: a simulator socket and tpm0 have no resource manager.
func TestResourceManaged(t *testing.T) {
	dir := t.TempDir()
	rmFile := filepath.Join(dir, "tpmrm0")
	rawFile := filepath.Join(dir, "tpm0")
	for _, f := range []string{rmFile, rawFile} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := filepath.Join(dir, "links")
	if err := os.Mkdir(links, 0o700); err != nil {
		t.Fatal(err)
	}
	toRM := filepath.Join(links, "tpm0")
	toRaw := filepath.Join(links, "tpmrm0")
	if err := os.Symlink(rmFile, toRM); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rawFile, toRaw); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"unix_socket", "unix:/x", false},
		{"tcp_socket", "tcp:127.0.0.1:1", false},
		{"missing_rm", "/nowhere/tpmrm0", true},
		{"missing_raw", "/nowhere/tpm0", false},
		{"link_to_rm", toRM, true},
		{"link_to_raw", toRaw, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceManaged(tc.path); got != tc.want {
				t.Fatalf("resourceManaged(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// echoOnce accepts one connection on l and sends back the one byte it reads.
func echoOnce(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		_, _ = c.Write(b)
	}()
}

// TestDialDevice reaches a simulator socket on both transports and carries
// one byte each way; a missing socket is an error, and openDevice names it.
func TestDialDevice(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ul.Close() })
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tl.Close() })

	for name, tc := range map[string]struct {
		l    net.Listener
		path string
	}{
		"unix": {ul, "unix:" + sock},
		"tcp":  {tl, "tcp:" + tl.Addr().String()},
	} {
		t.Run(name, func(t *testing.T) {
			echoOnce(t, tc.l)
			rw, err := dialDevice(context.Background(), tc.path)
			if err != nil {
				t.Fatalf("dialDevice(%q): %v", tc.path, err)
			}
			defer func() { _ = rw.Close() }()
			if _, err := rw.Write([]byte{0x5a}); err != nil {
				t.Fatalf("write: %v", err)
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(rw, b); err != nil || b[0] != 0x5a {
				t.Fatalf("read %x, %v; want 5a", b, err)
			}
		})
	}

	missing := "unix:" + filepath.Join(dir, "missing")
	t.Run("missing_socket", func(t *testing.T) {
		rw, err := dialDevice(context.Background(), missing)
		if err == nil {
			_ = rw.Close()
			t.Fatalf("dialDevice(%q) succeeded, want an error", missing)
		}
	})
	t.Run("open_refused_dial", func(t *testing.T) {
		dev, err := openDevice(missing, newFakeAllocator())
		if err == nil {
			_ = dev.close()
			t.Fatalf("openDevice(%q) succeeded, want a refusal", missing)
		}
		var de *DeviceError
		if !errors.As(err, &de) || de.Op != "open" || de.Path != missing {
			t.Fatalf("got %v, want a DeviceError for the open of %q", err, missing)
		}
	})
}

// TestOpenCharDevice refuses a relative path before any file system access
// and a path that is not a character device, and opens /dev/null.
func TestOpenCharDevice(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "f")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, want string
	}{
		// The relative path does not exist: an open would fail with
		// ENOENT, so the "not absolute" error shows nothing was touched.
		{"relative", "no/such/tpmrm0", "not absolute"},
		{"regular_file", regular, "not a character device"},
		// A read-write open of a directory fails with EISDIR before the
		// mode check: the refusal comes from the kernel.
		{"directory", dir, syscall.EISDIR.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := openCharDevice(tc.path)
			if err == nil {
				_ = f.Close()
				t.Fatalf("openCharDevice(%q) succeeded, want %q", tc.path, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("openCharDevice(%q) = %v, want %q", tc.path, err, tc.want)
			}
		})
	}

	t.Run("dev_null", func(t *testing.T) {
		f, err := openCharDevice("/dev/null")
		if err != nil {
			t.Fatalf("openCharDevice(/dev/null): %v", err)
		}
		if f == nil {
			t.Fatal("openCharDevice(/dev/null) returned a nil file")
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	})
}

// TestLockedAllocator_Free releases only what alloc handed out, once: every
// other slice is a no-op, and no case panics.
func TestLockedAllocator_Free(t *testing.T) {
	newLocked := func(t *testing.T) *lockedAllocator {
		t.Helper()
		a, ok := newAllocator().(*lockedAllocator)
		if !ok {
			t.Fatal("newAllocator is not a *lockedAllocator")
		}
		return a
	}
	mustAlloc := func(t *testing.T, a *lockedAllocator, n int) []byte {
		t.Helper()
		b, err := a.alloc(n)
		if err != nil {
			t.Skipf("alloc(%d): %v (locked memory unavailable)", n, err)
		}
		return b
	}

	// The no-op slices reach free through a table, the way a caller hands
	// back whatever it holds.
	for name, zero := range map[string]func(b []byte) []byte{
		"nil":          func([]byte) []byte { return nil },
		"zero_cap":     func([]byte) []byte { return make([]byte, 0) },
		"zero_cap_sub": func(b []byte) []byte { return b[:0:0] },
	} {
		t.Run(name, func(t *testing.T) {
			a := newLocked(t)
			b := mustAlloc(t, a, 16)
			defer a.free(b)
			a.free(zero(b))
			if len(a.maps) != 1 {
				t.Fatalf("free(%s) changed the maps: %d entries, want 1", name, len(a.maps))
			}
		})
	}
	t.Run("foreign", func(t *testing.T) {
		a := newLocked(t)
		b := mustAlloc(t, a, 16)
		defer a.free(b)
		a.free(make([]byte, 16))
		a.free(b[1:])
		if len(a.maps) != 1 {
			t.Fatalf("free of a foreign slice changed the maps: %d entries, want 1", len(a.maps))
		}
	})
	t.Run("twice", func(t *testing.T) {
		a := newLocked(t)
		b := mustAlloc(t, a, 16)
		a.free(b)
		a.free(b)
		if len(a.maps) != 0 {
			t.Fatalf("free twice left %d entries, want 0", len(a.maps))
		}
	})
	t.Run("alloc_zero", func(t *testing.T) {
		a := newLocked(t)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("alloc(0) panicked: %v", r)
			}
		}()
		b, err := a.alloc(0)
		if err != nil {
			if !errors.Is(err, ErrLockedMemory) {
				t.Fatalf("alloc(0) = %v, want an ErrLockedMemory error", err)
			}
			if len(a.maps) != 0 {
				t.Fatalf("a refused alloc(0) left %d entries", len(a.maps))
			}
			return
		}
		if len(b) != 0 {
			t.Fatalf("alloc(0) returned %d bytes, want 0", len(b))
		}
		a.free(b)
	})
}
