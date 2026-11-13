package armtrustzone

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// openFDs counts the file descriptors this process holds open.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot list /proc/self/fd: %v", err)
	}
	return len(ents)
}

// infoTEE is the fake TEE with GET_INFO answering version and flags in
// place of the interface the fake's TA reports.
type infoTEE struct {
	*fakeTEE
	version, flags uint64
}

func (f *infoTEE) ioctlBuf(fd int, req uintptr, p unsafe.Pointer, size uintptr) error {
	err := f.fakeTEE.ioctlBuf(fd, req, p, size)
	if err == nil && req == teeIOCInvoke {
		buf := (*teeInvokeBuf)(p)
		if buf.Arg.Func == taCmdGetInfo && buf.Arg.Ret == teecSuccess {
			buf.Params[0].A, buf.Params[0].B = f.version, f.flags
		}
	}
	return err
}

// fakeBackend returns a Backend with a session on drv's fake endpoint.
func fakeBackend(t *testing.T, drv teeDriver) *Backend {
	t.Helper()
	uuid, err := parseUUID(taUUID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := openClientOn(drv, fakeEndpoint, uuid)
	if err != nil {
		t.Fatalf("openClientOn: %v", err)
	}
	return &Backend{c: c}
}

func TestConnectMissingEndpoint(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "tee0")
	before := openFDs(t)
	b, err := Connect(endpoint)
	if b != nil {
		t.Fatalf("Connect returned a backend %v on a missing endpoint", b)
	}
	var de *DeviceError
	if !errors.As(err, &de) {
		t.Fatalf("Connect error = %v (%T), want a *DeviceError", err, err)
	}
	if de.Endpoint != endpoint {
		t.Errorf("DeviceError.Endpoint = %q, want %q", de.Endpoint, endpoint)
	}
	if after := openFDs(t); after != before {
		t.Errorf("open fds went from %d to %d", before, after)
	}
}

func TestConnectorConnectMissingEndpoint(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "tee0")
	_, want := Connect(endpoint)
	b, err := Connector{}.Connect(endpoint)
	if b != nil {
		t.Fatalf("Connector.Connect returned a non-nil enclave.Backend %#v", b)
	}
	var de *DeviceError
	if !errors.As(err, &de) {
		t.Fatalf("Connector.Connect error = %v (%T), want a *DeviceError", err, err)
	}
	if err.Error() != want.Error() {
		t.Errorf("Connector.Connect error = %q, want Connect's %q", err, want)
	}
}

func TestProbeNilContext(t *testing.T) {
	f := newFakeTEE(t, false)
	b := fakeBackend(t, f)
	defer func() { _ = b.Close() }()
	if err := b.Probe(nil); err != nil {
		t.Fatalf("Probe(nil) = %v", err)
	}
	if n := len(f.calls(taCmdGetInfo)); n != 1 {
		t.Errorf("GET_INFO ran %d times, want 1", n)
	}
}

func TestProbeCommandFailure(t *testing.T) {
	f := newFakeTEE(t, false)
	b := fakeBackend(t, f)
	defer func() { _ = b.Close() }()
	f.fail(taCmdGetInfo, fakeErrGeneric)
	err := b.Probe(context.Background())
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("Probe error = %v (%T), want a *CommandError", err, err)
	}
	if ce.Command != taCmdGetInfo || ce.Code != fakeErrGeneric {
		t.Errorf("CommandError = %+v, want command %#x code %#x", ce, taCmdGetInfo, fakeErrGeneric)
	}
}

func TestProbeRefusedInterface(t *testing.T) {
	for _, tc := range []struct {
		name           string
		version, flags uint64
	}{
		{"version", taInterfaceVersion + 1, taInfoFlags},
		{"flags", taInterfaceVersion, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &infoTEE{fakeTEE: newFakeTEE(t, false), version: tc.version, flags: tc.flags}
			b := fakeBackend(t, f)
			defer func() { _ = b.Close() }()
			err := b.Probe(context.Background())
			want := checkInfo(tc.version, tc.flags)
			var ie *InterfaceError
			if !errors.As(err, &ie) {
				t.Fatalf("Probe error = %v (%T), want an *InterfaceError", err, err)
			}
			if err.Error() != want.Error() {
				t.Errorf("Probe error = %q, want checkInfo's %q", err, want)
			}
		})
	}
}

func TestCloseTwice(t *testing.T) {
	f := newFakeTEE(t, false)
	b := fakeBackend(t, f)
	if err := b.Close(); err != nil {
		t.Fatalf("first Close = %v", err)
	}
	if err := b.Close(); !errors.Is(err, ErrBackendClosed) {
		t.Errorf("second Close = %v, want ErrBackendClosed", err)
	}
	if n := f.live(); n != 0 {
		t.Errorf("%d shared-memory objects live after Close", n)
	}
	f.mu.Lock()
	devs := len(f.devs)
	f.mu.Unlock()
	if devs != 0 {
		t.Errorf("%d device fds open after Close", devs)
	}
	if err := b.Probe(context.Background()); !errors.Is(err, ErrBackendClosed) {
		t.Errorf("Probe after Close = %v, want ErrBackendClosed", err)
	}
}
