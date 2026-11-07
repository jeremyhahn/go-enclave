package armtrustzone

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectOnAMissingDevice(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "tee0")
	b, err := Connect(endpoint)
	var de *DeviceError
	if b != nil || !errors.Is(err, ErrDeviceUnavailable) || !errors.As(err, &de) {
		t.Fatalf("Connect(%q) = %v, %v; want a DeviceError", endpoint, b, err)
	}
	if de.Endpoint != endpoint || de.Op != "open" || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("DeviceError = %+v, want the endpoint, op open and a cause matching fs.ErrNotExist", de)
	}
	if _, err := (Connector{}).Connect(endpoint); !errors.Is(err, ErrDeviceUnavailable) {
		t.Errorf("Connector.Connect(%q) = %v, want ErrDeviceUnavailable", endpoint, err)
	}
}

// TestCanceledWaitForTheSessionLock checks that a caller queued behind
// another holder of the session lock leaves once its context is done.
func TestCanceledWaitForTheSessionLock(t *testing.T) {
	c := &client{sem: make(chan struct{}, 1)}
	c.sem <- struct{}{} // another operation holds the session

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.getInfo(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("getInfo(canceled) = %v, want context.Canceled", err)
	}
	if err := c.fillRandom(canceled, make([]byte, 1), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("fillRandom(canceled) = %v, want context.Canceled", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := c.getInfo(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("getInfo(ctx) = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("getInfo still waits for the session lock after its context ended")
	}
	if len(c.sem) != 1 {
		t.Error("a canceled caller released a lock it never took")
	}
}
