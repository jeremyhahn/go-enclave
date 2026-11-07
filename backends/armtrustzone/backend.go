package armtrustzone

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the name the backend is registered under.
const Name = "arm-trustzone"

// rank places the backend above the secretmem backend: its random bytes come
// from the secure world, beyond the reach of this process's memory.
const rank = 2

// The trusted application's interface (trusted-firmware v0.4.2-alpha,
// optee/ta/include/tfw_ta.h). Commands 0x3 and 0x4 are held and never called.
const (
	taUUID             = "23751b49-3a76-4e49-b63c-e5853742fa1f"
	taCmdGetInfo       = 0x00000001 // TFW_TA_CMD_GET_INFO
	taCmdGetRandom     = 0x00000002 // TFW_TA_CMD_GET_RANDOM
	taInterfaceVersion = 1          // TFW_TA_INTERFACE_VERSION
	taInfoFlags        = 0          // TFW_TA_INFO_FLAGS
	taRandomMax        = 4096       // TFW_TA_RANDOM_MAX
)

// Backend is a session with the trusted application in OP-TEE, reached
// through the Linux TEE driver. It makes memory enclave handles filled with
// random bytes the secure world produced. Its methods are safe for concurrent
// use; calls to the TA are serialized on the session.
type Backend struct {
	c *client
}

// Connect opens the TEE device at endpoint (such as "/dev/tee0"), opens a
// session with the trusted application, and checks its interface with
// GET_INFO. A missing or refusing device is a [DeviceError], a missing TA or
// refused session a [SessionError], and an interface other than version 1 with
// flags 0 an [InterfaceError]. Close the Backend to end the session.
func Connect(endpoint string) (*Backend, error) {
	uuid, err := parseUUID(taUUID)
	if err != nil {
		return nil, err
	}
	c, err := openClient(endpoint, uuid)
	if err != nil {
		return nil, err
	}
	b := &Backend{c: c}
	if err := b.Probe(context.Background()); err != nil {
		_ = c.close()
		return nil, err
	}
	return b, nil
}

// Name is [Name].
func (b *Backend) Name() string { return Name }

// Rank is above the secretmem backend's.
func (b *Backend) Rank() int { return rank }

// Probe runs GET_INFO and accepts interface version 1 with flags 0 only. ctx
// bounds the call; a nil ctx never ends.
func (b *Backend) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	version, flags, err := b.c.getInfo(ctx)
	if err != nil {
		return err
	}
	return checkInfo(version, flags)
}

// Random returns a memory enclave handle of n bytes filled by GET_RANDOM, in
// chunks of at most 4096 bytes, each written straight into the handle. n below
// 1 is a [SizeError], refused before the TA is called. On any failure,
// including a canceled ctx, no handle is returned and the bytes already
// written are wiped.
func (b *Backend) Random(ctx context.Context, n int) (enclave.Handle, error) {
	if n < 1 {
		return nil, &SizeError{N: n}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mem, err := enclave.NewMemorySized(n)
	if err != nil {
		return nil, err
	}
	err = mem.WithBytes(func(dst []byte) error { return b.c.fillRandom(ctx, dst, chunkPlan(n)) })
	if err != nil {
		if derr := mem.Destroy(); derr != nil {
			return nil, &enclave.CleanupError{Failure: err, Causes: []error{derr}}
		}
		return nil, err
	}
	return &handle{ByteAccess: mem, backend: b}, nil
}

// Close ends the session and closes the device. It waits out a call in
// flight, and is idempotent; later calls return [ErrBackendClosed].
func (b *Backend) Close() error { return b.c.close() }

// Connector is the value to register with [enclave.Register]: it names the
// backend, and its Connect makes one.
type Connector struct{}

// Name is [Name].
func (Connector) Name() string { return Name }

// Connect is [Connect], as an [enclave.Backend].
func (Connector) Connect(endpoint string) (enclave.Backend, error) {
	b, err := Connect(endpoint)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// handle is a memory enclave the backend filled; it reports the backend as
// its maker.
type handle struct {
	enclave.ByteAccess
	backend *Backend
}

// Backend is the backend that filled the handle.
func (h *handle) Backend() enclave.Backend { return h.backend }

// chunk is one GET_RANDOM call: n bytes at off in the handle.
type chunk struct {
	off, n int
}

// chunkPlan splits n bytes into GET_RANDOM calls of at most taRandomMax bytes,
// in order.
func chunkPlan(n int) []chunk {
	plan := make([]chunk, 0, (n+taRandomMax-1)/taRandomMax)
	for off := 0; off < n; off += taRandomMax {
		plan = append(plan, chunk{off: off, n: min(taRandomMax, n-off)})
	}
	return plan
}

// checkInfo accepts GET_INFO's interface version 1 with flags 0, and nothing
// else.
func checkInfo(version, flags uint64) error {
	if version != taInterfaceVersion || flags != taInfoFlags {
		return &InterfaceError{Version: version, Flags: flags}
	}
	return nil
}
