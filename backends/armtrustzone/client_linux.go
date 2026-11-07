package armtrustzone

import (
	"context"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// client is a TEE context with one open session: TEEC_InitializeContext and
// TEEC_OpenSession over the TEE ioctls. mu serializes the calls on the
// session and guards fd against Close.
type client struct {
	endpoint string
	regMem   bool // the driver claims TEE_GEN_CAP_REG_MEM

	// sem is the session lock: a one-slot semaphore, so a caller waiting
	// for it can leave when its context is done.
	sem     chan struct{}
	fd      int
	session uint32
	closed  bool

	cancelID atomic.Uint32
}

// openClient opens endpoint, checks it is a GlobalPlatform TEE
// (TEEC_InitializeContext), and opens a public-login session with the TA
// named by uuid (TEEC_OpenSession).
func openClient(endpoint string, uuid teecUUID) (*client, error) {
	fd, err := unix.Open(endpoint, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &DeviceError{Endpoint: endpoint, Op: "open", Cause: os.NewSyscallError("open", err)}
	}
	c := &client{endpoint: endpoint, fd: fd, sem: make(chan struct{}, 1)}

	var v teeVersionData
	if err := ioctl(fd, teeIOCVersion, unsafe.Pointer(&v)); err != nil { //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
		_ = unix.Close(fd)
		return nil, c.deviceError("version", err)
	}
	if v.GenCaps&teeGenCapGP == 0 {
		_ = unix.Close(fd)
		return nil, &DeviceError{Endpoint: endpoint, Op: "version", Cause: ErrNotGlobalPlatform}
	}
	c.regMem = v.GenCaps&teeGenCapRegMem != 0

	var buf teeOpenSessionBuf
	buf.Arg.UUID = uuid.octets()
	buf.Arg.ClntLogin = teeIOCtlLoginPublic
	buf.Arg.CancelID = c.cancelID.Add(1)
	buf.Arg.NumParams = teeNumParams
	if err := ioctlBuf(fd, teeIOCOpenSession, unsafe.Pointer(&buf), unsafe.Sizeof(buf)); err != nil { //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
		_ = unix.Close(fd)
		return nil, c.deviceError("open-session", err)
	}
	if buf.Arg.Ret != teecSuccess {
		_ = unix.Close(fd)
		return nil, &SessionError{Code: buf.Arg.Ret, Origin: buf.Arg.RetOrigin}
	}
	c.session = buf.Arg.Session
	return c, nil
}

// getInfo invokes TFW_TA_CMD_GET_INFO: param 0 VALUE_OUTPUT, a the interface
// version and b the flags.
func (c *client) getInfo(ctx context.Context) (version, flags uint64, err error) {
	if err := c.lock(ctx); err != nil {
		return 0, 0, err
	}
	defer c.unlock()
	if c.closed {
		return 0, 0, ErrBackendClosed
	}
	var params [teeNumParams]teeParam
	params[0].Attr = teeParamAttrTypeValueOutput
	if err := c.invoke(ctx, taCmdGetInfo, &params); err != nil {
		return 0, 0, err
	}
	return params[0].A, params[0].B, nil
}

// fillRandom fills dst, the handle's locked pages, with TFW_TA_CMD_GET_RANDOM
// in the chunks of plan. Where the driver accepts it, dst itself is
// registered as the shared memory, so the TA writes into the handle; where it
// does not, a driver shared buffer carries each chunk and is zeroed after
// each copy and before it is unmapped, on every path.
func (c *client) fillRandom(ctx context.Context, dst []byte, plan []chunk) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.closed {
		return ErrBackendClosed
	}
	if c.regMem {
		// The driver holds dst's address for as long as the registration
		// lives: keep dst pinned until shmFD is closed (defers run in
		// reverse, so the close comes first).
		var pin runtime.Pinner
		defer pin.Unpin()
		if len(dst) > 0 {
			pin.Pin(unsafe.SliceData(dst)) //nolint:gosec // dst's backing array, len(dst) > 0; stays pinned until shmFD is closed
		}
		shmFD, id, err := c.registerShm(dst)
		if err == nil {
			defer unix.Close(shmFD)
			for _, ch := range plan {
				if err := c.getRandom(ctx, id, uint64(ch.off), ch.n); err != nil { //nolint:gosec // ch.off is a chunk offset in [0, len(dst)), never negative
					return err
				}
			}
			return nil
		}
		// The driver refused these pages (secretmem pages, for one, cannot
		// be pinned): fall back to driver shared memory.
	}
	return c.fillThroughDriverShm(ctx, dst, plan)
}

// fillThroughDriverShm is fillRandom through one driver shared buffer of the
// largest chunk's size.
func (c *client) fillThroughDriverShm(ctx context.Context, dst []byte, plan []chunk) error {
	size := 0
	for _, ch := range plan {
		size = max(size, ch.n)
	}
	alloc := teeShmAllocData{Size: uint64(size)}
	shmFD, err := ioctlRet(c.fd, teeIOCShmAlloc, unsafe.Pointer(&alloc)) //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
	if err != nil {
		return c.deviceError("shm-alloc", err)
	}
	defer unix.Close(shmFD)
	shm, err := unix.Mmap(shmFD, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return &DeviceError{Endpoint: c.endpoint, Op: "mmap", Cause: os.NewSyscallError("mmap", err)}
	}
	defer func() {
		clear(shm)
		_ = unix.Munmap(shm)
	}()
	for _, ch := range plan {
		err := c.getRandom(ctx, alloc.ID, 0, ch.n)
		if err == nil {
			copy(dst[ch.off:ch.off+ch.n], shm[:ch.n])
		}
		clear(shm[:ch.n])
		if err != nil {
			return err
		}
	}
	return nil
}

// getRandom invokes TFW_TA_CMD_GET_RANDOM for n bytes at off in the shared
// memory id: param 0 MEMREF_OUTPUT. The TA must report writing all n.
func (c *client) getRandom(ctx context.Context, id int32, off uint64, n int) error {
	var params [teeNumParams]teeParam
	params[0] = teeParam{Attr: teeParamAttrTypeMemrefOutput, A: off, B: uint64(n), C: uint64(uint32(id))} //nolint:gosec // n is a chunk size, 1 to 4096; id is the driver's shm id, reinterpreted as the header's u64
	if err := c.invoke(ctx, taCmdGetRandom, &params); err != nil {
		return err
	}
	if params[0].B != uint64(n) { //nolint:gosec // n is a chunk size, 1 to 4096
		return &ShortRandomError{Want: uint64(n), Got: params[0].B} //nolint:gosec // n is a chunk size, 1 to 4096
	}
	return nil
}

// registerShm registers buf as shared memory (TEE_IOC_SHM_REGISTER) and
// returns its file descriptor and id; closing the descriptor unregisters it.
func (c *client) registerShm(buf []byte) (int, int32, error) {
	reg := teeShmRegisterData{Addr: uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf)))), Length: uint64(len(buf))} //nolint:gosec // the TEE ioctl ABI passes the buffer's address to the kernel
	fd, err := ioctlRet(c.fd, teeIOCShmRegister, unsafe.Pointer(&reg))                                                //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
	runtime.KeepAlive(buf)
	if err != nil {
		return -1, 0, err
	}
	return fd, reg.ID, nil
}

// invoke is TEEC_InvokeCommand: it calls command fn with params and returns
// them as the TA left them. A ctx that ends during the call sends
// TEE_IOC_CANCEL for it, and the call returns ctx's error. The session lock is held.
func (c *client) invoke(ctx context.Context, fn uint32, params *[teeNumParams]teeParam) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var buf teeInvokeBuf
	id := c.cancelID.Add(1)
	buf.Arg = teeInvokeArg{Func: fn, Session: c.session, CancelID: id, NumParams: teeNumParams}
	buf.Params = *params

	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(canceled)
		arg := teeCancelArg{CancelID: id, Session: c.session}
		_ = ioctl(c.fd, teeIOCCancel, unsafe.Pointer(&arg)) //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
	})
	err := ioctlBuf(c.fd, teeIOCInvoke, unsafe.Pointer(&buf), unsafe.Sizeof(buf)) //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
	if !stop() {
		<-canceled
	}
	if ctxErr := ctx.Err(); ctxErr != nil && (err != nil || buf.Arg.Ret == teecErrorCancel) {
		return ctxErr
	}
	if err != nil {
		return c.deviceError("invoke", err)
	}
	if buf.Arg.Ret != teecSuccess {
		return &CommandError{Command: fn, Code: buf.Arg.Ret, Origin: buf.Arg.RetOrigin}
	}
	*params = buf.Params
	return nil
}

// close is TEEC_CloseSession and TEEC_FinalizeContext.
func (c *client) close() error {
	c.sem <- struct{}{}
	defer c.unlock()
	if c.closed {
		return ErrBackendClosed
	}
	c.closed = true
	arg := teeCloseSessionArg{Session: c.session}
	serr := ioctl(c.fd, teeIOCCloseSession, unsafe.Pointer(&arg)) //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
	cerr := unix.Close(c.fd)
	switch {
	case serr != nil:
		return c.deviceError("close-session", serr)
	case cerr != nil:
		return &DeviceError{Endpoint: c.endpoint, Op: "close", Cause: os.NewSyscallError("close", cerr)}
	}
	return nil
}

// lock takes the session lock, or returns ctx's error, as invoke does,
// once ctx is done before the lock is free.
func (c *client) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// unlock releases the session lock taken by lock.
func (c *client) unlock() { <-c.sem }

// deviceError is a DeviceError for a refused TEE ioctl.
func (c *client) deviceError(op string, errno error) error {
	return &DeviceError{Endpoint: c.endpoint, Op: op, Cause: os.NewSyscallError("ioctl", errno)}
}

// ioctlBuf passes p, a buffer of size bytes, through a struct
// tee_ioctl_buf_data, as TEE_IOC_OPEN_SESSION and TEE_IOC_INVOKE take it.
func ioctlBuf(fd int, req uintptr, p unsafe.Pointer, size uintptr) error {
	// BufPtr hides p from the runtime as an integer: pin the buffer so its
	// address holds until the kernel is done with it.
	var pin runtime.Pinner
	pin.Pin(p)
	defer pin.Unpin()
	data := teeBufData{BufPtr: uint64(uintptr(p)), BufLen: uint64(size)}
	return ioctl(fd, req, unsafe.Pointer(&data)) //nolint:gosec // the TEE ioctl ABI passes the struct's address to the kernel
}

// ioctl calls ioctl(2), retrying on EINTR.
func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, err := ioctlRet(fd, req, arg)
	return err
}

// ioctlRet calls ioctl(2), retrying on EINTR, and returns its result.
func ioctlRet(fd int, req uintptr, arg unsafe.Pointer) (int, error) {
	for {
		r, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
		switch errno {
		case 0:
			return int(r), nil
		case unix.EINTR:
			continue
		}
		return -1, errno
	}
}
