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

// seal runs SEAL (TFW_TA_CMD_SEAL) on plaintext under associated data ad and
// returns the sealed blob. The output buffer starts at
// len(plaintext)+sealOverhead bytes and grows once, to the size the TA
// reports, on TEE_ERROR_SHORT_BUFFER (see sealNext).
func (c *client) seal(ctx context.Context, plaintext, ad []byte) ([]byte, error) {
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if c.closed {
		return nil, ErrBackendClosed
	}
	size, retried := len(plaintext)+sealOverhead, false
	for {
		blob, got, err := c.sealOnce(ctx, plaintext, ad, size)
		next, err := sealNext(err, size, got, retried)
		switch {
		case err != nil:
			return nil, err
		case next == 0:
			return blob, nil
		}
		size, retried = next, true
	}
}

// sealOnce is one SEAL call with an output buffer of size bytes. Plaintext,
// ad and the output share one driver shared memory allocation, wiped after
// the call; got is the size the TA reported in its output memref.
func (c *client) sealOnce(ctx context.Context, plaintext, ad []byte, size int) (blob []byte, got uint64, err error) {
	err = c.withDriverShm(len(plaintext)+len(ad)+size, func(id int32, shm []byte) error {
		adOff, outOff := len(plaintext), len(plaintext)+len(ad)
		copy(shm, plaintext)
		copy(shm[adOff:], ad)
		var params [teeNumParams]teeParam
		params[0] = memref(teeParamAttrTypeMemrefInput, id, 0, len(plaintext))
		params[1] = memref(teeParamAttrTypeMemrefInput, id, adOff, len(ad))
		params[2] = memref(teeParamAttrTypeMemrefOutput, id, outOff, size)
		err := c.invoke(ctx, taCmdSeal, &params)
		got = params[2].B
		if err == nil && got <= uint64(size) { //nolint:gosec // size is a buffer length, never negative
			blob = append([]byte(nil), shm[outOff:outOff+int(got)]...) //nolint:gosec // got is at most size
		}
		return err
	})
	return blob, got, err
}

// unseal runs UNSEAL (TFW_TA_CMD_UNSEAL) on blob under associated data ad,
// writing the plaintext into dst. When the driver registers dst's pages the
// TA writes into dst directly; otherwise the plaintext lands in driver
// shared memory, is copied into dst and wiped. Errors are mapped by
// unsealResult; on an error dst may hold partial output, which the caller
// wipes.
func (c *client) unseal(ctx context.Context, blob, ad, dst []byte) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.closed {
		return ErrBackendClosed
	}
	var got uint64
	err := c.withDriverShm(len(blob)+len(ad)+len(dst), func(id int32, shm []byte) error {
		adOff, outOff := len(blob), len(blob)+len(ad)
		copy(shm, blob)
		copy(shm[adOff:], ad)
		var params [teeNumParams]teeParam
		params[0] = memref(teeParamAttrTypeMemrefInput, id, 0, len(blob))
		params[1] = memref(teeParamAttrTypeMemrefInput, id, adOff, len(ad))
		params[2] = memref(teeParamAttrTypeMemrefOutput, id, outOff, len(dst))
		direct := false
		if c.regMem && len(dst) > 0 {
			// The driver holds dst's address for as long as the
			// registration lives: keep dst pinned until dstFD is closed
			// (defers run in reverse, so the close comes first).
			var pin runtime.Pinner
			defer pin.Unpin()
			pin.Pin(unsafe.SliceData(dst)) //nolint:gosec // dst's backing array, len(dst) > 0; stays pinned until dstFD is closed
			if dstFD, dstID, err := c.registerShm(dst); err == nil {
				defer unix.Close(dstFD)
				params[2] = memref(teeParamAttrTypeMemrefOutput, dstID, 0, len(dst))
				direct = true
			}
			// Otherwise the driver refused these pages (secretmem pages
			// cannot be pinned): the output goes through shm.
		}
		err := c.invoke(ctx, taCmdUnseal, &params)
		got = params[2].B
		if err == nil && !direct && got == uint64(len(dst)) { //nolint:gosec // len(dst) is never negative
			copy(dst, shm[outOff:])
		}
		return err
	})
	return unsealResult(err, got, len(dst))
}

// withDriverShm allocates size bytes of driver shared memory, maps it and
// calls f with the allocation's id and the mapping. The mapping is wiped
// before it is released: it may have held key material.
func (c *client) withDriverShm(size int, f func(id int32, shm []byte) error) error {
	alloc := teeShmAllocData{Size: uint64(size)}                         //nolint:gosec // size is a sum of buffer lengths, never negative
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
	return f(alloc.ID, shm)
}

// memref is a memref parameter of type attr: n bytes at off in the shared
// memory with the driver's id.
func memref(attr uint64, id int32, off, n int) teeParam {
	return teeParam{Attr: attr, A: uint64(off), B: uint64(n), C: uint64(uint32(id))} //nolint:gosec // off and n are buffer offsets and lengths, never negative; id is the driver's shm id, reinterpreted as the header's u64
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
	// The params come back on a failed command too: TEE_ERROR_SHORT_BUFFER
	// reports the size it needed in its output memref.
	*params = buf.Params
	if buf.Arg.Ret != teecSuccess {
		return &CommandError{Command: fn, Code: buf.Arg.Ret, Origin: buf.Arg.RetOrigin}
	}
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
