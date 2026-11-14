package armtrustzone

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fakeEndpoint is the device node the fake TEE driver answers on.
const fakeEndpoint = "/dev/fake-tee0"

// Result codes the fake trusted application answers with, beside the ones
// the package declares.
const (
	fakeErrGeneric       uint32 = 0xffff0000 // TEE_ERROR_GENERIC
	fakeErrBadParameters uint32 = 0xffff0006 // TEE_ERROR_BAD_PARAMETERS
	fakeErrNotSupported  uint32 = 0xffff000a // TEE_ERROR_NOT_SUPPORTED
	fakeErrItemNotFound  uint32 = 0xffff0008 // TEE_ERROR_ITEM_NOT_FOUND
)

// fakeTEE is a teeDriver that stands in for the Linux TEE driver and, behind
// it, for a trusted application with GET_INFO, SEAL and UNSEAL. It checks
// what the driver checks (the device and shared-memory fds, the buffer
// sizes, each memref's shared memory and bounds) and what a SEAL-capable TA
// checks (the parameter types), and reads and writes the memrefs in the
// shared memory the client allocated or registered, as the kernel does.
//
// SEAL's blob is the TA's own: a 12-byte nonce, then AES-256-GCM of the
// plaintext under a key only the fake holds, with the associated data as
// the AAD. UNSEAL answers TEE_ERROR_BAD_FORMAT for a blob too short to be
// one and TEE_ERROR_MAC_INVALID for one that does not open.
type fakeTEE struct {
	regMem bool
	aead   cipher.AEAD

	mu         sync.Mutex
	devs       map[int]bool   // open device fds
	sessions   map[uint32]int // session → its device fd
	shms       map[int32]*fakeShm
	nextFD     int
	nextID     int32
	nextSess   uint32
	invokes    []fakeInvoke
	failures   map[uint32]uint32 // command → the code it answers with
	shortSeals int               // SEALs still to answer TEE_ERROR_SHORT_BUFFER
	shortSize  uint64            // the size those answers ask for
	blockCmd   uint32            // a command that waits for its cancel
	entered    chan struct{}     // closed when blockCmd arrives
	cancels    map[uint32]chan struct{}
	canceled   map[uint32]bool
	faults     []string
}

// fakeShm is a shared-memory object: driver memory from TEE_IOC_SHM_ALLOC,
// or the caller's pages from TEE_IOC_SHM_REGISTER. It is live while its fd
// is open or it is mapped.
type fakeShm struct {
	id         int32
	dev        int // the device fd it belongs to
	fd         int // -1 once closed
	mem        []byte
	mapped     bool
	registered bool
}

// fakeInvoke records one TEE_IOC_INVOKE the TA ran.
type fakeInvoke struct {
	cmd    uint32
	params [teeNumParams]fakeParam
}

// fakeParam is one parameter as the TA saw it. For a memref, window is its
// bytes in shared memory and in, for an input, their SHA-256 on entry: a
// digest, so the record holds no copy of a key for providertest's residue
// sweep to find.
type fakeParam struct {
	attr       uint64
	id         int32
	off, size  uint64
	in         [sha256.Size]byte
	window     []byte
	registered bool
}

var _ teeDriver = (*fakeTEE)(nil)

// newFakeTEE returns a fake TEE whose driver claims TEE_GEN_CAP_REG_MEM when
// regMem is set. When the test ends it fails the test for any fault the fake
// saw, and for any device fd, session or shared memory still open.
func newFakeTEE(t testing.TB, regMem bool) *fakeTEE {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTEE{
		regMem:   regMem,
		aead:     aead,
		devs:     map[int]bool{},
		sessions: map[uint32]int{},
		shms:     map[int32]*fakeShm{},
		nextFD:   100,
		nextID:   1,
		failures: map[uint32]uint32{},
		cancels:  map[uint32]chan struct{}{},
		canceled: map[uint32]bool{},
	}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, fault := range f.faults {
			t.Errorf("fake TEE: %s", fault)
		}
		if len(f.shms) != 0 {
			t.Errorf("fake TEE: %d shared-memory objects outlive the test", len(f.shms))
		}
		if len(f.sessions) != 0 {
			t.Errorf("fake TEE: %d sessions outlive the test", len(f.sessions))
		}
		if len(f.devs) != 0 {
			t.Errorf("fake TEE: %d device fds outlive the test", len(f.devs))
		}
	})
	return f
}

// live is the number of shared-memory objects not yet released.
func (f *fakeTEE) live() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.shms)
}

// calls returns the invocations of cmd so far.
func (f *fakeTEE) calls(cmd uint32) []fakeInvoke {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeInvoke
	for _, inv := range f.invokes {
		if inv.cmd == cmd {
			out = append(out, inv)
		}
	}
	return out
}

// fail makes cmd answer code from now on; a code of 0 restores it.
func (f *fakeTEE) fail(cmd, code uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code == 0 {
		delete(f.failures, cmd)
		return
	}
	f.failures[cmd] = code
}

// shortSeal makes the next times SEALs answer TEE_ERROR_SHORT_BUFFER, asking
// for size bytes.
func (f *fakeTEE) shortSeal(times int, size uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shortSeals, f.shortSize = times, size
}

// blockOn makes the next cmd wait for TEE_IOC_CANCEL on its cancel id and
// then answer TEEC_ERROR_CANCEL. The channel is closed once cmd is waiting.
func (f *fakeTEE) blockOn(cmd uint32) <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockCmd, f.entered = cmd, make(chan struct{})
	return f.entered
}

func (f *fakeTEE) faultf(format string, args ...any) {
	f.faults = append(f.faults, fmt.Sprintf(format, args...))
}

func (f *fakeTEE) open(path string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path != fakeEndpoint {
		return -1, unix.ENOENT
	}
	fd := f.newFD()
	f.devs[fd] = true
	return fd, nil
}

func (f *fakeTEE) newFD() int {
	f.nextFD++
	return f.nextFD
}

func (f *fakeTEE) addShm(dev int, mem []byte, registered bool) *fakeShm {
	s := &fakeShm{id: f.nextID, dev: dev, fd: f.newFD(), mem: mem, registered: registered}
	f.nextID++
	f.shms[s.id] = s
	return s
}

func (f *fakeTEE) shmByFD(fd int) *fakeShm {
	for _, s := range f.shms {
		if s.fd == fd {
			return s
		}
	}
	return nil
}

// release frees s once its fd is closed and it is unmapped.
func (f *fakeTEE) release(s *fakeShm) {
	if s.fd < 0 && !s.mapped {
		delete(f.shms, s.id)
	}
}

func (f *fakeTEE) ioctl(fd int, req uintptr, arg unsafe.Pointer) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.devs[fd] {
		f.faultf("ioctl %#x on fd %d, not an open device", req, fd)
		return -1, unix.EBADF
	}
	switch req {
	case teeIOCVersion:
		v := (*teeVersionData)(arg)
		*v = teeVersionData{ImplID: 1, GenCaps: teeGenCapGP}
		if f.regMem {
			v.GenCaps |= teeGenCapRegMem
		}
		return 0, nil
	case teeIOCShmAlloc:
		d := (*teeShmAllocData)(arg)
		if d.Size == 0 || d.Flags != 0 {
			return -1, unix.EINVAL
		}
		// Driver memory is not zeroed for the caller to rely on.
		s := f.addShm(fd, bytes.Repeat([]byte{0xee}, int(d.Size)), false)
		d.ID = s.id
		return s.fd, nil
	case teeIOCCancel:
		a := (*teeCancelArg)(arg)
		if dev, ok := f.sessions[a.Session]; !ok || dev != fd {
			f.faultf("CANCEL on session %d, not open on fd %d", a.Session, fd)
			return -1, unix.EINVAL
		}
		f.canceled[a.CancelID] = true
		if ch, ok := f.cancels[a.CancelID]; ok {
			close(ch)
			delete(f.cancels, a.CancelID)
		}
		return 0, nil
	case teeIOCCloseSession:
		a := (*teeCloseSessionArg)(arg)
		if dev, ok := f.sessions[a.Session]; !ok || dev != fd {
			f.faultf("CLOSE_SESSION on session %d, not open on fd %d", a.Session, fd)
			return -1, unix.EINVAL
		}
		delete(f.sessions, a.Session)
		return 0, nil
	}
	f.faultf("unexpected ioctl %#x", req)
	return -1, unix.ENOTTY
}

func (f *fakeTEE) ioctlBuf(fd int, req uintptr, p unsafe.Pointer, size uintptr) error {
	f.mu.Lock()
	if !f.devs[fd] {
		f.faultf("ioctl %#x on fd %d, not an open device", req, fd)
		f.mu.Unlock()
		return unix.EBADF
	}
	switch req {
	case teeIOCOpenSession:
		defer f.mu.Unlock()
		if size != unsafe.Sizeof(teeOpenSessionBuf{}) {
			f.faultf("OPEN_SESSION with a %d-byte buffer", size)
			return unix.EINVAL
		}
		return f.openSession(fd, (*teeOpenSessionBuf)(p))
	case teeIOCInvoke:
		if size != unsafe.Sizeof(teeInvokeBuf{}) {
			f.faultf("INVOKE with a %d-byte buffer", size)
			f.mu.Unlock()
			return unix.EINVAL
		}
		buf := (*teeInvokeBuf)(p)
		wait, err := f.invoke(fd, buf)
		f.mu.Unlock()
		if wait != nil {
			<-wait
			buf.Arg.Ret, buf.Arg.RetOrigin = teecErrorCancel, OriginComms
		}
		return err
	}
	f.faultf("unexpected buffer ioctl %#x", req)
	f.mu.Unlock()
	return unix.ENOTTY
}

func (f *fakeTEE) openSession(fd int, b *teeOpenSessionBuf) error {
	if b.Arg.NumParams != teeNumParams {
		return unix.EINVAL
	}
	uuid, err := parseUUID(taUUID)
	if err != nil {
		return err
	}
	if b.Arg.UUID != uuid.octets() || b.Arg.ClntLogin != teeIOCtlLoginPublic {
		b.Arg.Ret, b.Arg.RetOrigin = fakeErrItemNotFound, OriginTEE
		return nil
	}
	f.nextSess++
	f.sessions[f.nextSess] = fd
	b.Arg.Session, b.Arg.Ret, b.Arg.RetOrigin = f.nextSess, teecSuccess, OriginTrustedApp
	return nil
}

// invoke resolves the params' memrefs as the driver does, records the call
// and runs the TA. A non-nil channel means the call waits for its cancel.
func (f *fakeTEE) invoke(fd int, b *teeInvokeBuf) (<-chan struct{}, error) {
	if dev, ok := f.sessions[b.Arg.Session]; !ok || dev != fd {
		f.faultf("INVOKE on session %d, not open on fd %d", b.Arg.Session, fd)
		return nil, unix.EINVAL
	}
	if b.Arg.NumParams != teeNumParams {
		f.faultf("INVOKE with %d params", b.Arg.NumParams)
		return nil, unix.EINVAL
	}
	rec := fakeInvoke{cmd: b.Arg.Func}
	var mems [teeNumParams][]byte
	for i := range b.Params {
		p := &b.Params[i]
		rec.params[i].attr = p.Attr
		switch p.Attr {
		case teeParamAttrTypeNone, teeParamAttrTypeValueOutput:
			continue
		case teeParamAttrTypeMemrefInput, teeParamAttrTypeMemrefOutput:
		default:
			f.faultf("param %d has attribute %d", i, p.Attr)
			return nil, unix.EINVAL
		}
		id := int32(uint32(p.C))
		s, ok := f.shms[id]
		if !ok || s.dev != fd {
			f.faultf("param %d names shared memory %d, not live on fd %d", i, id, fd)
			return nil, unix.EINVAL
		}
		if p.A > uint64(len(s.mem)) || p.B > uint64(len(s.mem))-p.A {
			f.faultf("param %d: [%d, +%d) is outside shared memory %d of %d bytes", i, p.A, p.B, id, len(s.mem))
			return nil, unix.EINVAL
		}
		w := s.mem[p.A : p.A+p.B : p.A+p.B]
		mems[i] = w
		rec.params[i] = fakeParam{attr: p.Attr, id: id, off: p.A, size: p.B, window: w, registered: s.registered}
		if p.Attr == teeParamAttrTypeMemrefInput {
			rec.params[i].in = sha256.Sum256(w)
		}
	}
	f.invokes = append(f.invokes, rec)

	if code, ok := f.failures[b.Arg.Func]; ok {
		b.Arg.Ret, b.Arg.RetOrigin = code, OriginTrustedApp
		return nil, nil
	}
	if f.blockCmd != 0 && b.Arg.Func == f.blockCmd {
		f.blockCmd = 0
		close(f.entered)
		if f.canceled[b.Arg.CancelID] {
			b.Arg.Ret, b.Arg.RetOrigin = teecErrorCancel, OriginComms
			return nil, nil
		}
		ch := make(chan struct{})
		f.cancels[b.Arg.CancelID] = ch
		return ch, nil
	}
	b.Arg.Ret, b.Arg.RetOrigin = f.ta(b.Arg.Func, &b.Params, mems), OriginTrustedApp
	return nil, nil
}

// ta is the trusted application: it runs cmd on params, whose memrefs'
// bytes are mems, and returns the result code.
func (f *fakeTEE) ta(cmd uint32, params *[teeNumParams]teeParam, mems [teeNumParams][]byte) uint32 {
	var types [teeNumParams]uint64
	for i := range params {
		types[i] = params[i].Attr
	}
	sealTypes := [teeNumParams]uint64{teeParamAttrTypeMemrefInput, teeParamAttrTypeMemrefInput, teeParamAttrTypeMemrefOutput, teeParamAttrTypeNone}
	ns, tag := f.aead.NonceSize(), f.aead.Overhead()
	switch cmd {
	case taCmdGetInfo:
		if types != [teeNumParams]uint64{teeParamAttrTypeValueOutput} {
			return fakeErrBadParameters
		}
		params[0].A, params[0].B = taInterfaceVersion, taInfoFlags
		return teecSuccess
	case taCmdSeal:
		in, ad, out := mems[0], mems[1], mems[2]
		if types != sealTypes || len(in) == 0 {
			return fakeErrBadParameters
		}
		if f.shortSeals > 0 {
			f.shortSeals--
			params[2].B = f.shortSize
			return teecErrorShortBuffer
		}
		need := ns + len(in) + tag
		params[2].B = uint64(need)
		if len(out) < need {
			return teecErrorShortBuffer
		}
		if _, err := rand.Read(out[:ns]); err != nil {
			return fakeErrGeneric
		}
		f.aead.Seal(out[ns:ns], out[:ns], in, ad)
		return teecSuccess
	case taCmdUnseal:
		blob, ad, out := mems[0], mems[1], mems[2]
		if types != sealTypes {
			return fakeErrBadParameters
		}
		if len(blob) < ns+tag {
			return teecErrorBadFormat
		}
		pt, err := f.aead.Open(nil, blob[:ns], blob[ns:], ad)
		if err != nil {
			return teecErrorMACInvalid
		}
		defer clear(pt)
		params[2].B = uint64(len(pt))
		if len(out) < len(pt) {
			return teecErrorShortBuffer
		}
		copy(out, pt)
		return teecSuccess
	}
	return fakeErrNotSupported
}

func (f *fakeTEE) registerShm(fd int, buf []byte) (int, int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.devs[fd] {
		f.faultf("SHM_REGISTER on fd %d, not an open device", fd)
		return -1, 0, unix.EBADF
	}
	if !f.regMem || len(buf) == 0 {
		return -1, 0, unix.EINVAL
	}
	s := f.addShm(fd, buf, true)
	return s.fd, s.id, nil
}

func (f *fakeTEE) mmap(fd, size int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.shmByFD(fd)
	if s == nil {
		f.faultf("mmap of fd %d, not shared memory", fd)
		return nil, unix.EBADF
	}
	if s.registered || s.mapped || size <= 0 || size > len(s.mem) {
		f.faultf("mmap of %d bytes of shared memory %d", size, s.id)
		return nil, unix.EINVAL
	}
	s.mapped = true
	return s.mem[:size:size], nil
}

func (f *fakeTEE) munmap(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.shms {
		if s.mapped && len(b) > 0 && unsafe.SliceData(b) == unsafe.SliceData(s.mem) {
			for _, c := range b {
				if c != 0 {
					f.faultf("shared memory %d was unmapped without being wiped", s.id)
					break
				}
			}
			s.mapped = false
			f.release(s)
			return nil
		}
	}
	f.faultf("munmap of %d bytes that are not mapped shared memory", len(b))
	return unix.EINVAL
}

func (f *fakeTEE) close(fd int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.devs[fd] {
		delete(f.devs, fd)
		for sess, dev := range f.sessions {
			if dev == fd {
				f.faultf("device fd %d closed with session %d open", fd, sess)
				delete(f.sessions, sess)
			}
		}
		return nil
	}
	s := f.shmByFD(fd)
	if s == nil {
		f.faultf("close of fd %d, never opened", fd)
		return unix.EBADF
	}
	s.fd = -1
	f.release(s)
	return nil
}
