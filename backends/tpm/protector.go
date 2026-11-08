package tpm

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
)

// DefaultPath is the kernel's TPM resource manager, which Open uses when it
// is given an empty path.
const DefaultPath = "/dev/tpmrm0"

// maxResponseBytes bounds a TPM response; every TPM 2.0 response the
// provider receives fits.
const maxResponseBytes = 4096

// Retry defaults for TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING.
const (
	defaultAttempts = 5
	defaultBackoff  = 20 * time.Millisecond
)

// defaultCloseWait is how long Close waits for the call in progress before
// it interrupts it, and cleanupTimeout bounds the flushes that end a call,
// which run after its context has ended.
const (
	defaultCloseWait = 2 * time.Second
	cleanupTimeout   = 5 * time.Second
)

// opOpen is the DeviceError operation for opening the device.
const opOpen = "open"

var (
	_ enclave.KeyProtector   = (*KeyProtector)(nil)
	_ enclave.HealthReporter = (*KeyProtector)(nil)
)

// KeyProtector seals data-encryption keys into TPM 2.0 sealed-data objects
// under a transient, label-bound ECC P-256 storage primary. It serves
// [enclave.ModePerOperation]: pass it to [enclave.WithKeyProtector]. Its
// methods are safe for concurrent use; one TPM command sequence runs at a
// time.
type KeyProtector struct {
	// sem is a one-slot semaphore: holding it serializes the command
	// sequences, and a waiting call can still honor its context.
	sem    chan struct{}
	dev    device
	alloc  allocator
	closed bool // guarded by sem
	// closing is closed by the first Close before it waits for sem, so a
	// call waiting for sem, or one that takes it after, returns ErrClosed
	// without reaching the device.
	closing   chan struct{}
	closeOnce sync.Once
	// reclaimDue marks handles an interrupted call may have left in a TPM
	// without a resource manager; baseline lists the handles that call
	// found. Both are guarded by sem.
	reclaimDue bool
	baseline   []tpm2.TPMHandle
	// left lists handles the provider made whose flush the TPM refused on
	// a stream still in step; the next call flushes them first. Guarded by
	// sem.
	left      []tpm2.TPMHandle
	attempts  int
	backoff   time.Duration
	closeWait time.Duration
}

// Option configures [Open].
type Option func(*config)

type config struct {
	attempts int
	backoff  time.Duration
}

// WithRetry sets how many times a command is sent while the TPM answers
// TPM_RC_RETRY, TPM_RC_YIELDED or TPM_RC_TESTING (attempts, at least 1), and
// the first back-off, which doubles after each attempt.
func WithRetry(attempts int, backoff time.Duration) Option {
	return func(c *config) {
		c.attempts = max(attempts, 1)
		c.backoff = max(backoff, 0)
	}
}

// Open opens the TPM at path, the kernel's resource manager
// [DefaultPath] when path is empty, and returns a provider over it. On
// Linux, path may also name a TPM simulator's command socket as
// "unix:<path>" or "tcp:<host:port>". The device stays open until Close.
func Open(path string, opts ...Option) (*KeyProtector, error) {
	if path == "" {
		path = DefaultPath
	}
	cfg := config{attempts: defaultAttempts, backoff: defaultBackoff}
	for _, opt := range opts {
		opt(&cfg)
	}
	alloc := newAllocator()
	dev, err := openDevice(path, alloc)
	if err != nil {
		return nil, err
	}
	return newKeyProtector(dev, alloc, cfg), nil
}

func newKeyProtector(dev device, alloc allocator, cfg config) *KeyProtector {
	return &KeyProtector{
		sem:       make(chan struct{}, 1),
		closing:   make(chan struct{}),
		dev:       dev,
		alloc:     alloc,
		attempts:  cfg.attempts,
		backoff:   cfg.backoff,
		closeWait: defaultCloseWait,
	}
}

// Protect seals key, 1 to 128 bytes, and returns the blob. It keeps no copy
// of key: its transient is wiped before it returns, on every path.
func (p *KeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) == 0 || len(key) > maxKeyBytes {
		return nil, &KeySizeError{Len: len(key)}
	}
	return p.protect(ctx, key, parentTemplate())
}

// protect seals key under the primary of the given template.
func (p *KeyProtector) protect(ctx context.Context, key []byte, template tpm2.TPMTPublic) ([]byte, error) {
	if err := p.acquire(ctx); err != nil {
		return nil, err
	}
	defer p.release()

	data, err := p.alloc.alloc(len(key))
	if err != nil {
		return nil, err
	}
	defer p.free(data)
	copy(data, key)

	c := &call{p: p, ctx: ctx}
	var public, private []byte
	seqErr := c.begin()
	if seqErr == nil {
		public, private, seqErr = c.seal(template, data)
	}
	flushErr := c.cleanup()
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case flushErr != nil:
		return nil, flushErr
	case seqErr != nil:
		return nil, seqErr
	}
	return encodeBlob(public, private), nil
}

// Unprotect opens blob into key. It refuses, with an error matching
// [enclave.ErrSealedAuthentication], a blob this provider's Protect did not
// produce and a key whose length is not the sealed key's. key is written only
// on success, as the last step.
func (p *KeyProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	public, private, err := parseBlob(blob)
	if err != nil {
		return err
	}
	if len(key) == 0 || len(key) > maxKeyBytes {
		return &authError{reason: "no sealed key has the destination's length"}
	}
	if err := p.acquire(ctx); err != nil {
		return err
	}
	defer p.release()

	out, err := p.alloc.alloc(maxKeyBytes)
	if err != nil {
		return err
	}
	defer p.free(out)

	c := &call{p: p, ctx: ctx}
	var n int
	seqErr := c.begin()
	if seqErr == nil {
		n, seqErr = c.open(public, private, out)
	}
	flushErr := c.cleanup()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case flushErr != nil:
		return flushErr
	case seqErr != nil:
		return seqErr
	case n != len(key):
		return &authError{reason: "the sealed key's length is not the destination's"}
	}
	copy(key, out[:n])
	return nil
}

// Health returns nil: the key lives in the TPM, and Health does not block.
func (p *KeyProtector) Health() error { return nil }

// Close waits up to 2 seconds for the call in progress, if any, then
// interrupts it, and closes the device. An interrupted call returns a
// [DeviceError] as soon as its exchange with a simulator socket or a
// pollable device ends; on a device without deadlines, it ends when the
// kernel's TPM command timeout does, and its recovery then takes at most
// 5 seconds more. Without a resource manager, Close then finishes, within
// 5 seconds, the reclaim of handles an interrupted call left and the flush
// of handles the TPM refused to flush, and returns its failure joined with
// the close's. A call waiting for the provider when Close starts, and a
// call after Close, returns [ErrClosed] without reaching the device; a
// second Close returns nil.
func (p *KeyProtector) Close() error {
	// Refuse the calls queued behind the one in progress first: the one
	// interrupt below frees sem for Close only if none of them can take it.
	p.closeOnce.Do(func() { close(p.closing) })
	wait := time.NewTimer(p.closeWait)
	defer wait.Stop()
	select {
	case p.sem <- struct{}{}:
	case <-wait.C:
		p.dev.interrupt()
		p.sem <- struct{}{}
	}
	defer p.release()
	if p.closed {
		return nil
	}
	p.closed = true
	return errors.Join(p.closeLeft(), p.dev.close())
}

// closeLeft finishes, within cleanupTimeout, the reclaim a call left due and
// the flush of the handles a refused flush left, where closing the stream
// does not drop them: without a resource manager. It reopens a stream left
// out of step first, and flushes no handle the reclaim's baseline lists.
func (p *KeyProtector) closeLeft() error {
	defer func() { p.left, p.reclaimDue, p.baseline = nil, false, nil }()
	if p.dev.managed() || (!p.reclaimDue && len(p.left) == 0) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	return p.settle(ctx)
}

// acquire takes the semaphore, or returns ctx.Err() without touching the
// device if the context ends first, or ErrClosed once Close has begun. It
// reopens a device an interrupted call left out of step, finishes a reclaim a
// call left due, and flushes the handles a refused flush left, within
// cleanupTimeout.
func (p *KeyProtector) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closing:
		return ErrClosed
	case p.sem <- struct{}{}:
	}
	select {
	case <-p.closing:
		p.release()
		return ErrClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		p.release()
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	err := p.settle(rctx)
	cancel()
	if err != nil {
		p.release()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func (p *KeyProtector) release() { <-p.sem }

// free wipes a transient and returns it to the allocator.
func (p *KeyProtector) free(b []byte) {
	enclave.Wipe(b)
	p.alloc.free(b)
}

// call is one command sequence: the handles it holds, flushed by cleanup,
// and the handles begin found in a TPM without a resource manager.
type call struct {
	p      *KeyProtector
	ctx    context.Context
	held   []tpm2.TPMHandle
	before []tpm2.TPMHandle
	listed bool
}

// do sends one command of the sequence, unless the context has ended, and
// retries it while the TPM asks to.
func (c *call) do(cmd command, send func() error) error {
	for attempt := 1; ; attempt++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		err := send()
		if classify(cmd, err) != outcomeRetry || attempt >= c.p.attempts {
			return mapResult(cmd, err)
		}
		t := time.NewTimer(c.p.backoff << (attempt - 1))
		select {
		case <-c.ctx.Done():
			t.Stop()
			return c.ctx.Err()
		case <-t.C:
		}
	}
}

// seal is Protect's sequence: parent, salted session, TPM2_Create.
func (c *call) seal(template tpm2.TPMTPublic, data []byte) (public, private []byte, err error) {
	parent, s, err := c.parentAndSession(template, true)
	if err != nil {
		return nil, nil, err
	}
	err = c.do(cmdCreate, func() (err error) {
		public, private, err = c.p.dev.create(c.ctx, parent, s, data)
		return err
	})
	return public, private, err
}

// open is Unprotect's sequence: parent, salted session, TPM2_Load and
// TPM2_Unseal into out. It returns the unsealed length.
func (c *call) open(public, private, out []byte) (int, error) {
	parent, s, err := c.parentAndSession(parentTemplate(), false)
	if err != nil {
		return 0, err
	}
	var obj object
	if err := c.do(cmdLoad, func() (err error) {
		obj, err = c.p.dev.load(c.ctx, parent, public, private)
		return err
	}); err != nil {
		return 0, err
	}
	c.held = append(c.held, obj.handle)
	var n int
	err = c.do(cmdUnseal, func() (err error) {
		n, err = c.p.dev.unseal(c.ctx, obj, s, out)
		return err
	})
	return n, err
}

// parentAndSession creates the parent and starts a session salted to it,
// encrypting the first command parameter (in) or response parameter.
func (c *call) parentAndSession(template tpm2.TPMTPublic, in bool) (object, session, error) {
	var parent object
	if err := c.do(cmdCreatePrimary, func() (err error) {
		parent, err = c.p.dev.createPrimary(c.ctx, template)
		return err
	}); err != nil {
		return object{}, session{}, err
	}
	c.held = append(c.held, parent.handle)
	var s session
	if err := c.do(cmdStartAuthSession, func() (err error) {
		s, err = c.p.dev.startSession(c.ctx, parent, in)
		return err
	}); err != nil {
		return object{}, session{}, err
	}
	c.held = append(c.held, s.handle)
	return parent, s, nil
}

// cleanup flushes every handle the call holds, newest first, whether or not
// the context has ended, and returns the first flush error. If an interrupt
// left the device out of step, it reclaims instead: reopening a device
// behind the kernel's resource manager flushes what the old stream held,
// and on a device without one the reclaim flushes each handle begin did not
// find. Both run within cleanupTimeout, and a flush error stands whatever
// the reclaim returns.
func (c *call) cleanup() error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), cleanupTimeout)
	defer cancel()
	held := c.held
	c.held = nil
	var first error
	var kept []tpm2.TPMHandle
	for i := len(held) - 1; i >= 0 && !c.p.dev.outOfStep(); i-- {
		h := held[i]
		err := c.p.retry(ctx, func() error { return c.p.dev.flush(ctx, h) })
		if err := mapResult(cmdFlushContext, err); err != nil {
			kept = append(kept, h)
			if first == nil {
				first = err
			}
		}
	}
	if !c.p.dev.outOfStep() {
		// The TPM answered and kept these handles: the next call flushes
		// them before its own commands.
		c.p.left = append(c.p.left, kept...)
		return first
	}
	// A reopen behind a resource manager drops the handles this call kept;
	// without one, the reclaim finds them, since c.before predates them.
	if c.listed {
		c.p.reclaimDue, c.p.baseline = true, c.before
	}
	// A recovery that succeeds does not excuse the flush that failed.
	return errors.Join(first, c.p.settle(ctx))
}

// settle reopens a device left out of step, finishes a reclaim a call left
// due, and flushes the handles a refused flush left. The caller holds the
// semaphore and bounds ctx.
func (p *KeyProtector) settle(ctx context.Context) error {
	if p.dev.managed() && p.dev.outOfStep() {
		// The resource manager drops the old stream's handles with it.
		p.left = nil
	}
	if err := p.reclaim(ctx); err != nil {
		return err
	}
	return p.flushLeft(ctx)
}

// flushLeft flushes the handles a refused flush left. A handle whose flush
// fails again stays while the TPM still lists it, and the call fails; one the
// TPM no longer lists is gone.
func (p *KeyProtector) flushLeft(ctx context.Context) error {
	for len(p.left) > 0 {
		h := p.left[0]
		if err := p.retry(ctx, func() error { return p.dev.flush(ctx, h) }); err != nil {
			if p.dev.outOfStep() {
				return mapResult(cmdFlushContext, err)
			}
			hs, lerr := p.list(ctx)
			if lerr != nil {
				return lerr
			}
			if slices.Contains(hs, h) {
				return mapResult(cmdFlushContext, err)
			}
		}
		p.left = p.left[1:]
	}
	p.left = nil
	return nil
}

// object is a loaded TPM object: its handle, name and public area.
type object struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPMTPublic
}

// session is a started HMAC session.
type session struct {
	handle tpm2.TPMHandle
	auth   tpm2.Session
}

// device is the provider's TPM command seam: one method per command of the
// sequences. tpmDevice implements it over go-tpm; the tests fake it.
// Each command method returns ctx.Err() once ctx ends, interrupting the
// exchange in progress where the device allows it.
type device interface {
	createPrimary(ctx context.Context, template tpm2.TPMTPublic) (object, error)
	startSession(ctx context.Context, parent object, encryptIn bool) (session, error)
	create(ctx context.Context, parent object, s session, data []byte) (public, private []byte, err error)
	load(ctx context.Context, parent object, public, private []byte) (object, error)
	// unseal writes the unsealed data into dst if it fits, and returns its
	// length either way.
	unseal(ctx context.Context, obj object, s session, dst []byte) (int, error)
	flush(ctx context.Context, h tpm2.TPMHandle) error
	// handles lists the TPM's transient objects and loaded sessions.
	handles(ctx context.Context) ([]tpm2.TPMHandle, error)
	// managed reports whether the kernel's resource manager flushes the
	// handles of a closed stream.
	managed() bool
	// outOfStep reports whether an interrupt left the device out of step.
	outOfStep() bool
	// interrupt ends the exchange in progress, if any; any goroutine may
	// call it. The device is then out of step until reopen.
	interrupt()
	// reopen replaces a device an interrupted exchange left out of step,
	// and does nothing otherwise.
	reopen(ctx context.Context) error
	close() error
}

// allocator hands out key transients. The provider wipes a transient before
// it frees it.
type allocator interface {
	alloc(n int) ([]byte, error)
	free(b []byte)
}

// tpmDevice sends the provider's commands with go-tpm over a transport whose
// buffers it wipes after every command.
type tpmDevice struct {
	t  *streamTransport
	rm bool // behind the kernel's resource manager
}

func (d *tpmDevice) createPrimary(ctx context.Context, template tpm2.TPMTPublic) (object, error) {
	defer d.t.wipe()
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(template),
	}.Execute(d.t.bind(ctx))
	if err != nil {
		return object{}, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return object{}, err
	}
	return object{handle: rsp.ObjectHandle, name: rsp.Name, public: *pub}, nil
}

func (d *tpmDevice) startSession(ctx context.Context, parent object, encryptIn bool) (session, error) {
	defer d.t.wipe()
	dir := tpm2.EncryptOut
	if encryptIn {
		dir = tpm2.EncryptIn
	}
	s, _, err := tpm2.HMACSession(d.t.bind(ctx), tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(parent.handle, parent.public), tpm2.AESEncryption(128, dir))
	if err != nil {
		return session{}, err
	}
	return session{handle: s.Handle(), auth: s}, nil
}

func (d *tpmDevice) load(ctx context.Context, parent object, public, private []byte) (object, error) {
	defer d.t.wipe()
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: parent.handle, Name: parent.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: private},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](public),
	}.Execute(d.t.bind(ctx))
	if err != nil {
		return object{}, err
	}
	return object{handle: rsp.ObjectHandle, name: rsp.Name}, nil
}

func (d *tpmDevice) flush(ctx context.Context, h tpm2.TPMHandle) error {
	defer d.t.wipe()
	_, err := tpm2.FlushContext{FlushHandle: h}.Execute(d.t.bind(ctx))
	return err
}

func (d *tpmDevice) interrupt() { d.t.interrupt() }

func (d *tpmDevice) reopen(ctx context.Context) error { return d.t.reopen(ctx) }

func (d *tpmDevice) close() error { return d.t.close() }

// errOutOfStep is a command sent on a stream an interrupted exchange left
// out of step: the response to the interrupted command may still arrive.
var errOutOfStep = errors.New("an interrupted command left the stream out of step")

// streamTransport carries commands over the device file or a simulator
// socket. It wipes each command once written, and receives every response
// into one locked buffer that the device wipes after the command. An
// exchange that a context end interrupts, or that fails, leaves the stream
// out of step until reopen.
type streamTransport struct {
	rw    io.ReadWriteCloser // replaced only by reopen, under mu
	path  string
	rsp   []byte
	alloc allocator
	// dial opens a fresh stream for reopen; nil if the stream cannot be
	// reopened.
	dial func(context.Context) (io.ReadWriteCloser, error)

	mu        sync.Mutex // serializes interrupt and reopen
	outOfStep atomic.Bool
}

func newStreamTransport(rw io.ReadWriteCloser, path string, alloc allocator) (*streamTransport, error) {
	rsp, err := alloc.alloc(maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return &streamTransport{rw: rw, path: path, rsp: rsp, alloc: alloc}, nil
}

// boundTransport is go-tpm's transport.TPM for one command under ctx.
type boundTransport struct {
	t   *streamTransport
	ctx context.Context
}

func (b boundTransport) Send(cmd []byte) ([]byte, error) { return b.t.send(b.ctx, cmd) }

func (t *streamTransport) bind(ctx context.Context) boundTransport {
	return boundTransport{t: t, ctx: ctx}
}

// send writes cmd, wipes it, and reads the response, which aliases the
// transport's buffer and is valid until the next command or wipe. If ctx
// ends first, send interrupts the exchange and returns ctx.Err().
func (t *streamTransport) send(ctx context.Context, cmd []byte) ([]byte, error) {
	if t.outOfStep.Load() {
		enclave.Wipe(cmd)
		return nil, &DeviceError{Path: t.path, Op: "write", Err: errOutOfStep}
	}
	if err := ctx.Err(); err != nil {
		enclave.Wipe(cmd)
		return nil, err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		t.interrupt()
		close(interrupted)
	})
	rsp, err := t.exchange(cmd)
	if !stop() {
		<-interrupted
		return nil, ctx.Err()
	}
	return rsp, err
}

func (t *streamTransport) exchange(cmd []byte) ([]byte, error) {
	_, err := t.rw.Write(cmd)
	enclave.Wipe(cmd)
	if err != nil {
		t.outOfStep.Store(true)
		return nil, &DeviceError{Path: t.path, Op: "write", Err: err}
	}
	n, err := readResponse(t.rw, t.rsp)
	if err != nil {
		t.outOfStep.Store(true)
		return nil, &DeviceError{Path: t.path, Op: "read", Err: err}
	}
	return t.rsp[:n], nil
}

// interrupt marks the stream out of step and, if it has deadlines, sets one
// in the past, which ends the read or write in progress at once. A device
// file without deadlines finishes the command in progress first.
func (t *streamTransport) interrupt() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outOfStep.Store(true)
	if d, ok := t.rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Unix(1, 0))
	}
}

// reopen closes a stream left out of step and dials a fresh one.
func (t *streamTransport) reopen(ctx context.Context) error {
	if !t.outOfStep.Load() {
		return nil
	}
	if t.dial == nil {
		return &DeviceError{Path: t.path, Op: opOpen, Err: errOutOfStep}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.rw.Close()
	rw, err := t.dial(ctx)
	if err != nil {
		return &DeviceError{Path: t.path, Op: opOpen, Err: err}
	}
	t.rw = rw
	t.outOfStep.Store(false)
	return nil
}

// readResponse reads one TPM response into buf: a device returns it in one
// read, a socket may split it.
func readResponse(r io.Reader, buf []byte) (int, error) {
	const header = 10
	n := 0
	for {
		m, err := r.Read(buf[n:])
		n += m
		if n >= header {
			size := int(binary.BigEndian.Uint32(buf[2:6]))
			if size < header || size > len(buf) {
				return 0, errors.New("the response size field is out of range")
			}
			if n >= size {
				return size, nil
			}
		}
		if err == io.EOF {
			return 0, io.ErrUnexpectedEOF
		}
		if err != nil {
			return 0, err
		}
		if m == 0 {
			return 0, io.ErrNoProgress
		}
	}
}

func (t *streamTransport) wipe() { enclave.Wipe(t.rsp) }

func (t *streamTransport) close() error {
	t.wipe()
	t.alloc.free(t.rsp)
	t.rsp = nil
	return t.rw.Close()
}
