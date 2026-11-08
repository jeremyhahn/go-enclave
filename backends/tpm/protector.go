package tpm

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
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
	sem      chan struct{}
	dev      device
	alloc    allocator
	closed   bool // guarded by sem
	attempts int
	backoff  time.Duration
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
		sem:      make(chan struct{}, 1),
		dev:      dev,
		alloc:    alloc,
		attempts: cfg.attempts,
		backoff:  cfg.backoff,
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
	public, private, seqErr := c.seal(template, data)
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
	n, seqErr := c.open(public, private, out)
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

// Close waits for the call in progress, if any, and closes the device. A
// call after Close returns [ErrClosed]; a second Close returns nil.
func (p *KeyProtector) Close() error {
	p.sem <- struct{}{}
	defer p.release()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.dev.close()
}

// acquire takes the semaphore, or returns ctx.Err() without touching the
// device if the context ends first.
func (p *KeyProtector) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.sem <- struct{}{}:
	}
	if p.closed {
		p.release()
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		p.release()
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

// call is one command sequence: the handles it holds, flushed by cleanup.
type call struct {
	p    *KeyProtector
	ctx  context.Context
	held []tpm2.TPMHandle
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
		public, private, err = c.p.dev.create(parent, s, data)
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
		obj, err = c.p.dev.load(parent, public, private)
		return err
	}); err != nil {
		return 0, err
	}
	c.held = append(c.held, obj.handle)
	var n int
	err = c.do(cmdUnseal, func() (err error) {
		n, err = c.p.dev.unseal(obj, s, out)
		return err
	})
	return n, err
}

// parentAndSession creates the parent and starts a session salted to it,
// encrypting the first command parameter (in) or response parameter.
func (c *call) parentAndSession(template tpm2.TPMTPublic, in bool) (object, session, error) {
	var parent object
	if err := c.do(cmdCreatePrimary, func() (err error) {
		parent, err = c.p.dev.createPrimary(template)
		return err
	}); err != nil {
		return object{}, session{}, err
	}
	c.held = append(c.held, parent.handle)
	var s session
	if err := c.do(cmdStartAuthSession, func() (err error) {
		s, err = c.p.dev.startSession(parent, in)
		return err
	}); err != nil {
		return object{}, session{}, err
	}
	c.held = append(c.held, s.handle)
	return parent, s, nil
}

// cleanup flushes every handle the call holds, newest first, whether or not
// the context has ended, and returns the first flush error.
func (c *call) cleanup() error {
	var first error
	for i := len(c.held) - 1; i >= 0; i-- {
		h := c.held[i]
		var err error
		for attempt := 1; ; attempt++ {
			err = c.p.dev.flush(h)
			if classify(cmdFlushContext, err) != outcomeRetry || attempt >= c.p.attempts {
				break
			}
			time.Sleep(c.p.backoff << (attempt - 1))
		}
		if err := mapResult(cmdFlushContext, err); err != nil && first == nil {
			first = err
		}
	}
	c.held = nil
	return first
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
type device interface {
	createPrimary(template tpm2.TPMTPublic) (object, error)
	startSession(parent object, encryptIn bool) (session, error)
	create(parent object, s session, data []byte) (public, private []byte, err error)
	load(parent object, public, private []byte) (object, error)
	// unseal writes the unsealed data into dst if it fits, and returns its
	// length either way.
	unseal(obj object, s session, dst []byte) (int, error)
	flush(h tpm2.TPMHandle) error
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
	t *streamTransport
}

func (d *tpmDevice) createPrimary(template tpm2.TPMTPublic) (object, error) {
	defer d.t.wipe()
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(template),
	}.Execute(d.t)
	if err != nil {
		return object{}, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return object{}, err
	}
	return object{handle: rsp.ObjectHandle, name: rsp.Name, public: *pub}, nil
}

func (d *tpmDevice) startSession(parent object, encryptIn bool) (session, error) {
	defer d.t.wipe()
	dir := tpm2.EncryptOut
	if encryptIn {
		dir = tpm2.EncryptIn
	}
	s, _, err := tpm2.HMACSession(d.t, tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(parent.handle, parent.public), tpm2.AESEncryption(128, dir))
	if err != nil {
		return session{}, err
	}
	return session{handle: s.Handle(), auth: s}, nil
}

func (d *tpmDevice) create(parent object, s session, data []byte) (public, private []byte, err error) {
	defer d.t.wipe()
	sensitive := &tpm2.TPM2BSensitiveData{Buffer: data}
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: parent.handle, Name: parent.name, Auth: s.auth},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(sensitive),
		}},
		InPublic: tpm2.New2B(sealedTemplate(nil)),
	}.Execute(d.t)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), rsp.OutPublic.Bytes()...), append([]byte(nil), rsp.OutPrivate.Buffer...), nil
}

func (d *tpmDevice) load(parent object, public, private []byte) (object, error) {
	defer d.t.wipe()
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: parent.handle, Name: parent.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: private},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](public),
	}.Execute(d.t)
	if err != nil {
		return object{}, err
	}
	return object{handle: rsp.ObjectHandle, name: rsp.Name}, nil
}

func (d *tpmDevice) unseal(obj object, s session, dst []byte) (int, error) {
	defer d.t.wipe()
	rsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: obj.handle, Name: obj.name, Auth: s.auth},
	}.Execute(d.t)
	if err != nil {
		return 0, err
	}
	out := rsp.OutData.Buffer
	defer enclave.Wipe(out)
	if len(out) <= len(dst) {
		copy(dst, out)
	}
	return len(out), nil
}

func (d *tpmDevice) flush(h tpm2.TPMHandle) error {
	defer d.t.wipe()
	_, err := tpm2.FlushContext{FlushHandle: h}.Execute(d.t)
	return err
}

func (d *tpmDevice) close() error { return d.t.close() }

// streamTransport is a go-tpm transport over the device file or a simulator
// socket. It wipes each command once written, and receives every response
// into one locked buffer that the device wipes after the command.
type streamTransport struct {
	rw    io.ReadWriteCloser
	path  string
	rsp   []byte
	alloc allocator
}

func newStreamTransport(rw io.ReadWriteCloser, path string, alloc allocator) (*streamTransport, error) {
	rsp, err := alloc.alloc(maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return &streamTransport{rw: rw, path: path, rsp: rsp, alloc: alloc}, nil
}

// Send implements go-tpm's transport.TPM. The response aliases the
// transport's buffer and is valid until the next command or wipe.
func (t *streamTransport) Send(cmd []byte) ([]byte, error) {
	_, err := t.rw.Write(cmd)
	enclave.Wipe(cmd)
	if err != nil {
		return nil, &DeviceError{Path: t.path, Op: "write", Err: err}
	}
	n, err := readResponse(t.rw, t.rsp)
	if err != nil {
		return nil, &DeviceError{Path: t.path, Op: "read", Err: err}
	}
	return t.rsp[:n], nil
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
