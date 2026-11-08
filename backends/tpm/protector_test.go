package tpm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// fakeDevice plays the TPM at the command seam. It seals in the clear,
// refuses a blob it did not issue under the same parent with
// TPM_RC_INTEGRITY, and can block inside a chosen command until released.
type fakeDevice struct {
	mu      sync.Mutex
	next    tpm2.TPMHandle
	loaded  map[tpm2.TPMHandle]string // handle -> parent id, or sealed data
	issued  map[string]string         // parent id + public + private -> data
	log     []string
	errs    map[command][]error
	blockAt int // 1-based command number to block in; 0 never
	blocked chan struct{}
	release chan struct{}

	// unmanaged plays a stream without a resource manager: reopen keeps
	// every handle the old stream held.
	unmanaged bool
	// loseAt is the 1-based command number whose response an interrupt
	// loses: the command runs, then the stream is out of step until
	// reopen and the command returns context.Canceled. onLose runs then.
	loseAt  int
	onLose  func()
	stale   bool
	capErrs []error // returned by the next handle listings, in turn
}

// staleError is a command sent on a stream the fake left out of step.
func staleError() error { return &DeviceError{Path: "fake", Op: "write", Err: errOutOfStep} }

// lose drops the response of the loseAt'th command once it has run.
func (d *fakeDevice) lose(err *error) {
	d.mu.Lock()
	lost := d.loseAt != 0 && d.loseAt == len(d.log) && !d.stale
	if lost {
		d.stale, d.loseAt = true, 0
	}
	onLose := d.onLose
	d.mu.Unlock()
	if lost {
		if onLose != nil {
			onLose()
		}
		*err = context.Canceled
	}
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		next:   0x80000000,
		loaded: make(map[tpm2.TPMHandle]string),
		issued: make(map[string]string),
		errs:   make(map[command][]error),
	}
}

// enter logs a command, blocks if it is the chosen one, and returns the
// error queued for it, if any.
func (d *fakeDevice) enter(cmd command, detail string) error {
	d.mu.Lock()
	d.log = append(d.log, strings.TrimSpace(cmd.String()+" "+detail))
	if d.stale {
		d.mu.Unlock()
		return staleError()
	}
	block := d.blockAt == len(d.log)
	var err error
	if q := d.errs[cmd]; len(q) > 0 {
		err, d.errs[cmd] = q[0], q[1:]
	}
	d.mu.Unlock()
	if block {
		close(d.blocked)
		<-d.release
	}
	return err
}

func (d *fakeDevice) handle(v string) tpm2.TPMHandle {
	d.next++
	d.loaded[d.next] = v
	return d.next
}

func (d *fakeDevice) createPrimary(_ context.Context, template tpm2.TPMTPublic) (_ object, err error) {
	defer d.lose(&err)
	if err := d.enter(cmdCreatePrimary, ""); err != nil {
		return object{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	id := fmt.Sprintf("parent:%x", sha256.Sum256(tpm2.Marshal(template)))
	return object{handle: d.handle(id), name: tpm2.TPM2BName{Buffer: []byte(id)}}, nil
}

func (d *fakeDevice) startSession(context.Context, object, bool) (_ session, err error) {
	defer d.lose(&err)
	if err := d.enter(cmdStartAuthSession, ""); err != nil {
		return session{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return session{handle: d.handle("session")}, nil
}

func (d *fakeDevice) create(_ context.Context, parent object, _ session, data []byte) (public, private []byte, err error) {
	defer d.lose(&err)
	if err := d.enter(cmdCreate, ""); err != nil {
		return nil, nil, err
	}
	unique := make([]byte, 32)
	private = make([]byte, 48)
	_, _ = rand.Read(unique)
	_, _ = rand.Read(private)
	public = tpm2.Marshal(sealedTemplate(unique))
	d.mu.Lock()
	defer d.mu.Unlock()
	d.issued[string(parent.name.Buffer)+string(public)+string(private)] = string(data)
	return public, private, nil
}

func (d *fakeDevice) load(_ context.Context, parent object, public, private []byte) (_ object, err error) {
	defer d.lose(&err)
	if err := d.enter(cmdLoad, ""); err != nil {
		return object{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	data, ok := d.issued[string(parent.name.Buffer)+string(public)+string(private)]
	if !ok {
		return object{}, onParameter(tpm2.TPMRCIntegrity, 1)
	}
	return object{handle: d.handle(data)}, nil
}

func (d *fakeDevice) unseal(_ context.Context, obj object, _ session, dst []byte) (_ int, err error) {
	defer d.lose(&err)
	if err := d.enter(cmdUnseal, ""); err != nil {
		return 0, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	data := d.loaded[obj.handle]
	if len(data) <= len(dst) {
		copy(dst, data)
	}
	return len(data), nil
}

func (d *fakeDevice) flush(_ context.Context, h tpm2.TPMHandle) error {
	if err := d.enter(cmdFlushContext, fmt.Sprintf("%#x", uint32(h))); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.loaded[h]; !ok {
		return onHandle(tpm2.TPMRCHandle, 1)
	}
	delete(d.loaded, h)
	return nil
}

// handles lists the loaded handles, as TPM2_GetCapability would.
func (d *fakeDevice) handles(context.Context) (hs []tpm2.TPMHandle, err error) {
	defer d.lose(&err)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, "TPM2_GetCapability")
	if d.stale {
		return nil, staleError()
	}
	if len(d.capErrs) > 0 {
		err, d.capErrs = d.capErrs[0], d.capErrs[1:]
		return nil, err
	}
	for h := range d.loaded {
		hs = append(hs, h)
	}
	slices.Sort(hs)
	return hs, nil
}

func (d *fakeDevice) managed() bool { return !d.unmanaged }

func (d *fakeDevice) outOfStep() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stale
}

func (d *fakeDevice) interrupt() {}

// reopen replaces a stale stream. Behind a resource manager, the old
// stream's handles go with it.
func (d *fakeDevice) reopen(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stale && !d.unmanaged {
		clear(d.loaded)
	}
	d.stale = false
	return nil
}

func (d *fakeDevice) close() error { return nil }

func (d *fakeDevice) commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.log...)
}

// fakeAllocator observes the provider's transients: each must be wiped
// before it is freed.
type fakeAllocator struct {
	mu    sync.Mutex
	live  map[*byte]bool
	dirty int
}

func newFakeAllocator() *fakeAllocator { return &fakeAllocator{live: make(map[*byte]bool)} }

func (a *fakeAllocator) alloc(n int) ([]byte, error) {
	b := make([]byte, n)
	a.mu.Lock()
	a.live[&b[0]] = true
	a.mu.Unlock()
	return b, nil
}

func (a *fakeAllocator) free(b []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !bytes.Equal(b, make([]byte, len(b))) {
		a.dirty++
	}
	delete(a.live, &b[0])
}

func (a *fakeAllocator) check(t *testing.T) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.live) != 0 || a.dirty != 0 {
		t.Fatalf("at return: %d transients not freed, %d freed without a wipe", len(a.live), a.dirty)
	}
}

func newTestProtector(opts ...Option) (*KeyProtector, *fakeDevice, *fakeAllocator) {
	cfg := config{attempts: defaultAttempts, backoff: time.Millisecond}
	for _, opt := range opts {
		opt(&cfg)
	}
	d, a := newFakeDevice(), newFakeAllocator()
	return newKeyProtector(d, a, cfg), d, a
}

func canary(n int) []byte { return bytes.Repeat([]byte{0xc3}, n) }

func TestProtector_Conformance_OnFakeDevice(t *testing.T) {
	cfg := providertest.Config{
		New: func() (any, error) {
			p, _, _ := newTestProtector()
			return p, nil
		},
		Modes:            []enclave.Mode{enclave.ModePerOperation},
		SkipResidueSweep: "the fake device keeps sealed keys in the clear; the swtpm conformance test sweeps",
		Forge: func(kp enclave.KeyProtector, key []byte) ([]byte, error) {
			return kp.(*KeyProtector).protect(context.Background(), key, storageTemplate(make([]byte, 32)))
		},
		Logf: t.Logf,
	}
	if err := providertest.TestProvider(context.Background(), cfg); err != nil {
		t.Fatalf("the TPM provider fails conformance on the fake device: %v", err)
	}
}

// TestProtector_CancelMidCommand blocks each command of each sequence in
// turn, cancels the context while it blocks, then releases it.
func TestProtector_CancelMidCommand(t *testing.T) {
	const protectCommands, unprotectCommands = 5, 7
	for _, op := range []string{"Protect", "Unprotect"} {
		n := protectCommands
		if op == "Unprotect" {
			n = unprotectCommands
		}
		for i := 1; i <= n; i++ {
			t.Run(fmt.Sprintf("%s_command_%d", op, i), func(t *testing.T) {
				p, d, a := newTestProtector()
				key := canary(32)
				blob, err := p.Protect(context.Background(), []byte(strings.Repeat("k", 32)))
				if err != nil {
					t.Fatalf("Protect: %v", err)
				}
				start := len(d.commands())
				d.blockAt, d.blocked, d.release = start+i, make(chan struct{}), make(chan struct{})

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					if op == "Protect" {
						_, err := p.Protect(ctx, []byte(strings.Repeat("k", 32)))
						done <- err
						return
					}
					done <- p.Unprotect(ctx, blob, key)
				}()
				<-d.blocked
				cancel()
				select {
				case err := <-done:
					t.Fatalf("returned %v while a command was in flight", err)
				case <-time.After(10 * time.Millisecond):
				}
				close(d.release)
				err = <-done

				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want context.Canceled", err)
				}
				a.check(t)
				if !bytes.Equal(key, canary(32)) {
					t.Fatal("a canceled Unprotect wrote key")
				}
				after := d.commands()[start+i:]
				for _, c := range after {
					if !strings.HasPrefix(c, "TPM2_FlushContext") {
						t.Fatalf("%s reached the device after the canceled command; sent %v", c, after)
					}
				}
				if len(d.loaded) != 0 {
					t.Fatalf("handles left loaded: %v", d.loaded)
				}
			})
		}
	}
}

func TestProtector_FlushFailsAfterUnseal(t *testing.T) {
	p, d, a := newTestProtector()
	blob, err := p.Protect(context.Background(), canary(32)[:16])
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	start := len(d.commands())
	d.errs[cmdFlushContext] = []error{tpm2.TPMRCFailure}
	key := canary(16)
	err = p.Unprotect(context.Background(), blob, key)
	if !errors.Is(err, ErrCommandFailed) || errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("got %v, want the provider's ErrCommandFailed", err)
	}
	a.check(t)
	if !bytes.Equal(key, canary(16)) {
		t.Fatal("Unprotect wrote key although a flush failed")
	}
	if sent := d.commands()[start:]; len(sent) != 7 {
		t.Fatalf("sent %v, want every flush despite the failure", sent)
	}
}

// TestProtector_ReclaimAfterLostResponse loses the response of each command
// of each sequence in turn, as an interrupt does on a stream: the command
// ran, and a handle it made is unknown to the provider. Before the next call,
// every handle the call made must be gone, and a handle the provider did not
// make must stay. Behind a resource manager reopening is enough; without one,
// the provider lists and flushes.
func TestProtector_ReclaimAfterLostResponse(t *testing.T) {
	for _, unmanaged := range []bool{false, true} {
		for _, op := range []string{"Protect", "Unprotect"} {
			// The sequence's commands up to TPM2_Create or TPM2_Unseal; an
			// unmanaged stream first lists the handles.
			n := map[string]int{"Protect": 3, "Unprotect": 4}[op]
			if unmanaged {
				n++
			}
			for i := 1; i <= n; i++ {
				t.Run(fmt.Sprintf("unmanaged=%v/%s_command_%d", unmanaged, op, i), func(t *testing.T) {
					p, d, a := newTestProtector()
					d.unmanaged = unmanaged
					key := []byte(strings.Repeat("k", 32))
					blob, err := p.Protect(context.Background(), key)
					if err != nil {
						t.Fatalf("Protect: %v", err)
					}
					want := map[tpm2.TPMHandle]string{}
					var foreign tpm2.TPMHandle
					if unmanaged {
						foreign = d.handle("foreign")
						want[foreign] = "foreign"
					}
					start := len(d.commands())
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					d.loseAt, d.onLose = start+i, cancel
					if op == "Protect" {
						_, err = p.Protect(ctx, key)
					} else {
						err = p.Unprotect(ctx, blob, canary(32))
					}
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("got %v, want context.Canceled", err)
					}
					a.check(t)
					if !maps.Equal(d.loaded, want) {
						t.Fatalf("after the lost response, loaded %v, want %v; sent %v", d.loaded, want, d.commands()[start:])
					}
					sent := d.commands()
					if slices.Contains(sent, fmt.Sprintf("TPM2_FlushContext %#x", uint32(foreign))) {
						t.Fatalf("flushed a handle the provider did not make; sent %v", sent[start:])
					}
					if !unmanaged && slices.Contains(sent, "TPM2_GetCapability") {
						t.Fatalf("listed handles behind a resource manager; sent %v", sent)
					}

					got := canary(32)
					if blob, err = p.Protect(context.Background(), key); err != nil {
						t.Fatalf("Protect after the reclaim: %v", err)
					}
					if err := p.Unprotect(context.Background(), blob, got); err != nil || !bytes.Equal(got, key) {
						t.Fatalf("Unprotect after the reclaim: %v", err)
					}
					if !maps.Equal(d.loaded, want) {
						t.Fatalf("after the next calls, loaded %v, want %v", d.loaded, want)
					}
				})
			}
		}
	}

	// A reclaim the TPM refuses stays due: the next call finishes it before
	// it sends its own commands.
	t.Run("unmanaged/reclaim_deferred", func(t *testing.T) {
		p, d, a := newTestProtector()
		d.unmanaged = true
		key := []byte(strings.Repeat("k", 32))
		if _, err := p.Protect(context.Background(), key); err != nil {
			t.Fatalf("Protect: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d.loseAt = len(d.commands()) + 2 // TPM2_CreatePrimary
		d.onLose = func() {
			cancel()
			d.mu.Lock()
			d.capErrs = []error{tpm2.TPMRCFailure}
			d.mu.Unlock()
		}
		if _, err := p.Protect(ctx, key); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
		a.check(t)
		if len(d.loaded) != 1 {
			t.Fatalf("loaded %v, want the lost parent while the reclaim is due", d.loaded)
		}
		start := len(d.commands())
		if _, err := p.Protect(context.Background(), key); err != nil {
			t.Fatalf("Protect after the refused reclaim: %v", err)
		}
		if len(d.loaded) != 0 {
			t.Fatalf("loaded %v after the next call", d.loaded)
		}
		sent := d.commands()[start:]
		if len(sent) < 2 || sent[0] != "TPM2_GetCapability" || !strings.HasPrefix(sent[1], "TPM2_FlushContext") {
			t.Fatalf("the next call did not reclaim first; sent %v", sent)
		}
	})
}

func TestProtector_RefusesBeforeDeviceWork(t *testing.T) {
	p, d, a := newTestProtector()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	blob, err := p.Protect(context.Background(), canary(32))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	start := len(d.commands())
	cases := map[string]struct {
		run    func() error
		target error
	}{
		"protect_ended_context": {func() error { _, err := p.Protect(ended, canary(32)); return err }, context.Canceled},
		"protect_empty_key":     {func() error { _, err := p.Protect(context.Background(), nil); return err }, ErrKeySize},
		"protect_129_bytes":     {func() error { _, err := p.Protect(context.Background(), canary(129)); return err }, ErrKeySize},
		"unprotect_ended_context": {func() error {
			return p.Unprotect(ended, blob, canary(32))
		}, context.Canceled},
		"unprotect_empty_key": {func() error {
			return p.Unprotect(context.Background(), blob, nil)
		}, enclave.ErrSealedAuthentication},
		"unprotect_129_bytes": {func() error {
			return p.Unprotect(context.Background(), blob, canary(129))
		}, enclave.ErrSealedAuthentication},
		"unprotect_bad_framing": {func() error {
			return p.Unprotect(context.Background(), blob[:len(blob)-1], canary(32))
		}, enclave.ErrSealedAuthentication},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := c.run(); !errors.Is(err, c.target) {
				t.Fatalf("got %v, want %v", err, c.target)
			}
			if sent := d.commands()[start:]; len(sent) != 0 {
				t.Fatalf("sent %v before refusing", sent)
			}
			a.check(t)
		})
	}
}

func TestProtector_LengthMismatchIsAuthentication(t *testing.T) {
	p, d, a := newTestProtector()
	blob, err := p.Protect(context.Background(), canary(32))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	key := canary(16)
	if err := p.Unprotect(context.Background(), blob, key); !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("got %v, want ErrSealedAuthentication", err)
	}
	a.check(t)
	if !bytes.Equal(key, canary(16)) || len(d.loaded) != 0 {
		t.Fatal("a length mismatch wrote key or left a handle loaded")
	}
}

func TestProtector_WaitingCallHonorsContext(t *testing.T) {
	p, d, _ := newTestProtector()
	p.sem <- struct{}{} // another call holds the device
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.Protect(ctx, canary(32)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	p.release()
	if sent := d.commands(); len(sent) != 0 {
		t.Fatalf("a waiting call sent %v", sent)
	}
}

func TestProtector_Retry(t *testing.T) {
	p, d, a := newTestProtector(WithRetry(3, 0))
	d.errs[cmdCreatePrimary] = []error{tpm2.TPMRCRetry, tpm2.TPMRCYielded}
	if _, err := p.Protect(context.Background(), canary(32)); err != nil {
		t.Fatalf("Protect after two retries: %v", err)
	}
	d.errs[cmdCreate] = []error{tpm2.TPMRCTesting, tpm2.TPMRCTesting, tpm2.TPMRCTesting}
	_, err := p.Protect(context.Background(), canary(32))
	if !errors.Is(err, ErrCommandFailed) || !errors.Is(err, tpm2.TPMRCTesting) {
		t.Fatalf("got %v, want ErrCommandFailed wrapping TPM_RC_TESTING", err)
	}
	a.check(t)
	if len(d.loaded) != 0 {
		t.Fatalf("handles left loaded: %v", d.loaded)
	}
}

func TestProtector_CloseAndHealth(t *testing.T) {
	p, _, _ := newTestProtector()
	if err := p.Health(); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := p.Protect(context.Background(), canary(32)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Protect after Close: got %v, want ErrClosed", err)
	}
}

// chunkedRW answers every write with resp, returned in reads of at most
// chunk bytes.
type chunkedRW struct {
	resp, pending []byte
	chunk         int
	wrote         []byte
}

func (c *chunkedRW) Write(b []byte) (int, error) {
	c.wrote = append([]byte(nil), b...)
	c.pending = c.resp
	return len(b), nil
}

func (c *chunkedRW) Read(b []byte) (int, error) {
	if len(c.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(b[:min(len(b), c.chunk)], c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *chunkedRW) Close() error { return nil }

func TestStreamTransport(t *testing.T) {
	resp := []byte{0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 1, 2, 3, 4}
	for _, chunk := range []int{1, 3, len(resp)} {
		t.Run(fmt.Sprintf("chunk_%d", chunk), func(t *testing.T) {
			rw := &chunkedRW{resp: resp, chunk: chunk}
			tr, err := newStreamTransport(rw, "test", newFakeAllocator())
			if err != nil {
				t.Fatalf("newStreamTransport: %v", err)
			}
			cmd := []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 1, 0x7f}
			got, err := tr.send(context.Background(), cmd)
			if err != nil || !bytes.Equal(got, resp) {
				t.Fatalf("Send = %x, %v; want %x", got, err, resp)
			}
			if !bytes.Equal(rw.wrote, []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 1, 0x7f}) {
				t.Fatalf("wrote %x", rw.wrote)
			}
			if !bytes.Equal(cmd, make([]byte, len(cmd))) {
				t.Fatal("Send did not wipe the command")
			}
			tr.wipe()
			if !bytes.Equal(got, make([]byte, len(got))) {
				t.Fatal("wipe did not clear the response buffer")
			}
		})
	}
	for name, resp := range map[string][]byte{
		"short":         {0x80, 0x01, 0, 0},
		"size_too_big":  {0x80, 0x01, 0, 0, 0x20, 0, 0, 0, 0, 0},
		"size_too_tiny": {0x80, 0x01, 0, 0, 0, 2, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			tr, _ := newStreamTransport(&chunkedRW{resp: resp, chunk: 64}, "test", newFakeAllocator())
			if _, err := tr.send(context.Background(), []byte{0}); !errors.Is(err, ErrDeviceUnavailable) {
				t.Fatalf("got %v, want ErrDeviceUnavailable", err)
			}
		})
	}
}
