package armtrustzone

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// FuzzKeyProtectorUnprotect drives arbitrary blobs, key lengths and context
// states through KeyProtector.Unprotect, and through the client, shared
// memory and driver path under it, on fakeTEE with both drivers.
//
// The two fakes share one sealing key, so the one blob Protect makes opens
// on either. Unprotect must then open only that blob, untouched, into a
// key of its length; refuse every other input with
// enclave.ErrSealedAuthentication and a zeroed key; answer an ended
// context with ctx.Err() before any UNSEAL; leave the blob as it was; and
// leave no shared memory, session, device fd or driver fault behind.
func FuzzKeyProtectorUnprotect(f *testing.F) {
	type driver struct {
		name     string
		tee      *fakeTEE
		p        *KeyProtector
		sessions int
		devs     int
	}
	var drivers []*driver
	for _, tc := range []struct {
		name   string
		regMem bool
	}{{"registered memory", true}, {"driver memory", false}} {
		tee := newFakeTEE(f, tc.regMem)
		if len(drivers) > 0 {
			tee.aead = drivers[0].tee.aead
		}
		b, err := dialFakeTB(f, tee)
		if err != nil {
			f.Fatalf("%s: connect to the fake TEE: %v", tc.name, err)
		}
		tee.mu.Lock()
		d := &driver{name: tc.name, tee: tee, p: b.KeyProtector(), sessions: len(tee.sessions), devs: len(tee.devs)}
		tee.mu.Unlock()
		drivers = append(drivers, d)
	}

	key := testKey(32)
	sealed, err := drivers[0].p.Protect(context.Background(), key)
	if err != nil {
		f.Fatalf("Protect: %v", err)
	}

	const (
		ctxLive uint8 = iota
		ctxCanceled
		ctxExpired
		ctxStates
	)
	blobs := [][]byte{sealed, {}, make([]byte, sealMaxBlob+1)}
	for _, n := range []int{1, 12, 20, len(sealed) - 1} {
		blobs = append(blobs, bytes.Clone(sealed[:n]))
	}
	for _, i := range []int{0, 12, len(sealed) / 2, len(sealed) - 1} {
		flipped := bytes.Clone(sealed)
		flipped[i] ^= 0x01
		blobs = append(blobs, flipped)
	}
	for _, b := range blobs {
		for _, n := range []uint16{0, 31, 32, 33} {
			for c := range ctxStates {
				f.Add(b, n, c)
			}
		}
	}

	f.Fuzz(func(t *testing.T, blob []byte, keyLen uint16, ctxState uint8) {
		n := int(keyLen) % (sealMaxBlob + sealOverhead + 1)
		state := ctxState % ctxStates
		for _, d := range drivers {
			d.tee.mu.Lock()
			d.tee.invokes = nil
			d.tee.mu.Unlock()

			ctx := context.Background()
			switch state {
			case ctxCanceled:
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case ctxExpired:
				// The deadline has passed, so the context is already done
				// with DeadlineExceeded, and cancel does not change that.
				c, cancel := context.WithDeadline(ctx, time.Unix(1, 0))
				cancel()
				ctx = c
			}

			in := bytes.Clone(blob)
			dst := make([]byte, n)
			for i := range dst {
				dst[i] = 0xa5
			}
			err := d.p.Unprotect(ctx, in, dst)

			switch {
			case state != ctxLive:
				if want := ctx.Err(); !errors.Is(err, want) {
					t.Errorf("%s: Unprotect with an ended context = %v; want %v", d.name, err, want)
				}
				if u := len(d.tee.calls(taCmdUnseal)); u != 0 {
					t.Errorf("%s: Unprotect with an ended context ran UNSEAL %d times", d.name, u)
				}
			case n == len(key) && bytes.Equal(blob, sealed):
				if err != nil {
					t.Errorf("%s: Unprotect of the untouched blob = %v", d.name, err)
				} else if !bytes.Equal(dst, key) {
					t.Errorf("%s: Unprotect of the untouched blob = %x; want %x", d.name, dst, key)
				}
			default:
				if !errors.Is(err, enclave.ErrSealedAuthentication) {
					t.Errorf("%s: Unprotect of a %d-byte blob into a %d-byte key = %v; want ErrSealedAuthentication",
						d.name, len(blob), n, err)
				}
			}
			if err != nil && !bytes.Equal(dst, make([]byte, n)) {
				t.Errorf("%s: a refused Unprotect left bytes in the key", d.name)
			}
			if !bytes.Equal(in, blob) {
				t.Errorf("%s: Unprotect changed the blob", d.name)
			}
			if l := d.tee.live(); l != 0 {
				t.Errorf("%s: %d shared-memory objects are still live", d.name, l)
			}
			d.tee.mu.Lock()
			faults, sessions, devs := d.tee.faults, len(d.tee.sessions), len(d.tee.devs)
			d.tee.mu.Unlock()
			for _, fault := range faults {
				t.Errorf("%s: fake TEE: %s", d.name, fault)
			}
			if sessions != d.sessions || devs != d.devs {
				t.Errorf("%s: %d sessions and %d device fds open; want %d and %d",
					d.name, sessions, devs, d.sessions, d.devs)
			}
			if t.Failed() {
				t.FailNow()
			}
		}
	})
}

// dialFakeTB is dialFake for any testing.TB, so a fuzz target can hold one
// Backend for its whole run.
func dialFakeTB(tb testing.TB, f *fakeTEE) (*Backend, error) {
	uuid, err := parseUUID(taUUID)
	if err != nil {
		return nil, err
	}
	c, err := openClientOn(f, fakeEndpoint, uuid)
	if err != nil {
		return nil, err
	}
	b := &Backend{c: c}
	tb.Cleanup(func() { _ = b.Close() })
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}
