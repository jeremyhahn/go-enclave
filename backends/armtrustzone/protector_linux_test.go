package armtrustzone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
	"unsafe"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// These tests run the sealing transport, byte for byte through the client's
// own methods, against fakeTEE: a stand-in for the TEE driver and for a
// trusted application that implements SEAL and UNSEAL.

// dialFake connects a Backend to f as Connect does to a device, and closes
// it when the test ends.
func dialFake(t *testing.T, f *fakeTEE) (*Backend, error) {
	uuid, err := parseUUID(taUUID)
	if err != nil {
		return nil, err
	}
	c, err := openClientOn(f, fakeEndpoint, uuid)
	if err != nil {
		return nil, err
	}
	b := &Backend{c: c}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}

func connectFake(t *testing.T, f *fakeTEE) *KeyProtector {
	t.Helper()
	b, err := dialFake(t, f)
	if err != nil {
		t.Fatalf("connect to the fake TEE: %v", err)
	}
	return b.KeyProtector()
}

// forEachDriver runs fn against a driver that registers user memory and
// against one that does not, so UNSEAL's output takes both paths.
func forEachDriver(t *testing.T, fn func(t *testing.T, f *fakeTEE)) {
	for _, tc := range []struct {
		name   string
		regMem bool
	}{{"registered memory", true}, {"driver memory", false}} {
		t.Run(tc.name, func(t *testing.T) { fn(t, newFakeTEE(t, tc.regMem)) })
	}
}

func testKey(n int) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	return key
}

func wantMemref(t *testing.T, name string, got fakeParam, attr uint64, off, size int) {
	t.Helper()
	if got.attr != attr || got.off != uint64(off) || got.size != uint64(size) {
		t.Errorf("%s = attr %d, offset %d, size %d; want attr %d, offset %d, size %d",
			name, got.attr, got.off, got.size, attr, off, size)
	}
}

func TestKeyProtectorConformance_OnFakeTEE(t *testing.T) {
	forEachDriver(t, func(t *testing.T, f *fakeTEE) {
		cfg := providertest.Config{
			New: func() (any, error) {
				b, err := dialFake(t, f)
				if err != nil {
					return nil, err
				}
				return b.KeyProtector(), nil
			},
			Modes: []enclave.Mode{enclave.ModePerOperation},
			Logf:  t.Logf,
		}
		if err := providertest.TestProvider(context.Background(), cfg); err != nil {
			t.Fatalf("the KeyProtector fails conformance over the fake TEE: %v", err)
		}
	})
}

func TestSealTransportWiring(t *testing.T) {
	forEachDriver(t, func(t *testing.T, f *fakeTEE) {
		ctx := context.Background()
		p := connectFake(t, f)
		key, ad := testKey(32), []byte(keyProtectorLabel)

		blob, err := p.Protect(ctx, key)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		seals := f.calls(taCmdSeal)
		if len(seals) != 1 {
			t.Fatalf("Protect ran SEAL %d times; want 1", len(seals))
		}
		s := seals[0].params
		wantMemref(t, "SEAL param 0", s[0], teeParamAttrTypeMemrefInput, 0, len(key))
		wantMemref(t, "SEAL param 1", s[1], teeParamAttrTypeMemrefInput, len(key), len(ad))
		wantMemref(t, "SEAL param 2", s[2], teeParamAttrTypeMemrefOutput, len(key)+len(ad), len(key)+sealOverhead)
		if s[3].attr != teeParamAttrTypeNone {
			t.Errorf("SEAL param 3 has attribute %d; want none", s[3].attr)
		}
		if s[1].id != s[0].id || s[2].id != s[0].id {
			t.Errorf("SEAL's memrefs name shared memory %d, %d and %d; want one", s[0].id, s[1].id, s[2].id)
		}
		if !bytes.Equal(s[0].in, key) || !bytes.Equal(s[1].in, ad) {
			t.Errorf("SEAL's inputs are %x and %q; want the key and the label", s[0].in, s[1].in)
		}

		dst := make([]byte, len(key))
		if err := p.Unprotect(ctx, blob, dst); err != nil {
			t.Fatalf("Unprotect: %v", err)
		}
		unseals := f.calls(taCmdUnseal)
		if len(unseals) != 1 {
			t.Fatalf("Unprotect ran UNSEAL %d times; want 1", len(unseals))
		}
		u := unseals[0].params
		wantMemref(t, "UNSEAL param 0", u[0], teeParamAttrTypeMemrefInput, 0, len(blob))
		wantMemref(t, "UNSEAL param 1", u[1], teeParamAttrTypeMemrefInput, len(blob), len(ad))
		if !bytes.Equal(u[0].in, blob) || !bytes.Equal(u[1].in, ad) {
			t.Errorf("UNSEAL's inputs are %x and %q; want the blob and the label", u[0].in, u[1].in)
		}
		if u[1].id != u[0].id {
			t.Errorf("UNSEAL's inputs name shared memory %d and %d; want one", u[0].id, u[1].id)
		}
		if f.regMem {
			wantMemref(t, "UNSEAL param 2", u[2], teeParamAttrTypeMemrefOutput, 0, len(dst))
			if !u[2].registered || unsafe.SliceData(u[2].window) != unsafe.SliceData(dst) {
				t.Error("UNSEAL's output is not the key's own registered pages")
			}
		} else {
			wantMemref(t, "UNSEAL param 2", u[2], teeParamAttrTypeMemrefOutput, len(blob)+len(ad), len(dst))
			if u[2].id != u[0].id {
				t.Errorf("UNSEAL's output names shared memory %d; want %d", u[2].id, u[0].id)
			}
		}
		if u[3].attr != teeParamAttrTypeNone {
			t.Errorf("UNSEAL param 3 has attribute %d; want none", u[3].attr)
		}
		if !bytes.Equal(dst, key) {
			t.Errorf("Unprotect wrote %x; want %x", dst, key)
		}
	})
}

func TestSealRoundTrip(t *testing.T) {
	forEachDriver(t, func(t *testing.T, f *fakeTEE) {
		ctx := context.Background()
		p := connectFake(t, f)
		for _, n := range []int{1, 32, 64, 1024} {
			key := testKey(n)
			blob, err := p.Protect(ctx, key)
			if err != nil {
				t.Fatalf("Protect(%d bytes): %v", n, err)
			}
			if len(blob) != 12+n+16 {
				t.Errorf("Protect(%d bytes) = a %d-byte blob; want %d", n, len(blob), 12+n+16)
			}
			dst := make([]byte, n)
			if err := p.Unprotect(ctx, blob, dst); err != nil {
				t.Fatalf("Unprotect(%d bytes): %v", n, err)
			}
			if !bytes.Equal(dst, key) {
				t.Errorf("Unprotect(%d bytes) = %x; want %x", n, dst, key)
			}
		}
	})
}

func TestSealTransportReleasesSharedMemory(t *testing.T) {
	forEachDriver(t, func(t *testing.T, f *fakeTEE) {
		ctx := context.Background()
		p := connectFake(t, f)
		key := testKey(32)
		released := func(when string) {
			t.Helper()
			if n := f.live(); n != 0 {
				t.Errorf("%s: %d shared-memory objects are still live", when, n)
			}
		}

		blob, err := p.Protect(ctx, key)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		released("after Protect")
		dst := make([]byte, len(key))
		if err := p.Unprotect(ctx, blob, dst); err != nil {
			t.Fatalf("Unprotect: %v", err)
		}
		released("after Unprotect")

		var ce *CommandError
		f.fail(taCmdSeal, fakeErrGeneric)
		if _, err := p.Protect(ctx, key); !errors.As(err, &ce) || ce.Code != fakeErrGeneric {
			t.Errorf("Protect with SEAL failing = %v; want a CommandError %#x", err, fakeErrGeneric)
		}
		released("after a failed SEAL")
		f.fail(taCmdSeal, 0)

		f.fail(taCmdUnseal, fakeErrGeneric)
		err = p.Unprotect(ctx, blob, dst)
		if !errors.As(err, &ce) || ce.Code != fakeErrGeneric || errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("Unprotect with UNSEAL failing = %v; want a CommandError %#x", err, fakeErrGeneric)
		}
		if !bytes.Equal(dst, make([]byte, len(dst))) {
			t.Error("a failed Unprotect left bytes in the key")
		}
		released("after a failed UNSEAL")
		f.fail(taCmdUnseal, 0)

		for _, tc := range []struct {
			name string
			cmd  uint32
			call func(context.Context) error
		}{
			{"SEAL", taCmdSeal, func(ctx context.Context) error { _, err := p.Protect(ctx, key); return err }},
			{"UNSEAL", taCmdUnseal, func(ctx context.Context) error { return p.Unprotect(ctx, blob, make([]byte, len(key))) }},
		} {
			entered := f.blockOn(tc.cmd)
			cctx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- tc.call(cctx) }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s never reached the TA", tc.name)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("a canceled %s = %v; want context.Canceled", tc.name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("a canceled %s never returned", tc.name)
			}
			released("after a canceled " + tc.name)
		}
	})
}

func TestSealShortBufferRetry(t *testing.T) {
	ctx := context.Background()
	f := newFakeTEE(t, false)
	p := connectFake(t, f)
	key, ad := testKey(32), []byte(keyProtectorLabel)
	outOff := len(key) + len(ad)
	const asked = 200

	f.shortSeal(1, asked)
	blob, err := p.Protect(ctx, key)
	if err != nil {
		t.Fatalf("Protect after one short buffer: %v", err)
	}
	seals := f.calls(taCmdSeal)
	if len(seals) != 2 {
		t.Fatalf("Protect ran SEAL %d times after one short buffer; want 2", len(seals))
	}
	wantMemref(t, "the first SEAL's output", seals[0].params[2], teeParamAttrTypeMemrefOutput, outOff, len(key)+sealOverhead)
	wantMemref(t, "the retried SEAL's output", seals[1].params[2], teeParamAttrTypeMemrefOutput, outOff, asked)
	if !bytes.Equal(seals[1].params[0].in, key) || !bytes.Equal(seals[1].params[1].in, ad) {
		t.Error("the retried SEAL did not carry the key and the label")
	}
	dst := make([]byte, len(key))
	if err := p.Unprotect(ctx, blob, dst); err != nil || !bytes.Equal(dst, key) {
		t.Errorf("Unprotect of the retried blob = %v, %x; want nil, %x", err, dst, key)
	}

	for _, tc := range []struct {
		name  string
		times int
		size  uint64
		runs  int
	}{
		{"short twice", 2, asked, 2},
		{"short above the cap", 1, sealMaxBlob + 1, 1},
	} {
		before := len(f.calls(taCmdSeal))
		f.shortSeal(tc.times, tc.size)
		_, err := p.Protect(ctx, key)
		var ce *CommandError
		if !errors.As(err, &ce) || ce.Code != teecErrorShortBuffer {
			t.Errorf("%s: Protect = %v; want a short-buffer CommandError", tc.name, err)
		}
		if n := len(f.calls(taCmdSeal)) - before; n != tc.runs {
			t.Errorf("%s: Protect ran SEAL %d times; want %d", tc.name, n, tc.runs)
		}
		f.shortSeal(0, 0)
		if n := f.live(); n != 0 {
			t.Errorf("%s: %d shared-memory objects are still live", tc.name, n)
		}
	}
}

func TestUnprotectTamperedBlob(t *testing.T) {
	forEachDriver(t, func(t *testing.T, f *fakeTEE) {
		ctx := context.Background()
		p := connectFake(t, f)
		key := testKey(32)
		blob, err := p.Protect(ctx, key)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		cases := map[string][]byte{"truncated": blob[:20]}
		for _, i := range []int{0, 12, len(blob) / 2, len(blob) - 1} {
			tampered := bytes.Clone(blob)
			tampered[i] ^= 0x01
			cases[fmt.Sprintf("byte %d flipped", i)] = tampered
		}
		for name, b := range cases {
			dst := make([]byte, len(key))
			if err := p.Unprotect(ctx, b, dst); !errors.Is(err, enclave.ErrSealedAuthentication) {
				t.Errorf("%s: Unprotect = %v; want ErrSealedAuthentication", name, err)
			}
			if !bytes.Equal(dst, make([]byte, len(dst))) {
				t.Errorf("%s: a refused Unprotect left bytes in the key", name)
			}
		}
	})
}
