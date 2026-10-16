// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"errors"
	"testing"
)

// newWrappingKey returns a fresh key enclave the test destroys on cleanup.
func newWrappingKey(t testing.TB) *lockedRegion {
	t.Helper()
	k, err := newKeyEnclave(dekBytes)
	if err != nil {
		t.Fatalf("newKeyEnclave: %v", err)
	}
	t.Cleanup(func() { _ = k.Destroy() })
	return k
}

// TestWrapKey_FramesAndRoundTrips pins the blob layout: the frame for kind
// and generation, readable by parseBlobHeader, followed by a body that
// unwrapKey recovers into the caller's buffer.
func TestWrapKey_FramesAndRoundTrips(t *testing.T) {
	wrapping := newWrappingKey(t)
	key := bytes.Repeat([]byte{0x5C}, dekBytes)

	blob, err := wrapKey(wrapping, key, blobKindKEK, 7)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	if !bytes.Equal(blob[:blobHeaderLen], blobHeader(blobKindKEK, 7)) {
		t.Fatalf("blob frame = %x, want %x", blob[:blobHeaderLen], blobHeader(blobKindKEK, 7))
	}
	if len(blob) != blobHeaderLen+len(key)+sealedOverhead {
		t.Errorf("blob length = %d, want frame + key + AEAD overhead (%d)", len(blob), blobHeaderLen+len(key)+sealedOverhead)
	}
	kind, gen, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindKEK || gen != 7 {
		t.Fatalf("parseBlobHeader = (%d, %d, %v), want (%d, 7, nil)", kind, gen, err, blobKindKEK)
	}

	got := make([]byte, len(key))
	if err := unwrapKey(wrapping, blob, got); err != nil {
		t.Fatalf("unwrapKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("unwrapKey recovered the wrong key")
	}
}

// TestUnwrapKey_RefusesWhatWrapKeyDidNotProduce pins that the frame is bound
// as AAD: re-framing a blob under another kind or generation, truncating it,
// or opening it under another wrapping key fails authentication and writes
// nothing into the destination.
func TestUnwrapKey_RefusesWhatWrapKeyDidNotProduce(t *testing.T) {
	wrapping := newWrappingKey(t)
	key := bytes.Repeat([]byte{0x5C}, dekBytes)
	blob, err := wrapKey(wrapping, key, blobKindDEK, 3)
	if err != nil {
		t.Fatalf("wrapKey: %v", err)
	}
	reframed := func(kind byte, gen uint32) []byte {
		return append(blobHeader(kind, gen), blob[blobHeaderLen:]...)
	}

	cases := map[string]struct {
		wrapping *lockedRegion
		blob     []byte
	}{
		"another kind":          {wrapping, reframed(blobKindKEK, 3)},
		"another generation":    {wrapping, reframed(blobKindDEK, 4)},
		"shorter than a frame":  {wrapping, blob[:blobHeaderLen-1]},
		"frame only":            {wrapping, blob[:blobHeaderLen]},
		"body truncated":        {wrapping, blob[:len(blob)-1]},
		"another wrapping key":  {newWrappingKey(t), blob},
		"body bit flipped":      {wrapping, append(bytes.Clone(blob[:len(blob)-1]), blob[len(blob)-1]^1)},
		"another version frame": {wrapping, append([]byte{blobVersion + 1}, blob[1:]...)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dst := make([]byte, len(key))
			if err := unwrapKey(c.wrapping, c.blob, dst); !errors.Is(err, ErrSealedAuthentication) {
				t.Fatalf("unwrapKey = %v, want ErrSealedAuthentication", err)
			}
			if !bytes.Equal(dst, make([]byte, len(key))) {
				t.Error("a refused unwrap wrote into the destination")
			}
		})
	}
}

// TestOpenOnDeviceInto_RefusalWipesDst pins the device path's refusal
// contract: once the device's Open has run, every refusal leaves dst all zero,
// whatever the device wrote there; a refusal before it leaves dst untouched.
func TestOpenOnDeviceInto_RefusalWipesDst(t *testing.T) {
	const n = 16
	sealed := make([]byte, n+28)
	mark := func(dst []byte, k int) []byte {
		return append(dst, bytes.Repeat([]byte{fuzzDeviceMarker}, k)...)
	}
	failing := func(err error) func([]byte) ([]byte, error) {
		return func(dst []byte) ([]byte, error) {
			mark(dst, n)
			return nil, err
		}
	}
	var escaped []byte

	cases := map[string]struct {
		open func(dst []byte) ([]byte, error)
		want error
	}{
		"device failure":         {open: failing(errFuzzDevice), want: ErrOpenFailed},
		"authentication failure": {open: failing(ErrAEADAuthentication), want: ErrSealedAuthentication},
		"destroyed key":          {open: failing(ErrEnclaveDestroyed), want: ErrEnclaveDestroyed},
		"plaintext outside dst": {
			open: func(dst []byte) ([]byte, error) {
				mark(dst, n-1)
				escaped = bytes.Repeat([]byte{fuzzDeviceMarker}, n)
				return escaped, nil
			},
			want: ErrPlaintextEscaped,
		},
		"plaintext longer than dst": {
			open: func(dst []byte) ([]byte, error) { return mark(dst, n+1), nil },
			want: ErrPlaintextEscaped,
		},
		"plaintext shorter than dst": {
			open: func(dst []byte) ([]byte, error) { return mark(dst, n-1), nil },
			want: ErrSealedAuthentication,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			k := newFuzzDeviceKey(t).withNonceSize(0)
			k.open = c.open
			dst := fuzzDestination(n)
			err := openOnDeviceInto(k, sealed, nil, dst)
			if !errors.Is(err, c.want) {
				t.Fatalf("openOnDeviceInto = %v, want %v", err, c.want)
			}
			if !bytes.Equal(dst, make([]byte, n)) {
				t.Fatalf("dst = %x after the refusal, want it wiped", dst)
			}
		})
	}
	if !bytes.Equal(escaped, make([]byte, n)) {
		t.Error("the plaintext returned outside dst was not wiped")
	}

	k := newFuzzDeviceKey(t).withNonceSize(0)
	k.open = failing(errFuzzDevice)
	var oe *OpenError
	if err := openOnDeviceInto(k, sealed, nil, fuzzDestination(n)); !errors.As(err, &oe) || !errors.Is(err, errFuzzDevice) {
		t.Errorf("openOnDeviceInto = %v, want an *OpenError carrying the device failure", err)
	}

	// Refused before the device runs: dst is never handed over.
	for name, c := range map[string]struct {
		nonceSize uint8
		sealed    []byte
		dstLen    int
	}{
		"empty sealed":      {0, nil, n},
		"nonce only":        {12, make([]byte, 12), n},
		"empty destination": {0, sealed, 0},
	} {
		t.Run(name, func(t *testing.T) {
			k := newFuzzDeviceKey(t).withNonceSize(c.nonceSize)
			k.open = failing(errFuzzDevice)
			dst := fuzzDestination(c.dstLen)
			if err := openOnDeviceInto(k, c.sealed, nil, dst); !errors.Is(err, ErrSealedAuthentication) {
				t.Fatalf("openOnDeviceInto = %v, want ErrSealedAuthentication", err)
			}
			if !bytes.Equal(dst, fuzzDestination(c.dstLen)) {
				t.Fatalf("dst = %x after a refusal before the device ran, want it untouched", dst)
			}
		})
	}
}

// TestParseBlobHeader_RefusesMalformedFrames pins that a frame too short to
// hold a generation, or of another version, is an authentication failure
// rather than a misparse.
func TestParseBlobHeader_RefusesMalformedFrames(t *testing.T) {
	short := blobHeader(blobKindDEK, 1)[:blobHeaderLen-1]
	if _, _, err := parseBlobHeader(short); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("parseBlobHeader(short) = %v, want ErrSealedAuthentication", err)
	}
	other := blobHeader(blobKindDEK, 1)
	other[0] = blobVersion + 1
	if _, _, err := parseBlobHeader(other); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("parseBlobHeader(other version) = %v, want ErrSealedAuthentication", err)
	}
	if _, _, err := parseBlobHeader(nil); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("parseBlobHeader(nil) = %v, want ErrSealedAuthentication", err)
	}
}
