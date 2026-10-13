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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
)

// FuzzUnwrapKey feeds unwrapKey, and the parseBlobHeader it relies on, frames
// it did not produce. A frame shorter than blobHeaderLen or of another version
// is malformed and refused with ErrSealedAuthentication; every other frame
// parses to the bytes it carries. unwrapKey never panics, accepts only the one
// blob wrapKey produced, and refuses everything else with
// ErrSealedAuthentication, leaving dst untouched or wiped.
func FuzzUnwrapKey(f *testing.F) {
	const gen = 3
	wrapping := newWrappingKey(f)
	key := make([]byte, dekBytes)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	blob, err := wrapKey(wrapping, key, blobKindDEK, gen)
	if err != nil {
		f.Fatalf("wrapKey: %v", err)
	}

	f.Add([]byte(nil), uint8(dekBytes))
	f.Add(blob, uint8(dekBytes))
	f.Add(blob, uint8(dekBytes-1))
	f.Add(blob, uint8(dekBytes+1))
	f.Add(append([]byte{blobVersion + 1}, blob[1:]...), uint8(dekBytes))
	for _, c := range fuzzSeedMutations(blob) {
		f.Add(c, uint8(dekBytes))
	}

	f.Fuzz(func(t *testing.T, in []byte, dstLen uint8) {
		kind, g, perr := parseBlobHeader(in)
		malformed := len(in) < blobHeaderLen || in[0] != blobVersion
		switch {
		case malformed && !errors.Is(perr, ErrSealedAuthentication):
			t.Fatalf("parseBlobHeader(malformed frame) = %v, want ErrSealedAuthentication", perr)
		case !malformed && perr != nil:
			t.Fatalf("parseBlobHeader(well-formed frame) = %v, want nil", perr)
		case !malformed && !bytes.Equal(blobHeader(kind, g), in[:blobHeaderLen]):
			t.Fatalf("parseBlobHeader read kind %d generation %d from a frame that carries others", kind, g)
		}

		dst := fuzzDestination(int(dstLen))
		err := unwrapKey(wrapping, in, dst)
		switch {
		case err == nil:
			if malformed || kind != blobKindDEK || g != gen || !bytes.Equal(dst, key) {
				t.Fatal("unwrapKey accepted a blob wrapKey did not produce")
			}
		case !errors.Is(err, ErrSealedAuthentication):
			t.Fatalf("unwrapKey = %v, want ErrSealedAuthentication", err)
		case !refusedCleanly(dst):
			t.Fatal("a refused unwrapKey left the destination partly written")
		}
	})
}

// FuzzUnwrapKeyDevice is FuzzUnwrapKey for a wrapping key that encrypts in its
// device, the openOnDeviceInto path, at every nonce size the fuzzer picks, 0
// included. wrapKey followed by unwrapKey round-trips; unwrapKey never panics,
// accepts only the blob wrapKey produced, and refuses everything else with
// ErrSealedAuthentication, or ErrPlaintextEscaped when the genuine key is
// longer than dst, leaving dst wiped once the device has opened into it and
// untouched before.
func FuzzUnwrapKeyDevice(f *testing.F) {
	const gen = 3
	device := newFuzzDeviceKey(f)
	key := make([]byte, dekBytes)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}

	f.Add([]byte(nil), uint8(dekBytes), uint8(0))
	for _, ns := range []uint8{0, 1, 12} {
		blob, err := wrapKey(device.withNonceSize(ns), key, blobKindDEK, gen)
		if err != nil {
			f.Fatalf("wrapKey: %v", err)
		}
		f.Add(blob, uint8(dekBytes), ns)
		f.Add(blob, uint8(dekBytes-1), ns)
		f.Add(blob, uint8(dekBytes+1), ns)
		for _, c := range fuzzSeedMutations(blob) {
			f.Add(c, uint8(dekBytes), ns)
		}
	}

	f.Fuzz(func(t *testing.T, in []byte, dstLen, nonceSize uint8) {
		k := device.withNonceSize(nonceSize)
		blob, err := wrapKey(k, key, blobKindDEK, gen)
		if err != nil {
			t.Fatalf("wrapKey: %v", err)
		}
		back := make([]byte, len(key))
		if err := unwrapKey(k, blob, back); err != nil || !bytes.Equal(back, key) {
			t.Fatalf("unwrapKey(wrapKey(key)) = %v, want the key back", err)
		}

		dst := fuzzDestination(int(dstLen))
		err = unwrapKey(k, in, dst)
		switch {
		case err == nil:
			if !bytes.Equal(in[:blobHeaderLen], blobHeader(blobKindDEK, gen)) || !bytes.Equal(dst, key) {
				t.Fatal("unwrapKey accepted a blob wrapKey did not produce")
			}
		case errors.Is(err, ErrPlaintextEscaped):
			if len(dst) >= len(key) {
				t.Fatal("unwrapKey reported an escape for a plaintext that fits dst")
			}
		case !errors.Is(err, ErrSealedAuthentication):
			t.Fatalf("unwrapKey = %v, want ErrSealedAuthentication", err)
		}
		reached := len(in)-blobHeaderLen > int(nonceSize) && len(dst) > 0
		if err != nil && !refusedAsDocumented(dst, reached) {
			t.Fatal("a refused unwrapKey left the destination partly written")
		}
	})
}

// The behaviors of a fuzzDeviceKey's Open in FuzzOpenOnDeviceInto, picked by
// the mode byte modulo deviceModes.
const (
	// deviceHonest opens with the real AEAD.
	deviceHonest = iota
	// deviceEscapes returns n bytes of plaintext in a buffer of its own.
	deviceEscapes
	// deviceMisSized appends n bytes to dst: in place when they fit, in a
	// fresh buffer when they do not.
	deviceMisSized
	// deviceFails writes up to n bytes into dst and then fails with
	// deviceFailures[mode/deviceModes%3].
	deviceFails
	deviceModes
)

// fuzzDeviceMarker is the plaintext a misbehaving fuzzDeviceKey writes:
// neither fuzzUntouched nor zero, so refusedCleanly sees every byte of it.
const fuzzDeviceMarker byte = 0x3C

// errFuzzDevice is the device failure of a fuzzDeviceKey that fails.
var errFuzzDevice = errors.New("fuzz: device key failed")

// deviceFailures are the errors a failing fuzzDeviceKey returns: its own
// device failure and the two AEAD errors openOnDeviceInto maps.
var deviceFailures = [...]error{errFuzzDevice, ErrAEADAuthentication, ErrEnclaveDestroyed}

// FuzzOpenOnDeviceInto feeds openOnDeviceInto sealed bytes and additional data
// it did not produce, at every nonce size and dst length, through a device key
// that is honest or misbehaves. openOnDeviceInto never panics; sealOnDevice
// followed by openOnDeviceInto round-trips; the honest key's only accepted
// plaintext is the one sealed; a plaintext returned outside dst is refused with
// ErrPlaintextEscaped and wiped; one of the wrong length is refused with
// ErrSealedAuthentication; a device failure is an *OpenError carrying it,
// except ErrAEADAuthentication (ErrSealedAuthentication) and
// ErrEnclaveDestroyed (itself). Every refusal leaves dst wiped once the device
// has opened into it, untouched before.
func FuzzOpenOnDeviceInto(f *testing.F) {
	device := newFuzzDeviceKey(f)
	plaintext := make([]byte, dekBytes)
	if _, err := rand.Read(plaintext); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	aad := blobHeader(blobKindDEK, 3)

	f.Add([]byte(nil), []byte(nil), uint8(dekBytes), uint8(0), uint8(deviceHonest), uint8(0))
	for _, ns := range []uint8{0, 12} {
		sealed, err := sealOnDevice(device.withNonceSize(ns), plaintext, aad)
		if err != nil {
			f.Fatalf("sealOnDevice: %v", err)
		}
		f.Add(sealed, aad, uint8(dekBytes), ns, uint8(deviceHonest), uint8(0))
		f.Add(sealed, aad, uint8(dekBytes-1), ns, uint8(deviceHonest), uint8(0))
		f.Add(sealed, aad, uint8(dekBytes+1), ns, uint8(deviceHonest), uint8(0))
		f.Add(sealed, []byte(nil), uint8(dekBytes), ns, uint8(deviceHonest), uint8(0))
		f.Add(sealed, aad, uint8(dekBytes), ns, uint8(deviceEscapes), uint8(dekBytes))
		f.Add(sealed, aad, uint8(dekBytes), ns, uint8(deviceMisSized), uint8(dekBytes))
		f.Add(sealed, aad, uint8(dekBytes), ns, uint8(deviceMisSized), uint8(dekBytes+1))
		for i := range deviceFailures {
			f.Add(sealed, aad, uint8(dekBytes), ns, uint8(deviceFails+i*deviceModes), uint8(0))
		}
	}

	f.Fuzz(func(t *testing.T, sealed, aad []byte, dstLen, nonceSize, mode, n uint8) {
		k := device.withNonceSize(nonceSize)
		roundTrip, err := sealOnDevice(k, plaintext, aad)
		if err != nil {
			t.Fatalf("sealOnDevice: %v", err)
		}
		back := make([]byte, len(plaintext))
		if err := openOnDeviceInto(k, roundTrip, aad, back); err != nil || !bytes.Equal(back, plaintext) {
			t.Fatalf("openOnDeviceInto(sealOnDevice(plaintext)) = %v, want the plaintext back", err)
		}

		behavior, failure := int(mode)%deviceModes, deviceFailures[int(mode)/deviceModes%len(deviceFailures)]
		var stray []byte // a plaintext the device returned outside dst
		switch behavior {
		case deviceEscapes:
			k.open = func([]byte) ([]byte, error) {
				stray = bytes.Repeat([]byte{fuzzDeviceMarker}, int(n))
				return stray, nil
			}
		case deviceMisSized:
			k.open = func(dst []byte) ([]byte, error) {
				out := append(dst, bytes.Repeat([]byte{fuzzDeviceMarker}, int(n))...)
				if int(n) > cap(dst) {
					stray = out
				}
				return out, nil
			}
		case deviceFails:
			k.open = func(dst []byte) ([]byte, error) {
				_ = append(dst, bytes.Repeat([]byte{fuzzDeviceMarker}, min(int(n), cap(dst)))...)
				return nil, failure
			}
		}

		dst := fuzzDestination(int(dstLen))
		err = openOnDeviceInto(k, sealed, aad, dst)
		if !bytes.Equal(stray, make([]byte, len(stray))) {
			t.Fatal("openOnDeviceInto left a plaintext that escaped dst unwiped")
		}
		reached := len(sealed) > int(nonceSize) && len(dst) > 0
		switch {
		case !reached || behavior == deviceHonest:
			switch {
			case err == nil:
				if !reached || !bytes.Equal(dst, plaintext) {
					t.Fatal("openOnDeviceInto accepted bytes sealOnDevice did not produce")
				}
			case errors.Is(err, ErrPlaintextEscaped):
				if !reached || len(dst) >= len(plaintext) {
					t.Fatal("openOnDeviceInto reported an escape for a plaintext that fits dst")
				}
			case !errors.Is(err, ErrSealedAuthentication):
				t.Fatalf("openOnDeviceInto = %v, want ErrSealedAuthentication", err)
			}
		case behavior == deviceFails && failure == errFuzzDevice:
			var oe *OpenError
			if !errors.As(err, &oe) || !errors.Is(err, errFuzzDevice) {
				t.Fatalf("openOnDeviceInto = %v, want an *OpenError carrying the device failure", err)
			}
		case behavior == deviceFails && failure == ErrEnclaveDestroyed:
			if !errors.Is(err, ErrEnclaveDestroyed) {
				t.Fatalf("openOnDeviceInto = %v, want ErrEnclaveDestroyed", err)
			}
		case behavior == deviceFails, int(n) < len(dst) && behavior == deviceMisSized, n == 0:
			if !errors.Is(err, ErrSealedAuthentication) {
				t.Fatalf("openOnDeviceInto = %v, want ErrSealedAuthentication", err)
			}
		case int(n) == len(dst) && behavior == deviceMisSized:
			if err != nil {
				t.Fatalf("openOnDeviceInto = %v for a plaintext that fills dst, want nil", err)
			}
		case !errors.Is(err, ErrPlaintextEscaped):
			t.Fatalf("openOnDeviceInto = %v, want ErrPlaintextEscaped", err)
		}
		if err != nil && !refusedAsDocumented(dst, reached) {
			t.Fatal("a refused openOnDeviceInto left the destination partly written")
		}
	})
}

// fuzzDeviceKey is a wrapping key that encrypts in its device, implementing
// AEAD and not ByteAccess, at any nonce size: AES-256-GCM under a nonce it
// draws itself, so FIPS 140-only mode accepts it, with the caller's
// NonceSize-byte nonce bound as additional data. open, when set, replaces
// Open's decryption, so a target can model a device that breaks the AEAD
// contract.
// refusedAsDocumented reports whether a refused openOnDeviceInto left dst as
// its contract says: wiped whole once the device's Open has run (reached),
// untouched otherwise.
func refusedAsDocumented(dst []byte, reached bool) bool {
	if reached {
		return bytes.Equal(dst, make([]byte, len(dst)))
	}
	return bytes.Equal(dst, fuzzDestination(len(dst)))
}

type fuzzDeviceKey struct {
	gcm       cipher.AEAD
	nonceSize int
	open      func(dst []byte) ([]byte, error)
}

func newFuzzDeviceKey(tb testing.TB) *fuzzDeviceKey {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("rand.Read: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		tb.Fatalf("cipher.NewGCMWithRandomNonce: %v", err)
	}
	return &fuzzDeviceKey{gcm: gcm}
}

// withNonceSize returns an honest key under the same AES key that takes
// nonces of ns bytes.
func (k *fuzzDeviceKey) withNonceSize(ns uint8) *fuzzDeviceKey {
	return &fuzzDeviceKey{gcm: k.gcm, nonceSize: int(ns)}
}

func (k *fuzzDeviceKey) Size() int        { return 32 }
func (k *fuzzDeviceKey) IsAlive() bool    { return true }
func (k *fuzzDeviceKey) Destroy() error   { return nil }
func (k *fuzzDeviceKey) Backend() Backend { return namedBackend{} }
func (k *fuzzDeviceKey) NonceSize() int   { return k.nonceSize }
func (k *fuzzDeviceKey) Overhead() int    { return k.gcm.Overhead() }

func (k *fuzzDeviceKey) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != k.nonceSize {
		return nil, ErrInvalidNonce
	}
	return k.gcm.Seal(dst, nil, plaintext, append(bytes.Clone(nonce), additionalData...)), nil
}

func (k *fuzzDeviceKey) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != k.nonceSize {
		return nil, ErrInvalidNonce
	}
	if k.open != nil {
		return k.open(dst)
	}
	out, err := k.gcm.Open(dst, nil, ciphertext, append(bytes.Clone(nonce), additionalData...))
	if err != nil {
		return nil, ErrAEADAuthentication
	}
	return out, nil
}
