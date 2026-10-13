// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"encoding/binary"
	"errors"
)

// Blob framing. Every wrapped-key blob this package produces starts with a
// fixed header that is also the AAD of the wrapping, so a blob cannot be
// re-purposed across kinds or generations. [ModePerOperation] provider blobs
// are opaque.
const (
	// blobVersion makes an accidental format change fail authentication
	// instead of misparse. Sealed values do not outlive the process, so there
	// is no cross-version compatibility promise.
	blobVersion = 1

	blobKindDEK byte = 1 // a DEK wrapped under a KEK generation
	blobKindKEK byte = 2 // a KEK wrapped under the root
	// blobKindProvider marks a key protected by [SoftwareProvider]. Kind 4 is
	// reserved (an earlier build framed blobs with it); never assign it.
	blobKindProvider byte = 3

	// blobHeaderLen is version + kind + a 4-byte big-endian generation (zero
	// for kinds without one).
	blobHeaderLen = 6
)

func blobHeader(kind byte, gen uint32) []byte {
	h := make([]byte, blobHeaderLen)
	h[0] = blobVersion
	h[1] = kind
	binary.BigEndian.PutUint32(h[2:], gen)
	return h
}

// parseBlobHeader reads a blob's frame. Any malformation is an authentication
// failure.
func parseBlobHeader(blob []byte) (kind byte, gen uint32, err error) {
	if len(blob) < blobHeaderLen || blob[0] != blobVersion {
		return 0, 0, ErrSealedAuthentication
	}
	return blob[1], binary.BigEndian.Uint32(blob[2:blobHeaderLen]), nil
}

// wrapKey seals key under the key in wrapping and returns the blob: the
// frame for kind and gen, which the seal binds as AAD, then the sealed key.
// A wrapping handle with [AEAD] seals in its device; one with only
// [ByteAccess] seals in this process.
func wrapKey(wrapping Handle, key []byte, kind byte, gen uint32) ([]byte, error) {
	header := blobHeader(kind, gen)
	var body []byte
	var err error
	switch k := wrapping.(type) {
	case AEAD:
		body, err = sealOnDevice(k, key, header)
	case ByteAccess:
		body, err = sealWithKey(k, key, header)
	default:
		err = &CapabilityError{Backend: backendName(wrapping), Capability: CapabilityAEAD}
	}
	if err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// unwrapKey recovers the key in a wrapKey blob into dst, verifying the frame
// as AAD. The caller chooses wrapping from the frame (parseBlobHeader); any
// frame other than the one sealed fails authentication here.
func unwrapKey(wrapping Handle, blob, dst []byte) error {
	if len(blob) < blobHeaderLen {
		return ErrSealedAuthentication
	}
	sealed, header := blob[blobHeaderLen:], blob[:blobHeaderLen]
	switch k := wrapping.(type) {
	case AEAD:
		return openOnDeviceInto(k, sealed, header, dst)
	case ByteAccess:
		return openWithKeyInto(k, sealed, header, dst)
	default:
		return &CapabilityError{Backend: backendName(wrapping), Capability: CapabilityAEAD}
	}
}

// sealOnDevice is sealWithKey for a key that never leaves its device: the
// handle's AEAD seals, under a fresh random nonce carried in front.
func sealOnDevice(key AEAD, plaintext, aad []byte) ([]byte, error) {
	ns := key.NonceSize()
	out := make([]byte, ns, ns+len(plaintext)+key.Overhead())
	var nonce []byte
	if ns > 0 {
		nonce = out[:ns]
		if err := fillRandom(nonce); err != nil {
			return nil, &SealError{Cause: err}
		}
	}
	sealed, err := key.Seal(out, nonce, plaintext, aad)
	if err != nil {
		return nil, deviceFailure[SealError](err)
	}
	return sealed, nil
}

// openOnDeviceInto is openWithKeyInto for a key that never leaves its
// device, with the same refusal of a result that did not land in dst.
func openOnDeviceInto(key AEAD, sealed, aad, dst []byte) error {
	ns := key.NonceSize()
	if len(sealed) <= ns || len(dst) == 0 {
		return ErrSealedAuthentication
	}
	var nonce []byte
	if ns > 0 {
		nonce = sealed[:ns]
	}
	// The device may have written into dst before refusing, and a length
	// check cannot come first: Overhead is only an upper bound. So every
	// refusal from here wipes dst.
	got, err := key.Open(dst[:0:len(dst)], nonce, sealed[ns:], aad)
	if err != nil {
		Wipe(dst)
		return deviceFailure[OpenError](err)
	}
	if len(got) > 0 && &got[0] != &dst[0] {
		Wipe(got)
		Wipe(dst)
		return ErrPlaintextEscaped
	}
	if len(got) != len(dst) {
		Wipe(dst)
		return ErrSealedAuthentication
	}
	return nil
}

// deviceFailure translates an AEAD handle's error: a failed authentication
// is the envelope's, a destroyed handle is left for hierarchyFailure to
// judge, and anything else is the device's own failure, an E.
func deviceFailure[E causeShape, P causeError[E]](err error) error {
	switch {
	case errors.Is(err, ErrAEADAuthentication):
		return ErrSealedAuthentication
	case errors.Is(err, ErrEnclaveDestroyed):
		return err
	}
	return newCause[E, P](err)
}
