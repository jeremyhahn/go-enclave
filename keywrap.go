// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "encoding/binary"

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
func wrapKey(wrapping *MemoryEnclave, key []byte, kind byte, gen uint32) ([]byte, error) {
	header := blobHeader(kind, gen)
	body, err := sealWithKey(wrapping, key, header)
	if err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// unwrapKey recovers the key in a wrapKey blob into dst, verifying the frame
// as AAD. The caller chooses wrapping from the frame (parseBlobHeader); any
// frame other than the one sealed fails authentication here.
func unwrapKey(wrapping *MemoryEnclave, blob, dst []byte) error {
	if len(blob) < blobHeaderLen {
		return ErrSealedAuthentication
	}
	return openWithKeyInto(wrapping, blob[blobHeaderLen:], blob[:blobHeaderLen], dst)
}
