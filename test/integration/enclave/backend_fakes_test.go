// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/subtle"
	"errors"
	"sync"
	"sync/atomic"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The backend fakes the sealing, backends and shutdown-sweep suites share. A
// fake stands in for a device the process cannot see into: its keys live in
// the fake, and a test steers what each call returns.

// shape is what a fake backend's Import returns.
type shape int

const (
	// shapeDefault is an AEAD key for a key purpose and a ByteAccess handle
	// for PurposeMaterial.
	shapeDefault shape = iota
	// shapeInlineAEAD is an AEAD key that draws its own nonce: NonceSize is 0
	// and the nonce travels in the ciphertext.
	shapeInlineAEAD
	// shapeOpaque is a Handle with no capability at all.
	shapeOpaque
	// shapeNil is a nil Handle and no error.
	shapeNil
)

// errDevice is the generic failure a fake device reports.
var errDevice = errors.New("fake device: call failed")

// importCall records one Import.
type importCall struct {
	spec enclave.ImportSpec
	size int
}

// deviceFaults steers the AEAD calls of every key a deviceBackend made.
type deviceFaults struct {
	seal, open error
	// escape makes Open return the plaintext in a slice of its own instead of
	// the dst it was given.
	escape bool
	// short makes Open return one byte less than it decrypted.
	short bool
}

// deviceBackend is an Importer whose key handles implement AEAD and whose
// material handles implement ByteAccess.
type deviceBackend struct {
	name string

	mu         sync.Mutex
	calls      []importCall
	handles    []enclave.Handle // by call; nil where Import made none
	keys       shape
	material   shape
	hook       func(call int, spec enclave.ImportSpec) error
	withHandle bool // a failed Import still returns the handle it made
	faults     deviceFaults

	sealOps, openOps atomic.Int64
}

func newDeviceBackend() *deviceBackend {
	return &deviceBackend{name: uniqueBackendName("device")}
}

var (
	_ enclave.Importer   = (*deviceBackend)(nil)
	_ enclave.AEAD       = (*deviceKey)(nil)
	_ enclave.ByteAccess = (*deviceMaterial)(nil)
	_ enclave.ByteAccess = (*phantom)(nil)
	_ enclave.Sweeper    = (*sweepingBackend)(nil)
	_ enclave.Confiner   = confinedDevice{}
)

func (b *deviceBackend) Name() string { return b.name }

// Import implements enclave.Importer: the material is wiped on every path.
func (b *deviceBackend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	defer enclave.Wipe(material)
	spec, err := enclave.NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.calls = append(b.calls, importCall{spec: spec, size: len(material)})
	b.handles = append(b.handles, nil)
	call := len(b.calls)
	hook, keys, mat, withHandle := b.hook, b.keys, b.material, b.withHandle
	b.mu.Unlock()

	var failure error
	if hook != nil {
		failure = hook(call, spec)
	}
	if failure == nil {
		failure = ctx.Err()
	}
	if failure != nil && !withHandle {
		return nil, failure
	}

	h := b.newHandle(spec, material, keys, mat)
	b.mu.Lock()
	b.handles[call-1] = h
	b.mu.Unlock()
	return h, failure
}

func (b *deviceBackend) newHandle(spec enclave.ImportSpec, material []byte, keys, mat shape) enclave.Handle {
	base := &deviceHandle{b: b, size: len(material)}
	if spec.Purpose == enclave.PurposeMaterial {
		switch mat {
		case shapeNil:
			return nil
		case shapeOpaque:
			return &opaqueHandle{deviceHandle: base}
		}
		return &deviceMaterial{deviceHandle: base, data: bytes.Clone(material)}
	}
	switch keys {
	case shapeNil:
		return nil
	case shapeOpaque:
		return &opaqueHandle{deviceHandle: base}
	}
	blk, err := aes.NewCipher(material)
	if err != nil {
		panic(err) // the sealer imports 32-byte keys
	}
	// FIPS 140-only mode refuses a caller-chosen GCM nonce, so there every key
	// draws its own, as the inline shape does: a device that takes the nonce
	// from the caller cannot be built, and fipsOnly lets a test see that.
	inline := keys == shapeInlineAEAD || fipsOnly()
	var g cipher.AEAD
	if inline {
		g, err = cipher.NewGCMWithRandomNonce(blk)
	} else {
		g, err = cipher.NewGCM(blk)
	}
	if err != nil {
		panic(err)
	}
	return &deviceKey{deviceHandle: base, aead: g, inline: inline}
}

// fipsOnly reports whether the process runs with GODEBUG=fips140=only, which
// refuses AES-GCM with a caller-chosen nonce.
func fipsOnly() bool { return fips140.Enforced() }

// setHook installs fn, called with the 1-based number of each Import before it
// does anything; a non-nil result fails that Import.
func (b *deviceBackend) setHook(fn func(call int, spec enclave.ImportSpec) error) {
	b.mu.Lock()
	b.hook = fn
	b.mu.Unlock()
}

// setShapes selects what Import returns for key purposes and for
// PurposeMaterial.
func (b *deviceBackend) setShapes(keys, material shape) {
	b.mu.Lock()
	b.keys, b.material = keys, material
	b.mu.Unlock()
}

// setReturnsHandleWithError makes a failed Import return the live handle it
// made along with the error.
func (b *deviceBackend) setReturnsHandleWithError(v bool) {
	b.mu.Lock()
	b.withHandle = v
	b.mu.Unlock()
}

func (b *deviceBackend) setFaults(f deviceFaults) {
	b.mu.Lock()
	b.faults = f
	b.mu.Unlock()
}

func (b *deviceBackend) currentFaults() deviceFaults {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.faults
}

// imports returns the Imports so far, in order.
func (b *deviceBackend) imports() []importCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]importCall(nil), b.calls...)
}

// handle returns the handle the n-th (1-based) Import made, or nil.
func (b *deviceBackend) handle(n int) enclave.Handle {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 1 || n > len(b.handles) {
		return nil
	}
	return b.handles[n-1]
}

// live counts the handles Import made that are not destroyed.
func (b *deviceBackend) live() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, h := range b.handles {
		if h != nil && h.IsAlive() {
			n++
		}
	}
	return n
}

// deviceHandle is the Handle half every fake handle shares.
type deviceHandle struct {
	b    *deviceBackend
	size int
	dead atomic.Bool
}

func (h *deviceHandle) Size() int {
	if h.dead.Load() {
		return 0
	}
	return h.size
}
func (h *deviceHandle) IsAlive() bool            { return !h.dead.Load() }
func (h *deviceHandle) Destroy() error           { h.dead.Store(true); return nil }
func (h *deviceHandle) Backend() enclave.Backend { return h.b }

// opaqueHandle is a handle with no capability.
type opaqueHandle struct{ *deviceHandle }

// deviceKey is a key that never leaves the fake: an enclave.AEAD.
type deviceKey struct {
	*deviceHandle
	aead   cipher.AEAD
	inline bool
}

func (k *deviceKey) NonceSize() int {
	if k.inline {
		return 0
	}
	return k.aead.NonceSize()
}

// Overhead is the AEAD's: for the random-nonce GCM it already counts the nonce
// it prepends.
func (k *deviceKey) Overhead() int { return k.aead.Overhead() }

func (k *deviceKey) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if !k.IsAlive() {
		return nil, enclave.ErrEnclaveDestroyed
	}
	k.b.sealOps.Add(1)
	if err := k.b.currentFaults().seal; err != nil {
		return nil, err
	}
	if k.inline {
		// The nonce is drawn and prepended to the ciphertext.
		return k.aead.Seal(dst, nil, plaintext, additionalData), nil
	}
	if len(nonce) != k.aead.NonceSize() {
		return nil, enclave.ErrInvalidNonce
	}
	return k.aead.Seal(dst, nonce, plaintext, additionalData), nil
}

func (k *deviceKey) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if !k.IsAlive() {
		return nil, enclave.ErrEnclaveDestroyed
	}
	k.b.openOps.Add(1)
	f := k.b.currentFaults()
	if f.open != nil {
		return nil, f.open
	}
	if k.inline {
		nonce = nil // carried in the ciphertext
	} else if len(nonce) != k.aead.NonceSize() {
		return nil, enclave.ErrInvalidNonce
	}
	if f.escape {
		pt, err := k.aead.Open(nil, nonce, ciphertext, additionalData)
		if err != nil {
			return nil, enclave.ErrAEADAuthentication
		}
		return pt, nil
	}
	pt, err := k.aead.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, enclave.ErrAEADAuthentication
	}
	if f.short && len(pt) > 0 {
		return pt[:len(pt)-1], nil
	}
	return pt, nil
}

// deviceMaterial is the handle a PurposeMaterial import returns: a copy the
// process may read.
type deviceMaterial struct {
	*deviceHandle
	data []byte
}

func (m *deviceMaterial) Destroy() error {
	m.dead.Store(true)
	enclave.Wipe(m.data)
	return nil
}

func (m *deviceMaterial) WithBytes(fn func([]byte) error) error {
	if !m.IsAlive() {
		return enclave.ErrEnclaveDestroyed
	}
	return fn(m.data)
}

func (m *deviceMaterial) EqualTo(other []byte) (bool, error) {
	if !m.IsAlive() {
		return false, enclave.ErrEnclaveDestroyed
	}
	return subtle.ConstantTimeCompare(m.data, other) == 1, nil
}

// phantom is a ByteAccess handle that reports a size and holds nothing, for the
// sizes SealFrom refuses before it reads.
type phantom struct {
	b    *deviceBackend
	size int
}

func (p *phantom) Size() int                { return p.size }
func (p *phantom) IsAlive() bool            { return true }
func (p *phantom) Destroy() error           { return nil }
func (p *phantom) Backend() enclave.Backend { return p.b }
func (p *phantom) WithBytes(func([]byte) error) error {
	return errors.New("phantom: holds no bytes")
}
func (p *phantom) EqualTo([]byte) (bool, error) {
	return false, errors.New("phantom: holds no bytes")
}

// confinedDevice is a deviceBackend that also reports whether it confines the
// process.
type confinedDevice struct {
	*deviceBackend
	confines bool
}

func (c confinedDevice) ConfinesProcess() bool { return c.confines }

// sweepingBackend is a backend with a Sweep, registered for the shutdown sweep.
type sweepingBackend struct {
	name  string
	held  int
	err   error
	calls atomic.Int64
	// enter, when set, runs inside Sweep before it returns.
	enter func(ctx context.Context)
}

func (s *sweepingBackend) Name() string { return s.name }

func (s *sweepingBackend) Sweep(ctx context.Context) (int, error) {
	s.calls.Add(1)
	if s.enter != nil {
		s.enter(ctx)
	}
	return s.held, s.err
}
