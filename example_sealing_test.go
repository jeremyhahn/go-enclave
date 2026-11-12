// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Seal a credential under the process sealer, open it late, use it inside
// the borrow window and destroy everything early. NewSealed wipes the
// caller's slice, so the plaintext no longer sits on the heap.
func ExampleNewSealed() {
	ctx := context.Background()
	credential := []byte("correct horse battery staple")

	s, err := enclave.NewSealed(ctx, credential)
	if err != nil {
		fmt.Println("seal:", err)
		return
	}
	defer s.Destroy()
	fmt.Println("input wiped:", bytes.Equal(credential, make([]byte, len(credential))))

	// Later, per use: open late, destroy early.
	e, err := s.Open(ctx)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	err = e.WithBytes(func(b []byte) error {
		// b is valid only inside this function; use it, never keep it.
		fmt.Println("opened length:", len(b))
		return nil
	})
	if err != nil {
		fmt.Println("read:", err)
	}
	if err := e.Destroy(); err != nil {
		fmt.Println("destroy enclave:", err)
	}

	if err := s.Destroy(); err != nil {
		fmt.Println("destroy sealed:", err)
	}
	fmt.Println("sealed alive:", s.IsAlive())
	_, err = s.Open(ctx)
	fmt.Println("open after destroy:", errors.Is(err, enclave.ErrEnclaveDestroyed))
	// Output:
	// input wiped: true
	// opened length: 28
	// sealed alive: false
	// open after destroy: true
}

// Re-seal material already held in an enclave. Seal and NewSealed wipe their
// input, so they refuse a read-only view; NewSealedFrom only borrows the
// source and leaves it open and intact.
func ExampleNewSealedFrom() {
	ctx := context.Background()

	src, err := enclave.NewMemory([]byte("api-token-0123456789"))
	if err != nil {
		fmt.Println("memory:", err)
		return
	}
	defer src.Destroy()

	err = src.WithBytes(func(view []byte) error {
		_, err := enclave.NewSealed(ctx, view)
		return err
	})
	fmt.Println("seal of a read-only view:", errors.Is(err, enclave.ErrSealSourceReadOnly))

	s, err := enclave.NewSealedFrom(ctx, src)
	if err != nil {
		fmt.Println("seal from:", err)
		return
	}
	defer s.Destroy()
	fmt.Println("source alive:", src.IsAlive(), "size:", src.Size())

	e, err := s.Open(ctx)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer e.Destroy()
	err = src.WithBytes(func(want []byte) error {
		same, err := e.EqualTo(want)
		fmt.Println("opened equals source:", same)
		return err
	})
	if err != nil {
		fmt.Println("compare:", err)
	}
	// Output:
	// seal of a read-only view: true
	// source alive: true size: 20
	// opened equals source: true
}

// Open into an explicit backend. OpenIn returns a Handle; the default
// locked-memory backend's handle also offers ByteAccess.
func ExampleSealed_OpenIn() {
	ctx := context.Background()

	s, err := enclave.NewSealed(ctx, []byte("database-password"))
	if err != nil {
		fmt.Println("seal:", err)
		return
	}
	defer s.Destroy()

	h, err := s.OpenIn(ctx, enclave.DefaultBackend())
	if err != nil {
		fmt.Println("open in:", err)
		return
	}
	defer h.Destroy()
	fmt.Println("backend:", h.Backend().Name() == enclave.DefaultBackend().Name())
	fmt.Println("size:", h.Size())

	var ba enclave.ByteAccess
	fmt.Println("byte access:", enclave.As(h, &ba))

	if err := h.Destroy(); err != nil {
		fmt.Println("destroy:", err)
	}
	fmt.Println("handle alive:", h.IsAlive(), "sealed alive:", s.IsAlive())
	// Output:
	// backend: true
	// size: 17
	// byte access: true
	// handle alive: false sealed alive: true
}

// Construct a sealer over an explicit KeyProtector. WithKeyProtector selects
// ModePerOperation: every seal and open calls the provider on the value's
// data key. Here it is the software provider; a hardware provider plugs in
// the same way.
func ExampleNewSealer() {
	ctx := context.Background()

	sealer, err := enclave.NewSealer(enclave.WithKeyProtector(enclave.NewSoftwareProvider()))
	if err != nil {
		fmt.Println("new sealer:", err)
		return
	}
	defer sealer.Destroy()
	fmt.Println("mode:", sealer.Mode() == enclave.ModePerOperation)

	s, err := sealer.Seal(ctx, []byte("signing-key-seed"))
	if err != nil {
		fmt.Println("seal:", err)
		return
	}
	defer s.Destroy()
	fmt.Println("openable:", s.Openable() == nil)

	e, err := s.Open(ctx)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	fmt.Println("opened size:", e.Size())
	if err := e.Destroy(); err != nil {
		fmt.Println("destroy enclave:", err)
	}

	// A value opens only through the sealer that sealed it.
	if err := sealer.Destroy(); err != nil {
		fmt.Println("destroy sealer:", err)
	}
	_, err = s.Open(ctx)
	fmt.Println("open after sealer destroy:", errors.Is(err, enclave.ErrSealerDestroyed))
	// Output:
	// mode: true
	// openable: true
	// opened size: 16
	// open after sealer destroy: true
}
