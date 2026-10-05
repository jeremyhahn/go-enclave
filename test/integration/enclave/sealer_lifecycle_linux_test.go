// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && linux

package enclave_test

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestSealerDestroyReportsAndRetriesARefusedRelease: with munlock refused,
// Destroy reports that the keys' pages are still held, the sealer is already
// unusable, and a later Destroy releases them once the kernel allows it.
func TestSealerDestroyReportsAndRetriesARefusedRelease(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		f := installFaultInjector(t, 0)
		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v := sealNeedle(t, ctx, s, newNeedle(t))
		defer v.Destroy()
		base := vmLck(t)

		f.refuse(unix.SYS_MUNLOCK, unix.EPERM, 0)
		err = s.Destroy()
		requireRefused(t, f, unix.SYS_MUNLOCK)
		if err == nil || err.Error() == "" {
			t.Fatalf("Destroy with munlock refused = %v, want the refused release reported", err)
		}
		if got := vmLck(t); got != base {
			t.Errorf("VmLck = %d with the release refused, want %d: the pages are still held", got, base)
		}
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Errorf("Open after a Destroy whose release was refused = %v, want ErrSealerDestroyed", err)
		}

		f.allow(unix.SYS_MUNLOCK)
		if err := s.Destroy(); err != nil {
			t.Fatalf("Destroy once munlock is allowed = %v, want nil", err)
		}
		if got := vmLck(t); got >= base {
			t.Errorf("VmLck = %d after the retried Destroy, want below %d", got, base)
		}
		if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v), want (0, nil)", held, err)
		}
	})
}
