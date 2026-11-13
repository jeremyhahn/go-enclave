// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// ExampleTestProvider runs the conformance suite against the software
// provider, which serves both sealing modes. In a provider's own test, pass
// t.Context() and t.Logf, as the provider guide shows; an example discards
// the notes, since anything Logf printed would be checked as output.
func ExampleTestProvider() {
	cfg := providertest.Config{
		New: func() (any, error) { return enclave.NewSoftwareProvider(), nil },
		Modes: []enclave.Mode{
			enclave.ModeRootKey,
			enclave.ModePerOperation,
		},
		Logf: func(string, ...any) {},
	}
	// The residue sweep runs only on Linux; elsewhere it is unmeasured, and
	// the run would return an error matching ErrNotMeasured.
	if runtime.GOOS != "linux" {
		cfg.SkipResidueSweep = "the residue sweep runs only on Linux"
	}

	if err := providertest.TestProvider(context.Background(), cfg); err != nil {
		fmt.Println("does not conform:", err)
		return
	}
	fmt.Println("conforms")
	// Output: conforms
}

// ExampleTestProvider_invalidConfig shows the refusal of a Config the suite
// cannot run: one with no New and no Modes.
func ExampleTestProvider_invalidConfig() {
	err := providertest.TestProvider(context.Background(), providertest.Config{})
	fmt.Println(errors.Is(err, providertest.ErrInvalidConfig))
	// Output: true
}
