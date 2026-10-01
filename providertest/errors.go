// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"errors"
	"fmt"
)

// ErrInvalidConfig matches every error [TestProvider] returns because the
// [Config] it was handed cannot be run at all — as opposed to a provider that
// ran and failed a property. The distinction is the one a caller acts on: the
// first is a mistake in the test harness and the second is a defect in the
// provider, and only the message used to tell them apart.
var ErrInvalidConfig = errors.New("providertest: invalid Config")

// ConfigError is the concrete error behind [ErrInvalidConfig]: which Config
// field could not be used, and why. It matches ErrInvalidConfig under
// errors.Is.
type ConfigError struct {
	// Field is the Config field at fault, e.g. "New" or "Modes".
	Field string
	// Reason says what is wrong with it and what the suite needs instead.
	Reason string
}

// Error renders as "providertest: Config.<Field> <Reason>".
func (e *ConfigError) Error() string { return "providertest: Config." + e.Field + " " + e.Reason }

// Is reports whether target is [ErrInvalidConfig].
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

// PropertyError is one property of the seam that the provider under test did
// not honor. [TestProvider] returns every one it found joined with
// errors.Join, so a caller can walk them — via the joined error's
// Unwrap() []error — to act on each failed property individually rather than
// parsing the combined message.
type PropertyError struct {
	// Property names the property, as the suite's documentation does.
	Property string
	// Detail is what was observed and what the seam requires.
	Detail string
}

// Error renders as "<Property>: <Detail>".
func (e *PropertyError) Error() string { return e.Property + ": " + e.Detail }

// stepError attaches the step that failed to an error the suite could not
// proceed past, and keeps that error matchable.
type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return e.step + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

// nilProviderError is a Config.New that returned nil or a typed nil; see
// newProvider for why that is refused rather than called.
type nilProviderError struct{ provider any }

func (e *nilProviderError) Error() string {
	return fmt.Sprintf("Config.New returned a nil provider (%T); a typed nil satisfies the seam "+
		"interfaces and panics at the first call, which is why NewSealer refuses it with ErrProviderMode", e.provider)
}

// missingSeamError is a provider that lacks the interface a mode it claims in
// Config.Modes requires.
type missingSeamError struct {
	provider any
	iface    string
	mode     string
}

func (e *missingSeamError) Error() string {
	return fmt.Sprintf("%T does not implement %s, which Config.Modes claims it serves %s with",
		e.provider, e.iface, e.mode)
}

// errEmptySlice is addrOf asked for the address of nothing.
var errEmptySlice = errors.New("providertest: cannot take the address of an empty slice")
