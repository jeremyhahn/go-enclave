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
// [Config] it was handed cannot be run at all. No provider was tested: the
// mistake is in the test harness, not the provider.
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

// ErrAborted matches the error [TestProvider] returns when its context ended
// before the run finished. The run is incomplete: it is neither a pass nor, by
// itself, a finding against the provider. Properties that had already failed
// while the context was live are joined alongside it and are real.
var ErrAborted = errors.New("providertest: run aborted because its context ended")

// AbortedError is the concrete error behind [ErrAborted]. It matches
// ErrAborted under errors.Is and unwraps to the context's error, so a caller
// can also match context.Canceled or context.DeadlineExceeded.
type AbortedError struct {
	// Err is the run context's error.
	Err error
}

// Error renders as "providertest: run aborted before every property was
// checked: <Err>".
func (e *AbortedError) Error() string {
	return "providertest: run aborted before every property was checked: " + e.Err.Error()
}

// Is reports whether target is [ErrAborted].
func (e *AbortedError) Is(target error) bool { return target == ErrAborted }

// Unwrap returns the run context's error.
func (e *AbortedError) Unwrap() error { return e.Err }

// PropertyError is one property of the seam that the provider under test did
// not honor. [TestProvider] joins every one it found with errors.Join; walk
// them via the joined error's Unwrap() []error. Several may share a Property.
type PropertyError struct {
	// Property names the property, as the suite's documentation does.
	Property string
	// Detail is what was observed and what the seam requires.
	Detail string
}

// Error renders as "providertest: <Property>: <Detail>".
func (e *PropertyError) Error() string { return "providertest: " + e.Property + ": " + e.Detail }

// ErrNotMeasured matches the error [TestProvider] returns when a property
// could not be measured on this host and the [Config] did not accept that.
// It is neither a pass nor a finding against the provider.
var ErrNotMeasured = errors.New("providertest: property not measured")

// NotMeasuredError is the concrete error behind [ErrNotMeasured]: which
// property went unmeasured, and why. It matches ErrNotMeasured under
// errors.Is.
type NotMeasuredError struct {
	// Property names the property, as [PropertyError.Property] does.
	Property string
	// Reason says why it could not be measured.
	Reason string
}

// Error renders as "providertest: <Property>: not measured: <Reason>".
func (e *NotMeasuredError) Error() string {
	return "providertest: " + e.Property + ": not measured: " + e.Reason
}

// Is reports whether target is [ErrNotMeasured].
func (e *NotMeasuredError) Is(target error) bool { return target == ErrNotMeasured }

type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return "providertest: " + e.step + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

type nilProviderError struct{ provider any }

func (e *nilProviderError) Error() string {
	return fmt.Sprintf("Config.New returned a nil provider (%T); a typed nil satisfies the seam "+
		"interfaces and panics at the first call, which is why NewSealer refuses it with ErrInvalidProvider", e.provider)
}

type missingSeamError struct {
	provider any
	iface    string
	mode     string
}

func (e *missingSeamError) Error() string {
	return fmt.Sprintf("%T does not implement %s, which Config.Modes claims it serves %s with",
		e.provider, e.iface, e.mode)
}

var errEmptySlice = errors.New("providertest: cannot take the address of an empty slice")
