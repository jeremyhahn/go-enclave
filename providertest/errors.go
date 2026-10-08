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

// AbortedError is the concrete error behind [ErrAborted]. Its Err is the run
// context's error: it matches ErrAborted under errors.Is and unwraps to Err,
// so a caller can also match context.Canceled or context.DeadlineExceeded. It
// renders as "providertest: run aborted because its context ended: <Err>".
type AbortedError = causeError[aborted]

// PropertyError is one property of the seam that the provider under test did
// not honor. [TestProvider] joins every one it found; walk them via the joined
// error's Unwrap() []error. Several may share a Property.
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

// kind names the sentinel a causeError matches; each is an empty struct.
type kind interface{ sentinel() error }

type aborted struct{}

func (aborted) sentinel() error { return ErrAborted }

// causeError is the shape of every exported providertest error that carries a
// cause: it renders as its sentinel's text, then ": " and the cause when there
// is one, matches the sentinel under errors.Is, and unwraps to the cause.
type causeError[K kind] struct {
	// Err is the cause.
	Err error
}

func (e *causeError[K]) Error() string {
	var k K
	if e.Err == nil {
		return k.sentinel().Error()
	}
	return k.sentinel().Error() + ": " + e.Err.Error()
}

func (e *causeError[K]) Is(target error) bool {
	var k K
	return target == k.sentinel()
}

func (e *causeError[K]) Unwrap() error { return e.Err }

// joinFindings reports a run's findings as one error: nil when there are none,
// otherwise a join a caller walks via its Unwrap() []error.
func joinFindings(findings []error) error { return errors.Join(findings...) }
