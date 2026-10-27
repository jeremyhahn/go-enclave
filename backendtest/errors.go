package backendtest

import (
	"errors"
	"fmt"
	"strconv"

	enclave "github.com/jeremyhahn/go-enclave"
)

// ErrInvalidConfig matches every error [TestBackend] returns because the
// [Config] it was handed cannot be run at all. No backend was tested: the
// mistake is in the test harness, not the backend.
var ErrInvalidConfig = errors.New("backendtest: invalid Config")

// ConfigError is the concrete error behind [ErrInvalidConfig]: which Config
// field could not be used, and why. It matches ErrInvalidConfig under
// errors.Is.
type ConfigError struct {
	// Field is the Config field at fault, e.g. "New" or "Handles".
	Field string
	// Reason says what is wrong with it and what the suite needs instead.
	Reason string
}

// Error renders as "backendtest: Config.<Field> <Reason>".
func (e *ConfigError) Error() string { return "backendtest: Config." + e.Field + " " + e.Reason }

// Is reports whether target is [ErrInvalidConfig].
func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

// ErrAborted matches the error [TestBackend] returns when its context ended
// before the run finished. The run is incomplete: it is neither a pass nor, by
// itself, a finding against the backend. Properties that had already failed
// while the context was live are reported alongside it and are real; a
// failure observed after it ended is not reported.
var ErrAborted = errors.New("backendtest: run aborted because its context ended")

// AbortedError is the concrete error behind [ErrAborted]. Its Cause is the
// run context's error: it matches ErrAborted under errors.Is and unwraps to
// Cause, so a caller can also match context.Canceled or
// context.DeadlineExceeded.
type AbortedError struct {
	// Cause is the run context's error.
	Cause error
}

// Error renders as "backendtest: run aborted because its context ended:
// <Cause>", or [ErrAborted]'s text alone for a nil Cause.
func (e *AbortedError) Error() string {
	if e.Cause == nil {
		return ErrAborted.Error()
	}
	return ErrAborted.Error() + ": " + e.Cause.Error()
}

// Is reports whether target is [ErrAborted].
func (e *AbortedError) Is(target error) bool { return target == ErrAborted }

// Unwrap returns the cause.
func (e *AbortedError) Unwrap() error { return e.Cause }

// FindingsError is what [TestBackend] returns when its run found anything:
// every [*PropertyError], [*NotMeasuredError], [*UncheckedCapabilityError] and
// [*AbortedError] of the run, in the order they were found. errors.Is and
// errors.As reach each one through Unwrap.
type FindingsError struct {
	// Findings holds the run's findings, never empty in an error TestBackend
	// returns.
	Findings []error
}

// Error renders each finding on its own line.
func (e *FindingsError) Error() string {
	msg := ""
	for i, f := range e.Findings {
		if i > 0 {
			msg += "\n"
		}
		if f != nil {
			msg += f.Error()
		}
	}
	return msg
}

// Unwrap returns the findings.
func (e *FindingsError) Unwrap() []error { return e.Findings }

// PropertyError is one property of the seam that the backend under test did
// not honor. [TestBackend] reports every one it found in a [*FindingsError].
// Several may share a Property.
type PropertyError struct {
	// Property names the property, as the suite's documentation does.
	Property string
	// Detail is what was observed and what the seam requires.
	Detail string
}

// Error renders as "backendtest: <Property>: <Detail>".
func (e *PropertyError) Error() string { return "backendtest: " + e.Property + ": " + e.Detail }

// ErrNotMeasured matches the error [TestBackend] returns when a property
// could not be measured on this host and the [Config] did not accept that.
// It is neither a pass nor a finding against the backend.
var ErrNotMeasured = errors.New("backendtest: property not measured")

// NotMeasuredError is the concrete error behind [ErrNotMeasured]: which
// property went unmeasured, and why. It matches ErrNotMeasured under
// errors.Is.
type NotMeasuredError struct {
	// Property names the property, as [PropertyError.Property] does.
	Property string
	// Reason says why it could not be measured.
	Reason string
}

// Error renders as "backendtest: <Property>: not measured: <Reason>".
func (e *NotMeasuredError) Error() string {
	return "backendtest: " + e.Property + ": not measured: " + e.Reason
}

// Is reports whether target is [ErrNotMeasured].
func (e *NotMeasuredError) Is(target error) bool { return target == ErrNotMeasured }

// ErrNoEndpoint matches the error a conformance harness reports when the
// endpoint it reaches a backend's device through, such as a TEE client
// device, is not set: the environment variable that names it is empty. No
// backend was tested, which is neither a pass nor a finding.
var ErrNoEndpoint = errors.New("backendtest: no endpoint is set for the backend")

// EndpointError is the concrete error behind [ErrNoEndpoint]: which
// environment variable was empty. It matches ErrNoEndpoint under errors.Is.
type EndpointError struct {
	// Variable is the environment variable that names the endpoint.
	Variable string
}

// Error renders as "backendtest: no endpoint is set for the backend:
// $<Variable> is empty".
func (e *EndpointError) Error() string {
	return ErrNoEndpoint.Error() + ": $" + e.Variable + " is empty"
}

// Is reports whether target is [ErrNoEndpoint].
func (e *EndpointError) Is(target error) bool { return target == ErrNoEndpoint }

// ErrNoRegistration matches the error a conformance harness reports when the
// test binary carries no in-process registration of the backend it tests: no
// file built into it registers the backend with [enclave.Register]. A fixture
// in another process cannot fill this process's registry. No backend was
// tested, which is neither a pass nor a finding.
var ErrNoRegistration = errors.New("backendtest: no in-process registration of the backend is built in")

// RegistrationError is the concrete error behind [ErrNoRegistration]: which
// backend has no registration in the binary. It matches ErrNoRegistration
// under errors.Is.
type RegistrationError struct {
	// Backend is the name the backend would register under.
	Backend string
}

// Error renders as "backendtest: no in-process registration of the backend
// is built in: <Backend>".
func (e *RegistrationError) Error() string {
	return ErrNoRegistration.Error() + ": " + e.Backend
}

// Is reports whether target is [ErrNoRegistration].
func (e *RegistrationError) Is(target error) bool { return target == ErrNoRegistration }

// ErrUncheckedCapability matches the error [TestBackend] returns for a
// capability the backend or a handle case declares but whose contract the
// suite cannot exercise: one the enclave package does not name, or one whose
// behavior the seam does not specify closely enough for the handle at hand.
// The suite refuses such a backend rather than certify a capability it never
// ran.
var ErrUncheckedCapability = errors.New("backendtest: declared capability cannot be checked")

// UncheckedCapabilityError is the concrete error behind
// [ErrUncheckedCapability]: which capability of which case, and why the suite
// cannot check it. It matches ErrUncheckedCapability under errors.Is.
type UncheckedCapabilityError struct {
	// Case is the [HandleCase] name, or empty for the backend's own
	// capabilities.
	Case string
	// Capability is the capability the suite refused.
	Capability enclave.Capability
	// Reason says why its contract cannot be exercised.
	Reason string
}

// Error renders as "backendtest: declared capability cannot be checked:
// <capability> of <case>: <Reason>", with the capability and case quoted.
func (e *UncheckedCapabilityError) Error() string {
	owner := "the backend"
	if e.Case != "" {
		owner = "case " + strconv.Quote(e.Case)
	}
	return ErrUncheckedCapability.Error() + ": " + strconv.Quote(string(e.Capability)) + " of " + owner + ": " + e.Reason
}

// Is reports whether target is [ErrUncheckedCapability].
func (e *UncheckedCapabilityError) Is(target error) bool { return target == ErrUncheckedCapability }

type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return "backendtest: " + e.step + ": " + e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

type nilBackendError struct{ backend any }

func (e *nilBackendError) Error() string {
	return fmt.Sprintf("Config.New returned a nil backend (%T); a typed nil satisfies the seam interfaces and panics at the first call", e.backend)
}

type nilHandleError struct {
	step   string
	handle any
}

func (e *nilHandleError) Error() string {
	return fmt.Sprintf("%s returned a nil handle (%T) with a nil error; a handle factory returns a live handle or an error", e.step, e.handle)
}

// panicError carries a panic out of a concurrency worker to the check, which
// reports it as panic safety.
type panicError struct{ value any }

func (e *panicError) Error() string {
	return fmt.Sprintf("backendtest: operation panicked: %v", e.value)
}

// raceError is what a concurrency worker observed racing Destroy that no live
// or destroyed handle reports, such as a Size that is neither.
type raceError struct{ detail string }

func (e *raceError) Error() string { return e.detail }

// errBorrowProbe is what the suite's own fn returns from inside WithBytes, to
// see that WithBytes returns fn's error.
var errBorrowProbe = errors.New("backendtest: probe error returned by fn inside WithBytes")

// findingsOf reports a run's findings: nil when there are none, otherwise a
// [*FindingsError] holding them.
func findingsOf(findings []error) error {
	if len(findings) == 0 {
		return nil
	}
	return &FindingsError{Findings: findings}
}
