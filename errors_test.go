// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// causeErrorCase is one error type that is a sentinel plus a cause: a value
// with cause, its sentinel, and an errors.As probe for exactly that type.
type causeErrorCase struct {
	name     string
	withNil  error
	withErr  func(cause error) error
	sentinel error
	as       func(error) bool
}

func asType[T any](err error) bool {
	var target T
	return errors.As(err, &target)
}

func causeErrorCases() []causeErrorCase {
	return []causeErrorCase{
		{"LockedMemoryError", &LockedMemoryError{},
			func(c error) error { return &LockedMemoryError{Cause: c} },
			ErrLockedMemoryUnavailable, asType[*LockedMemoryError]},
		{"UnwipedReleaseError", &UnwipedReleaseError{},
			func(c error) error { return &UnwipedReleaseError{Cause: c} },
			ErrReleasedWithoutWipe, asType[*UnwipedReleaseError]},
		{"LimitDiscoveryError", &LimitDiscoveryError{},
			func(c error) error { return &LimitDiscoveryError{Cause: c} },
			ErrLimitDiscoveryFailed, asType[*LimitDiscoveryError]},
		{"ProcessHardeningError", &ProcessHardeningError{},
			func(c error) error { return &ProcessHardeningError{Cause: c} },
			ErrProcessHardeningFailed, asType[*ProcessHardeningError]},
		{"CoreDumpLimitError", &CoreDumpLimitError{},
			func(c error) error { return &CoreDumpLimitError{Cause: c} },
			ErrCoreDumpLimitFailed, asType[*CoreDumpLimitError]},
		{"SealError", &SealError{},
			func(c error) error { return &SealError{Cause: c} },
			ErrSealFailed, asType[*SealError]},
		{"OpenError", &OpenError{},
			func(c error) error { return &OpenError{Cause: c} },
			ErrOpenFailed, asType[*OpenError]},
		{"SealerWipedError", &SealerWipedError{},
			func(c error) error { return &SealerWipedError{Cause: c} },
			ErrSealerWiped, asType[*SealerWipedError]},
		{"MemfdSecretError", &MemfdSecretError{},
			func(c error) error { return &MemfdSecretError{Cause: c} },
			ErrMemfdSecretUnavailable, asType[*MemfdSecretError]},
	}
}

// TestCauseErrors pins the shared shape: the sentinel's text then the cause's,
// a match on its own sentinel only, Unwrap to the cause, and an errors.As that
// tells the types apart.
func TestCauseErrors(t *testing.T) {
	cases := causeErrorCases()
	cause := errors.New("mprotect: operation not permitted")
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := tc.withNil.Error(), tc.sentinel.Error(); got != want {
				t.Errorf("Error() with no cause = %q, want %q", got, want)
			}
			if got := errors.Unwrap(tc.withNil); got != nil {
				t.Errorf("Unwrap() with no cause = %v, want nil", got)
			}

			err := tc.withErr(cause)
			if got, want := err.Error(), tc.sentinel.Error()+": "+cause.Error(); got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
			if got := errors.Unwrap(err); got != cause {
				t.Errorf("Unwrap() = %v, want the cause", got)
			}
			if !errors.Is(err, tc.sentinel) || !errors.Is(err, cause) {
				t.Errorf("errors.Is does not reach both the sentinel and the cause: %v", err)
			}
			if !tc.as(&pagesHeldError{err: err}) {
				t.Errorf("errors.As does not reach the %s through a wrapper", tc.name)
			}
			for j, other := range cases {
				if j == i {
					continue
				}
				if errors.Is(err, other.sentinel) {
					t.Errorf("matches %s's sentinel", other.name)
				}
				if other.as(err) {
					t.Errorf("errors.As reads it as a %s", other.name)
				}
			}
		})
	}
}

func TestWithCause(t *testing.T) {
	if err := withCause[SealerWipedError](nil); err != ErrSealerWiped {
		t.Errorf("withCause(nil) = %v, want the bare sentinel", err)
	}
	cause := errors.New("hkdf failed")
	err := withCause[SealerWipedError](cause)
	var swe *SealerWipedError
	if !errors.As(err, &swe) || swe.Cause != cause {
		t.Errorf("withCause(cause) = %#v, want a *SealerWipedError carrying the cause", err)
	}
}

func TestBudgetErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		sentinel error
		text     string
	}{
		{"BudgetError", &BudgetError{Requested: 10, InUse: 20, Limit: 25}, ErrBudgetExhausted,
			"enclave: locked-memory budget exhausted: 10 bytes requested, 20 of 25 bytes in use"},
		{"BudgetInUseError", newBudgetInUseError(10, 25, 5), ErrBudgetInUse,
			"enclave: budget would fall below the locked memory already reserved: 10 bytes requested, 20 of 25 bytes in use"},
		{"RLimitError", &RLimitError{Requested: 1 << 20, Limit: LockedMemoryLimit{Bytes: 65536, Bounded: true, Source: LimitRLimit}},
			ErrBudgetExceedsRLimit,
			"enclave: allocator budget exceeds the process's locked-memory limit: 1048576 bytes requested, RLIMIT_MEMLOCK is 65536 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.text {
				t.Errorf("Error() = %q, want %q", got, tc.text)
			}
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("does not match its sentinel %v", tc.sentinel)
			}
			for _, other := range []error{ErrBudgetExhausted, ErrBudgetInUse, ErrBudgetExceedsRLimit, ErrInvalidBudget, ErrLockedMemoryUnavailable} {
				if other != tc.sentinel && errors.Is(tc.err, other) {
					t.Errorf("matches the unrelated %v", other)
				}
			}
		})
	}
}

func TestContextError(t *testing.T) {
	why := errors.New("shutting down")
	provider := errors.New("tpm: busy")
	for _, tc := range []struct {
		name string
		err  *contextError
		text string
		want []error
	}{
		{"ended only", &contextError{ended: context.Canceled},
			"context canceled", []error{context.Canceled}},
		{"with cause", &contextError{ended: context.Canceled, cause: why},
			"context canceled: shutting down", []error{context.Canceled, why}},
		{"with provider", &contextError{ended: context.DeadlineExceeded, cause: why, provider: provider},
			"context deadline exceeded: shutting down; provider: tpm: busy",
			[]error{context.DeadlineExceeded, why, provider}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.text {
				t.Errorf("Error() = %q, want %q", got, tc.text)
			}
			if got := tc.err.Unwrap(); len(got) != len(tc.want) {
				t.Errorf("Unwrap() = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !errors.Is(tc.err, w) {
					t.Errorf("does not match %v", w)
				}
			}
		})
	}
}

func TestWithCleanupFailure(t *testing.T) {
	failure := &SealError{Cause: errors.New("aead")}
	cleanup := &LockedMemoryError{Cause: errors.New("munmap")}
	if got := withCleanupFailure(nil, nil); got != nil {
		t.Errorf("withCleanupFailure(nil, nil) = %v, want nil", got)
	}
	if got := withCleanupFailure(failure, nil); got != error(failure) {
		t.Errorf("withCleanupFailure(failure, nil) = %v, want failure unchanged", got)
	}
	if got := withCleanupFailure(nil, cleanup); got != error(cleanup) {
		t.Errorf("withCleanupFailure(nil, cleanup) = %v, want cleanup unchanged", got)
	}
	retained := &CleanupError{Causes: []error{cleanup}}
	if got := withCleanupFailure(nil, nil, retained); got != error(retained) {
		t.Errorf("withCleanupFailure(nil, nil, retained) = %v, want the CleanupError unchanged", got)
	}
	both := withCleanupFailure(failure, cleanup)
	if !errors.Is(both, ErrSealFailed) || !errors.Is(both, ErrLockedMemoryUnavailable) || !errors.Is(both, ErrCleanupFailed) {
		t.Errorf("withCleanupFailure = %v, want both failures and ErrCleanupFailed matchable", both)
	}
	var se *SealError
	var lme *LockedMemoryError
	if !errors.As(both, &se) || !errors.As(both, &lme) {
		t.Errorf("withCleanupFailure = %v, want both failures readable with errors.As", both)
	}
	var ce *CleanupError
	if !errors.As(both, &ce) || ce.Failure != error(failure) || len(ce.Causes) != 1 || ce.Causes[0] != error(cleanup) {
		t.Errorf("withCleanupFailure = %#v, want a CleanupError{failure, [cleanup]}", both)
	}
}

// TestWithCleanupFailureStaysFlat pins that several cleanup failures, and
// CleanupErrors among them or as the failure, merge into one CleanupError
// whose Causes keep their order.
func TestWithCleanupFailureStaysFlat(t *testing.T) {
	first := &LockedMemoryError{Cause: errors.New("munlock")}
	second := &LockedMemoryError{Cause: errors.New("munmap")}
	third := errors.New("handle refused")

	refused := withCleanupFailure(nil, first, nil, second)
	var ce *CleanupError
	if !errors.As(refused, &ce) || ce.Failure != nil || !slices.Equal(ce.Causes, []error{first, second}) {
		t.Fatalf("withCleanupFailure(nil, first, nil, second) = %#v, want CleanupError{nil, [first second]}", refused)
	}

	merged := withCleanupFailure(ErrEnclaveCorrupted, refused, &CleanupError{Causes: []error{third}})
	if !errors.As(merged, &ce) || ce.Failure != ErrEnclaveCorrupted || !slices.Equal(ce.Causes, []error{first, second, third}) {
		t.Fatalf("merged = %#v, want CleanupError{ErrEnclaveCorrupted, [first second third]}", merged)
	}

	extended := withCleanupFailure(merged, &CleanupError{Failure: first, Causes: []error{second}})
	if !errors.As(extended, &ce) || ce.Failure != ErrEnclaveCorrupted ||
		!slices.Equal(ce.Causes, []error{first, second, third, first, second}) {
		t.Fatalf("extended = %#v, want the failure kept and every cause appended", extended)
	}
	if !errors.As(merged, &ce) || len(ce.Causes) != 3 {
		t.Errorf("extending a CleanupError changed it: %#v", merged)
	}
	for _, w := range []error{ErrCleanupFailed, ErrEnclaveCorrupted, ErrLockedMemoryUnavailable, third} {
		if !errors.Is(extended, w) {
			t.Errorf("extended = %v, does not match %v", extended, w)
		}
	}
}

// TestCleanupErrorShape pins CleanupError's text and Unwrap: the failure
// first, then the sentinel and each cause, nil ones skipped.
func TestCleanupErrorShape(t *testing.T) {
	a, b := errors.New("a"), errors.New("b")
	for _, tc := range []struct {
		name   string
		err    *CleanupError
		text   string
		unwrap []error
	}{
		{"empty", &CleanupError{}, ErrCleanupFailed.Error(), []error{}},
		{"one cause", &CleanupError{Causes: []error{a}}, ErrCleanupFailed.Error() + ": a", []error{a}},
		{"failure and causes", &CleanupError{Failure: ErrSealFailed, Causes: []error{a, nil, b}},
			ErrSealFailed.Error() + "; " + ErrCleanupFailed.Error() + ": a; b", []error{ErrSealFailed, a, b}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.text {
				t.Errorf("Error() = %q, want %q", got, tc.text)
			}
			if got := tc.err.Unwrap(); !slices.Equal(got, tc.unwrap) {
				t.Errorf("Unwrap() = %v, want %v", got, tc.unwrap)
			}
			if !errors.Is(tc.err, ErrCleanupFailed) {
				t.Error("does not match ErrCleanupFailed")
			}
		})
	}
}

func TestPagesHeldErrorIsTransparent(t *testing.T) {
	inner := &LockedMemoryError{Cause: errors.New("munlock")}
	err := error(&pagesHeldError{err: inner, locked: true})
	if err.Error() != inner.Error() {
		t.Errorf("Error() = %q, want the wrapped failure's %q", err.Error(), inner.Error())
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) || !pagesHeld(err) || !lockedPagesHeld(err) {
		t.Errorf("pagesHeldError hides what it wraps: %v", err)
	}
}

// TestCanceledSealIsATypedSealError drives the public path a caller sees: a
// canceled context yields a *SealError that still matches ctx.Err() and the
// context's cause.
func TestCanceledSealIsATypedSealError(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("shutting down")
	cancel(why)

	_, err := newSealed(ctx, []byte("material"))
	var se *SealError
	if !errors.As(err, &se) {
		t.Fatalf("NewSealed(canceled) = %v, want a *SealError", err)
	}
	for _, w := range []error{ErrSealFailed, context.Canceled, why} {
		if !errors.Is(err, w) {
			t.Errorf("NewSealed(canceled) = %v, does not match %v", err, w)
		}
	}
	if errors.Is(err, ErrOpenFailed) {
		t.Errorf("a seal failure matched ErrOpenFailed: %v", err)
	}
}

// TestContextFailure pins the shape of the cancellation error as a pure
// function: nil while live; otherwise the operation's sentinel AND the
// context's error, with a provider's own wrapping of that error preferred to
// the bare one, an unrelated provider error kept alongside, and a distinct
// cancellation cause kept too.
func TestContextFailure(t *testing.T) {
	if err := contextFailure[SealError](t.Context(), nil); err != nil {
		t.Fatalf("contextFailure(live) = %v, want nil", err)
	}

	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("shutting down")
	cancel(why)

	wrapped := &providerWrapError{err: context.Canceled}
	unrelated := errors.New("tpm: resource manager busy")
	for name, tc := range map[string]struct {
		cause error
		want  []error
	}{
		"no provider error": {nil, []error{ErrOpenFailed, context.Canceled, why}},
		"provider wrapped":  {wrapped, []error{ErrOpenFailed, context.Canceled, why}},
		"provider other":    {unrelated, []error{ErrOpenFailed, context.Canceled, why, unrelated}},
	} {
		err := contextFailure[OpenError](ctx, tc.cause)
		for _, w := range tc.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: contextFailure = %v, does not match %v", name, err, w)
			}
		}
		var oe *OpenError
		if !errors.As(err, &oe) {
			t.Errorf("%s: contextFailure = %T, want an *OpenError", name, err)
		}
		var pw *providerWrapError
		if tc.cause == wrapped && !errors.As(err, &pw) {
			t.Errorf("%s: the provider's own wrapping was dropped: %v", name, err)
		}
	}

	// A plain cancellation has no distinct cause to add.
	plain, cancelPlain := context.WithCancel(t.Context())
	cancelPlain()
	if got, want := contextFailure[SealError](plain, nil).Error(), ErrSealFailed.Error()+": "+context.Canceled.Error(); got != want {
		t.Errorf("contextFailure(plain cancel) = %q, want %q", got, want)
	}
}

// providerWrapError is a provider's own wrapping of a context error.
type providerWrapError struct{ err error }

func (e *providerWrapError) Error() string { return "device: call aborted: " + e.err.Error() }

func (e *providerWrapError) Unwrap() error { return e.err }

// TestProviderOpenFailure pins the open-side shaping: a verdict on the blob
// and this package's own sentinels pass through untouched, and an
// infrastructure failure is joined under ErrOpenFailed — reachable, and never
// readable as a forgery.
func TestProviderOpenFailure(t *testing.T) {
	if providerFailure[OpenError](nil) != nil {
		t.Error("providerFailure[OpenError](nil) is not nil")
	}
	for _, sentinel := range []error{ErrSealedAuthentication, ErrSealerWiped, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed} {
		if got := providerFailure[OpenError](sentinel); got != sentinel {
			t.Errorf("providerFailure[OpenError](%v) = %v, want it untouched", sentinel, got)
		}
	}
	down := errors.New("hsm: no session available")
	got := providerFailure[OpenError](down)
	if !errors.Is(got, ErrOpenFailed) || !errors.Is(got, down) || errors.Is(got, ErrSealedAuthentication) {
		t.Errorf("providerFailure[OpenError](infrastructure) = %v, want ErrOpenFailed joined with the cause, and not ErrSealedAuthentication", got)
	}
}

func TestErrSealerDestroyed_PassesThroughProviderShaping(t *testing.T) {
	if err := providerFailure[SealError](ErrSealerDestroyed); err != ErrSealerDestroyed { //nolint:errorlint // identity is the point
		t.Errorf("providerFailure[SealError] joined ErrSealerDestroyed: %v", err)
	}
	if err := providerFailure[OpenError](ErrSealerDestroyed); err != ErrSealerDestroyed { //nolint:errorlint // identity is the point
		t.Errorf("providerFailure[OpenError] joined ErrSealerDestroyed: %v", err)
	}
	if !strings.HasPrefix(ErrSealerDestroyed.Error(), "enclave: ") || !strings.HasPrefix(ErrSealerNotConstructed.Error(), "enclave: ") {
		t.Error("sentinels must carry the package prefix")
	}
}

// errorsFile is the one root-package file that may declare sentinels and
// error types.
const errorsFile = "errors.go"

// TestErrorLayout pins the typed-error layer: every sentinel and every
// ...Error type is declared in errors.go, no ...Error type is an alias (go doc
// would hide its fields and methods), no production code builds an
// errors.Join composite, and nothing calls fmt.Errorf.
func TestErrorLayout(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, decl := range f.Decls {
			checkErrorDecl(t, fset, name, decl)
			checkErrorTypeDefined(t, fset, decl)
		}
		checkErrorCalls(t, fset, f)
	}
	if checked == 0 {
		t.Fatal("no production files found; the gate checked nothing")
	}
}

// checkErrorDecl reports a sentinel or error type declared outside errorsFile.
func checkErrorDecl(t *testing.T, fset *token.FileSet, file string, decl ast.Decl) {
	t.Helper()
	gen, ok := decl.(*ast.GenDecl)
	if !ok || file == errorsFile {
		return
	}
	for _, spec := range gen.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if strings.HasSuffix(s.Name.Name, "Error") {
				t.Errorf("%s: error type %s declared outside %s", fset.Position(s.Pos()), s.Name.Name, errorsFile)
			}
		case *ast.ValueSpec:
			for _, v := range s.Values {
				if isCall(v, "errors", "New") {
					t.Errorf("%s: sentinel declared outside %s", fset.Position(v.Pos()), errorsFile)
				}
			}
		}
	}
}

// checkErrorTypeDefined reports an exported ...Error type declared as an
// alias.
func checkErrorTypeDefined(t *testing.T, fset *token.FileSet, decl ast.Decl) {
	t.Helper()
	gen, ok := decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gen.Specs {
		if s, ok := spec.(*ast.TypeSpec); ok && s.Assign.IsValid() &&
			s.Name.IsExported() && strings.HasSuffix(s.Name.Name, "Error") {
			t.Errorf("%s: error type %s is an alias; declare it as a defined type", fset.Position(s.Pos()), s.Name.Name)
		}
	}
}

// checkErrorCalls reports fmt.Errorf and errors.Join anywhere.
func checkErrorCalls(t *testing.T, fset *token.FileSet, f *ast.File) {
	t.Helper()
	for _, decl := range f.Decls {
		ast.Inspect(decl, func(n ast.Node) bool {
			switch {
			case isCall(n, "fmt", "Errorf"):
				t.Errorf("%s: fmt.Errorf builds an untyped error", fset.Position(n.Pos()))
			case isCall(n, "errors", "Join"):
				t.Errorf("%s: errors.Join builds an untyped composite", fset.Position(n.Pos()))
			}
			return true
		})
	}
}

// isCall reports whether n is a call to pkg.name.
func isCall(n ast.Node, pkg, name string) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}
