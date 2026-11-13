// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// contractPrefix starts every message of the package.
const contractPrefix = "enclave: "

// contractMarker stands for material that reached a caller-supplied field: raw
// bytes, some not printable, that must never appear verbatim in a message.
const contractMarker = "\x00\xffcontract-marker\x7f\x01"

// contractSentinels is every exported sentinel of the package, by name. The
// completeness check holds it to the declarations.
var contractSentinels = map[string]error{
	"ErrEmptyEnclave":                ErrEmptyEnclave,
	"ErrEnclaveDestroyed":            ErrEnclaveDestroyed,
	"ErrInvalidSize":                 ErrInvalidSize,
	"ErrLockedMemoryUnavailable":     ErrLockedMemoryUnavailable,
	"ErrReleasedWithoutWipe":         ErrReleasedWithoutWipe,
	"ErrEnclaveCorrupted":            ErrEnclaveCorrupted,
	"ErrNilFunc":                     ErrNilFunc,
	"ErrCoreDumpLimitUnsupported":    ErrCoreDumpLimitUnsupported,
	"ErrBudgetExhausted":             ErrBudgetExhausted,
	"ErrInvalidBudget":               ErrInvalidBudget,
	"ErrBudgetInUse":                 ErrBudgetInUse,
	"ErrInvalidTransfer":             ErrInvalidTransfer,
	"ErrNilAllocator":                ErrNilAllocator,
	"ErrAllocatorNotConstructed":     ErrAllocatorNotConstructed,
	"ErrAllocatorInstalled":          ErrAllocatorInstalled,
	"ErrBudgetExceedsRLimit":         ErrBudgetExceedsRLimit,
	"ErrLimitDiscoveryFailed":        ErrLimitDiscoveryFailed,
	"ErrProcessHardeningUnsupported": ErrProcessHardeningUnsupported,
	"ErrProcessHardeningFailed":      ErrProcessHardeningFailed,
	"ErrCoreDumpLimitFailed":         ErrCoreDumpLimitFailed,
	"ErrCoreDumpLimitNotApplied":     ErrCoreDumpLimitNotApplied,
	"ErrSealFailed":                  ErrSealFailed,
	"ErrOpenFailed":                  ErrOpenFailed,
	"ErrSealedAuthentication":        ErrSealedAuthentication,
	"ErrUnknownSealedVersion":        ErrUnknownSealedVersion,
	"ErrPlaintextEscaped":            ErrPlaintextEscaped,
	"ErrMaterialTooLarge":            ErrMaterialTooLarge,
	"ErrSealerWiped":                 ErrSealerWiped,
	"ErrOpenabilityUnknown":          ErrOpenabilityUnknown,
	"ErrInvalidProvider":             ErrInvalidProvider,
	"ErrSealerExhausted":             ErrSealerExhausted,
	"ErrInvalidRotationLimit":        ErrInvalidRotationLimit,
	"ErrSealerInstalled":             ErrSealerInstalled,
	"ErrNilSealer":                   ErrNilSealer,
	"ErrSealerDestroyed":             ErrSealerDestroyed,
	"ErrSealerNotConstructed":        ErrSealerNotConstructed,
	"ErrInvalidSealerOption":         ErrInvalidSealerOption,
	"ErrSealSourceReadOnly":          ErrSealSourceReadOnly,
	"ErrKeyScheduleExposed":          ErrKeyScheduleExposed,
	"ErrProviderMessageLimit":        ErrProviderMessageLimit,
	"ErrProviderNotConstructed":      ErrProviderNotConstructed,
	"ErrBackendNotRegistered":        ErrBackendNotRegistered,
	"ErrBackendExists":               ErrBackendExists,
	"ErrInvalidBackend":              ErrInvalidBackend,
	"ErrCapabilityUnsupported":       ErrCapabilityUnsupported,
	"ErrInvalidImport":               ErrInvalidImport,
	"ErrInvalidNonce":                ErrInvalidNonce,
	"ErrAEADAuthentication":          ErrAEADAuthentication,
	"ErrBackendUnavailable":          ErrBackendUnavailable,
	"ErrMemfdSecretUnavailable":      ErrMemfdSecretUnavailable,
	"ErrCleanupFailed":               ErrCleanupFailed,
	"ErrSweepInProgress":             ErrSweepInProgress,
}

// unwrapShape is how a type exposes what it wraps.
type unwrapShape int

const (
	unwrapNone   unwrapShape = iota // neither Unwrap method
	unwrapSingle                    // Unwrap() error
	unwrapMulti                     // Unwrap() []error
)

// contractRow is one exported error type held to the contract.
type contractRow struct {
	// zero is a pointer to the type's zero value.
	zero error
	// zeroIs is every sentinel the zero value matches.
	zeroIs []error
	// populated builds a value with every field set; cause, when the type
	// wraps one, is what it wraps.
	populated func(cause error) error
	// is is every sentinel the populated value matches.
	is []error
	// unwrap is how the type exposes its cause.
	unwrap unwrapShape
	// marked builds a value with contractMarker in every string field; nil
	// only for a type without one.
	marked func(marker string) error
	// as recovers the type from a chain with errors.As.
	as func(err error) (error, bool)
}

// asOf is a contractRow.as for the pointer type P.
func asOf[P error]() func(error) (error, bool) {
	return func(err error) (error, bool) {
		var target P
		if !errors.As(err, &target) {
			return nil, false
		}
		return target, true
	}
}

// contractRows is the table: one row per exported error type, by type name.
func contractRows() map[string]contractRow {
	return map[string]contractRow{
		"LockedMemoryError": {
			zero: &LockedMemoryError{}, zeroIs: []error{ErrLockedMemoryUnavailable},
			populated: func(c error) error { return &LockedMemoryError{Cause: c} },
			is:        []error{ErrLockedMemoryUnavailable}, unwrap: unwrapSingle,
			as: asOf[*LockedMemoryError](),
		},
		"UnwipedReleaseError": {
			zero: &UnwipedReleaseError{}, zeroIs: []error{ErrReleasedWithoutWipe},
			populated: func(c error) error { return &UnwipedReleaseError{Cause: c} },
			is:        []error{ErrReleasedWithoutWipe}, unwrap: unwrapSingle,
			as: asOf[*UnwipedReleaseError](),
		},
		"BudgetError": {
			zero: &BudgetError{}, zeroIs: []error{ErrBudgetExhausted},
			populated: func(error) error { return &BudgetError{Requested: 8192, InUse: 4096, Limit: 8192} },
			is:        []error{ErrBudgetExhausted}, unwrap: unwrapNone,
			as: asOf[*BudgetError](),
		},
		"BudgetInUseError": {
			zero: &BudgetInUseError{}, zeroIs: []error{ErrBudgetInUse},
			populated: func(error) error { return &BudgetInUseError{Requested: 4096, InUse: 8192, Limit: 16384} },
			is:        []error{ErrBudgetInUse}, unwrap: unwrapNone,
			as: asOf[*BudgetInUseError](),
		},
		"RLimitError": {
			zero: &RLimitError{}, zeroIs: []error{ErrBudgetExceedsRLimit},
			populated: func(error) error {
				return &RLimitError{Requested: 1 << 20, Limit: LockedMemoryLimit{Bytes: 65536, Bounded: true, Source: LimitRLimit}}
			},
			is: []error{ErrBudgetExceedsRLimit}, unwrap: unwrapNone,
			as: asOf[*RLimitError](),
		},
		"LimitDiscoveryError": {
			zero: &LimitDiscoveryError{}, zeroIs: []error{ErrLimitDiscoveryFailed},
			populated: func(c error) error { return &LimitDiscoveryError{Cause: c} },
			is:        []error{ErrLimitDiscoveryFailed}, unwrap: unwrapSingle,
			as: asOf[*LimitDiscoveryError](),
		},
		"ProcessHardeningError": {
			zero: &ProcessHardeningError{}, zeroIs: []error{ErrProcessHardeningFailed},
			populated: func(c error) error { return &ProcessHardeningError{Cause: c} },
			is:        []error{ErrProcessHardeningFailed}, unwrap: unwrapSingle,
			as: asOf[*ProcessHardeningError](),
		},
		"CoreDumpLimitError": {
			zero: &CoreDumpLimitError{}, zeroIs: []error{ErrCoreDumpLimitFailed},
			populated: func(c error) error { return &CoreDumpLimitError{Cause: c} },
			is:        []error{ErrCoreDumpLimitFailed}, unwrap: unwrapSingle,
			as: asOf[*CoreDumpLimitError](),
		},
		"SealError": {
			zero: &SealError{}, zeroIs: []error{ErrSealFailed},
			populated: func(c error) error { return &SealError{Cause: c} },
			is:        []error{ErrSealFailed}, unwrap: unwrapSingle,
			as: asOf[*SealError](),
		},
		"OpenError": {
			zero: &OpenError{}, zeroIs: []error{ErrOpenFailed},
			populated: func(c error) error { return &OpenError{Cause: c} },
			is:        []error{ErrOpenFailed}, unwrap: unwrapSingle,
			as: asOf[*OpenError](),
		},
		"SealerWipedError": {
			zero: &SealerWipedError{}, zeroIs: []error{ErrSealerWiped},
			populated: func(c error) error { return &SealerWipedError{Cause: c} },
			is:        []error{ErrSealerWiped}, unwrap: unwrapSingle,
			as: asOf[*SealerWipedError](),
		},
		"KeyScheduleExposedError": {
			zero: &KeyScheduleExposedError{}, zeroIs: []error{ErrKeyScheduleExposed},
			populated: func(error) error { return &KeyScheduleExposedError{Name: "aes-256-gcm"} },
			is:        []error{ErrKeyScheduleExposed}, unwrap: unwrapNone,
			marked: func(m string) error { return &KeyScheduleExposedError{Name: m} },
			as:     asOf[*KeyScheduleExposedError](),
		},
		"BackendNotRegisteredError": {
			zero: &BackendNotRegisteredError{}, zeroIs: []error{ErrBackendNotRegistered},
			populated: func(error) error { return &BackendNotRegisteredError{Name: "contract"} },
			is:        []error{ErrBackendNotRegistered}, unwrap: unwrapNone,
			marked: func(m string) error { return &BackendNotRegisteredError{Name: m} },
			as:     asOf[*BackendNotRegisteredError](),
		},
		"BackendExistsError": {
			zero: &BackendExistsError{}, zeroIs: []error{ErrBackendExists},
			populated: func(error) error { return &BackendExistsError{Name: "contract"} },
			is:        []error{ErrBackendExists}, unwrap: unwrapNone,
			marked: func(m string) error { return &BackendExistsError{Name: m} },
			as:     asOf[*BackendExistsError](),
		},
		"CapabilityError": {
			zero: &CapabilityError{}, zeroIs: []error{ErrCapabilityUnsupported},
			populated: func(error) error { return &CapabilityError{Backend: "contract", Capability: Capability("seal")} },
			is:        []error{ErrCapabilityUnsupported}, unwrap: unwrapNone,
			marked: func(m string) error { return &CapabilityError{Backend: m, Capability: Capability(m)} },
			as:     asOf[*CapabilityError](),
		},
		"ProbeError": {
			zero: &ProbeError{}, zeroIs: []error{ErrBackendUnavailable},
			populated: func(c error) error { return &ProbeError{Backend: "contract", Cause: c} },
			is:        []error{ErrBackendUnavailable}, unwrap: unwrapSingle,
			marked: func(m string) error { return &ProbeError{Backend: m} },
			as:     asOf[*ProbeError](),
		},
		"MemfdSecretError": {
			zero: &MemfdSecretError{}, zeroIs: []error{ErrMemfdSecretUnavailable},
			populated: func(c error) error { return &MemfdSecretError{Cause: c} },
			is:        []error{ErrMemfdSecretUnavailable}, unwrap: unwrapSingle,
			as: asOf[*MemfdSecretError](),
		},
		"CleanupError": {
			zero: &CleanupError{}, zeroIs: []error{ErrCleanupFailed},
			// Failure is the operation's own error, which comes first in the
			// message: a package error, so the prefix holds.
			populated: func(c error) error {
				return &CleanupError{Failure: ErrInvalidSize, Causes: []error{nil, c}}
			},
			is: []error{ErrCleanupFailed, ErrInvalidSize}, unwrap: unwrapMulti,
			as: asOf[*CleanupError](),
		},
		"SweepError": {
			zero: &SweepError{}, zeroIs: nil,
			populated: func(c error) error {
				return &SweepError{Corrupt: 1, Unwiped: 2, Backends: []BackendSweepFailure{
					{Backend: "contract-nil"}, {Backend: "contract", Err: c},
				}}
			},
			is: []error{ErrEnclaveCorrupted, ErrReleasedWithoutWipe}, unwrap: unwrapMulti,
			marked: func(m string) error {
				return &SweepError{Backends: []BackendSweepFailure{{Backend: m}}}
			},
			as: asOf[*SweepError](),
		},
	}
}

// contractMessage calls Error, turning a panic into a test failure.
func contractMessage(t *testing.T, what string, err error) (msg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: Error() panicked: %v", what, r)
			msg = ""
		}
	}()
	return err.Error()
}

// checkMessage holds one message to the contract.
func checkMessage(t *testing.T, what string, err error) {
	t.Helper()
	msg := contractMessage(t, what, err)
	if msg == "" {
		t.Errorf("%s: Error() is empty", what)
		return
	}
	if !strings.HasPrefix(msg, contractPrefix) {
		t.Errorf("%s: Error() = %q, want prefix %q", what, msg, contractPrefix)
	}
}

// checkSentinels holds err to matching exactly want among every package
// sentinel.
func checkSentinels(t *testing.T, what string, err error, want []error) {
	t.Helper()
	for name, sentinel := range contractSentinels {
		if got, w := errors.Is(err, sentinel), slices.Contains(want, sentinel); got != w {
			t.Errorf("%s: errors.Is(err, %s) = %v, want %v", what, name, got, w)
		}
	}
}

// hasStringField reports whether t, or a struct in a slice it holds, has a
// string-kinded field.
func hasStringField(t reflect.Type) bool {
	for f := range t.Fields() {
		ft := f.Type
		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.String:
			return true
		case reflect.Struct:
			if hasStringField(ft) {
				return true
			}
		}
	}
	return false
}

// TestErrorContract holds every exported error type of the package to one
// contract (#345): its message, its sentinels, errors.As and Unwrap through
// wrapping, and that raw bytes in a caller-supplied field never reach the
// message verbatim.
func TestErrorContract(t *testing.T) {
	for name, row := range contractRows() {
		t.Run(name, func(t *testing.T) {
			cause := errors.New("contract: the cause")

			if got := reflect.TypeOf(row.zero).Elem().Name(); got != name {
				t.Fatalf("row %s holds a %s", name, got)
			}
			checkMessage(t, "zero", row.zero)
			checkSentinels(t, "zero", row.zero, row.zeroIs)

			err := row.populated(cause)
			if reflect.TypeOf(err) != reflect.TypeOf(row.zero) {
				t.Fatalf("populated is a %T, want %T", err, row.zero)
			}
			checkMessage(t, "populated", err)

			once := fmt.Errorf("contract: %w", err)
			twice := fmt.Errorf("contract: %w", once)
			joined := errors.Join(errors.New("contract: other"), once)
			for what, chain := range map[string]error{
				"populated": err, "wrapped once": once, "wrapped twice": twice, "joined": joined,
			} {
				checkSentinels(t, what, chain, row.is)
				if got, ok := row.as(chain); !ok || got != err {
					t.Errorf("%s: errors.As = %v, %v; want the populated value", what, got, ok)
				}
			}

			single, isSingle := err.(interface{ Unwrap() error })
			multi, isMulti := err.(interface{ Unwrap() []error })
			switch row.unwrap {
			case unwrapNone:
				if isSingle || isMulti {
					t.Errorf("Unwrap is implemented; the row says the type wraps nothing")
				}
			case unwrapSingle:
				if !isSingle {
					t.Fatalf("no Unwrap() error")
				}
				if got := single.Unwrap(); got != cause {
					t.Errorf("Unwrap() = %v, want the cause", got)
				}
				if got := row.zero.(interface{ Unwrap() error }).Unwrap(); got != nil {
					t.Errorf("zero Unwrap() = %v, want nil", got)
				}
			case unwrapMulti:
				if !isMulti {
					t.Fatalf("no Unwrap() []error")
				}
				got := multi.Unwrap()
				if !slices.Contains(got, cause) {
					t.Errorf("Unwrap() = %v, want it to hold the cause", got)
				}
				if slices.Contains(got, nil) {
					t.Errorf("Unwrap() = %v holds a nil", got)
				}
				if got := row.zero.(interface{ Unwrap() []error }).Unwrap(); len(got) != 0 {
					t.Errorf("zero Unwrap() = %v, want none", got)
				}
			}
			if row.unwrap != unwrapNone && !errors.Is(twice, cause) {
				t.Errorf("errors.Is(wrapped twice, cause) = false")
			}

			if row.marked == nil {
				if hasStringField(reflect.TypeOf(row.zero).Elem()) {
					t.Fatalf("%s has a string field and no marked constructor", name)
				}
				return
			}
			marked := row.marked(contractMarker)
			checkMessage(t, "marked", marked)
			if msg := contractMessage(t, "marked", marked); strings.Contains(msg, contractMarker) {
				t.Errorf("marked: Error() = %q carries the marker verbatim", msg)
			}
		})
	}
}

// TestErrorContractComplete fails on an exported error type or sentinel of the
// package without a row in TestErrorContract, and on a row naming nothing the
// package declares.
func TestErrorContractComplete(t *testing.T) {
	types, sentinels := declaredErrors(t)
	rows := contractRows()

	for _, name := range types {
		if _, ok := rows[name]; !ok {
			t.Errorf("exported error type %s has no row in contractRows", name)
		}
	}
	for name := range rows {
		if !slices.Contains(types, name) {
			t.Errorf("row %s names no exported error type of the package", name)
		}
	}
	for _, name := range sentinels {
		if _, ok := contractSentinels[name]; !ok {
			t.Errorf("exported sentinel %s is not in contractSentinels", name)
		}
	}
	for name := range contractSentinels {
		if !slices.Contains(sentinels, name) {
			t.Errorf("contractSentinels names %s, which the package does not declare", name)
		}
	}
	if len(types) == 0 || len(sentinels) == 0 {
		t.Fatalf("found %d error types and %d sentinels; the parse saw nothing", len(types), len(sentinels))
	}
}

// declaredErrors parses the package's non-test files and returns its exported
// types named ...Error and its exported variables named Err....
func declaredErrors(t *testing.T) (types, sentinels []string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() && strings.HasSuffix(s.Name.Name, "Error") {
						types = append(types, s.Name.Name)
					}
				case *ast.ValueSpec:
					if gen.Tok != token.VAR {
						continue
					}
					for _, id := range s.Names {
						if id.IsExported() && strings.HasPrefix(id.Name, "Err") {
							sentinels = append(sentinels, id.Name)
						}
					}
				}
			}
		}
	}
	return types, sentinels
}
