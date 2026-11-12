package backendtest

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// packageSentinels is every exported Err... sentinel the package declares.
// TestErrorContractIsComplete fails when the package grows one this list
// lacks, so the "no other sentinel" checks below always run against all of
// them.
var packageSentinels = map[string]error{
	"ErrInvalidConfig":       ErrInvalidConfig,
	"ErrAborted":             ErrAborted,
	"ErrNotMeasured":         ErrNotMeasured,
	"ErrNoEndpoint":          ErrNoEndpoint,
	"ErrNoRegistration":      ErrNoRegistration,
	"ErrUncheckedCapability": ErrUncheckedCapability,
}

// errorContractRow is the contract of one exported error type.
type errorContractRow struct {
	// name is the type's name; it must match the type of zero and full.
	name string
	// zero is a pointer to the zero value, full a populated one.
	zero, full error
	// zeroIs and fullIs name every package sentinel errors.Is matches on
	// zero and full; every other sentinel must not match.
	zeroIs, fullIs []string
	// as runs errors.As with the row's pointer type.
	as func(error) (error, bool)
	// cause is what full's Unwrap() error returns; findings is what its
	// Unwrap() []error returns. Both nil: the type has no Unwrap method.
	cause    error
	findings []error
}

func asType[T error](err error) (error, bool) {
	var target T
	if !errors.As(err, &target) {
		return nil, false
	}
	return target, true
}

var errorContractCause = errors.New("contract cause")

func errorContractRows() []errorContractRow {
	property := &PropertyError{Property: "sealing", Detail: "unseal returned other bytes"}
	notMeasured := &NotMeasuredError{Property: "latency", Reason: "no clock"}
	return []errorContractRow{
		{
			name:   "ConfigError",
			zero:   &ConfigError{},
			full:   &ConfigError{Field: "New", Reason: "is nil"},
			zeroIs: []string{"ErrInvalidConfig"},
			fullIs: []string{"ErrInvalidConfig"},
			as:     asType[*ConfigError],
		},
		{
			name:   "AbortedError",
			zero:   &AbortedError{},
			full:   &AbortedError{Cause: errorContractCause},
			zeroIs: []string{"ErrAborted"},
			fullIs: []string{"ErrAborted"},
			as:     asType[*AbortedError],
			cause:  errorContractCause,
		},
		{
			name:     "FindingsError",
			zero:     &FindingsError{},
			full:     &FindingsError{Findings: []error{property, notMeasured}},
			fullIs:   []string{"ErrNotMeasured"},
			as:       asType[*FindingsError],
			findings: []error{property, notMeasured},
		},
		{
			name: "PropertyError",
			zero: &PropertyError{},
			full: &PropertyError{Property: "sealing", Detail: "unseal returned other bytes"},
			as:   asType[*PropertyError],
		},
		{
			name:   "NotMeasuredError",
			zero:   &NotMeasuredError{},
			full:   &NotMeasuredError{Property: "latency", Reason: "no clock"},
			zeroIs: []string{"ErrNotMeasured"},
			fullIs: []string{"ErrNotMeasured"},
			as:     asType[*NotMeasuredError],
		},
		{
			name:   "EndpointError",
			zero:   &EndpointError{},
			full:   &EndpointError{Variable: "BACKEND_ENDPOINT"},
			zeroIs: []string{"ErrNoEndpoint"},
			fullIs: []string{"ErrNoEndpoint"},
			as:     asType[*EndpointError],
		},
		{
			name:   "RegistrationError",
			zero:   &RegistrationError{},
			full:   &RegistrationError{Backend: "example"},
			zeroIs: []string{"ErrNoRegistration"},
			fullIs: []string{"ErrNoRegistration"},
			as:     asType[*RegistrationError],
		},
		{
			name:   "UncheckedCapabilityError",
			zero:   &UncheckedCapabilityError{},
			full:   &UncheckedCapabilityError{Case: "sealed", Capability: enclave.Capability("seal"), Reason: "no probe"},
			zeroIs: []string{"ErrUncheckedCapability"},
			fullIs: []string{"ErrUncheckedCapability"},
			as:     asType[*UncheckedCapabilityError],
		},
	}
}

// TestErrorContract holds every exported error type to one contract.
func TestErrorContract(t *testing.T) {
	for _, row := range errorContractRows() {
		t.Run(row.name, func(t *testing.T) {
			for _, v := range []error{row.zero, row.full} {
				if got, want := fmt.Sprintf("%T", v), "*backendtest."+row.name; got != want {
					t.Fatalf("row %s holds a %s, want %s", row.name, got, want)
				}
			}
			t.Run("message", func(t *testing.T) {
				checkErrorMessage(t, "zero", row.zero)
				checkErrorMessage(t, "full", row.full)
			})
			t.Run("is", func(t *testing.T) {
				checkSentinels(t, "zero", row.zero, row.zeroIs)
				for _, w := range wrapForms(row.full) {
					checkSentinels(t, w.name, w.err, row.fullIs)
				}
			})
			t.Run("as", func(t *testing.T) {
				for _, w := range wrapForms(row.full) {
					got, ok := row.as(w.err)
					if !ok || got != row.full {
						t.Errorf("%s: errors.As = %v, %v; want the row's own value", w.name, got, ok)
					}
				}
			})
			t.Run("unwrap", func(t *testing.T) {
				checkUnwrap(t, row)
			})
		})
	}
}

type wrapForm struct {
	name string
	err  error
}

// wrapForms is err itself, wrapped by %w one and two levels deep, and
// joined with an unrelated error.
func wrapForms(err error) []wrapForm {
	one := fmt.Errorf("one: %w", err)
	return []wrapForm{
		{"bare", err},
		{"%w", one},
		{"%w%w", fmt.Errorf("two: %w", one)},
		{"Join", errors.Join(errors.New("unrelated"), err)},
	}
}

func checkErrorMessage(t *testing.T, label string, err error) {
	t.Helper()
	var msg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s: Error() panicked: %v", label, r)
			}
		}()
		msg = err.Error()
	}()
	if !strings.HasPrefix(msg, "backendtest: ") || len(msg) == len("backendtest: ") {
		t.Errorf("%s: Error() = %q, want a non-empty message with the backendtest: prefix", label, msg)
	}
}

func checkSentinels(t *testing.T, label string, err error, want []string) {
	t.Helper()
	wanted := make(map[string]bool, len(want))
	for _, name := range want {
		if _, ok := packageSentinels[name]; !ok {
			t.Fatalf("row names %s, which is not a package sentinel", name)
		}
		wanted[name] = true
	}
	for name, sentinel := range packageSentinels {
		if got := errors.Is(err, sentinel); got != wanted[name] {
			t.Errorf("%s: errors.Is(%v, %s) = %v, want %v", label, err, name, got, wanted[name])
		}
	}
}

func checkUnwrap(t *testing.T, row errorContractRow) {
	t.Helper()
	single := func(err error) (error, bool) {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return nil, false
		}
		return u.Unwrap(), true
	}
	multi := func(err error) ([]error, bool) {
		u, ok := err.(interface{ Unwrap() []error })
		if !ok {
			return nil, false
		}
		return u.Unwrap(), true
	}
	switch {
	case row.cause != nil:
		if got, ok := single(row.full); !ok || got != row.cause {
			t.Errorf("full: Unwrap() = %v, %v; want the cause", got, ok)
		}
		if got, ok := single(row.zero); !ok || got != nil {
			t.Errorf("zero: Unwrap() = %v, %v; want nil", got, ok)
		}
	case row.findings != nil:
		got, ok := multi(row.full)
		if !ok || len(got) != len(row.findings) {
			t.Fatalf("full: Unwrap() = %v, %v; want the findings", got, ok)
		}
		for i := range got {
			if got[i] != row.findings[i] {
				t.Errorf("full: Unwrap()[%d] = %v, want %v", i, got[i], row.findings[i])
			}
		}
		if got, ok := multi(row.zero); !ok || len(got) != 0 {
			t.Errorf("zero: Unwrap() = %v, %v; want no findings", got, ok)
		}
	default:
		if _, ok := single(row.full); ok {
			t.Error("has Unwrap() error, but the row names no cause")
		}
		if _, ok := multi(row.full); ok {
			t.Error("has Unwrap() []error, but the row names no findings")
		}
	}
}

// TestErrorContractIsComplete fails on any exported ...Error type without a
// row in errorContractRows and any exported Err... sentinel missing from
// packageSentinels, and on rows or sentinels the package no longer declares.
func TestErrorContractIsComplete(t *testing.T) {
	types, sentinels := exportedErrorDecls(t)
	rows := make(map[string]bool)
	for _, row := range errorContractRows() {
		if rows[row.name] {
			t.Errorf("two rows for %s", row.name)
		}
		rows[row.name] = true
	}
	checkCovered(t, "error type", types, rows, "errorContractRows")
	listed := make(map[string]bool, len(packageSentinels))
	for name := range packageSentinels {
		listed[name] = true
	}
	checkCovered(t, "sentinel", sentinels, listed, "packageSentinels")
}

func checkCovered(t *testing.T, kind string, declared, covered map[string]bool, list string) {
	t.Helper()
	var missing, stale []string
	for name := range declared {
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	for name := range covered {
		if !declared[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("exported %s without an entry in %s: %v", kind, list, missing)
	}
	if len(stale) > 0 {
		t.Errorf("%s entries the package does not declare: %v", list, stale)
	}
}

// exportedErrorDecls parses the package's non-test files and returns the
// exported ...Error type names and Err... variable names.
func exportedErrorDecls(t *testing.T) (types, sentinels map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	types, sentinels = make(map[string]bool), make(map[string]bool)
	fset := token.NewFileSet()
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() && strings.HasSuffix(s.Name.Name, "Error") {
						types[s.Name.Name] = true
					}
				case *ast.ValueSpec:
					for _, id := range s.Names {
						if gen.Tok == token.VAR && id.IsExported() && strings.HasPrefix(id.Name, "Err") {
							sentinels[id.Name] = true
						}
					}
				}
			}
		}
	}
	if parsed == 0 || len(types) == 0 || len(sentinels) == 0 {
		t.Fatalf("parsed %d files, found %d error types and %d sentinels; the check checked nothing", parsed, len(types), len(sentinels))
	}
	return types, sentinels
}
