package tpm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// errorRow is one error type of the module and the contract it keeps.
type errorRow struct {
	// zero is the type's zero value.
	zero error
	// populated builds a filled-in value around cause; types without a
	// cause ignore it.
	populated func(cause error) error
	// sentinels are the sentinels the type matches with errors.Is.
	sentinels []error
	// wraps reports whether the type exposes its cause through Unwrap.
	wraps bool
	// as reports whether errors.As finds the row's type in err.
	as func(err error) bool
	// prefix is the message prefix every value carries.
	prefix string
	// defect, when set, skips the zero-value check: a known defect.
	defect string
}

func asType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// errorRows holds every error type of the module, keyed by type name.
var errorRows = map[string]errorRow{
	"PlatformError": {
		zero:      &PlatformError{},
		populated: func(error) error { return &PlatformError{GOOS: "plan9"} },
		sentinels: []error{ErrUnsupportedPlatform},
		as:        asType[*PlatformError],
		prefix:    "tpm: ",
	},
	"DeviceError": {
		zero: &DeviceError{},
		populated: func(cause error) error {
			return &DeviceError{Path: "/dev/tpmrm0", Op: "open", Err: cause}
		},
		sentinels: []error{ErrDeviceUnavailable},
		wraps:     true,
		as:        asType[*DeviceError],
		prefix:    "tpm: ",
	},
	"CommandError": {
		zero: &CommandError{},
		populated: func(cause error) error {
			return &CommandError{Command: cmdUnseal.String(), Err: cause}
		},
		sentinels: []error{ErrCommandFailed},
		wraps:     true,
		as:        asType[*CommandError],
		prefix:    "tpm: ",
		defect:    "CommandError.Error dereferences a nil Err",
	},
	"KeySizeError": {
		zero:      &KeySizeError{},
		populated: func(error) error { return &KeySizeError{Len: 129} },
		sentinels: []error{ErrKeySize},
		as:        asType[*KeySizeError],
		prefix:    "tpm: ",
	},
	"authError": {
		zero: &authError{},
		populated: func(cause error) error {
			return &authError{reason: cmdUnseal.String() + " refused the blob", err: cause}
		},
		sentinels: []error{enclave.ErrSealedAuthentication},
		wraps:     true,
		as:        asType[*authError],
		prefix:    enclave.ErrSealedAuthentication.Error() + ": tpm: ",
	},
}

// sentinelRows holds every Err sentinel of the module, keyed by name.
var sentinelRows = map[string]error{
	"ErrUnsupportedPlatform": ErrUnsupportedPlatform,
	"ErrDeviceUnavailable":   ErrDeviceUnavailable,
	"ErrCommandFailed":       ErrCommandFailed,
	"ErrKeySize":             ErrKeySize,
	"ErrLockedMemory":        ErrLockedMemory,
	"ErrClosed":              ErrClosed,
}

// allSentinels is every sentinel an error of this module may match.
func allSentinels() []error {
	all := []error{enclave.ErrSealedAuthentication}
	for _, s := range sentinelRows {
		all = append(all, s)
	}
	return all
}

func containsErr(list []error, target error) bool {
	for _, e := range list {
		if e == target {
			return true
		}
	}
	return false
}

// errMarker stands for key or blob bytes; it must never reach a message.
var errMarker = []byte("\x00key-marker-5e1f\xff")

func TestErrorContract_Types(t *testing.T) {
	for name, row := range errorRows {
		t.Run(name, func(t *testing.T) {
			if got := fmt.Sprintf("%T", row.zero); got != "*tpm."+name {
				t.Fatalf("row %s holds a %s", name, got)
			}
			t.Run("zero", func(t *testing.T) {
				if row.defect != "" {
					t.Skip("defect: " + row.defect)
				}
				checkMessage(t, row.zero, row.prefix)
				if row.wraps && errors.Unwrap(row.zero) != nil {
					t.Errorf("zero %T unwraps to %v, want nil", row.zero, errors.Unwrap(row.zero))
				}
			})

			cause := errors.New("cause")
			err := row.populated(cause)
			checkMessage(t, err, row.prefix)

			for _, s := range allSentinels() {
				if got, want := errors.Is(err, s), containsErr(row.sentinels, s); got != want {
					t.Errorf("errors.Is(%T, %q) = %v, want %v", err, s, got, want)
				}
			}

			wrapped := fmt.Errorf("outer: %w", err)
			joined := errors.Join(errors.New("other"), err)
			for _, e := range []error{err, wrapped, joined} {
				if !row.as(e) {
					t.Errorf("errors.As does not find %T in %q", err, e)
				}
				for _, s := range row.sentinels {
					if !errors.Is(e, s) {
						t.Errorf("errors.Is(%q, %q) = false through wrapping", e, s)
					}
				}
			}

			if got := errors.Unwrap(err); row.wraps && got != cause {
				t.Errorf("Unwrap(%T) = %v, want the cause", err, got)
			} else if !row.wraps && got != nil {
				t.Errorf("Unwrap(%T) = %v, want nil", err, got)
			}
			if row.wraps && errors.Unwrap(row.populated(nil)) != nil {
				t.Errorf("%T with a nil cause unwraps to non-nil", err)
			}

			checkNoMarker(t, err)
		})
	}
}

func TestErrorContract_Sentinels(t *testing.T) {
	for name, s := range sentinelRows {
		t.Run(name, func(t *testing.T) {
			checkMessage(t, s, "tpm: ")
			for _, other := range allSentinels() {
				if got, want := errors.Is(s, other), other == s; got != want {
					t.Errorf("errors.Is(%s, %q) = %v, want %v", name, other, got, want)
				}
			}
			if !errors.Is(errors.Join(errors.New("other"), s), s) {
				t.Errorf("%s is lost in errors.Join", name)
			}
		})
	}
}

func checkMessage(t *testing.T, err error, prefix string) {
	t.Helper()
	var msg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%T.Error() panics: %v", err, r)
			}
		}()
		msg = err.Error()
	}()
	if !strings.HasPrefix(msg, prefix) {
		t.Errorf("%T.Error() = %q, want prefix %q", err, msg, prefix)
	}
}

// checkNoMarker places errMarker in every byte field of err and checks the
// message does not carry it. The module's error types hold no key or blob
// bytes; a byte field added later must keep them out of the message.
func checkNoMarker(t *testing.T, err error) {
	t.Helper()
	v := reflect.ValueOf(err)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return
	}
	s := reflect.New(v.Elem().Type()).Elem()
	s.Set(v.Elem())
	for i := range s.NumField() {
		f, sf := s.Field(i), s.Type().Field(i)
		if !isBytes(sf.Type) {
			continue
		}
		if !sf.IsExported() {
			t.Errorf("%T.%s holds bytes the contract cannot reach", err, sf.Name)
			continue
		}
		if f.Kind() == reflect.Slice {
			f.SetBytes(bytes.Clone(errMarker))
		} else {
			reflect.Copy(f, reflect.ValueOf(errMarker))
		}
	}
	msg := s.Addr().Interface().(error).Error()
	if bytes.Contains([]byte(msg), errMarker) {
		t.Errorf("%T.Error() carries the marker: %q", err, msg)
	}
}

func isBytes(t reflect.Type) bool {
	return (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t.Elem().Kind() == reflect.Uint8
}

// TestErrorContract_Complete fails on an exported error type or an Err
// sentinel of the module's non-test files that has no row above.
func TestErrorContract_Complete(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					n := s.Name.Name
					if ast.IsExported(n) && strings.HasSuffix(n, "Error") {
						if _, ok := errorRows[n]; !ok {
							t.Errorf("%s: error type %s has no contract row", name, n)
						}
					}
				case *ast.ValueSpec:
					for _, id := range s.Names {
						n := id.Name
						if ast.IsExported(n) && strings.HasPrefix(n, "Err") {
							if _, ok := sentinelRows[n]; !ok {
								t.Errorf("%s: sentinel %s has no contract row", name, n)
							}
						}
					}
				}
			}
		}
	}
}
