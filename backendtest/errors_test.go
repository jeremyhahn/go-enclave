package backendtest

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestAbortedError pins the cause shape behind AbortedError: its text, its
// sentinel, and its cause under errors.Is, errors.As and errors.Unwrap.
func TestAbortedError(t *testing.T) {
	if got, want := (&AbortedError{}).Error(), ErrAborted.Error(); got != want {
		t.Errorf("AbortedError{}.Error() = %q, want %q", got, want)
	}
	err := &AbortedError{Cause: context.Canceled}
	if got, want := err.Error(), ErrAborted.Error()+": "+context.Canceled.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrAborted) || !errors.Is(err, context.Canceled) {
		t.Errorf("%v does not match both ErrAborted and its cause", err)
	}
	if errors.Is(err, ErrNotMeasured) || errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrUncheckedCapability) {
		t.Errorf("%v matches another package sentinel", err)
	}
	if errors.Unwrap(err) != context.Canceled {
		t.Errorf("Unwrap() = %v, want the cause", errors.Unwrap(err))
	}
	var ae *AbortedError
	if !errors.As(findingsOf([]error{&PropertyError{}, err}), &ae) || ae != err {
		t.Error("errors.As does not reach an AbortedError among the findings")
	}
}

// TestDetailErrorsMatchTheirSentinels pins that ConfigError,
// NotMeasuredError and UncheckedCapabilityError match their own sentinel only,
// and that a PropertyError matches none.
func TestDetailErrorsMatchTheirSentinels(t *testing.T) {
	sentinels := []error{ErrInvalidConfig, ErrNotMeasured, ErrUncheckedCapability, ErrAborted}
	tests := []struct {
		err  error
		want error
	}{
		{err: &ConfigError{Field: "New", Reason: "is nil"}, want: ErrInvalidConfig},
		{err: &NotMeasuredError{Property: "p", Reason: "r"}, want: ErrNotMeasured},
		{err: &UncheckedCapabilityError{Capability: enclave.CapabilitySign, Reason: "r"}, want: ErrUncheckedCapability},
		{err: &PropertyError{Property: "p", Detail: "d"}},
	}
	for _, tc := range tests {
		if !strings.HasPrefix(tc.err.Error(), "backendtest: ") {
			t.Errorf("%T renders %q, without the package prefix", tc.err, tc.err)
		}
		for _, s := range sentinels {
			if got := errors.Is(tc.err, s); got != (s == tc.want) {
				t.Errorf("errors.Is(%v, %v) = %v", tc.err, s, got)
			}
		}
	}
}

// TestUncheckedCapabilityError pins that the error names the capability and
// its owner, the backend or a quoted case.
func TestUncheckedCapabilityError(t *testing.T) {
	backend := &UncheckedCapabilityError{Capability: enclave.CapabilityAttest, Reason: "r"}
	want := ErrUncheckedCapability.Error() + ": " + strconv.Quote(string(enclave.CapabilityAttest)) + " of the backend: r"
	if got := backend.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	handle := &UncheckedCapabilityError{Case: "key", Capability: enclave.CapabilitySign, Reason: "r"}
	want = ErrUncheckedCapability.Error() + ": " + strconv.Quote(string(enclave.CapabilitySign)) + ` of case "key": r`
	if got := handle.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestFindingsError pins that a run with no findings reports nil, and that a
// FindingsError renders one finding per line and reaches each one.
func TestFindingsError(t *testing.T) {
	if err := findingsOf(nil); err != nil {
		t.Errorf("findingsOf(nil) = %v, want nil", err)
	}
	pe := &PropertyError{Property: "p", Detail: "d"}
	ne := &NotMeasuredError{Property: "q", Reason: "r"}
	err := findingsOf([]error{pe, ne})
	var fe *FindingsError
	if !errors.As(err, &fe) || len(fe.Findings) != 2 {
		t.Fatalf("findingsOf = %#v, want a *FindingsError holding both findings", err)
	}
	if got, want := err.Error(), pe.Error()+"\n"+ne.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got := (&FindingsError{Findings: []error{nil, pe}}).Error(); got != "\n"+pe.Error() {
		t.Errorf("Error() with a nil finding = %q", got)
	}
	var got *PropertyError
	if !errors.As(err, &got) || got != pe || !errors.Is(err, ErrNotMeasured) {
		t.Errorf("%v does not reach each finding", err)
	}
	if errors.Is(err, ErrAborted) || errors.Is(err, ErrInvalidConfig) {
		t.Errorf("%v matches a sentinel none of its findings carries", err)
	}
}

// TestInternalErrors pins the unexported errors' causes and texts.
func TestInternalErrors(t *testing.T) {
	step := &stepError{step: "Config.New", err: context.Canceled}
	if !errors.Is(step, context.Canceled) || !strings.HasPrefix(step.Error(), "backendtest: Config.New: ") {
		t.Errorf("stepError %q does not carry its step and cause", step)
	}
	for _, err := range []error{&nilBackendError{}, &nilHandleError{step: "k.New"}} {
		if err.Error() == "" {
			t.Errorf("%T renders empty", err)
		}
	}
}

// errorsFile is the one backendtest file that may declare sentinels and
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
		}
		checkErrorCalls(t, fset, f)
	}
	if checked == 0 {
		t.Fatal("no production files found; the gate checked nothing")
	}
}

// checkErrorDecl flags an error type or errors.New sentinel declared outside
// errorsFile, and an exported error type declared as an alias anywhere.
func checkErrorDecl(t *testing.T, fset *token.FileSet, file string, decl ast.Decl) {
	t.Helper()
	gen, ok := decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gen.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if s.Assign.IsValid() && s.Name.IsExported() && strings.HasSuffix(s.Name.Name, "Error") {
				t.Errorf("%s: error type %s is an alias; declare it as a defined type", fset.Position(s.Pos()), s.Name.Name)
			}
			if file != errorsFile && strings.HasSuffix(s.Name.Name, "Error") {
				t.Errorf("%s: error type %s declared outside %s", fset.Position(s.Pos()), s.Name.Name, errorsFile)
			}
		case *ast.ValueSpec:
			for _, v := range s.Values {
				if file != errorsFile && isCall(v, "errors", "New") {
					t.Errorf("%s: sentinel declared outside %s", fset.Position(v.Pos()), errorsFile)
				}
			}
		}
	}
}

// checkErrorCalls flags fmt.Errorf and errors.Join anywhere.
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
