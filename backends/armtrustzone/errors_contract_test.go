package armtrustzone

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// errorSentinels is every exported Err... sentinel the package declares,
// by name. TestErrorContractComplete fails when it and the source differ.
var errorSentinels = map[string]error{
	"ErrUnsupportedPlatform":  ErrUnsupportedPlatform,
	"ErrDeviceUnavailable":    ErrDeviceUnavailable,
	"ErrNotGlobalPlatform":    ErrNotGlobalPlatform,
	"ErrSessionRefused":       ErrSessionRefused,
	"ErrCommandFailed":        ErrCommandFailed,
	"ErrInterfaceUnsupported": ErrInterfaceUnsupported,
	"ErrRandomSize":           ErrRandomSize,
	"ErrShortRandom":          ErrShortRandom,
	"ErrInvalidUUID":          ErrInvalidUUID,
	"ErrBackendClosed":        ErrBackendClosed,
}

// errorContractRow is the contract of one exported error type or sentinel.
type errorContractRow struct {
	// name is the declared name: an exported ...Error type or an Err... sentinel.
	name string
	// zero is the type's zero value; nil for a sentinel.
	zero error
	// full is a populated value; the sentinel itself for a sentinel.
	full error
	// is are the sentinels both values match; is[0] begins every message.
	is []string
	// fullIs are the further sentinels only full matches, through its cause.
	fullIs []string
	// cause is what Unwrap returns on full; the zero value unwraps to nil.
	cause error
	// msg is full's message.
	msg string
}

func errorContractRows() []errorContractRow {
	rows := []errorContractRow{
		{
			name: "PlatformError",
			zero: &PlatformError{},
			full: &PlatformError{GOOS: "darwin"},
			is:   []string{"ErrUnsupportedPlatform"},
			msg:  `armtrustzone: the Linux TEE subsystem is not available on this platform: "darwin"`,
		},
		{
			name:   "DeviceError",
			zero:   &DeviceError{},
			full:   &DeviceError{Endpoint: "/dev/tee0", Op: "version", Cause: ErrNotGlobalPlatform},
			is:     []string{"ErrDeviceUnavailable"},
			fullIs: []string{"ErrNotGlobalPlatform"},
			cause:  ErrNotGlobalPlatform,
			msg:    `armtrustzone: the TEE device is unavailable: "/dev/tee0": version: armtrustzone: the TEE is not GlobalPlatform compliant`,
		},
		{
			name: "SessionError",
			zero: &SessionError{},
			full: &SessionError{Code: 0xffff0008, Origin: 3},
			is:   []string{"ErrSessionRefused"},
			msg:  "armtrustzone: the TEE refused a session with the trusted application: result 0xffff0008, origin 3",
		},
		{
			name: "CommandError",
			zero: &CommandError{},
			full: &CommandError{Command: 2, Code: 0xffff000c, Origin: 4},
			is:   []string{"ErrCommandFailed"},
			msg:  "armtrustzone: the trusted application's command failed: command 0x00000002: result 0xffff000c, origin 4",
		},
		{
			name: "InterfaceError",
			zero: &InterfaceError{},
			full: &InterfaceError{Version: 2, Flags: 0x1_0000_0001},
			is:   []string{"ErrInterfaceUnsupported"},
			msg:  "armtrustzone: the trusted application's interface is not supported: version 2, flags 0x100000001",
		},
		{
			name: "SizeError",
			zero: &SizeError{},
			full: &SizeError{N: -1},
			is:   []string{"ErrRandomSize"},
			msg:  "armtrustzone: a random request must be at least one byte: -1",
		},
		{
			name: "ShortRandomError",
			zero: &ShortRandomError{},
			full: &ShortRandomError{Want: 32, Got: 7},
			is:   []string{"ErrShortRandom"},
			msg:  "armtrustzone: the trusted application returned fewer random bytes than asked: want 32, got 7",
		},
		{
			name: "UUIDError",
			zero: &UUIDError{},
			full: &UUIDError{Text: "not-a-uuid"},
			is:   []string{"ErrInvalidUUID"},
			msg:  `armtrustzone: not an RFC 9562 UUID: "not-a-uuid"`,
		},
	}
	// Every sentinel is a row of its own: it matches itself and no other.
	names := make([]string, 0, len(errorSentinels))
	for name := range errorSentinels {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err := errorSentinels[name]
		rows = append(rows, errorContractRow{name: name, full: err, is: []string{name}, msg: err.Error()})
	}
	return rows
}

// errorText returns err.Error(), or the panic it raised.
func errorText(err error) (msg string, panicked any) {
	defer func() { panicked = recover() }()
	return err.Error(), nil
}

// errorWraps returns err as returned, wrapped one and two levels deep with
// %w, and joined with another error.
func errorWraps(err error) map[string]error {
	return map[string]error{
		"bare":   err,
		"%w":     fmt.Errorf("one: %w", err),
		"%w %w":  fmt.Errorf("two: %w", fmt.Errorf("one: %w", err)),
		"Join":   errors.Join(errors.New("other"), err),
		"Join+w": fmt.Errorf("one: %w", errors.Join(err, errors.New("other"))),
	}
}

func TestErrorContract(t *testing.T) {
	for _, row := range errorContractRows() {
		t.Run(row.name, func(t *testing.T) {
			if row.zero != nil {
				checkErrorValue(t, "zero", row, row.zero, row.is, nil)
			}
			checkErrorValue(t, "full", row, row.full, append(slices.Clone(row.is), row.fullIs...), row.cause)
			if msg, _ := errorText(row.full); msg != row.msg {
				t.Errorf("full: Error() = %q; want %q", msg, row.msg)
			}
		})
	}
}

// checkErrorValue holds one value of row to the contract: is are the
// sentinels it matches and cause what it unwraps to.
func checkErrorValue(t *testing.T, label string, row errorContractRow, err error, is []string, cause error) {
	t.Helper()
	msg, panicked := errorText(err)
	if panicked != nil {
		t.Fatalf("%s: Error() panicked: %v", label, panicked)
	}
	if msg == "" {
		t.Errorf("%s: Error() is empty", label)
	}
	if !strings.HasPrefix(msg, "armtrustzone: ") {
		t.Errorf("%s: Error() = %q; want the armtrustzone: prefix", label, msg)
	}
	if lead, ok := errorSentinels[row.is[0]]; ok && !strings.HasPrefix(msg, lead.Error()) {
		t.Errorf("%s: Error() = %q; want it to begin with %s's text", label, msg, row.is[0])
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("%s: Unwrap() = %v; want %v", label, got, cause)
	}
	for _, name := range is {
		if _, ok := errorSentinels[name]; !ok {
			t.Fatalf("%s: row names %s, which is not a package sentinel", label, name)
		}
	}
	for how, wrapped := range errorWraps(err) {
		for name, sentinel := range errorSentinels {
			if got, want := errors.Is(wrapped, sentinel), slices.Contains(is, name); got != want {
				t.Errorf("%s %s: errors.Is(%s) = %t; want %t", label, how, name, got, want)
			}
		}
		if row.zero == nil {
			continue // a sentinel has no type of its own to read
		}
		target := reflect.New(reflect.TypeOf(err))
		if !errors.As(wrapped, target.Interface()) {
			t.Errorf("%s %s: errors.As(*%T) = false", label, how, err)
		} else if got := target.Elem().Interface(); got != err {
			t.Errorf("%s %s: errors.As(*%T) = %v; want the wrapped value", label, how, err, got)
		}
	}
}

// TestErrorContractComplete parses the package's non-test files and fails
// on an exported ...Error type or Err... sentinel without a contract row,
// and on a row or sentinel entry the source does not declare.
func TestErrorContractComplete(t *testing.T) {
	types, sentinels := declaredErrors(t)
	rows := map[string]errorContractRow{}
	for _, row := range errorContractRows() {
		if _, dup := rows[row.name]; dup {
			t.Errorf("%s: two contract rows", row.name)
		}
		rows[row.name] = row
	}
	for name := range types {
		row, ok := rows[name]
		if !ok {
			t.Errorf("exported error type %s has no contract row", name)
			continue
		}
		want := "*armtrustzone." + name
		if row.zero == nil || fmt.Sprintf("%T", row.zero) != want || fmt.Sprintf("%T", row.full) != want {
			t.Errorf("%s: row values are %T and %T; want %s", name, row.zero, row.full, want)
		}
	}
	for name := range sentinels {
		if _, ok := errorSentinels[name]; !ok {
			t.Errorf("sentinel %s is missing from errorSentinels", name)
		}
		if _, ok := rows[name]; !ok {
			t.Errorf("sentinel %s has no contract row", name)
		}
	}
	for name := range errorSentinels {
		if !sentinels[name] {
			t.Errorf("errorSentinels names %s, which the package does not declare", name)
		}
	}
	for name := range rows {
		if !types[name] && !sentinels[name] {
			t.Errorf("contract row %s names nothing the package declares", name)
		}
	}
}

// declaredErrors returns the exported ...Error types and Err... sentinels
// declared in the package's non-test files, whatever their build tags.
func declaredErrors(t *testing.T) (types, sentinels map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	types, sentinels = map[string]bool{}, map[string]bool{}
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
						if id.IsExported() && strings.HasPrefix(id.Name, "Err") {
							sentinels[id.Name] = true
						}
					}
				}
			}
		}
	}
	if checked == 0 || len(types) == 0 || len(sentinels) == 0 {
		t.Fatalf("parsed %d files, found %d types and %d sentinels; the check checked nothing", checked, len(types), len(sentinels))
	}
	return types, sentinels
}
