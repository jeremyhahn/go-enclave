package enclave

import (
	"errors"
	"fmt"
	"testing"
)

// sameErrors reports whether got and want hold the same error values, by
// identity, in the same order.
func sameErrors(got, want []error) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] { //nolint:errorlint // identity is the point
			return false
		}
	}
	return true
}

func TestErrorHelpersWithCleanupFailure(t *testing.T) {
	failure := errors.New("failure")
	c1 := errors.New("cleanup one")
	c2 := errors.New("cleanup two")
	c3 := errors.New("cleanup three")
	inner := errors.New("inner failure")

	flat := &CleanupError{Failure: inner, Causes: []error{c2, c3}}
	flatNoFailure := &CleanupError{Causes: []error{c2}}
	wrapped := fmt.Errorf("wrapped: %w", &CleanupError{Failure: inner, Causes: []error{c2}})
	topFailure := &CleanupError{Failure: inner, Causes: []error{c1}}

	tests := []struct {
		name     string
		failure  error
		cleanups []error
		// same: the result is this exact value; otherwise a *CleanupError
		// with wantFailure and wantCauses.
		same        error
		wantFailure error
		wantCauses  []error
	}{
		{name: "no cleanups", failure: failure, same: failure},
		{name: "no cleanups nil failure", failure: nil, same: nil},
		{name: "all nil cleanups", failure: failure, cleanups: []error{nil, nil}, same: failure},
		{name: "nil failure one cleanup", failure: nil, cleanups: []error{nil, c1}, same: c1},
		{name: "nil failure one CleanupError cleanup", failure: nil, cleanups: []error{flat}, same: flat},
		{name: "nil failure two cleanups", failure: nil, cleanups: []error{c1, nil, c2}, wantCauses: []error{c1, c2}},
		{name: "failure and one cleanup", failure: failure, cleanups: []error{c1}, wantFailure: failure, wantCauses: []error{c1}},
		{name: "top-level CleanupError cleanup flattened", failure: failure, cleanups: []error{c1, flat}, wantFailure: failure, wantCauses: []error{c1, inner, c2, c3}},
		{name: "CleanupError cleanup without failure flattened", failure: failure, cleanups: []error{flatNoFailure, c1}, wantFailure: failure, wantCauses: []error{c2, c1}},
		{name: "wrapped CleanupError kept whole", failure: failure, cleanups: []error{wrapped}, wantFailure: failure, wantCauses: []error{wrapped}},
		{name: "CleanupError failure gets causes appended", failure: topFailure, cleanups: []error{c2, c3}, wantFailure: inner, wantCauses: []error{c1, c2, c3}},
		{name: "CleanupError failure and flattened cleanup", failure: topFailure, cleanups: []error{flat}, wantFailure: inner, wantCauses: []error{c1, inner, c2, c3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := withCleanupFailure(tt.failure, tt.cleanups...)
			if tt.wantFailure == nil && tt.wantCauses == nil {
				if got != tt.same { //nolint:errorlint // identity is the point
					t.Fatalf("withCleanupFailure = %v, want %v unchanged", got, tt.same)
				}
				return
			}
			ce, ok := got.(*CleanupError) //nolint:errorlint // top level is the contract
			if !ok {
				t.Fatalf("withCleanupFailure = %T %v, want *CleanupError", got, got)
			}
			if ce == tt.failure { //nolint:errorlint // identity is the point
				t.Fatal("withCleanupFailure returned the input CleanupError, want a new one")
			}
			if ce.Failure != tt.wantFailure { //nolint:errorlint // identity is the point
				t.Errorf("Failure = %v, want %v", ce.Failure, tt.wantFailure)
			}
			if !sameErrors(ce.Causes, tt.wantCauses) {
				t.Errorf("Causes = %v, want %v", ce.Causes, tt.wantCauses)
			}
		})
	}
}

func TestErrorHelpersWithCleanupFailureLeavesInputCauses(t *testing.T) {
	inner := errors.New("inner failure")
	c1 := errors.New("cleanup one")
	spare := errors.New("spare slot")
	backing := make([]error, 2, 4)
	backing[0], backing[1] = c1, nil
	backing = backing[:1]
	full := backing[:3]
	full[2] = spare
	in := &CleanupError{Failure: inner, Causes: backing}
	cleanupIn := &CleanupError{Failure: inner, Causes: backing}

	added := errors.New("added")
	got := withCleanupFailure(in, added, cleanupIn)
	ce, ok := got.(*CleanupError) //nolint:errorlint // top level is the contract
	if !ok {
		t.Fatalf("withCleanupFailure = %T, want *CleanupError", got)
	}
	if !sameErrors(ce.Causes, []error{c1, added, inner, c1}) {
		t.Errorf("Causes = %v", ce.Causes)
	}
	if len(in.Causes) != 1 || cap(in.Causes) != 4 || in.Causes[0] != c1 { //nolint:errorlint // identity
		t.Errorf("input Causes changed: len %d cap %d %v", len(in.Causes), cap(in.Causes), in.Causes)
	}
	if full[1] != nil || full[2] != spare { //nolint:errorlint // identity
		t.Errorf("input backing array written: %v", full)
	}
	if &ce.Causes[0] == &backing[0] {
		t.Error("result Causes shares the input backing array")
	}
}

func TestErrorHelpersAsCleanupError(t *testing.T) {
	top := &CleanupError{Failure: errors.New("f")}
	tests := []struct {
		name string
		err  error
		want *CleanupError
	}{
		{name: "nil", err: nil},
		{name: "plain", err: errors.New("plain")},
		{name: "top-level", err: top, want: top},
		{name: "wrapped", err: fmt.Errorf("w: %w", top)},
		{name: "joined", err: errors.Join(top)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ce *CleanupError
			ok := asCleanupError(tt.err, &ce)
			if ok != (tt.want != nil) || ce != tt.want {
				t.Errorf("asCleanupError = %v, %p; want %v, %p", ok, ce, tt.want != nil, tt.want)
			}
		})
	}
}

func TestErrorHelpersDestroyOnFailure(t *testing.T) {
	e, err := newMemory([]byte("destroy-on-failure"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	failure := errors.New("failure")
	if got := destroyOnFailure(failure, e); got != failure { //nolint:errorlint // identity is the point
		t.Errorf("destroyOnFailure = %v, want the failure unchanged", got)
	}
	if e.IsAlive() {
		t.Error("region still alive after destroyOnFailure")
	}
}

func TestErrorHelpersText(t *testing.T) {
	sentinel := errors.New("enclave: sentinel")
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "causeText nil", got: causeText(sentinel, nil), want: "enclave: sentinel"},
		{name: "causeText cause", got: causeText(sentinel, errors.New("why")), want: "enclave: sentinel: why"},
		{name: "nameText plain", got: nameText(sentinel, "key"), want: `enclave: sentinel: "key"`},
		{name: "nameText quote and newline", got: nameText(sentinel, "a\"b\nc"), want: `enclave: sentinel: "a\"b\nc"`},
		{name: "nameText empty", got: nameText(sentinel, ""), want: `enclave: sentinel: ""`},
		{name: "budgetText", got: budgetText(sentinel, 4096, "limit 1024"), want: "enclave: sentinel: 4096 bytes requested, limit 1024"},
		{name: "budgetText zero", got: budgetText(sentinel, 0, "x"), want: "enclave: sentinel: 0 bytes requested, x"},
		{name: "budgetText negative", got: budgetText(sentinel, -1, "x"), want: "enclave: sentinel: -1 bytes requested, x"},
		{name: "inUseOf", got: inUseOf(10, 20), want: "10 of 20 bytes in use"},
		{name: "inUseOf zero", got: inUseOf(0, 0), want: "0 of 0 bytes in use"},
		{name: "inUseOf negative", got: inUseOf(-5, 8), want: "-5 of 8 bytes in use"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
