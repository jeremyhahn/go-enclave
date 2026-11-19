// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"context"
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

// msgPrefix starts every message the package's errors render.
const msgPrefix = "providertest: "

// contractSentinels names every exported Err... sentinel of the package.
// TestErrorContractIsComplete fails on a sentinel missing here.
var contractSentinels = map[string]error{
	"ErrInvalidConfig": ErrInvalidConfig,
	"ErrAborted":       ErrAborted,
	"ErrNotMeasured":   ErrNotMeasured,
}

// contractRow is one value of an exported error type and what the contract
// expects of it.
type contractRow struct {
	name string
	err  error
	// is lists the package sentinels err matches; it matches no other.
	is []error
	// as reports what errors.As finds for err's concrete type.
	as func(error) error
	// causes is what Unwrap exposes, in order; nil when there is no cause.
	causes []error
}

func asType[T error](err error) error {
	var target T
	if errors.As(err, &target) {
		return target
	}
	return nil
}

func contractRows() []contractRow {
	property := &PropertyError{Property: "seal-open round trip", Detail: "opened bytes differ"}
	notMeasured := &NotMeasuredError{Property: "zeroize", Reason: "no memory scanner on this host"}
	aborted := &AbortedError{Cause: context.DeadlineExceeded}
	return []contractRow{
		{name: "ConfigError/zero", err: &ConfigError{},
			is: []error{ErrInvalidConfig}, as: asType[*ConfigError]},
		{name: "ConfigError/populated", err: &ConfigError{Field: "New", Reason: "is nil"},
			is: []error{ErrInvalidConfig}, as: asType[*ConfigError]},
		{name: "AbortedError/zero", err: &AbortedError{},
			is: []error{ErrAborted}, as: asType[*AbortedError]},
		{name: "AbortedError/populated", err: &AbortedError{Cause: context.Canceled},
			is: []error{ErrAborted}, as: asType[*AbortedError], causes: []error{context.Canceled}},
		{name: "FindingsError/zero", err: &FindingsError{}, as: asType[*FindingsError]},
		{name: "FindingsError/populated", err: &FindingsError{Findings: []error{property, notMeasured, aborted}},
			is: []error{ErrNotMeasured, ErrAborted}, as: asType[*FindingsError],
			causes: []error{property, notMeasured, aborted}},
		{name: "PropertyError/zero", err: &PropertyError{}, as: asType[*PropertyError]},
		{name: "PropertyError/populated", err: property, as: asType[*PropertyError]},
		{name: "NotMeasuredError/zero", err: &NotMeasuredError{},
			is: []error{ErrNotMeasured}, as: asType[*NotMeasuredError]},
		{name: "NotMeasuredError/populated", err: notMeasured,
			is: []error{ErrNotMeasured}, as: asType[*NotMeasuredError]},
	}
}

// wrappings returns err as callers see it: bare, wrapped by %w one and two
// levels deep, and joined with an unrelated error.
func wrappings(err error) map[string]error {
	once := fmt.Errorf("one: %w", err)
	return map[string]error{
		"bare": err,
		"%w":   once,
		"%w%w": fmt.Errorf("two: %w", once),
		"Join": errors.Join(errors.New("unrelated"), err),
	}
}

// checkSentinels asserts that err matches exactly the sentinels in want.
func checkSentinels(t *testing.T, how string, err error, want []error) {
	t.Helper()
	for name, s := range contractSentinels {
		wanted := slices.Contains(want, s)
		if got := errors.Is(err, s); got != wanted {
			t.Errorf("%s: errors.Is(err, %s) = %v, want %v", how, name, got, wanted)
		}
	}
}

// unwrapped returns what err's own Unwrap exposes, or nil without one.
func unwrapped(err error) []error {
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		return u.Unwrap()
	case interface{ Unwrap() error }:
		if c := u.Unwrap(); c != nil {
			return []error{c}
		}
	}
	return nil
}

func TestErrorContract(t *testing.T) {
	for _, row := range contractRows() {
		t.Run(row.name, func(t *testing.T) {
			msg := row.err.Error()
			if msg == "" || !strings.HasPrefix(msg, msgPrefix) {
				t.Errorf("Error() = %q, want a non-empty message starting %q", msg, msgPrefix)
			}
			for how, err := range wrappings(row.err) {
				checkSentinels(t, how, err, row.is)
				if got := row.as(err); got != row.err {
					t.Errorf("%s: errors.As found %v, want the row's own value", how, got)
				}
			}
			got := unwrapped(row.err)
			if len(got) != len(row.causes) {
				t.Fatalf("Unwrap exposes %d causes %v, want %d", len(got), got, len(row.causes))
			}
			for i, c := range row.causes {
				if got[i] != c {
					t.Errorf("Unwrap()[%d] = %v, want %v", i, got[i], c)
				}
				if !errors.Is(row.err, c) {
					t.Errorf("errors.Is(err, cause %d) = false, want true", i)
				}
			}
		})
	}
}

func TestSentinelContract(t *testing.T) {
	for name, s := range contractSentinels {
		t.Run(name, func(t *testing.T) {
			if msg := s.Error(); !strings.HasPrefix(msg, msgPrefix) || msg == msgPrefix {
				t.Errorf("Error() = %q, want a non-empty message starting %q", msg, msgPrefix)
			}
			for how, err := range wrappings(s) {
				checkSentinels(t, how, err, []error{s})
			}
		})
	}
}

// TestErrorContractIsComplete fails on an exported ...Error type or Err...
// sentinel of the package's non-test files that the contract has no row for,
// and on a sentinel no row's type matches.
func TestErrorContractIsComplete(t *testing.T) {
	types, sentinels := exportedErrorDecls(t)
	// covered records, per type, whether a zero and a populated row exist.
	covered := map[string][2]bool{}
	matched := map[error]bool{}
	for _, row := range contractRows() {
		name := strings.TrimPrefix(fmt.Sprintf("%T", row.err), "*providertest.")
		c := covered[name]
		if reflect.ValueOf(row.err).Elem().IsZero() {
			c[0] = true
		} else {
			c[1] = true
		}
		covered[name] = c
		for _, s := range row.is {
			matched[s] = true
		}
	}
	for _, name := range types {
		if c := covered[name]; !c[0] || !c[1] {
			t.Errorf("exported error type %s needs a zero and a populated row in contractRows, has %v", name, c)
		}
	}
	for _, name := range sentinels {
		s, ok := contractSentinels[name]
		switch {
		case !ok:
			t.Errorf("exported sentinel %s is missing from contractSentinels", name)
		case !matched[s]:
			t.Errorf("no row in contractRows matches sentinel %s", name)
		}
	}
}

// exportedErrorDecls parses the package's non-test files and returns the
// names of its exported ...Error types and Err... sentinels.
func exportedErrorDecls(t *testing.T) (types, sentinels []string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
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
					for _, n := range s.Names {
						if n.IsExported() && strings.HasPrefix(n.Name, "Err") {
							sentinels = append(sentinels, n.Name)
						}
					}
				}
			}
		}
	}
	if len(types) == 0 || len(sentinels) == 0 {
		t.Fatal("no exported error types or sentinels found; the check checked nothing")
	}
	return types, sentinels
}
