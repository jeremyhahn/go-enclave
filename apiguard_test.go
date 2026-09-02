// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSealedEnclave_NoForeignBytesConstructor makes the no-foreign-sealed-
// bytes invariant EXECUTABLE. The invariant is the absence of an API — no
// exported way to turn caller-supplied bytes into an openable *SealedEnclave
// except the sanctioned plaintext constructors — and an absence is exactly
// what a well-meaning future change erodes: someone adds a reasonable-looking
// UnmarshalBinary for a cache, and the property is gone with no test failing.
//
// # Why the guard exists NOW — read before "fixing" a failure
//
// This invariant used to be a security necessity: #21's confidentiality-only
// design was safe ONLY because no entry point existed through which a forged
// envelope could arrive. That rationale is OBSOLETE — #22 requires every
// provider to authenticate, so a forged envelope now fails Unprotect — and a
// guard citing it would be worse than no guard, because the next engineer
// would observe the providers authenticate, conclude the guard is stale, and
// delete it.
//
// The rationale that holds today is a FORMAT CONTRACT, not forgery: this
// package makes no persistence promise. The envelope layout is internal and
// unversioned across releases, and every sealed value is keyed to a Sealer
// whose keys live and die with this process. An unmarshaller would make that
// format accidentally permanent — commitments (versioning, migration, format
// stability) acquired by API accretion instead of by decision. If persistence
// or transport is ever wanted, it is designed as a requirement then, and THIS
// TEST is amended as part of that design, not deleted to make a PR compile.
func TestSealedEnclave_NoForeignBytesConstructor(t *testing.T) {
	// The sanctioned constructors: both take PLAINTEXT and produce a sealed
	// value, which is the direction the contract permits. Nothing else may
	// combine bytes-in with *SealedEnclave-out.
	allowed := map[string]bool{
		"NewSealed": true, // package-level, process sealer
		"Seal":      true, // (*Sealer), explicit sealer
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	fset := token.NewFileSet()
	checkedFiles, flagged := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checkedFiles++

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}

			// Decoder-shaped methods on the sealed types are refused BY NAME,
			// whatever their signature: these are the interfaces (encoding,
			// gob, json) through which foreign bytes arrive implicitly, where
			// no reviewer sees a call site at all.
			if recv := receiverTypeName(fn); recv == "SealedEnclave" || recv == "Sealer" {
				switch fn.Name.Name {
				case "UnmarshalBinary", "UnmarshalText", "UnmarshalJSON", "GobDecode", "DecodeMsgpack", "UnmarshalCBOR":
					flagged++
					t.Errorf("%s: %s.%s is a decoder for foreign bytes; see this test's rationale — "+
						"there is no persistence contract to decode against", name, recv, fn.Name.Name)
				}
			}

			if !returnsSealedEnclave(fn) || !takesForeignBytes(fn) {
				continue
			}
			if allowed[fn.Name.Name] {
				continue
			}
			flagged++
			t.Errorf("%s: exported %s takes caller bytes and returns a *SealedEnclave. "+
				"If those bytes are PLAINTEXT, add it to this test's allowlist with a comment. "+
				"If they are SEALED bytes, stop: sealed values have no persistence contract — no "+
				"stable format, no versioning, keys that die with the process — and this "+
				"constructor would make the internal format accidentally permanent. Design "+
				"persistence as a requirement (versioning, migration, provider signing for "+
				"transported envelopes) before adding any such entry point.", name, fn.Name.Name)
		}
	}

	// Vacuity guards: the walk must have seen the package and the allowlist
	// must describe reality — a renamed constructor would otherwise leave an
	// allowlist entry matching nothing and the guard checking nothing.
	if checkedFiles == 0 {
		t.Fatal("the guard parsed no files; it is checking nothing")
	}
	if flagged == 0 {
		for name := range allowed {
			if !functionExists(t, fset, name) {
				t.Errorf("allowlist names %q but no such function exists; update the allowlist with the rename", name)
			}
		}
	}
}

// receiverTypeName returns the bare type name of a method receiver, or "".
func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// returnsSealedEnclave reports whether any result is *SealedEnclave or
// SealedEnclave.
func returnsSealedEnclave(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, res := range fn.Type.Results.List {
		expr := res.Type
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		if ident, ok := expr.(*ast.Ident); ok && ident.Name == "SealedEnclave" {
			return true
		}
	}
	return false
}

// takesForeignBytes reports whether any parameter is a []byte, a string, or
// an io.Reader — the shapes through which caller-supplied bytes arrive.
func takesForeignBytes(fn *ast.FuncDecl) bool {
	for _, param := range fn.Type.Params.List {
		switch typ := param.Type.(type) {
		case *ast.ArrayType:
			if typ.Len == nil {
				if ident, ok := typ.Elt.(*ast.Ident); ok && ident.Name == "byte" {
					return true
				}
			}
		case *ast.Ident:
			if typ.Name == "string" {
				return true
			}
		case *ast.SelectorExpr:
			if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == "io" && typ.Sel.Name == "Reader" {
				return true
			}
		}
	}
	return false
}

// functionExists reports whether an exported function or method of that name
// is declared in any non-test file of the package.
func functionExists(t *testing.T, fset *token.FileSet, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}
	for _, entry := range entries {
		fname := entry.Name()
		if !strings.HasSuffix(fname, ".go") || strings.HasSuffix(fname, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", fname), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", fname, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return true
			}
		}
	}
	return false
}
