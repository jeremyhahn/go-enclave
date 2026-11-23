package intelsgx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// TestBackendIsNotAnAttester holds the backend to confinement: attestation
// is go-xkms's, so *Backend implements no enclave.Attester.
func TestBackendIsNotAnAttester(t *testing.T) {
	if _, ok := any(newTestBackend()).(enclave.Attester); ok {
		t.Fatal("*Backend implements enclave.Attester; attestation is go-xkms's")
	}
}

// TestPackageExportsNoAttestationSurface parses the package's non-test
// sources, for every GOOS and GOARCH, and refuses an exported EvidenceFormat
// or Attest.
func TestPackageExportsNoAttestationSurface(t *testing.T) {
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
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "Attest" {
					t.Errorf("%s declares Attest", name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if vs, ok := s.(*ast.ValueSpec); ok {
						for _, n := range vs.Names {
							if n.Name == "EvidenceFormat" {
								t.Errorf("%s declares EvidenceFormat", name)
							}
						}
					}
				}
			}
		}
	}
}
