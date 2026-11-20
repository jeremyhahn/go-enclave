//go:build !(linux && amd64)

package confidentialvm

import "context"

// supported is false off linux/amd64: no SEV-SNP or TDX guest runs here, and
// the constructors refuse with no Cause.
const supported = false

// openDevice refuses: there is no SEV-SNP guest device here.
func openDevice(string) error { return &DerivedKeyError{} }

// deriveKey refuses: there is no SEV-SNP guest device here.
func deriveKey(context.Context, string, keyRequest, []byte) error { return &DerivedKeyError{} }
