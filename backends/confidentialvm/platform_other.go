//go:build !(linux && amd64)

package confidentialvm

// supported is false off linux/amd64: no SEV-SNP or TDX guest runs here, and
// the constructor refuses with no Cause.
const supported = false
