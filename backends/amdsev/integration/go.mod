// The SEV-SNP guest kit's tests live in their own module, as the backends do:
// it requires a released root module, never the reverse, so the root's go.mod
// gains no dependency and make test never runs a hardware test. Do NOT add a
// replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/amdsev/integration

go 1.27.4

require (
	github.com/jeremyhahn/go-enclave v0.12.0-alpha
	golang.org/x/sys v0.50.0
)
