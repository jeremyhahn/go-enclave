// The TPM provider lives in its own module on purpose, as the arm-trustzone
// backend does: it requires the root module, never the reverse, so the root's
// go.mod gains no dependency. Do NOT add a replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/tpm

go 1.27.4

require (
	github.com/google/go-tpm v0.9.8
	github.com/jeremyhahn/go-enclave v0.11.1-alpha
	golang.org/x/sys v0.49.0
)
