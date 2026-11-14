// The imx-edgelock-enclave backend lives in its own module on purpose (#195,
// docs/backends/imx-edgelock-enclave.md Q2, the recommended option): it
// requires the root module, never the reverse, so the root's go.mod stays
// interface-only. Do NOT add a replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/imxele

go 1.27.4

require (
	github.com/jeremyhahn/go-enclave v0.11.1-alpha
	golang.org/x/sys v0.50.0
)
