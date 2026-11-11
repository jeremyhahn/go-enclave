// The arm-trustzone backend lives in its own module on purpose (#206, ruling
// 176434): it requires the root module, never the reverse, so the root's
// go.mod stays interface-only. Do NOT add a replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/armtrustzone

go 1.27.4

require (
	github.com/jeremyhahn/go-enclave v0.11.1-alpha
	golang.org/x/sys v0.49.0
)
