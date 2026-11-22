// The intel-sgx backend lives in its own module, as backends/armtrustzone
// does: it requires the root module, never the reverse, so the root's go.mod
// stays interface-only. Do NOT add a replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/intelsgx

go 1.27.4

require github.com/jeremyhahn/go-enclave v0.11.1-alpha

require golang.org/x/sys v0.49.0 // indirect
