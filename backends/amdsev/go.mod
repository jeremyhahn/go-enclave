// The SEV-SNP backend lives in its own module on purpose: it requires the
// root module, never the reverse, so the root's go.mod stays interface-only.
// Do NOT add a replace or a go.work.
module github.com/jeremyhahn/go-enclave/backends/amdsev

go 1.27.4

require golang.org/x/sys v0.50.0
