// The action-pin gate lives in its own module on purpose; see doc.go. Keeping
// a YAML parser out of the root module is the point, so do NOT move these
// requirements up to ../../go.mod.
module github.com/jeremyhahn/go-enclave/test/buildgates

go 1.27.1

require github.com/goccy/go-yaml v1.19.2
