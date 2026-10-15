### Changed

- **`make cross-build` links every package's test binaries for each target** (#188). After `go build` and `go vet`, it runs `go test -c` for every `CROSS_TARGETS` entry, so a test that compiles but does not link off Linux fails the gate; nothing runs. This is option E of [runtime testing](docs/memory-enclave/runtime-testing.md#e-link-the-test-binaries-in-cross-build-complement-not-an-answer) and does not close #188. Nothing changes for Go callers.
