### Added

- **backend-conformance**: `backendtest.ExampleTestBackend` is a runnable example that certifies the shipped locked-memory backend with a minimal `Config`, and the backend conformance guide links it ([#367](https://github.com/jeremyhahn/go-enclave/issues/367)).

### Fixed

- **backend-conformance**: `backendtest.TestBackend` reports the residue property as `ErrNotMeasured` for material that is one repeated byte, such as a fresh zeroed region, instead of failing it ([#367](https://github.com/jeremyhahn/go-enclave/issues/367)).
