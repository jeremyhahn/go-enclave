### Added

- `backendtest.ExampleTestBackend`, a runnable example of the conformance suite: it certifies the shipped locked-memory backend (`enclave.DefaultBackend()`) with a minimal `Config`, and the backend conformance user guide links it (#367).

### Fixed

- `backendtest.TestBackend` no longer fails the residue property for a handle whose material is one repeated byte, such as a fresh zeroed region: such bytes are everywhere in a process, so the sweep now reports the case as `ErrNotMeasured` and asks for random material (#367).
