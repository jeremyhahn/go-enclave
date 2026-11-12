### Added

- Runnable sealing examples, `ExampleNewSealed`, `ExampleNewSealedFrom`, `ExampleSealed_OpenIn` and `ExampleNewSealer`: seal, open late inside the borrow window, open into an explicit backend, and seal through a sealer over an explicit `KeyProtector`; `go test` runs each against its output, and none prints material (#340).
