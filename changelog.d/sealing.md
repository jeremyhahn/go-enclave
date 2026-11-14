### Added

- **sealing**: Runnable examples `ExampleNewSealed`, `ExampleNewSealedFrom`, `ExampleSealed_OpenIn` and `ExampleNewSealer` show sealing, a late open inside the borrow window, an open into an explicit backend and a sealer over an explicit `KeyProtector`, and `go test` checks each against its output without printing material.
- **sealing**: Known-answer vectors for blob contract v1 in `testdata/contract-v1/` (SoftwareProvider blob, ModeRootKey KEK and DEK blobs, sealed values under envelope versions 1 and 2, and the blobs a reader must refuse) are rebuilt byte for byte by a standard-library reference encoder written from `docs/sealing/engineering.md` and opened through the package. A second implementer, such as a trusted application, can check its bytes against the same files.
