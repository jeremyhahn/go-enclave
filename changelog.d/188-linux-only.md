### Changed

- **Tests run on Linux only** (#188). By the owner's ruling, the BSDs and Windows get no runtime testing: they stay build-only, and `make cross-build` compiles, vets and links their test binaries with nothing executed. The design proposal is withdrawn; [runtime testing](docs/memory-enclave/runtime-testing.md) states the ruling, and the SPEC row `bsd-windows-runtime-testing` is now `future`. Nothing changes for Go callers.
