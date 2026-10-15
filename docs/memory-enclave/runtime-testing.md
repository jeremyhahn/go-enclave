# Runtime testing: Linux only

> **Status: REFERENCE** · Scope: go-enclave · Last verified: 2026-10-15
> The owner's ruling of 2026-10-15 closed #188: Linux only for now, with no
> BSD or Windows runtime testing. The design proposal this page held is
> withdrawn.

Tests run on Linux only. The BSDs (freebsd, openbsd, netbsd, dragonfly) and
Windows are build-only: `make cross-build` compiles, vets and links their test
binaries for every `CROSS_TARGETS` entry, and nothing executes. Their rows in
the [platform contract](engineering.md#platform-contract) therefore describe
what the code does, not behavior a test has observed.

The status of every other platform is in
[test status](engineering.md#test-status).
