### Changed

- **The user-namespace `RLIMIT_MEMLOCK` test fails instead of skipping** (#136). `TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace` moved to `memlock_userns_linux_test.go`, built with `-tags=userns`, and runs through `make integration-test-userns` in a new `userns` compose service whose seccomp profile (`build/docker/devcontainer/seccomp-userns.json`) differs from Docker's default only in permitting `CLONE_NEWUSER`. Where the namespace cannot be created, or carries no capabilities, it fails. `make integration-test-<feature>` for the budget feature depends on it. `registry_test.go` no longer calls a failing sweep a skip.
- **The feature map is machine-readable** (#136). `scripts/features.map` gives each feature its unit package, integration suite, integration-test name prefix and source globs; `scripts/features.sh`, the Makefile and the build gates read it. The integration tests are renamed `Test<Feature>_…`, and `make integration-test-<feature>` runs only the feature's tests, without the whole-suite coverage floor, which `integration-test-enclave` and `ci-integration` keep.
- **The workflow pin gate covers container images** (#136). A job's `container:` and `services.<name>.image` must name a `@sha256:` digest, in every YAML spelling the action gate already reads.

### Added

- **Build gates for the feature map and the toolchain** (#136). Every non-test source file must match exactly one feature's globs and every glob a file; every integration test must carry exactly one feature's prefix in its suite, and every prefix be used; every `docs/<feature>/` needs a line in the map. The Dockerfile's Go version must equal the `go` directive in `go.mod`.
