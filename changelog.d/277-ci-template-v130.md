### Changed

- CI adopts ci-template v1.30 and nightly.yml v1.9: the CI Gate checks each job with the template's `check()`, lint runs in its own job, `make docker-build-toolchain` builds the toolchain image alone, `make lint-sweeps` serves the nightly job, and publish-images stays off until a release runner serves the repository (#277). Nothing changes for Go callers.
