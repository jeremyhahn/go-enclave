### Changed

- Describe the arm-trustzone row as shipped in `docs/SPEC.md`, its design and the harness's engineering document, the `optee-fixture-image` help and the optee job's fail-closed check: the fixture image is pinned by ghcr digest and the `optee` job runs the arm-trustzone `backendtest` on it and passes (#206).
