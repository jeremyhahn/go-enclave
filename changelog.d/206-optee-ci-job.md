### Added

- CI gains an `optee` job that runs the arm-trustzone harness in the OP-TEE QEMU fixture image (`OPTEE_FIXTURE_IMAGE`, pinned by digest in `scripts/tool-pins.sh`) on its prebuilt stack, on the full tier and every nightly when the backend, its harness or their pins change. The job fails while the pin is empty, and `docs/backend-conformance/engineering.md` states the fixture image contract (#206, #250). Nothing changes for Go callers.
