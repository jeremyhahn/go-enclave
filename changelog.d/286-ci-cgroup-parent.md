### Changed

- The CI toolchain container started by `scripts/in-toolchain-image.sh` is bounded by the job slot's memory (`--memory` with an equal `--memory-swap`; `IN_IMAGE_MEMORY` overrides) and charged to the runner host's `ci.slice` (`--cgroup-parent`; `CI_CGROUP_PARENT` overrides, empty passes none) (#286). Nothing changes for Go callers.
