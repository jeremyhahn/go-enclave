### Changed

- **The devcontainer's `toolchain` and `integration` stages carry node, git, bash and tar** (#212). CI runs each stage's jobs with `container:` set to the image, so the runner's JavaScript actions (checkout, cache, upload) execute inside it; `toolchain` gains `nodejs`, `integration` gains `bash git tar nodejs` and still runs as `dev`. Nothing changes for Go callers.
