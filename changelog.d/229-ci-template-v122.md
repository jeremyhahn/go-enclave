### Changed

- **CI: ci-template v1.22, caches in named host volumes** (#229). The devcontainer image job's stages keep the Go build, golangci-lint and module caches in named volumes on the runner's Docker host, split into a `main` set (written only by a push to `main`) and a `pr` set, instead of the job container's layer. The new `scripts/trim-ci-caches.sh` runs after the image build and keeps this repository's volumes under 32 GiB per host. Nothing changes for Go callers.
- **CI: ci-template v1.22.1, a push to `main` never cancels a `main` run** (#229). One concurrency group per ref: a newer push to a PR still cancels that PR's older run, but a push to `main` no longer cancels an in-flight `main` run, so every merge keeps its run. Nothing changes for Go callers.
