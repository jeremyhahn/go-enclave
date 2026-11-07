### Changed

- The toolchain image build fetches the backend modules' private root through `GO_BUILD_PROXY`, a LAN Go module proxy that the self-hosted pool's environment carries as `GOPROXY` in CI, instead of the `gomodauth` BuildKit secret; `make docker-build GO_BUILD_PROXY=<url>` passes it as a build argument, and every CI and release job that builds an image runs on `bigdisk` (#293). Nothing changes for Go callers.
