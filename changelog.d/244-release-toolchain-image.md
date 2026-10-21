### Fixed

- **The release workflow gates the tag in the same toolchain image as CI** (#244). `release.yml` built and tested the tag on the bare runner with the runner's own tools, so a Go bump failed the release's lint until every runner was rebuilt. Its gate now builds the content-addressed toolchain image from the tagged commit and runs lint, build, security with `trivy`, and the unit tests with the FIPS 140-3 strict run in it, and its integration job follows CI's; a Go bump no longer needs a runner rebuild before a release. Nothing changes for Go callers.
