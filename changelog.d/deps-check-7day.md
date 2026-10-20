### Changed

- **`make deps-check` reports a release under 7 days old instead of failing** (DS-2913). A module behind a latest release published less than 7 days ago, with no `// held: <reason>` comment, is named on stdout with the release time and passes; once that release is 7 days old, or its publish time is unknown, it fails as before. `scripts/deps-check.sh` reads the publish time from the same `go list -m -u` call. Nothing changes for Go callers.
