### Changed

- **docs: Upgrading covers v0.10.0-alpha, v0.11.0-alpha, v0.11.1-alpha and the next release.** [docs/README.md](docs/README.md#upgrading) gains one section per release, newest first: the next release's minimum Go 1.27.4, why the `Sealed` envelope version 2 needs no upgrade order (no envelope leaves the process that sealed it), and how to require the nested `backends/armtrustzone` and `backends/tpm` modules; v0.11.1-alpha and v0.11.0-alpha need no change; v0.10.0-alpha needs Go 1.27.3. Documentation only. Nothing changes for Go callers.
