### Changed

- CI rebuilds the integration image when Alpine ships a package update, and the lint-gates job stops at the first failing gate (ci-template v1.29.2). Nothing changes for Go callers.
