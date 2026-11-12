### Added

- `make release-tree-check TAG=vX.Y.Z REF=<published ref>` checks, offline in the local clone, that the published commit's tree is byte-identical to the release tag's tree, and refuses naming both trees when they differ, when either does not resolve, or when the tag is not a release version (#332). It writes nothing. Nothing changes for Go callers.
