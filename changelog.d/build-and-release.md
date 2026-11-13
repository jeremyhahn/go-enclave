### Added

- **build-and-release**: a build gate for `build/ci/release-tag.sh`: plain version tags such as `v1.2.3` and `v1.2.3-alpha.1` become exactly the `tag=` and `sha=` release outputs, and a branch ref, an empty or unset ref, or a tag holding shell metacharacters, spaces, slashes, quotes, backticks, `$(...)`, newlines or a leading dash is refused with nothing written and the name not echoed (#370).
- **build-and-release**: A build gate, `TestMarkdownRelativeLinksResolve`, checks that every relative link in the repository's Markdown resolves to a path in the repository, or to an issue, pull request or milestone at the depth that reaches the repository root. The backend documents' links to the Linux secretmem design now resolve.
