### Added

- A build gate, `TestMarkdownRelativeLinksResolve`, that every relative link in the repository's Markdown resolves: a repository path must exist, and a link that leaves the repository must name an issue, pull request or milestone at the depth that reaches the repository root. The six backend documents' links to the Linux secretmem design now resolve (#339).
