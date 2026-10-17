### Fixed

- **providertest: a nondeterministic root no longer reads as unwritten bytes.** When two `UnsealRoot` calls disagree, the root-unsealer check takes a third call under a third canary and calls a byte UNWRITTEN only if it kept its own fill on all three, so a provider whose root changes per call fails on "DIFFERENT roots" (it matched both canaries by chance about once in 2,000 runs) while a partial writer still fails on UNWRITTEN. Nothing changes for Go callers.
