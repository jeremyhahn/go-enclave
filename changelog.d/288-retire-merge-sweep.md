### Removed

- The scheduled merge sweep workflow and the dispatch-only batch workflow leave the tree: pull requests merge through GitHub's native auto-merge, and `.github/CODEOWNERS` names the reviewers (#288). Nothing changes for Go callers.
