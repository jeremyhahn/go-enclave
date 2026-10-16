### Changed

- **CI: a label change starts no pull request run** (DS-2281). `ci.yml`'s `pull_request` trigger drops the `labeled` type, so a `task:*`, `code-review` or review-request label no longer starts a run that cancels the one in flight; `ci:full` takes effect on the PR's next push or update-branch, or via `workflow_dispatch`. Nothing changes for Go callers.
