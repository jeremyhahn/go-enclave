### Changed

- **A merge train lands as one up-to-date PR** (#122). `automerge.yml` v7
  opens each `merge-train/*` branch as a PR into main and squash-merges that PR
  once its CI is green, so main keeps `block_on_outdated_branch` on. Its PRs
  are then closed with a comment naming the squash commit, and the issues they
  close are closed.
- **CI no longer runs on pushes to `merge-train/**`** (#122). A train is a PR,
  so it gets CI from the `pull_request` trigger like any other.
