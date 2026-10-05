### Changed

- **Auto-merge lands ready PRs in batches through a merge train** (#118).
  `automerge.yml` v6 merges every ready PR that is behind main onto a new
  `merge-train/*` branch, runs CI once on that combined tree, then
  squash-merges the PRs in order and deletes the branch. A red train drops its
  newest PR and retries; a PR that conflicts is left out with a comment. While
  main still requires up-to-date branches, PRs are updated one at a time as
  before.
- **CI runs every stage at once** (#118). Security, Test and Integration no
  longer wait for Lint and Build; CI Gate still needs every job and fails
  closed on any result but success. `ci.yml` also runs on pushes to
  `merge-train/**`.
