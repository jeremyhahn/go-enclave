### Fixed

- `make release`, `make release-candidate` and `make release-alpha` refuse unless
  local `main` equals `dev/main` and the forge reports a green combined commit
  status for it (`FORGE_API_URL`, `FORGE_REPOSITORY` and `FORGE_TOKEN` are now
  read; an unreachable forge is a refusal), and push `main` and the tag in one
  atomic push, so a rejected `main` can no longer burn an immutable tag.
- `release.yml` runs every job on the commit Verify resolved, not the tag ref
  again, and publishes the release with that commit as its `target_commitish`.
- `automerge.yml` declares `permissions: contents: read`, and a build gate
  requires every workflow to declare a top-level `permissions:` block without a
  write scope.
- The integration job takes trivy from the pinned toolchain image instead of
  downloading it on every run, and `make ci-integration` scans the image once.
