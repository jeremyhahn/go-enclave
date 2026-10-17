### Changed

- **CI: the Devcontainer image job runs on the `bigdisk` runner** (#225). `ci.yml`'s `image` job moves from `ubuntu-latest` to the `bigdisk` label on the Dell and omega runners, so its image builds stop filling the small runners' disks; `.github/actionlint.yaml` lists the label. Nothing changes for Go callers.
