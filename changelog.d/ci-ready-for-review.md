### Changed

- CI follows ci-template v1.35.3 and the review follows code-review v5.10.12: marking a draft pull request ready (`ready_for_review`) now runs CI and the code review, so a PR leaves draft with a real gate and no empty commit. A buildgates test pins both triggers. Nothing changes for Go callers.
