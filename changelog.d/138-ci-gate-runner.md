### Changed

- **The CI Gate runs on its own reserved runner label, `ci-gate`** (#138). In Gitea Actions even a needs-only job takes a runner slot, so the gate sat queued behind PR jobs after every job it gates had passed, delaying the green combined status a release cut needs. The gate is now one shell step with no checkout: it carries `build/ci/summary.sh` inline, and the build gates hold that copy to the file.
