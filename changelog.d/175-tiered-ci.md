### Changed

- **CI runs in two tiers and cancels superseded runs** (#175). Every pull request runs the PR tier (lint, build, test, security and CI Gate). The full tier (FIPS and integration) runs on push to `main`, on `workflow_dispatch` and on a PR labelled `ci:full`. CI Gate passes a full-tier job's skip only in a run that did not select the full tier. `ci.yml` cancels a ref's run in progress when the ref gets a new push. `nightly.yml` has no schedule and runs on dispatch. A build gate (`TestCIGateTiersMatchTheJobs`) holds the jobs, their conditions and the gate's tier tags to one another.
