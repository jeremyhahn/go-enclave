### Fixed

- A push to main no longer cancels the CI run of the previous main commit, so every merge keeps a completed run; the FIPS integration job runs on the same runner class as the other integration jobs. Nothing changes for Go callers.
- The devcontainer and integration images build from the current `golang:1.27.3-alpine3.24` base, which takes the Alpine brotli fix (CVE-2026-111497). Nothing changes for Go callers.
