### Changed

- **`make help` states deps-check's 7-day grace** (DS-2913). The `deps-check` help line now says a module behind a latest release under 7 days old is reported, not failed, as `scripts/deps-check.sh` does since #232. Nothing changes for Go callers.
