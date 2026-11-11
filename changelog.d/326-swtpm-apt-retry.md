### Fixed

- CI's swtpm conformance job now retries its apt install: apt retries each download, and the update and install run up to three times, so one transient package mirror or DNS error no longer fails the job (#326). Nothing changes for Go callers.
