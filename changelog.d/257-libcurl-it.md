### Fixed

- The integration image applies Alpine's security updates at build time, as the base stage does, and so takes libcurl 8.23.0-r0 (CVE-2026-92392). Nothing changes for Go callers.
