### Fixed

- The memscan test that sweeps for the needle while signals land on the sweeping thread is bounded under the race detector: each round signals every 200 µs for 50 ms over a 1 MiB dense fill, sweeps from the same thread, and fails after 30 s instead of hanging (#328). Nothing changes for Go callers.
