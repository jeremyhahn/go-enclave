### Fixed

- The memscan test that sweeps for the needle while signals land on the sweeping thread is bounded under the race detector: each round signals every 200 µs over 64 KiB dense compare passes, counts a signal only when the thread was inside one comparison from before it was sent until after, needs 50 of them, sweeps from the same thread, and fails after 30 s instead of hanging (#328). Nothing changes for Go callers.
