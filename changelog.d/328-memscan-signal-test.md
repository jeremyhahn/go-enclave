### Fixed

- The memscan test that sweeps for the needle while signals land on the sweeping thread is bounded under the race detector: each round signals the sweeping thread through compare passes of at least 200 ms over 64 KiB of dense memory, counts a signal only when the thread was inside one comparison from before it was sent until after and /proc showed it running, with more time on the CPU, around the signal, needs 50 of them, sweeps from the same thread, and fails after 30 s instead of hanging (#328). Nothing changes for Go callers.
