### Fixed

- The memscan signal test counts a signal only when it lands inside a needle comparison, never in the buffer clear the search runs before it returns: a compare window now ends when the search reads its next buffer, and the read after which the search returns opens none. A new negative control, whose searches skip the compare and only clear their buffer, must count no signal (#331). Nothing changes for Go callers.
