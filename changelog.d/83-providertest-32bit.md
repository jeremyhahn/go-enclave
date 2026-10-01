### Fixed

- **`providertest` builds on 32-bit Linux again** (#83). The residue sweep's
  signed-offset guard compared a `uintptr` against `math.MaxInt64`, which does
  not compile where `uintptr` is 32 bits, so `GOARCH=386` and `GOARCH=arm`
  could not build the package at all. The guard now widens to `uint64` first.
  `/proc/self/maps` bounds are also parsed at the width of a `uintptr` rather
  than a fixed 64 bits, so a bound that does not fit the platform is rejected
  as unparsable instead of being narrowed into a different range, and the
  header parser's table test now compiles and runs on 32-bit targets.
