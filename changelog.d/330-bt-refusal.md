### Added

- `backendtest.CheckRefusal`, a check hardware backend modules share: on a host without their hardware, the constructor and probe must refuse with the module's typed unavailable error naming the failing step, register no backend and leave the locked-memory budget unchanged; each broken property is a `*PropertyError` (#330).
