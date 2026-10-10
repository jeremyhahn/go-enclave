### Fixed

- **`backendtest` certified a `Destroy` that returned while a racing `WithBytes` borrow was still open** (#152), so a backend that wiped after returning passed. A `Destroy` that returns before the held borrow exits is now a concurrent-use failure.
- **`backendtest` accepted live results after a racing `Destroy` returned nil** (#152). Each goroutine's last pass now requires the destroyed state: `IsAlive` false, `Size` 0, `Backend` unchanged, and `ErrEnclaveDestroyed` from every error-returning capability, reported apart.
- **`backendtest` ignored the handle a refused `Import` returned** (#152), so an importer that refused with `ErrInvalidImport` but kept a live handle passed. A live handle returned with a refusal is now an `Importer` failure, and any returned handle is destroyed.
- **`backendtest` checked a swept handle only by `IsAlive`** (#152), so a `Sweep` that cleared the flag but kept the material passed. A swept handle must now be destroyed in every way a destroyed handle is, and for a `Sweeper` the residue sweep also runs after `Sweep`.
