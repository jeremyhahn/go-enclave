### Fixed

- **KEK rotation no longer re-keys a sealer after an overlapping `WipeAll`**
  (#102). Rotation mints the next generation while borrowing the root and the
  new KEK, and a sweep skips borrowed enclaves, so a `WipeAll` in that window
  destroyed the old current KEK, left the root standing, and rotation then
  published the new generation: the sealer kept working after a sweep — the
  silent re-keying `ErrSealerWiped` exists to prevent. Rotation now records
  the sweep sequence before it inspects anything and, on any overlap,
  destroys the new KEK, the old KEK and the root and returns `ErrSealerWiped`,
  as initialization already did.
- **A release refused while discarding a key is reported, never suppressed**
  (#102) — in the rotation cleanup above, and when a KEK whose mint failed is
  discarded in rotation or initialization. The sealer retries its published
  root and KEK on every seal or open that finds the hierarchy dead; an
  unpublished generation is owned by the `WipeAll` ledger, which retries every
  refused release. Key bytes are wiped before any unmap is attempted, so a
  refusal leaves locked pages, never key material.
