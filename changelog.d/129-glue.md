### Changed — one process singleton, no transitional helpers

- **`SetSealer` and the process sealer use the same install-once singleton as
  the process allocator** (#129), replacing the sealer's hand-written mutex,
  instance and lazy default. Behaviour is unchanged: `SetSealer` is still
  one-shot, and a lazily built default still counts as installed.
- The transitional helpers `destroyTransient`, `allocSized` and the lowercase
  `wipe` are gone; their call sites use `Destroy`, `NewSized` and `Wipe`
  directly. An allocation now rounds its size to whole pages once, where the
  allocator did it twice. No exported identifier, error or behaviour changes.
