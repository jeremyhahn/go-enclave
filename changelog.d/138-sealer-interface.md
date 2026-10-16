### Changed — BREAKING:

- **`Sealer` is an interface; its implementation is internal** (#138). `*enclave.Sealer` becomes `enclave.Sealer`; callers drop the `*`. See [Upgrading](docs/README.md#constructors-return-interfaces).
  - `NewSealer` returns the `Sealer` interface (`Seal`, `SealFrom`, `Mode` and `Destroy`), was `*Sealer`, and a nil interface on every refusal.
  - `SetSealer` takes a `Sealer`, was `*Sealer`. It refuses a nil or typed-nil one with `ErrNilSealer`, one `NewSealer` did not build (another implementation included) with `ErrSealerNotConstructed`, and a destroyed one with `ErrSealerDestroyed`, installing nothing.
  - A caller can no longer declare a zero `Sealer` or call through a nil pointer, so `Seal` and `SealFrom` no longer return `ErrSealerNotConstructed` or `ErrNilSealer` to callers.
