### Fixed

- **A `ModeRootKey` sealer no longer calls `UnsealRoot` again after it
  succeeded** (#83). If minting the first KEK failed after a successful
  unseal (locked memory exhausted, for example), the root was destroyed and
  the next seal unsealed it again. That breaks the `RootUnsealer` contract
  ("at most once, retrying only if that call failed") and any one-shot root
  provider. The unsealed root is now kept and the retry re-attempts only the
  KEK mint. The kept root is an ordinary registered enclave, so `WipeAll`
  still destroys it. If a sweep does, the sealer reports `ErrSealerWiped`
  instead of unsealing a replacement.
