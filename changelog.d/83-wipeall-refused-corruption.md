### Fixed

- **`WipeAll` reports canary corruption even when the corrupt enclave's pages
  could not be released** (#83). The sweep tallied corruption only on the
  attempt that reclaimed the pages, so a corrupt enclave whose munlock or
  munmap was refused for the whole sweep was reported as still held and the
  error came back nil. Corruption is now recorded per enclave on any attempt
  that detects it, counted once however many passes retry it; such an enclave
  appears in both the count and the error.
