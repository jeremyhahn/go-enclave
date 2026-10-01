### Fixed

- **A failed `Allocator.New` or `Allocator.NewSized` no longer refunds
  budget for pages it could not release** (#83). When construction failed
  after the pages were mapped and locked, and the rollback was refused too,
  the allocator still refunded the full charge. The budget then offered
  locked memory the process still held. The charge is now kept only while
  the pages are still mlock'd, and is returned once `WipeAll` reclaims them
  (see the failed-construction entry). A cleanup that unlocked the pages
  and was then refused the `munmap` costs address space, not locked memory,
  and is refunded at once. That is a different policy from `DestroyErr`,
  which keeps an enclave's reservation until its pages are unmapped,
  because there the enclave is the handle a retry goes through.
  The rollback of a partly built mapping also falls back to a bare `munmap`
  when `memcall.Free` is refused, as release already did, and now reports
  pages left mapped but unlocked as held. It previously reported them as
  released when both unmaps were refused after a successful `munlock`.
