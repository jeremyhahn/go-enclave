### Fixed

- **`BudgetError.InUse` can no longer be negative** (#83). A refusal reads
  the headroom counter and then the budget without a lock, and the guard
  against an impossible pair caught only one of the two skews: a raise
  racing an over-subscribed allocator, which wraps. A lowering between the
  two reads (an idle allocator refusing a three-page request at two pages
  free, quiesced by `SetLimit(0)` in that window) paired a budget of 0 with
  two pages of headroom and reported `InUse` as -8192 on a 4 KiB-page host.
  Any negative result now takes the read-locked fallback, as a wrap already
  did. Admission is unchanged and still lock-free.
