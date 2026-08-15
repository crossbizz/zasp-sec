# M1-03 Canonical ID Implementation Plan

**Goal:** Add the first product-owned canonical ID and external-source reference
types without allowing vendor identity to become a product primary key.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- `ProductID` is an opaque `pid_`-prefixed canonical UUIDv4 value.
- External source identity remains a separate opaque type and is never used to
  generate, parse, or populate product identity.
- Validation is bounded, deterministic, dependency-free, and local.
- M1-04 remains Pending until M1-03 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-03

- [x] Add a repository contract binding the source, design, plan, completed
  M1-02, exact ID grammar, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-03 to In progress at `692/1/32/3` overall and M1
  `68/59/1/8/0`; document the identity boundary.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-03 canonical IDs`.

### Task 2: Implement canonical IDs tests-first

- [ ] Add Go tests before production and capture genuine missing-symbol RED.
- [ ] Implement opaque product UUIDv4 IDs, strict text behavior, external IDs,
  and validating external-source references without third-party dependencies.
- [ ] Cover entropy failures, canonical grammar, text round trips, invalid
  references, UUID-shaped vendor IDs, and product/external separation.
- [ ] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add canonical product IDs`.

### Task 3: Review the identity boundary

- [ ] Audit randomness, UUID bits, canonical parsing, zero values, text receiver
  safety, bounds, type separation, API misuse paths, and tests.
- [ ] Add tests-first fixes for every concrete finding and rerun affected gates.
- [ ] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-03

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-03 to Complete at `692/0/33/3` and M1
  `68/59/0/9/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-03 canonical IDs`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-04.
