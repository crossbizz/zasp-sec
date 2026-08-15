# M1-05 Evidence Model Implementation Plan

**Goal:** Define strict typed evidence references, evidence confidence, and
capability/path state values for later product entities.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Evidence references contain only valid nonzero canonical product IDs.
- Confidence accepts only exact, strong, probable, or unattributed.
- Capability/path state accepts only configured, reachable, observed,
  verified, or blocked.
- Confidence, capability/path state, and finding severity never share a type or
  accepted vocabulary.
- M1-06 remains Pending until M1-05 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-05

- [ ] Add a repository contract binding the source, canonical vocabularies,
  design, plan, completed M1-04, unique active status, arithmetic, and blockers.
- [ ] Capture focused RED at the still-Pending README/tracker state.
- [ ] Move only M1-05 to In progress at `690/1/34/3` overall and M1
  `68/57/1/10/0`; document the evidence boundary.
- [ ] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-05 evidence model`.

### Task 2: Implement evidence values tests-first

- [ ] Add Go tests before production and capture genuine missing-symbol RED.
- [ ] Implement opaque EvidenceRef construction/text round trip and strict
  confidence/capability-path enum parse/text round trips.
- [ ] Cover zero/malformed references, every canonical enum value, aliases,
  case/whitespace/unknown forms, receiver clearing, and severity separation.
- [ ] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add evidence model values`.

### Task 3: Review the evidence boundary

- [ ] Audit typed identity, scope non-authorization, exact vocabularies, zero
  values, receiver behavior, error secrecy, comparability, and misuse paths.
- [ ] Add tests-first fixes for every concrete finding and rerun affected gates.
- [ ] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-05

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-05 to Complete at `690/0/35/3` and M1
  `68/57/0/11/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-05 evidence model`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-06.
