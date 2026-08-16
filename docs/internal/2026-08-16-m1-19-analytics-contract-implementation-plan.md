# M1-19 Analytics Contract Implementation Plan

## Goal

Implement, review, complete, and ship the dependency-free product analytics
contract in `docs/internal/2026-08-16-m1-19-analytics-contract-design.md`.
Every behavior and status change requires a witnessed tests-only RED before
production or status edits. M1-20 remains Pending throughout M1-19.

## Invariants

- Preserve exact Organization, Workspace, and Environment scope.
- Construct a typed driver record from a closed catalog; never forward caller
  fields or an arbitrary property collection.
- Reject every missing, duplicate, unknown, wrong-kind, malformed, or surplus
  field before driver I/O.
- Allow only the exact `proof_completed` catalog event with `source` text and
  `success` boolean fields.
- Make one bounded non-idempotent capture attempt with no retry.
- Emit only fixed product errors; contain driver panics and reject malformed
  acknowledgements.
- Keep analytics optional and non-authoritative; add no PostHog adapter,
  endpoint, credential, network, Docker, database, cache, or shared-resource
  behavior.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Keep tracked changes atomic and secret-scan every scoped commit and final
  history.

## Task 1: Start M1-19 with a repository contract

**Files**

- Add `app/quality/product-telemetry-contract.test.ts`.
- Modify `README.md`, `docs/internal/implementation_status_v1.5.md`, and every
  current aggregate status fixture changed by the arithmetic transition.
- Create ignored Task 1 report and append-only progress ledger.

- [x] Capture the focused Pending-state RED.

  The new contract must bind the authoritative source, PRD, design, and this
  plan; require exactly one M1-19 In progress row; require M1-18 Complete and
  M1-20 absent; preserve the three blockers; and require overall
  `676/1/48/3` plus M1 `68/43/1/24/0`.

- [x] Move only M1-19 to In progress and obtain focused/full GREEN.

  Pinned Node produced one intended stale-status failure and one source/design
  pass before status edits. GREEN is 52 quality files and 236 tests with only
  M1-19 active at `676/1/48/3` overall and `68/43/1/24/0` for M1.

  Commit message: `docs: start M1-19 analytics contract`.

## Task 2: Implement the serializer and telemetry boundary tests-first

**Files**

- Add `services/platform/producttelemetry/producttelemetry_test.go` first.
- Add `services/platform/producttelemetry/producttelemetry.go` only after the
  compiler RED.
- Create ignored Task 2 report and append the progress ledger.

- [x] Capture a genuine compiler RED on the complete wished-for public API.

- [x] Implement the minimum allowlist serializer and one-attempt tracker.

  Cover exact canonical records, field-order independence, every invalid and
  prohibited field form, invalid direct state, scope and token grammar,
  typed-nil driver, timeout/cancellation, panic, malformed acknowledgement,
  receiver misuse, and concurrency.

- [x] Run six consecutive focused race passes, 100 focused repetitions,
  coverage, full platform race/tidy-diff/module verification/vet, diff checks,
  and pinned secret scans.

  The compiler RED named only the absent M1-19 API. GREEN covers the exact
  catalog, prohibited and unknown fields, malformed opaque field state, scope,
  source grammar, configuration, cancellation, panic, acknowledgement drift,
  receiver misuse, and 64-way concurrency. Six race passes, 100 repetitions,
  the full platform race suite, module gates, vet, and 100% production
  statement coverage pass.

  Commit message: `feat: add scoped product telemetry contract`.

## Task 3: Expose the hermetic root contract

**Files**

- Modify `package.json`, `README.md`, and the M1-19 repository contract.
- Create ignored Task 3 report and append the progress ledger.

- [x] Capture a focused RED for the absent root command and documentation.

- [x] Add `producttelemetry:test` and document exact privacy, optionality,
  non-authority, deferred-adapter, and zero-I/O boundaries.

- [x] Run the root race command, full platform gates, pinned repository
  verification, all repository build targets, production dependency audit,
  diff checks, and secret scans.

  Focused RED was 2 pass/1 fail at the missing script. GREEN is 3/3 plus the
  root race command. Full pinned verification passes 56 files/257 tests,
  typecheck, lint, build, all 8 repository build targets, and zero production
  vulnerabilities.

  Commit message: `docs: expose product telemetry contract`.

## Task 4: Review the whole M1-19 range

**Files**

- Modify only files required by tests-first review fixes.
- Add a tracked review record to this plan after zero findings.
- Create ignored Task 4 report and append the progress ledger.

- [ ] Review the exact M1-19 range against the source task, PRD, design, plan,
  privacy proof, implementation, tests, docs, status, dependency, and secret
  boundaries.

- [ ] Reproduce every finding with focused RED evidence and fix it one item at
  a time.

- [ ] Require Critical 0, Important 0, Minor 0, six final race passes, 100%
  production statement coverage, full platform/repository/build/audit gates,
  exact-range/full-history secret scans, and clean tracked state.

  Review-fix commits must be separate and narrowly scoped. Record the final
  zero-finding review in `docs: record M1-19 review`.

## Task 5: Complete, push, and close M1-19

**Files**

- Modify the M1-19 contract, `README.md`, tracker, current aggregate status
  fixtures, and this plan's checkboxes.
- Update ignored Task 5 and authoritative M1-19 reports/ledgers.

- [ ] Capture the completion transition RED.

  Require exactly one M1-19 Complete row, M1-18 Complete, M1-20 absent,
  unchanged blockers, overall `676/0/49/3`, and M1 `68/43/0/25/0` before
  changing status sources.

- [ ] Move only M1-19 to Complete and repeat all final local gates.

  Commit message: `docs: complete M1-19 analytics contract`.

- [ ] Push and watch the exact completion SHA to Runnable UI success.

  Require local/upstream/remote/run/job SHA identity and terminal success.

- [ ] Record plan-only closure without advancing M1-20.

  Commit message: `docs: close M1-19 analytics contract`. Push and watch that
  exact closure SHA to terminal success, then prove synchronized clean state.
