# M1-20 AI Gateway Contract Implementation Plan

## Goal

Deliver the provider-neutral, scoped `AIGateway` request/result and complete
data-policy metadata contract. Prove that an unapproved purpose and every
incomplete policy state fail before driver I/O. Do not add an OpenRouter
adapter, hosted endpoint, provider credential, or planner/action authority.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- The only approved purpose is `finding_explanation`; purpose expansion
  requires a source change and tests.
- A request carries a complete approved data-policy record and only bounded
  redacted product content.
- No arbitrary map, provider-native request, raw prompt, raw evidence, secret,
  PII, PHI, credential, endpoint, model selector, tool, URL, or action crosses
  the driver boundary.
- Generation is one bounded non-idempotent attempt with no retry, panic
  containment, fixed errors, and exact response identity/schema/policy checks.
- AI output is non-authoritative and cannot affect deterministic policy,
  authorization, action execution, or verification.
- M1-21 remains Pending throughout M1-20. M0-09, M0-18, and M0-19 remain
  Blocked.

## Task 1: Start M1-20 with a repository contract

**Files**

- Add `app/quality/ai-gateway-contract.test.ts`.
- Modify `README.md`, the authoritative tracker, and current aggregate status
  fixtures.
- Add ignored Task 1 report and append-only progress evidence.

- [x] Capture the focused status-contract RED before status edits.

  Bind the exact source task, PRD privacy/data-policy rules, design, and this
  plan. Require exactly one M1-20 In progress row; require M1-19 Complete and
  M1-21 absent; require unchanged blockers and exact aggregate arithmetic.

  RED was 1 pass/1 intended fail at the stale README/tracker state; the
  source, PRD, design, and plan boundary passed before status edits.

- [x] Move only M1-20 to In progress and obtain focused/full GREEN.

  Expected counts are `675/1/49/3` overall and `68/42/1/25/0` for M1.

  GREEN is 2/2 focused, 5/5 with the predecessor contract, and 53 quality
  files/239 tests. M1-19 remains Complete, M1-21 remains Pending, and blockers
  are unchanged.

- [x] Commit the exact Task 1 status/contract package.

  Commit message: `docs: start M1-20 AI gateway contract`.

## Task 2: Implement the contract tests-first

**Files**

- Add `services/platform/aigateway/aigateway_test.go` first.
- Add `services/platform/aigateway/aigateway.go` only after compiler RED.
- Update this plan and ignored Task 2 evidence.

- [x] Capture a genuine compiler RED on the absent public API.

  The test must name the wished-for gateway, request/result, purpose,
  data-policy, driver, constructor, and fixed error symbols before production
  or dependency edits.

  After correcting a tests-only module-import typo, the compiler RED failed
  only on the absent request/result, driver, gateway, purpose, policy, config,
  constructor, and fixed-error symbols. No production file existed.

- [x] Implement minimal GREEN for the exact happy contract.

  Copy one valid scoped request to one typed driver call and validate one exact
  structured result.

  The focused package passes with one exact typed request and exact version-1
  result through the fake driver.

- [x] Expand RED/GREEN adversarial coverage.

  Cover unapproved/zero/forged/mismatched purposes; every missing, false,
  unknown, or mismatched policy field; malformed scope/subject/summary/result;
  schema and identity drift; nil receiver/context/driver; timeout,
  cancellation, panic, extra calls, and concurrency.

  Coverage includes six unapproved-purpose cases, every policy safety field,
  malformed request/result/configuration states, one-attempt timeout/error/
  panic containment, typed-nil drivers, and 32 concurrent calls.

- [x] Run six race passes, repetitions, full platform gates, and coverage.

  Require `go test -race -count=1 ./aigateway` six times, a 100-repetition
  focused run, full platform race, tidy-diff, module verification, vet, and
  100% production statement coverage.

  All six race passes, 100 focused repetitions, full platform race,
  tidy-diff/module verification/vet, and 100% production statement coverage
  pass.

- [x] Commit the exact Task 2 implementation package.

  Commit message: `feat: add scoped AI gateway contract`.

## Task 3: Expose the hermetic root contract

**Files**

- Modify `package.json`, `README.md`, and the M1-20 repository contract.
- Update this plan and ignored Task 3 evidence.

- [x] Capture a focused repository-contract RED for the absent root command
  and documentation boundary.

  RED was 2 pass/1 intended fail at the absent `aigateway:test` script before
  package or README edits.

- [x] Add `aigateway:test` and document its exact hermetic scope.

  The command runs only the Go race suite. Documentation must state that there
  is no OpenRouter/provider/network/Docker/credential I/O and that M1-21 stays
  Pending.

  GREEN is 3/3 and the root race command passes.

- [x] Run focused contract, root gateway, full pinned repository, build, audit,
  formatting, and secret gates.

  Pinned verification passes 57 files/260 tests, typecheck, lint, production
  build, all 8 repository build targets, and zero production vulnerabilities.

- [x] Commit the exact Task 3 wiring package.

  Commit message: `docs: expose AI gateway contract`.

## Task 4: Review the whole M1-20 range

**Files**

- Review the exact design-base to implementation-head range.
- Add tests-first fix commits only for evidenced findings.
- Update this plan and ignored Task 4 evidence.

- [x] Review the exact range against the source task, PRD, design, plan,
  implementation, tests, root command, README, tracker, and evidence.

  Exact range `cc1c995..f8f87b6` was reviewed end to end. Critical 0,
  Important 0, Minor 0.

- [x] Reproduce every finding with tests-only RED before production edits.

  No finding survived source, behavior, or gate verification, so no production
  review fix was warranted.

- [x] Repeat all affected and full gates after each separate fix commit.

  There was no fix commit. Fresh package/full platform race and vet, root
  command, focused repository contract, and range diff checks pass.

- [x] Record a zero-finding final re-review before completion.

  Commit only plan evidence in `docs: record M1-20 review` when no tracked fix
  is required in the final review round.

## Task 5: Complete, push, and close M1-20

**Files**

- Modify the M1-20 contract, `README.md`, tracker, current aggregate status
  fixtures, and this plan's checkboxes.
- Update ignored Task 5 and authoritative M1-20 reports/ledgers.

- [x] Capture the completion transition RED.

  Require exactly one M1-20 Complete row, M1-19 Complete, M1-21 absent,
  unchanged blockers, overall `675/0/50/3`, and M1 `68/42/0/26/0` before
  changing status sources.

  RED was 2 pass/1 intended fail at the stale In-progress README/tracker state.

- [x] Move only M1-20 to Complete and repeat all final local gates.

  GREEN is 3/3 focused and 53 quality files/240 tests. Six root race cycles,
  full platform race/tidy-diff/module verification/vet, 100% production
  statement coverage, pinned repository 57 files/260 tests plus typecheck/lint/
  build, all 8 build targets, and zero production vulnerabilities pass.

  Commit message: `docs: complete M1-20 AI gateway contract`.

- [ ] Push and watch the exact completion SHA to Runnable UI success.

  Require local/upstream/remote/run/job SHA identity and terminal success.

- [ ] Record plan-only closure without advancing M1-21.

  Commit message: `docs: close M1-20 AI gateway contract`. Push and watch that
  exact closure SHA to terminal success, then prove synchronized clean state.
