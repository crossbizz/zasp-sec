# M0-21a Security Agent planner boundary proof implementation plan

Date: August 15, 2026

## Goal

Build, review, and run the local fixed-catalog Security Agent planner proof,
then decide R-14 from the combined M0-21/M0-21a evidence.
Every behavior change follows a witnessed tests-only RED.

## Invariants

- The request exposes exactly two typed actions and exact in-scope IDs.
- Untrusted injection text is a bounded data field, never policy or authority.
- The returned plan is structured data and has no execution authority.
- Unknown/new actions, arguments, targets, URLs, shell content, tool calls, and
  schema drift fail closed.
- Only a synthetic numeric-loopback endpoint is allowed; no hosted credential,
  SDK, dotenv, proxy, profile, model setting, arbitrary network, or shell exists.
- Absolute deadlines, fixed output, independent cleanup, and cleanup precedence
  apply on every path.

## Tasks

### Task 1: Record design and start status

- [x] Capture the tests-only repository-contract RED.
- [x] Add this design and executable plan.
- [x] Move only M0-21a from Pending to In progress at `702/1/21/3` overall and
  `27/1/1/21/3` in M0; leave R-14 Not run.

### Task 2: Implement request and catalog boundary

- [x] RED/GREEN exact separated system/goal/untrusted-evidence/catalog/scope
  request with closed schemas and zero ambient/provider authority.
- [x] RED/GREEN hostile object, alias, duplicate, bound, identity, catalog,
  scope, destination, and injection-field handling.

### Task 3: Implement plan validation and lifecycle

- [x] RED/GREEN strict OpenRouter response and exact two-step plan validation.
- [x] RED/GREEN new action/argument, arbitrary URL/shell/tool, out-of-scope ID,
  order/count, model, parser, header, deadline, cleanup, and fixed-output cases.

### Task 4: Expose root commands and evidence

- [x] Add hermetic test/run scripts and README boundary.
- [x] Run exact local proof and record R-14 only from combined M0-21/M0-21a
  retained evidence.

### Task 5: Review, verify, and ship

- [ ] Fix every adversarial review finding tests-first.
- [ ] Run six focused passes, full pinned repository gates, audit, whitespace,
  and redacted secret scans.
- [ ] Transition only M0-21a to Complete and R-14 to PASS after proof/review;
  otherwise Block it with the exact failing dependency.
- [ ] Keep M0-22 Pending through the transition.
- [ ] Commit, push, and watch the exact-SHA Runnable UI gate.
