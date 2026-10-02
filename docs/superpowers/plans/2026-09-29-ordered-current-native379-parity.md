# Ordered-Current 379-Rule Native Parity Plan

> **For agentic workers:** use `superpowers:subagent-driven-development` task by
> task, grouped TDD, and independent review after every task. Root owns the sole
> native PostgreSQL slot.

**Goal:** Build, execute, and retain one source-pinned PostgreSQL 18.3 packet
that proves the complete dormant ordered-current evaluator against all 379
rules and 10,231 facts, including truth, drift, NULL/error/lazy-demand,
forged-entry, source-frame, and restoration behavior. This closes local native
parity only; portability, installed-worker, capacity, deployment, and provider
gates remain.

**Starting point:** The independently approved dormant manifest contains 379
unique rules, 10,231 facts, 565 declared role-sites, zero unclassified sites,
and fixed Task 1–4 contract hashes. It remains `installable:false`,
`nativeVerified:false`, and runtime-refused. Existing direct, missing-reference,
and private-successor captures are accepted local component evidence but do not
constitute a full evaluator run.

## Global constraints

- Preserve every original requirement, all 728 mappings, and the approved
  Temporal/OpenFGA/Stytch architecture.
- Use PostgreSQL 18.3 and pgcrypto 1.4 in a fresh owned disposable cluster.
- Expected truth comes only from the tracked dormant manifest and fixed source
  contracts. Never derive expected facts, caps, or mutations from target output.
- Preserve explicit NULL versus absent, duplicates/multiplicity, scalar
  zero-row and multi-row errors, lazy branch/helper demand, source frames, and
  first-error ordering.
- Do not reuse failed/stale complete-capture artifacts or ephemeral
  `/private/tmp` manifests as authority.
- Keep `installable:false`, production routing disabled, and Go runtime refusal
  throughout this plan. Set `nativeVerified:true` only after a retained,
  independently reviewed full run is bound to exact packet/log/result hashes.
- Use deterministic local tests and the cheapest available model for review.
  Do not use `.env`, network services, paid APIs, live providers, commits, or
  pushes in this plan.
- Do not start the long native run while unrelated host load makes the bounded
  result unreliable. Root owns the run decision and cleanup verification.

## Task 1: Fixed native-parity packet and validator

**Files:**

- Create `services/platform/migrations/tools/ordered-current-native379-packet-v1.mjs`
- Create `services/platform/migrations/tools/ordered-current-native379-packet-v1.test.mjs`
- Add a narrow tracked artifact directory only if immutable packet inputs are
  not already present under the Task 2 authority bundle
- Do not modify generated evaluator behavior

**Acceptance:**

- Admit the current dormant evaluator, Task 1–4 hashes, exact PostgreSQL/pgcrypto
  identity, 379 unique rule descriptors, 10,231 facts, and 565 role-sites with
  zero unclassified.
- Emit exact ordered phases: preflight, pristine truth, drift, forged entry,
  NULL/error/lazy demand, frame/restoration, and cleanup/result.
- Define a representative mutation matrix covering every rule family and every
  structural category without target-derived expected values. Bind exact rule,
  fact, source-site, mutation, expected verdict/SQLSTATE, restoration, and
  first-error identities.
- Define positive finite per-phase and total row/byte/time caps. Overflow,
  truncation, missing/extra/duplicate rules or controls, caller-selected paths
  or hashes, unknown mutations, stale Task 1–4 pins, and mutable generated-file
  authority fail closed.
- Packet status remains `NATIVE-PARITY-PENDING`, `installable:false`, and is not
  capture authority.

Grouped RED must precede implementation and cover every refusal family.

## Task 2: Owned PostgreSQL 18.3 native fixture

**Files:**

- Create
  `services/platform/apiserver/authorization_worker_ordered_current_integrity_postgres_test.go`
- Reuse existing owned PostgreSQL helpers and exact source installers; make only
  narrow shared-helper changes if independently justified
- Add Go packet/result types beside the test only if no production consumer is
  required

**Acceptance:**

- An explicit opt-in `TestP7OrderedCurrentIntegrityNative` provisions a fresh
  owned PostgreSQL 18.3 cluster, installs the exact pinned source candidate and
  dormant module, verifies server/pgcrypto identity, and performs bounded
  cleanup with normal join on success and failure.
- Test refuses absent/wrong packet pins, wrong server/version/extension,
  pre-existing output, partial install, unexpected grants, or a nonempty target
  outside its owned fixture.
- Pristine evaluation proves complete key-set and value equality for all 379
  rules/10,231 facts, registration, manifest, evaluator/entry admission, and
  complete result cardinality. It must not use target observations to construct
  expected truth.
- Result format is deterministic, owner-only, mode 0600, bounded, and records
  exact stage durations, hashes, row counts, SQLSTATEs, restoration, and cleanup.

Task 2 ends with component tests and fixture compilation; no long native run
until independent review approves the packet and fixture.

## Task 3: Drift, forged-entry, NULL/error, and frame probes

**Files:**

- Extend the Task 1 packet/tests and Task 2 native fixture
- Add focused SQL helpers only inside the owned test fixture; do not weaken the
  production evaluator or add runtime bypasses

**Acceptance:**

- Execute packet-declared mutations across body, owner, ACL/default ACL, config,
  RLS, constraint/index, trigger, saved definitions, registration, additions,
  missing dependencies, and all rule families. Every mutation must refuse and
  restore before the next probe.
- Prove forged evaluator/entry, wrong manifest, extra/missing expected rows,
  wrong caller/frame, and post-admission drift refuse before protected selector
  trust or mutation.
- Prove explicit NULL/empty, duplicate bag, scalar zero-row NULL,
  multi-row `21000`, invalid cast/reg-object, unselected-helper no-demand,
  selected-helper error, aggregate ordering, and first-error behavior for the
  approved temporal77/mixed/wrapper/retired63/64 boundaries.
- Prove role, search path, timezone, read-only, transaction, advisory/schema
  lock, and modified catalog state are restored. No timeout counts as denial.
- Node/Go component tests validate result admission and reject truncated,
  partial, reordered, duplicate, forged, or over-cap results.

## Task 4: Execute, review, and bind local native evidence

**Execution:**

- First run short offline Node/Go packet, generator, refusal, and fixture compile
  checks with exact toolchains.
- When host load is suitable, run only
  `TestP7OrderedCurrentIntegrityNative` serially with `-p=1`, `-count=1`, `-v`,
  and a 15-minute outer timeout in one fresh fixture.
- Retain the immutable packet, result, and full log; verify hashes, permissions,
  all phases, cleanup, and absence of surviving owned processes/resources.

**Acceptance:**

- One complete run passes every declared phase without skip, timeout-as-denial,
  truncation, cap relaxation, or manual result editing.
- Independent review reproduces packet/result/log identities and validates the
  assertions and cleanup.
- Only then bind the accepted native evidence into the dormant manifest and
  authoritative ledger, set local `nativeVerified:true`, keep
  `installable:false`, `executableReplacementVerified:false`, component-only
  status, runtime refusal, and production routing unchanged.
- Regenerate deterministically, run affected Node suites, focused Go refusal
  tests, and the 728-row ledger validator.
- Record the remaining gates exactly: varied-login/OID and exact production
  PostgreSQL; connected installed-worker acceptance; full100 capacity under
  unchanged limits; deployment/provider acceptance.

## After this plan

Proceed in order to varied-login/OID portability, then a connected
installed-current fixture beside `TestP7OrderedConnectedCatalogInstall`, then
measured full100 under unchanged limits. Production routing is last.
