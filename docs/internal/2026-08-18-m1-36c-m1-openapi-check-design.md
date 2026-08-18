# M1-36c M1 OpenAPI Check Design

Date: August 18, 2026

## Goal

Run the repository's reviewed OpenAPI generator and prove that its exact output
is already committed. M1-36c records drift evidence only; it does not change the
product OpenAPI, generated client surface, operation inventory, or UI/API map.

## Selected boundary

M1-23 and M1-24 already own the required implementation:

- `openapi/openapi.yaml` is the self-contained OpenAPI 3.1 product root;
- `apps/web/api/generated.ts` is its committed generated TypeScript surface;
- exact-pinned `openapi-typescript` 7.13.0 is the only supported generator;
- `npm run openapi:generate` is the only supported writer; and
- `npm run openapi:check` runs the same input, output, and flags with the
  generator's official non-writing `--check` mode.

M1-36c therefore adds no wrapper, second manifest, checksum file, generated
copy, or dependency. The execution sequence is:

```bash
npm run openapi:test
npm run openapi:lint
npm run openapi:generate
git diff --exit-code -- apps/web/api/generated.ts
npm run openapi:check
```

The writer run directly satisfies the source deliverable. The path-scoped Git
comparison proves it produced no uncommitted client drift. The official check
mode independently re-proves the same byte comparison without rewriting the
working tree. Strict tests and lint validate the local source and both committed
OpenAPI documents before completion.

## Reproducibility and safety

Execution uses repository-pinned Node.js 22.23.1, npm 10.9.8,
`openapi-typescript` 7.13.0, and Redocly CLI 2.43.1 from the locked local
installation. The generator has one local input and one tracked output with an
exact fixed flag set. The OpenAPI root contains no remote references. Redocly
telemetry and update checks are disabled by the existing lint command.

The task starts from a clean tracked tree and records the generated file's bytes
before execution. Success requires the same bytes afterward, no path-scoped Git
diff, the non-writing drift gate to pass, and the tracked tree to remain clean.
If the writer exposes genuine drift, the task stops before status completion and
reviews that generated change in scope; it does not discard or conceal it.

No command contacts a provider, database, container runtime, Kubernetes,
LocalStack, customer environment, or customer state. No dependency installation
or network fetch is permitted. `openapi/internal-health.yaml` remains a separate
strictly linted internal contract and does not feed the public generated client.

## Scope and successor boundary

M1-36c proves only generation and committed-client drift. M1-36d remains
Pending and separately owns the UI/API traceability validator. This task does
not add an OpenAPI operation, mark a UI action available, run local
infrastructure, or pre-claim M1-36d or M1-36e.

A repository quality contract binds the exact source row, M1-36b dependency,
existing command and pin set, generated path, no-drift evidence, successor
boundary, status arithmetic, and exact blockers. README documents the bounded
gate and commands.

M1-36c starts at 649 Pending / 1 In progress / 75 Complete / 3 Blocked overall
and M1 68 total / 16 Pending / 1 In progress / 51 Complete / 0 Blocked. It may
move to Complete only after genuine status RED/GREEN, six consecutive drift
checks, an exact writer/no-diff run, strict tests and lint, full pinned repository
verification, production dependency audit, pinned secret scans, zero-finding
whole-range review, push, and exact-SHA Runnable UI success. Completion is 649
Pending / 0 In progress / 76 Complete / 3 Blocked overall and M1
16 / 0 / 52 / 0. M1-36d remains Pending throughout.

## Alternatives rejected

- A new orchestrator would duplicate the reviewed generator and drift command.
- Generating into a second committed location would create another authority
  that could drift independently.
- Using only `git diff` without running the generator would not satisfy the
  source deliverable.
- Using only the writing command without `--check` would weaken repeatable CI
  verification and could leave drift as an unexplained worktree mutation.
- Folding UI/API coverage or local infrastructure into this task would
  pre-claim M1-36d or M1-36e.
