# Compliance CI batch, ready for scoped review

The five-file change is implemented. Local acceptance passed on macOS against the assembled API and worker, and all owned handles joined. Hosted Ubuntu execution is still unverified. The advisory release gate still blocks publication.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.
Branch: `codex/cached-runtime-ship-20260917`.
HEAD stayed `8733b16f8d939d38a8157dd2519e57fc6f630542`.

## What changed

`scripts/browser-prerequisites.mjs` selects the existing macOS Chrome default, installed Linux Chrome/Chromium on an absolute PATH entry, or explicit `ZASP_COMBINED_E2E_CHROME`. An explicit invalid value fails without fallback. Relative paths, empty values and Unicode control characters fail; the selected target must be an executable regular file. Paths containing spaces or shell punctuation are literal executable names. The existing argument-array launch is unchanged.

The harness now checks Chrome, Go, Docker, OpenSSL, pg_config, the returned PostgreSQL directory and psql, vinext, and the compiled UI before allocating its temporary root, creating a database or compiling Go. pg_config uses a five-second deadline, SIGKILL on timeout, bounded output and argument-array execution. There are no downloads, skips or tool-install fallbacks.

The Ubuntu workflow adds two steps after `npm run verify` and before the unchanged advisory gate. A ten-minute prerequisite step pulls and inspects the exact owned PostgreSQL digest, validates the installed browser with the same selector, records its version, and saves its absolute path. A fifteen-minute acceptance step runs the prerequisite/helper tests and invokes `ZASP_COMBINED_E2E_COMPLIANCE=true node scripts/production-combined-e2e.mjs` through the step environment. It consumes the already-built UI. The combined npm command and separate legacy mode are not invoked by this new step.

Every existing workflow step is unchanged, checked by parsed YAML equality. The PostgreSQL image is still `postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`, verified against the owned helper. No change to release pins or the advisory script.

## Tests, including the failures

Superpowers TDD drove the selector and fail-before-setup behavior. The first focused run failed all 22 tests: the exports did not exist, and the real harness still reached pg_config before rejecting an invalid browser. Those tests then passed. A separate C1-control test failed before changing the validation expression to Unicode Cc; this also removed the initial ESLint no-control-regex error without a suppression.

The first affected group had 145 passes, two failures and two existing opt-in container skips. Both failures were old source-string checks for inline Chrome/pg_config assignments. I removed just those obsolete checks, preserving all other assertions. Their replacement tests execute actual filesystem and command inputs, including the real harness's nonzero early exit. The diagnostic group output is retained.

The corrected group passed: 146 passed, zero failed, two existing opt-in container tests skipped, 148 total. The controller then requested explicit invalid pg_config input coverage while that rerun was in flight. Four characterization cases were added for relative, embedded-control and empty output, plus nonzero pg_config exit. The final focused suite passed all 27 cases. Production code did not change after the grouped rerun.

Final scoped lint passed. YAML parsing and both new shell blocks passed `bash -n`; existing CI commands compare equal to BEFORE. Exact commands, exit statuses and log paths are in `compliance-ci-commands.md`.

## Actual browser, one run

Command exited zero. Local prerequisites were Node v22.23.1, Google Chrome 153.0.8010.48 on darwin, cached Go dependencies, and the existing exact PostgreSQL Docker digest. No image was pulled or built locally. No host PostgreSQL was started.

The run compiled the current migration, API test and worker test executables. Its real SQL registrations and worker interrupt/resume passed; the provider was controlled local SDK transport, not live AWS.

Job: `pid_4d44712e-d23b-4a08-a91f-06415a504000`.
Persisted package SHA256: `88f9d16e20558a0c6bc6616845111778fe910876d72b5c2ab2f1d467247bb551`.
Native JSON was 760 bytes, CSV 568 bytes, readable text 770 bytes. The unchanged browser flow asserted exact persisted member bytes, changed-source/version conflict, worker/API restart durability, grant replay refusal, sibling/foreign denials, authorized positive controls and final session/scope/DOM continuity.

The final screenshot was inspected. It shows the signed-in Staging scope, SOC 2 Security / Policy definitions, version 8 evidence and a visible Create evidence export action. The final bootstrap was 200 with the expected principal and primary scope, controls/export action true, sign-in false, and an empty console-kind list. Old-scope requests during the switch did return 401; the retained continuity trace shows they did not destroy the current session or final mounted view.

The harness printed every cleanup stage and exited zero. Before/after Docker inventories are identical, including all unrelated voxeval containers. No matching API/worker/vinext process remained in the final process-name check. All tool sessions were joined. The owned evidence directory `/tmp/zasp-compliance-browser-p5x89H` was intentionally retained and copied into `compliance-ci-evidence/artifacts/`; it contains controlled fixture bytes and no live credentials.

## Source identity and scope

The captured BEFORE harness blob was `909efa2957edefb3ce917b2bcbfd44ce87c72a13`, matching reviewed Task5 fix1, not HEAD. BEFORE copies were taken before editing each existing file. `compliance-ci-blobs.json` contains Git blob IDs, SHA256 and byte sizes for all five changed files; new files have null BEFORE identities. `compliance-ci-scoped.patch` is an incremental patch against those working copies.

All 18 recorded Task5/fix1 UI/package source identities still match. I reused the reviewed UI/type/lint/build evidence, including 2096 passing UI tests, under the controller's unchanged-source instruction. This batch did not rebuild or edit the UI. A 4513-file source/build identity capture is equal before and after the actual browser run. These snapshots include the current API source used by this browser run; the older browser result is not relabeled as current API evidence.

Self-review confirmed the compliance assertion body, browser launch/flags body, and bounded cleanup body are byte-identical to BEFORE. Only the harness prerequisite/import/temporary-root boundary changed. No product API/UI/SQL behavior, permissions, advisory policy, authoritative ledger, package command, container helper, or legacy assertions were edited. Nothing staged, committed or pushed. No child agent was dispatched.

## Still open

Hosted Linux acceptance has not run here. Linux selection tests and macOS browser acceptance do not close that gap. The workflow is ready to exercise the installed hosted browser, its sandbox and pinned Docker image; a hosted failure must fail the job, not trigger an automatic skip or sandbox weakening.

The independent spec-and-quality review is pending with root. Root owns final publication checks and the authoritative ledger. Full final-assembled UI/type/lint/build gates before publication, fresh approved exact-lock advisory evidence, and live-provider requirements remain separate gates. This change does not promote availability or establish production deployment.

## Retained files

All paths below are relative to `.superpowers/sdd/2026-09-18-compliance-production-plan/`:

- `compliance-ci-report.md` and `compliance-ci-commands.md`.
- The five-file delta is `compliance-ci-scoped.patch`; its identities are in `compliance-ci-blobs.json`.
- BEFORE copies: `compliance-ci-before/`. Full browser-boundary source/build snapshots: `compliance-ci-before-browser-identities.json` and `compliance-ci-after-identities.json`.
- `compliance-ci-capture.mjs` regenerates the identity/scope checks and incremental patch.
- Logs and screenshots live in `compliance-ci-evidence/`, including both failed diagnostics, grouped/focused acceptance, lint, browser output, container inventories, local versions and source checks. `artifacts/` holds the final PNG, continuity trace, exact object envelope, summary and three native downloads.

Review this scoped patch against the batch brief and audit before retaining it for publication.
