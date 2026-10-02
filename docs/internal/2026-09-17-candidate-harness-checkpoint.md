# Candidate harness batch checkpoint

The preceding goal turn made progress: reviewed test/docs transfer, full UI2001
and lint verification, and an authoritative ledger update. This continuation
starts the remaining source-harness/staging correction under the same Task3
shipping requirement. It does not reopen completed SQL/operator implementation.

## Controller evidence

Candidate HEAD and freshly queried remote main both remain
8733b16f8d939d38a8157dd2519e57fc6f630542 (remote query60395, exit0).
Candidate index is empty. git diff --check passed.

Source-only Node batch14ef64 exited0:44 passed,0 failed,0 skipped. Command:

    node --test --test-reporter=spec scripts/check-production-imports.test.mjs scripts/existing-test-mounted-browser.test.mjs scripts/runtime-pipeline-dependencies.test.mjs scripts/red-team-runtime-proof.test.mjs scripts/owned-browser-postgres.test.mjs

Pinned Node22.23.1 and offline npm were used. These are import/compiled-closure
guards, mounted-evidence contract checks and injected command-boundary lifecycle
tests. No containers, database servers or live providers were started by this run.

Before repair dispatch, a byte comparison of every recovery git-status file
against the candidate found only the missing runtime evidence document. That
document was then copied after adding a superseding UI-result paragraph. This
comparison is an assembly check, not independent acceptance of all inherited code.

Before this checkpoint file was added, sorted repository path/content SHA256
inventory (git ls-files --cached --others --exclude-standard; deduplicated paths;
JSON pairs of path and SHA256 of bytes, or deleted sentinel) returned:
- all2809 files: fb0bd3b9c0afeb5f208589b65e40f9f236a0b811aeb1bec5276b2bbfd963b85f
- nonDocs2405 files, excluding docs/ and README.md:
  5aaed71aaf4d11926e0d24babf46b1cb4c394b0fcf60ca512907c5bd34b3d756

## Active correction and limits

/root/candidate_harness_batch owns only the two source-harness/staging test files
and the stale README hidden-surfaces paragraph in recovery. Its explicit brief
requires RED/GREEN, nonempty mounted-proof cleanup/failure retention, exact55
positive/negative rollout coverage, preserved owned-resource/download guards,
source-only grouped verification and a frozen incremental patch for independent
review. It cannot change product behavior, stage, commit or push.

README source inspection also confirmed mounted Attack Lab, capability-gated
audit export props and persisted approval rationale. Correcting the old blanket
hidden claim must retain the distinction between source surfaces and deployment.

No original task classification changed. Publication, full candidate review,
approved fresh advisory evidence and real deployment/provider/load gates remain
open. No local fixture or source test is recorded as live production proof.

## Repair report and independent acceptance

Implementer reported the frozen three-file repair ready. Root read the complete
report, verified patch SHA256 and reverse applicability without modifying files:
0085faa68ae86110d8572f636f565864cb3bdfdf34658d8def5aa3701929effe.
Assigned RED reproduced12 failures. Focused GREEN passed14. Final grouped
source-only Node run passed101 tests; focused README contracts passed12; scoped
ESLint exited0. Mutation checks detected removed mounted cleanup, removed error
retention and removed pull/build refusal, then were restored before final GREEN.
These are implementer results awaiting independent source review, not new root
reruns or whole-candidate acceptance.

Three SIGTERM tests were explicitly excluded with --test-skip-pattern=SIGTERM;
Node22 omitted them from its test/skip totals. Two also require explicit runtime
opt-in. No unfiltered101-test/live-signal claim is made.

Reviewer /root/candidate_harness_review now owns read-only spec and quality review
of this exact frozen patch. Nothing from this repair has been transferred into
the shipping candidate yet. Report and incremental patch are in the plan's SDD
workspace as candidate-harness-batch-report.md and candidate-harness-batch.patch.

Superseding result: reviewer returned spec APPROVED and quality APPROVED, no
actionable findings, after checking actual branch boundaries, Docker ownership,
cleanup failure retention,55 rollout and README source claims. The three-file
patch was then transferred into the candidate with exact git blob verification:
- README.md: e34a51f37daece300c20936fd36783e07e66e216
- scripts/production-combined-e2e.test.mjs:54ccee51899742d4eccd2d2d0a42099b0d586fc4
- deploy/staging/gate.test.mjs:1ddd986194159d863bc7a2579cfc73ec2d5c4380

Root candidate rerun72458 exited0:101 passed,0 failed. It used the same explicit
SIGTERM exclusion described above. Root README/source-map rerun78050 exited0:
12 passed,0 failed,0 pending, with JSON at
/private/tmp/zasp-schema55-candidate-tests.47H9Oq/harness-readme-contracts.json.
Scoped ESLint3262 exited0. git diff --check passed after transfer. All root and
implementation test handles are terminal. These repairs close the recorded
source-harness/staging failures, not whole-candidate or live release acceptance.
