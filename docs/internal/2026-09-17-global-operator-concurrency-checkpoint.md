# Global operator concurrency, local checkpoint

Owned matrix38266 passed all8 selected tests with zero skips. Root inspected the
retained log, verified frozen source hashes and scoped patch reverse application,
and confirmed container removal. Independent review returned spec PASS and
quality APPROVE with no findings. Shipping remains incomplete.

Coverage includes observed stop/admission and stop/invocation waits, binding
revocation during a wait, tenant recovery holds across transitions, queued parent
cancellation and linked-child cancellation/reconciliation/history while disabled,
and both operator-use/unused-rollback orderings. The tests create runs and leases
through public SQL boundaries with real registered connections, not owner-seeded
runs or temporary private-core grants. Discovery/provider inputs remain fixtures.

The rolled-back-stop negative control failed as intended after observing the
same wait: admission succeeded without the committed stop, violating the expected
refusal. This demonstrates assertion sensitivity, not a product defect. Intended
source was restored before final compilation. Existing SQL, CLI and pins did not
change. Invocation authorization committed before stop remains valid; these DB
tests do not send external requests or prove external cancellation.

```
96dcd2a9c67e8c48e9607b4caa35d01c0d5246d4f247ee766fccfd3a3cb185e4  task-3.patch
f248d34913f0ce7b08be60b3510190bf4ba81cf47f238f8f589911976ce2c86d  final-matrix.log
886cbc08024f55a37be174f6ecda7a6fbd25f57599b9671baf29c469c8f973ff  concurrency test
e5a4ecb7db2790d18142b2960ae1e4186a01fdafccf689bf3c2a0dfdc4b17f6a  rollback concurrency test
```

Full commands/results, earlier failed test expectations and cleanup are retained
in `.superpowers/sdd/2026-09-17-global-execution-control-plan/task-3-report.md`.
The eight cases ran only inside the owned cached PostgreSQL container with
`--pull=never --network none --user postgres --rm`; no host database or online
provider was used.

Current-pin mounted browser attempt43062 exited1 before browser cases. It reached
schema55, then the harness's exact fingerprint assertion still expected the old
`5982d49a...` pin instead of accepted `2c324e78...`. Root verified the single stale
literal in scripts/production-combined-e2e.mjs. A one-line expected-value correction
is assigned; the exact-match assertion remains mandatory. All harness cleanup
stages ran. Failure log: `/private/tmp/zasp-global-final-mounted.ilmfyO/mounted-current55.log`.
This failed run is not current-pin browser acceptance. The correction separately
passed independent spec/quality review with no findings, patch SHA256
`a29a4bc62d02d0387cc72264506c01fe4c8a4a7cd433a8fab6d860ab75be4889`.

## Fresh-build browser and UI evidence

Run7598 passed all four current-pin mounted cases and cleanup. Root then rebuilt
the UI (session26219, exit0) and passed compiled imports:7 client/8 server chunks.
The sorted dist-content digest changed during this build, so root repeated the
browser matrix on the fresh output instead of assuming artifact equivalence.

Fresh-build run31668 exited0, all four outcome cases plus reload/history,
cross-tenant refusals and owner cancellation passed. Full log:
`/private/tmp/zasp-global-final-mounted.ilmfyO/mounted-current55-run3.log`, SHA256
`fb3921d349574c1f43637524198e7937a37825ff44aa69d27c778cbd15252d6a`.
Its stored JSON/PNG evidence directory is
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-existing-test-browser-evidence-E93ZlH`.
Root inspected the comparable-rerun screenshot: recorded-evidence disclaimer,
Remediated/test_condition_changed result, matching proof digest and before-run
link are visible. This remains local composition, not current provider health.

| Case | Security Agent run | Stored result |
| --- | --- | --- |
| Supervised run_test, fail | pid_e240309f-0fa4-44cd-bd02-a85447dbd3f6 | needs_human / test_condition_persists |
| Autonomous rerun_test, comparable fail-to-pass | pid_28317d91-cbc8-4bd3-822c-f65f2715032a | remediated / test_condition_changed |
| Autonomous run_test, no baseline | pid_cfa06eda-4282-4222-9c00-9fdf43139cfb | needs_human / test_baseline_unavailable |
| Supervised rerun_test, engine error | pid_f2c07f87-4090-4980-ac68-f6b2b7061876 | inconclusive / test_outcome_unknown |

The sorted SHA256-list digest of all2672 dist files is
`5b4effed0f58036ef92652f2dd04e8224cd81539af58db00f202ab8565fa1c57`, unchanged
between the fresh build and completed run31668. An initially truncated full-list
capture was discarded; the aggregate was computed over the complete list.
Separate standalone smoke1efaf8 returned root200 and all7 emitted JS/CSS assets200.
Owned server14263 on loopback50931 terminated with SIGTERM and was joined.
Harness cleanup completed; the two pre-existing daemon-replay containers were
left untouched, not attributed to these runs.

`npm run production:release:test` session1800 exited0:222 passing tests,0 failed,
0 skipped,24.79s. This covers release-source/rollout assertions and fail-closed
advisory orchestration, not advisory clearance or a completed production release.
Current-pin lifecycle/versioned-definition run11820 exited0: both selected tests
passed (18.84s and9.76s), no skips, including malformed/stale/disabled/foreign-scope
definition refusals. Both owned PostgreSQL children joined normally. It reused
the already compiled current-pin binary, with no product edits or new compile.

No deployment, push or original-task availability promotion is claimed. Exact
shipping-candidate dependency closure/review, required external release evidence,
push and CI remain open. The prior mounted limitations still apply: synthetic
image identity and local cloud/customer/credential fixtures are not live proof.
