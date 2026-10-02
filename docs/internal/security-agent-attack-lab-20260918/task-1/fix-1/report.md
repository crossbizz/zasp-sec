# Fix1 addendum, frozen for re-review

P2 is addressed. The route classifier no longer requires a lease that a committed acceptance/failure receipt has cleared. It returns only the action-family boolean to a registered worker under compiled57 readiness. Classification uses a full-scope stored plan or the run's exact current/historical definition version. A newer definition cannot reinterpret the old receipt.

Fresh authorization remains in each requested operation. Acceptance/failure match the complete retained receipt intent before replay, or require the current lease/context for new work. Prepare has no retained receipt branch; its stale retry still fails without mutations. No new Prepare replay behavior was invented.

P3 needs no source change. The controller moved the real reconciliation/settlement fragments to Task2. No placeholder or catalog enablement was added.

The original task1 patch, blobs and report remain unchanged as the review baseline. This file is their append-only companion. The fix has3 files: new registered-repository regression test, the57 route function and its compiled fingerprint. No published1..56 SQL/pin, Go production routing method, UI, catalog, or Task2 runtime changed.

## Evidence

`red.log`, session60348 exit1,26.75s: actual repository acceptance/failure lost-response replay failed for start_attack_lab, run_test and rerun_test. All three stale Prepare denials passed. Tests also exercise wrong-lease, missing-run and foreign-scope refusal through the real repository and registered PostgreSQL login.

`pin-calibration.log`, session11812: new installed fingerprint calibration only, not behavioral acceptance.

`affected-batch.log`, session43697 exit1: authority33.84s and exact release-cycle7.12s passed at the new pin. Immediate acceptance/failure replay passed. Failure replay after a definition edit exposed a test setup omission: the predecessor owner-seed helper never inserts a definition-history row. The test now inserts a distinct retained version per case; no production correction followed that fixture error.

`postgres-green.log`, session21001 exit0,28.54s: all9 repository cases passed on final bytes. For all three actions, acceptance/failure returns the retained JSON with replayed=true, leaves parent/plan/step/approval/receipt/audit state unchanged and refuses altered model intent. Replay also survives a current definition-version edit through the exact historical version. Fresh wrong leases and missing/foreign scope fail. Fresh Prepare succeeds and its stale retry fails without new work. The response recorder only observes the real database adapter; it does not replace database behavior.

The affected authority/release-cycle successes were reused after the fixture-only correction. Existing native race evidence was reused because no Go production code changed. No native test execution occurred in this fix round. All PostgreSQL execution was inside the plan's cached pinned Docker image with --pull=never and --network none. No host PostgreSQL or provider access occurred in this round.

Cross-compilation command, workdir services/platform:

```
env GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-attack-lab-fix1.test
```

Successful compile sessions12213,23957,10759,60954 exited0 with no output. Initial compile32812 failed on an unused test import; the subsequent premature Docker command exited125 because no test binary existed. Neither is counted as behavioral RED. The import was removed before the retained registered-role RED. Exact Docker commands and full outputs are in the logs above.

## Frozen identities

Fix patch SHA256: `039634996c5351ca512a1d6885001007702ae9261ec98f8056da52dc3dfffa34`.

Original patch SHA256 remains `61cc67271f26fe641c256158796d8cc6db3aa914b09a196d2bb3c7385a65c1aa`.

Release57 checksum: `b6bf12e6ee5ed9880615201572ebcaabb20de9cd5540ef863d763e0e5c7df603`.

Release57 fingerprint: `797b6bdf674dd33b0a2459e12f10660a262a0a365b213944db3bb4f2469849fd`.

All3 current hashes match fix-1/blobs.json; each modified before hash matches the original reviewed after hash. `git apply --reverse --check` passes for the fix-only scoped.patch. HEAD remains8733b16f8d939d38a8157dd2519e57fc6f630542. No staging, commit or push.

Owned PostgreSQL processes reported normal joined exit. Final container check found no zasp-attack-lab-fix1 container. Task2/3 and deployment/provider/publication gates remain pending. Independent scoped re-review is the next gate.
