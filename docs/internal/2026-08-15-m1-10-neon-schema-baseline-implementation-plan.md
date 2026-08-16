# M1-10 Neon Schema Baseline Implementation Plan

1. Add a repository contract test for the authoritative M1-10 dependency,
   deliverable, verification, design boundary, root commands, and exact
   In-progress tracker transition. Capture RED before changing status.
2. Mark only M1-10 In progress, update the aggregate/M1 counts and README, run
   the focused and full pinned repository gates, scan, and commit the start
   transition.
3. Add tests before production for the embedded version-1 metadata, strict
   transaction protocol, exact state reads, rollback, cancellation, malformed
   adapters, and fixed errors. Record the compile RED.
4. Implement the dependency-free `services/platform/migrations` runner and its
   exact versioned up/down SQL assets until the focused and full platform Go
   suites pass repeatedly under race.
5. Add a narrow pgx adapter and `schema-baseline` mode to the reviewed
   disposable Neon migration proof. Add hermetic adapter/lifecycle tests and
   stable root test/run commands without weakening the existing M0-05 proof.
6. Run the exact live root command against one proof-owned disposable Neon
   branch. Require fresh up, exact version 1, down rollback, baseline restored,
   branch deleted, and fixed output. Reconcile or clean only resources proven
   by the retained M0-05 ownership boundary.
7. Run six focused stability passes, all Go module race/tidy/verify/vet/build
   gates, every service/worker/root regression, pinned Node verification,
   production dependency audit, whitespace/source audit, and redacted pinned
   Gitleaks scans.
8. Request independent whole-task review of the exact live up/down proof. Fix every confirmed finding tests-first
   and repeat affected live/local gates. Only a zero-finding review may move
   M1-10 to Complete.
9. Update the README/tracker to Complete (`685/0/40/3`; M1 `68/52/0/16/0`),
   preserve all blocker/risk boundaries, commit, push, and require exact-SHA
   Runnable UI success. Then leave M1-11 Pending and close the ignored evidence.

## Completion

- [x] Execute steps 1-8 tests-first, including three fresh disposable live
  up/down proofs and a zero-finding final review.
- [x] Move only M1-10 to Complete at `685/0/40/3` and M1
  `68/52/0/16/0`; preserve M1-11 and all blocker/risk boundaries.
- [x] Commit and push the completion plus test stabilization, then require
  exact-SHA Runnable UI run `31919574384`, job `95097114861`, to succeed.
- [x] Close this plan and keep M1-11 Pending until the close SHA passes CI.
