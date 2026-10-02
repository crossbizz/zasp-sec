# Release61 fingerprint binds a fixture-specific owner

Confirmed application migration defect, not an external prerequisite. The clean CLI60→61 route fails before Temporal ownership migration66. Established product fixtures pass61 because their original authorized-scopes table owner is named `zasp_e2e`; the CLI fixture's owner is `zasp_test`.

`0061_production_security_agent_multistep.admission.sql:12-23` creates private `lock_scope` and assigns ownership to the current owner of `public.zasp_authorized_scopes`. `0061_production_security_agent_multistep.pricing.sql:84-93` does the same for `pricing_lock_scope`. The registered fingerprint at `0061_production_security_agent_multistep.promote.sql:81` includes private function owner names and raw ACL text. Its compiled expected value was derived from the `zasp_e2e` fixture. Legitimate owner-name variation changes two function identities and fails final61 readiness.

## Reproduction and isolation

Original reproduction from services/platform: `go test ./agentsec-migrate -run '^TestTemporalOwnershipShippedCommandPostgres$' -count=1 -v`. The actual existing CLI wrapper reaches exact60, then unchanged `Runner.UpProductionSecurityAgentMultistep` refuses its final readiness. Actual hash: `7c225146d18715e24bc74d8a2cbdb8e6cdb91736818eb71d8f3d612d39c18958`; expected: `6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92`.

Controller added temporary read-only diagnostics to the failing CLI fixture and passing `runOrderedProgressionFixture`. Command: `go test ./agentsec-migrate ./apiserver -run '^TestControllerFingerprintDiagnostic$' -count=1 -v`. Three focused runs narrowed the mismatch from categories to individual functions to owner/ACL values. Each failed the CLI migration and passed the established fixture; the last run took9.560s and8.185s respectively. Both disposable PostgreSQL processes exited normally.

Every fingerprint category matched except private functions: saved definitions, candidate/base fingerprints, schema, tables, columns, constraints, indexes, triggers, foreign-key triggers, policies and legacy action/approval fences were identical. Within private functions, only `lock_scope` and `pricing_lock_scope` differed. Final query returned:

| Fixture | Table and both function owners | ACL of both functions |
| --- | --- | --- |
| Actual CLI setup | `zasp_test` | `{zasp_test=X/zasp_test,zasp_discovery_authority=X/zasp_test}` |
| Established product setup | `zasp_e2e` | `{zasp_e2e=X/zasp_e2e,zasp_discovery_authority=X/zasp_e2e}` |

No production code, historical SQL, checksum or fingerprint pin changed during this diagnosis. Temporary test files were removed from the build and retained under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/fingerprint61-diagnostic/`. This report records the earlier category/function comparisons; the retained final diagnostics query owner and ACL values.

## Required repair, not a waiver

Do not rename deployment principals to a fixture name, create a production `zasp_e2e` owner, weaken owner/ACL checks or replace the expected fingerprint with the observed value. A reviewed install/upgrade transition must preserve historical migration evidence while validating portable owner authority and exact grants. It must reject authority drift, and be tested using at least the two legitimate owner names above through the actual shipped command. Determine the additive readiness/registration contract before implementing that repair.

P3A may prove66 installation against an exact registered61 fixture, but that does not prove a fresh CLI installation or close this issue. Parent P3 activation and publication remain gated on this repair. This is unfinished implementation work, not an external credential blocker and not a new completed microtask.

Further source check: the candidate fingerprint in historical61 up.sql includes the public `zasp_sa_multistep_` function definitions, including the registered fingerprint/readiness functions created by promotion. Replacing one with an ad hoc normalizer changes the pinned authority graph. The preferred repair is an explicit additive Temporal install/cutover authority, alongside P3B/P3C domain replacement, supporting clean60 and retained61 states with owner-portable checks. It must retire superseded readiness dependencies and preserve prior evidence. This is a required integration deliverable, not permission to bypass old checks or call the current installation complete. No normalizer or pin change has been implemented.
