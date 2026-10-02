# Post-login fix1 re-review

Finding 1, resource-only Security Agent page: ADDRESSED.

Finding 2, strict native output before commit: ADDRESSED.

SPEC: PASS for the scoped fix. QUALITY: APPROVED. Zero open findings; zero new Critical, Important or Minor findings.

## Resource access survives catalog denial

`services/platform/apiserver/authorization_post_login.go:159` adds `security-agents.catalog.read` from environment `view` with no resource fallback. The existing resource-derived `security-agents.read` rule stays intact. `app/features/securityagents/SecurityAgentsView.tsx:691` consumes that distinct capability; the loader at `:257` skips only templates/actions when it is absent and still loads definitions, runs and approvals. There is no blanket 403 catch.

The empty local arrays don't claim a successful catalog response: the separate availability flag reaches the page, builder and detail panel. The page states that catalog authority is missing (`:672`), and the detail panel explains the same condition instead of calling configured actions unsupported (`:444`). Template-based creation and metadata-dependent activation require catalog availability. Resource editing/deletion, simulation, manual runs and approvals keep their existing independent gates.

The production-page test at `app/components/ZaspProductionApp.post-login.test.tsx:14` uses the strict API client with a real definition-shaped response. Unauthorized catalog calls would return 403; the denial branch asserts that no such request occurs, the permitted definition opens, deletion stays enabled and the missing-authority text appears (`:39`). Its allowed branch confirms both catalog requests and creation visibility. Existing scoped-controls cases remain in the passing file.

The actual PostgreSQL/OpenFGA fixture now supplies a direct definition grant and checks that bootstrap emits resource access without catalog access (`services/platform/apiserver/authorization_post_login_postgres_test.go:302`). It checks the real collection authorizer allows that definition and both environment catalog operations deny. This is adapter/authorizer evidence plus a strict-client UI consumer, not a mounted Security Agent HTTP read or a live browser/provider claim. It closes the reported capability-to-page mismatch without broadening authority.

## Malformed output stops before commit

`services/platform/apiserver/identity_post_login.go:28` replaces raw nested principal JSON with typed fields. The validator at `:37` requires the expected identity, valid references/role and active status. Snapshot decoding at `:115` and final decoding at `:170` now use exact typed envelopes and the existing strict decoder, which rejects unknown nested/outer fields and trailing content (`services/platform/apiserver/discovery_repository.go:1484`). Final correlation must be a valid ID and match the freshly generated value.

Revision pointer fields distinguish omission/null from legitimate pending zeros (`services/platform/apiserver/identity_post_login.go:43`). Validation at `:54` checks organization, numeric bounds and configured/unconfigured store/model shape. The pending path is preserved: applied zero and an unconfigured generation-zero/empty-ID pair are valid snapshots, then preparation returns authorization pending without an FGA Check. Rejected snapshots return a zero result at `:134`; rejected final results return no payload. Legacy decoding and native SQL didn't change.

`services/platform/apiserver/identity_post_login_test.go:66` exercises the actual native transaction callback through a controlled output driver. Exact results commit. Unknown outer/principal fields, missing/null principal, wrong identity/type/value, missing revision applied, invalid model, and missing/wrong correlation produce zero returned data, no commit and one rollback (`:146`). `TestP7PostLoginPendingOutput` at `:154` checks both pending forms and rejects any provider Check. These tests establish the application decoding/transaction boundary; they don't substitute for native privilege tests.

## Checked evidence

I read the original two findings, the fix brief, the complete report and the 483-line six-path fix diff. The comparison base is the reviewed dirty 2,686-source packet preserved in `fix1/before` and `baseline.json`, not HEAD. HEAD remains the supplied identifier `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`.

Independent SHA-256 checks matched all supplied pins:

- Report: `7a90aa57a19cd747153db8eda5fb20c0e8488eaa89145db63feca542819f9e60`.
- The fix patch is `69c880c7686dd2e3ccb530e6b53e961ce32935f50b979d6b8e00259f117dd9f1`.
- Frozen manifest: `8df50ce4288d7487bd9e6c289bbf3c60ef25219b6a841ff22e7a10a0536b2052`.

The controller independently verified 2,687 final source hashes, nine stable logs/manifests and all five passing runs against final sources. I used that source-match result without duplicating the scan. I inspected recorded RED assertions for the denied catalog, missing environment capability and malformed native output, then read the covering GREEN output: native focused tests PASS in 1.087 seconds; the complete bounded post-login backend group PASS in 61.506 seconds; UI 110/110 PASS; typecheck and all five build stages exit 0. No unresolved warning appears in these final outputs.

Evidence lives under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-post-login/fix1/`: `native-red.log`, `ui-red-2.log`, `catalog-red.log`, `native-green.log`, `backend-green.log`, `ui-green.log`, `typecheck.log` and `build.log`. The backend log records joined owned PostgreSQL shutdown. No SQL/profile input changed, so repeating installation/profile tests wasn't needed for this fix.

## New breakage and limits

New breakage in the fix diff: None.

Out-of-scope observations: None newly identified. The existing fourteen migration cases, unrelated package failures, full startup/worker/P7-P8 acceptance, live provider/browser, immutable-profile deployment and Go toolchain-parity gates stay open. This scoped approval doesn't change the 728-row scope or any availability classification.

I ran no tests, started no services, made no database or git changes, and dispatched no subagents. Only this report was written. Both findings are addressed; accept this fix round within the stated local evidence limits.
