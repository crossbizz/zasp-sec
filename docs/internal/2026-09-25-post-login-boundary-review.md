# Post-login boundary review, September 25

SPEC: Issues found. QUALITY: Needs fixes.

Two Important findings, zero Critical, zero Minor. This verdict covers the 19-path post-login batch against its captured dirty baseline. It isn't a whole-branch or release approval.

## What holds up

The admission split is narrow. `services/platform/apiserver/router.go:130` prepares only the three self-read operations, and `services/platform/apiserver/identity_post_login.go:127` names that closed set. `services/platform/apiserver/repository.go:343` and `:404` require the prepared native path in current mode. The diff doesn't add a generic SQL exception or manufacture a product grant.

`services/platform/migrations/sql/0080_identity_post_login.sql:14` finds the credential by its digest and credential ID, compares caller identity fields, then locks the organization, active membership and credential in that order. The checks at `:30` include current expiry, revocation, scope membership, browser CSRF and exact PAT ceiling. The final read at `:49` restricts purpose, refuses PATs for browser-only purposes, checks the same revision/store/model through the native fence, and rechecks credentials before return. `services/platform/migrations/sql/0080_authorization_identity_profile.sql:275` keeps the private helper ungranted while `:282` grants the two read entries. The unchanged `api_ready()` at `:31` checks the registered API session user.

Current policy checks run after the snapshot transaction returns (`services/platform/apiserver/authorization_post_login.go:38`). Decisions are request-local, deduplicated, revision-bound and deadline-bound; incomplete or excessive candidates fail closed (`:93`, `:122`). Compliance uses a conjunction on one target, and organization identity gets its own target (`:162`, `:201`). No role-derived fallback appears in this diff.

The UI preserves generation/cancellation guards and removes authenticated capabilities on pending/error results (`app/auth/SessionProvider.tsx:143`, `:179`). `app/components/ZaspProductionApp.tsx:140` distinguishes pending authorization, while `:143` keeps scope selection on the no-product-capabilities screen. Organization identity and group-mapping subviews now load separately (`app/features/identity/IdentityAccessView.tsx:88`, `:111`); the new execution-control consumer uses its scoped capability (`app/features/securityagents/SecurityAgentsView.tsx:690`).

## Fix these

### Important 1: resource-only Security Agent access cannot load its page

Changed entry point: `services/platform/apiserver/authorization_post_login.go:158`.

The new capability rule correctly emits `security-agents.read` for an allowed definition, run or approval even when environment `view` is denied. But its actual consumer still calls `listSecurityAgentTemplates` and `listSecurityActions` unconditionally in the same `Promise.all` as the permitted collections (`app/features/securityagents/SecurityAgentsView.tsx:257`). Both endpoints require `view` (`services/platform/apiserver/composition.go:160`) and resolve to the selected environment (`services/platform/apiserver/authorization_targets.go:19`). A direct resource grant doesn't satisfy those checks. Either 403 rejects the entire page load, which displays the forbidden state at `app/features/securityagents/SecurityAgentsView.tsx:696` instead of the resource the user can read.

This misses the released requirement that resource-only grants remain usable at their product UI/API surfaces. The new UI test masks the problem by returning successful empty catalog responses for every security-agent-prefixed request (`app/components/ZaspProductionApp.post-login.test.tsx:27`). Its mocked bootstrap also supplies no environment-read distinction.

Keep the legitimate resource-only capability. Separate resource collection loading from environment-only catalog loading, gate the latter with a checked target-specific contract, and leave permitted definitions/runs/approvals usable without those catalogs. Add a consuming case with environment `view` denied, one real resource read allowed, and catalog requests either absent or handled through an explicitly authorized separate state. Don't turn the fix into an environment-wide prerequisite for resource access or silently swallow arbitrary 403s.

### Important 2: final native output isn't strictly decoded before commit

Changed boundary: `services/platform/apiserver/identity_post_login.go:119`; the snapshot has the same nested gap at `:76`.

The bootstrap/me validator calls `validateBootstrapMembership` and `bootstrapCorrelationMatches`, both of which use permissive `json.Unmarshal` (`services/platform/apiserver/repository.go:517`, `:534`). They validate selected values but ignore unknown fields. A valid principal with an extra property passes; so does a final result with an extra top-level property. The snapshot's outer strict decoder doesn't fix this because its principal is `json.RawMessage` (`services/platform/apiserver/identity_post_login.go:22`) and goes through the same permissive membership validator.

The transaction commits after that callback (`services/platform/apiserver/identity_lifecycle_postgres.go:72`). Unexpected fields then survive into bootstrap through the map-based serializer (`services/platform/apiserver/production.go:382`) or into `/me` through the raw principal (`:482`). The pinned SQL currently emits the intended fields, so this isn't a demonstrated credential exploit. It is a missing part of the explicitly required strict native-output/rollback boundary: a malformed result can be accepted and published, and the new tests don't exercise that refusal.

Use exact typed envelopes with a strictly decoded principal for snapshot and final results, validate required values/correlation, and only commit after the complete shape passes. Keep legacy decoding unchanged if other callers need it. Add focused malformed-result tests for unknown outer and principal fields, wrong/missing required values, and commit-versus-rollback behavior. The final native transaction must not commit or return a payload on any rejected result.

## Evidence I checked

I read the brief and released proposal first, then the review brief, implementation report and all 1,510 lines of `p7-post-login/frozen.patch`. Existing-file hunks were reviewed against `before/`, not HEAD. The packet identifies HEAD as `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`; it is only an identifier for this dirty-baseline review.

I independently checked these SHA-256 values:

- Frozen diff: `c581e7e8459d55aa2c6208351a8f4ac14c35c9ff921245beae879b58a58b960f`.
- `frozen.json` is `8e8885275303adfed3b302a91bf8f5dc30b2bc9753970164290420be17470794`.
- Implementation report: `9bb3a84f5a412a1eb90a561ac0c5df67e4d01bf856359565cb55c7309057248d`.

The controller supplied the 2,686-file/19-change/19-manifest comparison with zero mismatches. I didn't duplicate that scan. I read the complete final backend log: `p7-post-login/contract-green-4.log` records the mounted native-cookie, nonsuperuser API and official OpenFGA group passing, including foreign/forged bindings, denial, resource-only findings, pending/recovery, outage/recovery, revision changes, scope switching, PAT ceiling and final credential expiry/revocation. It finishes PASS, 53.712 seconds. These are existing run results, not tests I reran.

`p7-post-login/ui-focused-4.log:14` records 7/7 passing; `typecheck-2.log:11` and `build.log:40` record exit 0. The retained suites passed in the earlier focused runs; their aggregate failures were in the new controls fixtures, as the report states. The final selected UI run is warning-free. Earlier timer warnings were corrected before that run. The build predates final test-selector-only edits, which the controller checked against the frozen sources.

`p7-post-login/retained-identity-1.log:104` records base and composed installation/maintenance passing, alongside retained administration/PAT consumers. The before-overlay and after profile logs each contain eleven pins: only the identity checksum and assembled installer differ. Identity changes from `e7a01b65...` to `a5f37dc0...`; the installer changes from `b76edd03...` to `3da00231...`. This supports the stated profile extension, not an installed-old-profile upgrade.

Paths beginning `p7-post-login/` above are under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`.

## Focused checks outside the diff

I checked unchanged code only for named risks. The private transaction's commit/rollback path and membership/correlation decoders answered the malformed-output risk; their changed hunks end mid-function, so I read the necessary function bodies. For capability-to-endpoint mismatch, I checked the existing resolver, operation target inventory, current permission conjunction, and Security Agent page loader. For the new scope-onboarding capability, I checked its organization/workspace calls and `authorization/mapping.go:56`: those aliases use the selected environment, so I found no separate organization-view mismatch. The existing compliance consumer at `app/components/ZaspProductionApp.tsx:67` still requires both `compliance.read` and the permission conjunction. I also checked the controller's recorded mixed-authority ruling (`progress.md:35`) to resolve whether the extra identity subview split was authorized; it was.

No suites, service starts, database operations, package installs, git commands or subagents. Only this report was written.

## What this review cannot close

The 728-row scope and availability ledger are outside this diff. The controller must keep their IDs, acceptance requirements and historical production/component/external distinctions intact; local post-login tests don't promote those rows.

Deployed Stytch/provider/browser acceptance, the immutable-profile deployment/upgrade, full startup and P7/P8 cross-task acceptance remain unverified here. So do the fourteen unfinished migration cases, known unrelated package failures and Go 1.25.6 versus CI 1.25.13 parity. These limits are explicit in `p7-post-login-report.md:73`; I didn't expand this review to resolve them.

The SQL credential/revision checks are present and the supplied integration tests exercise changes before the final read. They don't independently prove every concurrent writer's lock ordering or all between-request races. Those unchanged cross-task contracts still belong to the controller's acceptance record.

Task quality: Needs fixes. Route admission and current-policy fencing are substantially implemented, but the real resource-only page load and strict output boundary must pass their focused consuming tests before accepting this batch.
