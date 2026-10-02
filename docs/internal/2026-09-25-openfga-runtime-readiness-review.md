# Guarded runtime readiness: independent review

SPEC: PASS for the bounded readiness repair. QUALITY: APPROVED.

Findings: 0 Critical, 0 Important, 0 Minor. Full production construction, aggregate deadlines and deployment remain unverified.

## Scope and evidence identity

I used the Superpowers task-reviewer prompt against `p7-readiness-repair-brief.md`, the approved `p7-readiness-routing/repair-proposal.md`, the implementer report and the complete 717-line scoped diff. The prior audit-isolation review's remaining gates still apply. The effective baseline is three dirty-before files plus six new files, not unchanged HEAD `6e7d759`.

Packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-readiness-repair/`. Its scoped diff SHA256 is `ac4642da8000912c4c7100480544f8ac52b73eab1c8060989fc38bd119ffd69a`; report SHA256 is `c12e83331e86349909eddbdd24392dc8fc4c00401a559cd65c31d27cd463aa4a`. Root verified 44 source/artifact hashes, including nine live sources; I relied on that identity verification rather than repeating it.

References below use the packet's frozen `after/` files unless marked unchanged. I changed only this review report. No tests, services, database calls, product edits, Git operations or subagents ran.

## Contract checks

The native endpoint is constrained. `migrations/sql/0080_authorization_audit_profile.sql:116` checks exact assembled80/audit identities, the closed composed/guarded selector, current registration/catalog and verifier version. It selects one of two existing session-bound API principal predicates. A supplied authority label cannot replace the connected login. The SECURITY DEFINER owner and fixed search_path are explicit; lines 137-140 grant only API schema USAGE and this endpoint's EXECUTE. No private table or helper grant is added.

The typed route preserves an independent integrity check. `apiserver/authorization_runtime_readiness.go:11` returns both80.ready and the new endpoint result from one fixed driver query. Line 19 validates mode, role and key shape, holds the existing database RLock, rejects closed/missing drivers, and requires both booleans plus an uncanceled context after Scan. False, scan/SQL failure and late cancellation return unavailable. It has no caller-supplied SQL or checksum, no product-query admission and no human proof fabrication. The installed allow-valued-endpoint case confirms that independent80 still refuses when the endpoint's catalog identity changes.

Checksum construction remains finite. `migrations/production_authorization_audit_profile.go:17` memoizes only the immutable assembled source checksum used by installation. It does not cache live readiness. The audit source depends on80; this diff does not introduce an audit-checksum dependency back into80. Catalog code hashes the new endpoint definition but does not invoke it. The endpoint reaches full80/78/79 through the existing composed readiness function.

Startup is wired, not merely represented by a test helper. In `agentsec-api/production_runtime.go:84`, the real constructor calls `checkAuthorizationRuntimeReady` on the two enforcing adapters and derived attestation-key version before provider/runtime composition. On failure it closes both databases and the existing deferred service cleanup remains active. At line 117, the real periodic callback uses `authorizationRuntimeReadiness`. Its implementation at `agentsec-api/authorization_runtime_readiness.go:21` runs services readiness first, applies the existing runtime timeout to both typed calls, and delegates to the earlier callback only after success. The startup/helper errors retain the existing unavailable contract; services/previous callback errors retain their existing propagation. Stytch construction, pool ownership and shutdown wiring are not bypassed.

Base-guarded and composed-none remain valid compatibility installations but fail this production gate. An absent namespace/function fails through SQL error or the closed native predicate; there is no permissive fallback. Exact older-source refusal is separate from catalog validity: the caller supplies its compiled audit checksum, which must equal the endpoint's compiled checksum and registration.

## Focused dependency checks

I read the frozen constructor and earlier callback beyond the diff's split hunks to check cleanup, the actual shared-helper call sites, Stytch preservation and continued delegation. The unchanged earlier callback remains responsible for repository/export/dependency readiness (`agentsec-api/production_runtime.go:522`); this repair does not claim those full product dependencies now succeed.

For role impersonation, unchanged source10 `0010_production_discovery.up.sql:707` and source18 `0018_security_agent_execution.up.sql:320` bind their API predicates to session_user, registered role membership and nonsuperuser/non-BYPASSRLS login attributes. For readiness recursion, unchanged composed SQL `0080_authorization_temporal_profile.sql:95` combines its catalog,78 and80 checks; unchanged `0080_authorization_attestation.sql:27` checks80 plus the current verifier version. Neither calls the new endpoint.

For adapter lifetime, unchanged `postgres_database.go:530` takes the matching exclusive lock before closing, and `authorization_transaction.go:20` enables current mode only on an open transaction-capable adapter. For deadline claims, unchanged `agentsec-api/runtime.go:439` bounds the whole health callback with ProviderTimeout. Those checks support the narrow wiring assessment, not an executed whole-constructor or aggregate-budget result.

## Retained tests and limits

I read the raw meaningful callback RED, unit/startup GREEN and both installed logs. No covered tests were rerun.

| Evidence | Result |
|---|---|
| callback-red2.log | Meaningful FAIL1.341s: the healthy callback stops before either driver query and fails its routing expectations. The preceding unused-import build failure is not behavioral RED. |
| unit-green.log | Adapter/characterization, callback and checksum groups PASS2.077s/1.014s/1.178s. Exact fixed query/arguments, both booleans, cancellation, input/mode/closed refusal and generic unproved QueryJSON denial are covered. |
| installed1.log | Aggregate FAIL97.373s. The rotation fixture reused its deterministic original key, so the expected refusal was invalid; stale-source checks were not reached. Base-guarded11.86s and composed-none38.24s pass. Three owned PostgreSQL processes joined normally. |
| installed2.log | Corrected composed group PASS51.274s. A distinct-key assertion makes rotation meaningful. Both real registered API identities, private-access denials, profile/source/guard/endpoint drift, restoration, atomic installer rollback/replay and consistent older-source refusal pass. Owned PostgreSQL37441 joined normally. |
| startup-green.log | Shared startup-gate matrix PASS1.253s, covering healthy, either-role refusal, canceled context and malformed key. This does not instantiate the full production constructor. |

`apiserver/authorization_runtime_readiness_postgres_test.go:188` constructs a synthetic internally consistent older audit source. It first proves independent80=true and the old-checksum endpoint=true, then requires the current typed caller and installer to refuse. It restores current definitions/registration and both current API positives. This is stronger than passing a random wrong checksum; it is still an owned synthetic fixture, not a deployed upgrade.

The adapter's scan-error test covers the refusal path used for unscannable NULL; it is not an installed NULL-result probe. Callback tests prove shared-helper ordering and deadline presence, not elapsed aggregate budget. Actual native positives take about a second per API call, and both calls plus services and the previous callback share the real outer budget. Successful full construction and configured aggregate timing remain mandatory acceptance work. No deadline was increased here.

Critical: none. Important: none. Minor: none in the released change.

Keep the original728 requirements open where not independently completed: deployment/profile/key provisioning, discovery of older/copied installations and an approved additive transition when needed, full constructor/provider/export composition, worker task/effect/phase/compensation authority, valid integration mutations, cross-family/native-human current-P7 composition and original automatic77 execution gates. This review accepts the closed readiness repair, not those follow-on outcomes.
