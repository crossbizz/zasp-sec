# Guarded audit isolation: independent review

SPEC: PASS for the released audit-isolation batch. QUALITY: APPROVED.

Findings: 0 Critical, 0 Important, 0 Minor. This is not full P7 or production acceptance.

## Scope checked

I used the Superpowers task-reviewer prompt to review the approved public57 six-query projection, guarded selector, independent base/composed entry checks, native write restriction, installers and affected tests. The binding inputs were `p7-audit-isolation-brief.md`, the three referenced audit design/feasibility documents, their controller decision, and the ownership amendments in `progress.md`. The accepted profile-F1 and rejection reviews supplied their existing limits, not substitute acceptance for this change.

The effective comparison is the packet's dirty `before/` and `after/`, not unchanged HEAD `6e7d759`. I read the full 988-line scoped diff and implementer report. Root had verified all 53 packet hashes, including 12 live sources; I relied on that identity check and did not repeat it. Packet identities supplied by the controller and recorded in the ledger are:

| Artifact under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-audit-isolation/` | SHA256 |
|---|---|
| report.md | daa4a72ec9ae6fa873a01c78ef1660473ab7f742b13fdf518f73847b6686c486 |
| manifest.json | 9d1651e7339ef6d833a1cfef5b98f550959a27e6b8bbad435a4e0db9e52b2455 |
| scoped.diff | 514aee1b30dcae864bebbf404f8222dcf69087a4baef4efa546b139ad39ebbcb |

Source references below use that packet's frozen `after/` unless marked unchanged. I changed only this review. No tests, services, database calls, Git operations or subagents ran.

## Contract and quality checks

The native boundary is narrow. `migrations/sql/0080_authorization_audit_profile.sql:24` defines a SECURITY INVOKER statement trigger, so its current_user is the actual writer. Lines 29-32 admit the exact captured registered login/table owner, or INSERT from the existing nonlogin, nonsuperuser, non-BYPASSRLS discovery authority. Other raw writes raise 42501. No request metadata, GUC, action string or session_user-only exception grants access. `guard_ready()` at line 35 checks the exact trigger shape/arguments, function ownership, invoker mode, configuration and ACL; it retains the source52 source-ACL predicate. The change neither reassigns the source table nor enables its RLS.

Projection stays computed. SQL line 51 copies the current five retained private queries and public57 query, redirects each predecessor call exactly once, and excludes only the exact new trigger when its guard contract is valid. The public57 self-row substitutes its captured original definition; other identities remain live. The original five private functions and historical52..78 source files are not edited. The full catalog at line 83 binds private functions/storage, saved definitions, the live delegate and source relation/column/default/constraint/index/policy/trigger facts. `catalog_ready()` at line 96 checks its compiled checksum, live catalog, exact80 catalog/selector and source52 pins without evaluating the projected predecessor chain or full80 readiness. I found no recursive readiness path in this addition.

Independent entry checks are present. Main80 SQL line 41 adds the closed audit dispatcher, while line 81 makes80.ready require it. Composed profile SQL line 92 adds the same gate to the existing independently enforced profile catalog. Missing guarded state cannot become none mode. The none branch requires absence of the audit namespace and named audit trigger; it is compatibility behavior, not isolated production selection. Existing protected selector/catalog machinery binds the new column and actual value.

Installation and replay do not bless an arbitrary live catalog. `migrations/production_authorization_audit_profile.go:56` validates the registered migration principal and canonical lineage, checks exact optional79, and performs the new work under the existing transaction/schema lock. Its helper at line 26 compares original and projected57 at the same bootstrap phase. Final registration/readiness must succeed before commit. The composed function's diff was cut into separate hunks, so I read its frozen full function to check ordering: `production_authorization_temporal_profile.go:71` explicitly compares the current compiled audit checksum on replay, lines 128-150 install/register the audit extension within the same transaction, and the final check requires the complete profile/canonical ancestry. Existing68/72 projections are retained. Unknown or mismatched profiles are refused, not repaired.

The CLI path is explicit. `agentsec-migrate/authorization_audit_profile.go:13` checks the actual registered migration session before forwarding; `agentsec-migrate/main.go:361` checks selected profile/audit mode and readiness after migration. The dispatch has no generic SQL admission or production fallback. The mode-none enforcement installer now refuses guarded state (`production_authorization_enforcement.go:129`). The two added command names and runner methods match the controller decision.

Tests exercise the installed boundary. `apiserver/authorization_audit_isolation_postgres_test.go:29` covers base/composed with and without exact79; line 77 requires the injected registration fault to be reached and checks rollback of all new schemas plus public57 restoration. Its later probes establish signed API/native78 positives before replacing public57 with the exact accepted computed value, require refusal, then restore working entry calls. `authorization_audit_catalog_test.go:31` covers guard/source/storage/selector/checksum drift and all six projectors. Its final case tests current-binary checksum refusal even with an allow-valued catalog predicate. These are behavioral checks, not string-only assertions.

## Focused unchanged-code checks

I checked three named risks outside the diff:

- Writer-identity impersonation: unchanged source10 `0010_production_discovery.up.sql:722` refuses API principals that inherit discovery-authority membership. The retained guarded hierarchy case at `apiserver/authorization_hierarchy_create_postgres_test.go:557` actually tries SET ROLE to both the migration owner and discovery authority and expects refusal. The affected controls/hierarchy logs also establish a real nonsuperuser migration-owner session and its restoration. This supports the new trigger's exact-role boundary; it does not prove every historical callable writer has current OpenFGA proof.
- Source52 privilege regression: unchanged `0052_production_audit_exports.up.sql:77` requires the saved source ACL, RLS-off state and authority SELECT/INSERT without UPDATE/DELETE. The new guard invokes this predicate unchanged. The final native log records the same legacy-export false/source-ACL true pair before and after installation. That is preservation of an existing prerequisite failure, not export success.
- False-positive independent-entry evidence: unchanged `authorization_temporal_profile_postgres_test.go:286` checks actual connection identity without an ACL mutation. Its helper at line 321 supplies current membership/scope, signed proof and the enforcing repository call; the negative probe reuses the granted context and must fail at the database boundary. Decisions are controlled fixtures here, not live-provider authorization. I also read the frozen composed install function because its diff omitted the intervening checks, as noted above.

## Retained evidence

I read the meaningful native RED, guarded affected output and corrected native-read output, including terminal status and teardown. I inspected the retained mode-none regression results in installed-1. No covered check was rerun.

| Log | What it establishes |
|---|---|
| native-red-2.log | FAIL49.397s. Actual registered API INSERT/UPDATE/DELETE succeeded before the guard; TRUNCATE was already denied. Accepted-value constant57 bypassed signed API admission in both profiles and native78/API readiness in composed mode. Both owned clusters joined. |
| installed-1.log | CLI0.758s/API296.582s PASS, including retained mode-none profile regression. This precedes the explicit current-audit-checksum replay check; it is not evidence for that later delta. |
| guarded-final.log | Aggregate FAIL303.084s, not a claimed aggregate GREEN. The only failing top-level case is the old mode-none replay assertion in TestP7AuthorizationPostgres. Guarded four-profile checks147.03s, controls16.60s, hierarchy25.17s, rejection54.71s, sensors47.30s and CLI1.021s pass. Source drift is empty and owned clusters joined normally. |
| guarded-native-final.log | Corrected TestP7AuthorizationPostgres PASS65.943s with both opt-ins. Audit/read-purpose positives and negatives, mounted compliance and enforcing pagination pass. Source drift is empty; owned PostgreSQL33394 joined normally. |

The manifest distinguishes these checkpoints: all twelve final files match the corrected native run, eleven match the preceding affected run, and the intervening delta is the explicitly released existing test fixture/assertion file. Product sources did not change between those two runs. Keeping the failed aggregate visible and supplementing only its affected test is accurate evidence accounting.

The hierarchy group preserves actual source19 deprovision/audit behavior. Controls preserve the owner/helper path; sensors and checked rejection retain queryable audit results and atomic rollback/denial checks under guarded base80. Composed evidence establishes installed API/native78 admission and catalog refusal. It does not establish every mounted writer on the composed profile.

## Findings and limits

Critical: none. Important: none. Minor: none in the released change.

Cannot verify from this diff, and still required: complete source52 export create/worker composition; exact guarded production startup/current-checksum enforcement; unknown deployed/copied80 inventory and any required additive upgrade; all original728-task acceptance, remaining valid integration/provider/discovery flows, machine task/effect/phase/compensation authorization, UI and release/deployment proof. `p7-audit-isolation/report.md:56` records these limits. The registered native78 probe is admission, not worker effect execution. Local controlled signer/Check fixtures are not live Stytch/provider evidence.

This review accepts the bounded guarded audit-write isolation and its compatibility/independent-entry implementation. Keep the listed gates open before production acceptance.
