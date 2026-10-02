# The profile installs, but its runtime guard can be bypassed

SPEC: CHANGES REQUIRED. QUALITY: CHANGES REQUIRED. One Important finding, no Critical or Minor findings in this bounded review.

The fresh/exact79 transition and retained local GREEN are useful evidence. They do not establish independent enforcement of the actual72 wrapper identity at the native API boundary. That is the blocking issue below.

## Scope and source identity

I read the complete packet report, review instructions, approved composed-readiness proposal, manifest and 695-line scoped diff, then inspected the six candidate sources and the named predecessor/readiness context. This is the Superpowers SPEC/QUALITY review of `p7-temporal-profile`, not a foundation, fix72, hierarchy or worker re-review. I did not run tests, launch services, edit product files or dispatch another reviewer. Only this report was written.

Packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-temporal-profile/`. `A/` below means its frozen `after/services/platform/`; `B/` means its frozen `before/services/platform/`. The uncommitted dirty-baseline manifest is authoritative. Equal Git base/head values are not the review diff.

I independently verified all 75 `hashes.sha256` entries and all six candidate hashes against `installed4.source.json`, with no mismatch. Manifest SHA-256: `b28b27cbf8c4204714ced4978ad05c3389817ebdeee796d95712725be270dc42`. Scoped diff: `ca4392b8685308407d3a50d216cb8354581f06a416de3af51c67761b722771a7`. Hash list: `fb3de8356fa47cb450565463c6cce292e7c49264eff17718851048a8f935813c`.

For the specific public61 ancestry trace, I also checked the existing 67 base, 68 executor and 71 legacy SQL against the installed4 source checkpoint. All three match. Those files are unchanged caller context, not additional candidate changes. Later live80/hierarchy edits are excluded from this verdict.

## Important F1: the changed wrapper is the only path to its own independent guard

SPEC and QUALITY. Primary source: `A/migrations/sql/0080_authorization_temporal_profile.sql:100`. Related guard/catalog: lines 70 and 80. Missing regression: `A/apiserver/authorization_temporal_profile_postgres_test.go:164`.

The new profile fingerprint includes the actual `zasp_temporal72.fingerprint()` wrapper, but runtime entry into that independent profile guard exists only inside the wrapper being protected. Replacing the wrapper with a plausible allow-valued result skips the guard. The native API fence does not independently require the named profile's catalog.

A concrete single-object drift is to replace only the wrapper body with the compiled72 fingerprint, preserving owner, ACL, SQL/STABLE attributes and search path:

```sql
CREATE OR REPLACE FUNCTION zasp_temporal72.fingerprint()
RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS
'SELECT ''b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e''::text';
```

This is a proposed regression mutation in an owned fixture, not an operation I executed. No registration rewrite or second catalog mutation is needed.

Here is the source path:

| Boundary | Why the constant-return wrapper is not independently rejected |
| --- | --- |
| New profile catalog | SQL line 70 hashes the actual wrapper, so `catalog_ready()` and `profile.ready()` reject the changed source. But the replacement wrapper never calls them. |
| Existing72 readiness | `B/migrations/sql/0072_production_temporal_discovery.up.sql:152` compares the returned fingerprint with the compiled pin. Its saved predecessor checks do not independently hash its own72 wrapper. The constant satisfies this comparison. |
| Retained source51/60 compatibility | The same72 source at lines 910, 915 and 938 gates the retained execution/schedule/precision projections on `72.fingerprint()` equaling that pin. They also accept the constant. Their original retained computations and registrations are otherwise unchanged. |
| Temporal78 readiness | The retained chain reaches `73.ready` and its `72.ready` dependency (`B/migrations/sql/0073_production_temporal_admission.up.sql:30`). It does not independently enter the new profile guard. |
| Native human API fence | `B/migrations/sql/0080_production_authorization_enforcement.up.sql:145` calls `80.ready`. Lines 23–26 require the80 catalog,79 readiness and public61 readiness, not the named profile guard. The79/80 catalog queries do not include the72 wrapper. |
| Public61 dependency | Checkpoint-matched `services/platform/migrations/sql/0068_production_temporal_executor.up.sql:287` delegates to68.current_ready. Its retained predecessor path uses the unchanged retained catalog computations above; there is no separate new-profile check here. |

So the profile's diagnostic readiness can be false while the actual composed API fence/read remains admissible with an otherwise valid signed decision. This violates the approved requirement that tampering with the actual wrapper cannot be hidden by the retained projection and that wrapper drift refuse both readiness and disclosure. It is a catalog-drift integrity failure, not a claim that an ordinary API principal can replace SQL functions.

The retained test changes the wrapper to `SELECT NULL::text`. That proves only fail-closed output propagates. It does not test a changed wrapper that still returns the expected value, and the reported 16 passing drift cases do not cover this case. The finding is based on the exact source path; it is not presented as an executed reproduction.

Smallest acceptable correction shape: require the active named profile's independently anchored catalog check at the native composed readiness/disclosure boundary, outside the replaceable72 fingerprint wrapper. Keep the catalog check nonrecursive and preserve the standalone base profile; absent or invalid composed profile state must not become a base fallback. Add the constant-pin mutation above to the installed drift group and require both the named profile check and the actual signed discovery-API read to refuse, followed by a restored positive read. Merely adding another call inside72.fingerprint does not fix this entrypoint gap. Source ownership for any80 boundary change must be released separately; I made no fix.

## Other reviewed boundaries

The atomic installer at `A/migrations/production_authorization_temporal_profile.go:24` uses one transaction and the existing schema advisory lock. It validates canonical61 metadata/registered migration membership and requires78. Fresh entry checks full compiled78 readiness before unchanged79 DDL. Exact79 recovery checks79 readiness and78's independent catalog, creates the private saved/projected objects, validates the old `kind` trigger shape and projected72 value, then executes unchanged80 DDL. Final `product_kind` validation precedes wrapper activation, profile registration and full readiness. No nested public runner transaction is used.

Existing profile replay checks the current compiled profile checksum and final readiness without rewriting registration. Existing80 without a profile is refused. The retained injected failure immediately before profile registration tests rollback of profile/80 and either removal of freshly installed79 or preservation of pre-existing79. I found no separate atomicity or replay defect in these branches.

The trigger contract at `A/migrations/sql/0080_authorization_temporal_profile.sql:20` is narrow: four exact public relations plus the exact trigger name/function OID, enabled state, row/event flags, no WHEN/column/transition/constraint/deferrability additions, and byte-exact NUL-delimited arguments. Runtime calls use final `product_kind`; the old `kind` shape is installer-only. Capture owner, SECURITY DEFINER, search path and ACL are checked explicitly, with its definition bound through79 and the profile catalog.

The full domain clone removes only the four relation+trigger identities. Other user triggers, table/column/constraint/index/policy/FK rows remain live. The72 clone substitutes the domain result and its own saved definition while preserving live owner/ACL and the handoff definitions. Exact-count substitutions reject unexpected source shapes. The original domain function remains live. The normal wrapper recomputes the projected result; it does not return a saved hash constant. These properties are worth retaining when fixing F1.

The private schema, authority-owned tables, forced RLS, immutable saved/registration rows and function revokes introduce no application mutation or registration grant. The CLI branches are closed to one command with no positional options. `A/agentsec-migrate/authorization_temporal_profile.go:13` verifies the actual session against the configured registered migration identity before invoking the installer; the SQL installer repeats the registered authority check.

## What the retained runs establish

I read the full `installed4.log`. The command exits0: migrate0.551s, apiserver99.379s, installed case98.53s. It contains ten actual executable outcomes, three installed parent branches and sixteen drift subcases. Owned PostgreSQL13974/14165/14302 joined normally. This is the packet's passing local run, not a test I reran.

Fresh installation, exact79 recovery and replay work under the exercised registered owner. Missing78 and damaged intermediate79 refuse. The standalone61+79+80 branch remains ready after the composed-command refusal. The live domain function reports1204 rows and its unchanged final digest; projected72 and guarded72 equal the original compiled pin.

The typed read uses `security_agent_v33_discovery_api_login`, whose existing finding SELECT privilege is checked before and after installation. It goes through the actual authorizer, signed proof, repository/query classifier and native transaction fence. The outbox projection login is registered; Check, tuple writer and attestation key are controlled fixtures. No permission grant was added to make the read pass. The explicit role-assumption/registration negative statements at test line198 use the separate security-agent API connection, not the discovery connection used for the typed read; I do not conflate those assertions.

The earlier failures remain failures: command absence0.991s; installed1 session-ID constraint75.000s; installed2 missing current membership84.149s; installed3 wrong API table privilege90.539s. The source and retained diagnostics support their fixture attribution. They do not supply earlier human-read or drift acceptance.

Installed4's only recorded source drift is the detached, unselected hierarchy test. The six profile inputs match its captured checkpoint. Installed3's detached hierarchy SQL drift was outside the embedded profile inputs. This is not evidence that every captured file or later live composition was tested together.

## Cannot verify here

The constant-return drift requires the new focused regression; no executable result for it exists in this packet. WHEN clauses, column restrictions and every constraint variant are not individually injected. Neither reverse-order adoption nor arbitrary deployment owners are accepted by this transition.

Full P7, hierarchy, worker task/effect/phase authority, signer/compensation, live FGA/provider behavior, deployment ownership, real key provisioning and release remain outside this review. Earlier accepted72/foundation fixes are unchanged and are not reopened by F1.

Fix the independent native profile check, retain the frozen packet, and re-review that scoped correction before accepting this component.
