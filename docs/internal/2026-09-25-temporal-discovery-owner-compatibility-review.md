# The unpublished72 correction is acceptable; composition still fails

SPEC: PASS for the bounded owner-identity correction and its dependent pins. QUALITY: PASS for that same scope. I found no Critical, Important or Minor finding in the nine-source correction.

This is an independent review of fix72, not a repeat P7 review or acceptance of the policy-family preflight. The composed 79/80 installation remains blocked. No release or deployed-installation approval follows from this report.

## The bytes and the boundary

I read the complete review brief, report, owner-compatibility decision and source diff, then inspected the frozen implementation, metadata builders, lineage tests and retained evidence. I used the Superpowers SPEC/QUALITY review and evidence-before-claims approach. No tests or services were run, no product source changed and no additional reviewer was dispatched. Only this report was written.

Packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-policy-preflight/fix72/`. Below, `A/` means that packet's frozen `after/`, and `B/` means `before/`. Source citations refer to these snapshots.

I independently verified all 125 entries across `source.sha256`, `before.sha256`, `after.sha256` and `evidence.sha256`, with no mismatch. Comparing both source manifests confirms exactly nine changed files: the 72 SQL, seven 72–78 Go fingerprint constants, and the lineage test. All captured 73–78 SQL templates/fragments are byte-identical. The source-diff SHA-256 is `af8f6999e514c0d3bb3d7b27b525137a7a55c4d5f56bb64e6af25a390f05b7c4`; `after.sha256` is `ddc70208a23c104f359d54ec3a407024b44961db9644f1398edd68551b024c07`; `evidence.sha256` is `d2490aa205625dd4dc5ebd2218a8f45b3f76e0d58c9e706c6cf0363c6621f307`.

The controller's authorization is for an unpublished local candidate. The checkout/publication decision does not prove that no external copy exists. If a persistent installation uses the old72 checksum, this replacement is not its upgrade path.

## Two identities, with checks before projection

`A/migrations/sql/0072_production_temporal_discovery.up.sql:120` adds `migration_helper_identity`. It accepts only `zasp_valid_product_id(text)` and `zasp_workflow_replay(text,text,text,text,text,text,jsonb)`.

The authority check is concrete. Both `public.zasp_authorized_scopes` and `public.zasp_core_payloads` must have the same owner; that owner must be a login named by the discovery migration-authority binding. The supplied saved owner must equal this catalog-derived role, the actual helper must have that owner, and its raw ACL text must equal the saved ACL. Merely changing a live helper and its saved owner to the same unrelated role cannot satisfy the check. Existing predecessor/principal readiness remains in the conjunction.

| Helper | Accepted ACL and fingerprint representation |
| --- | --- |
| `zasp_valid_product_id(text)` | Requires `proacl IS NULL`, preserving the existing default-function ACL. An explicit empty ACL is not treated as equivalent. The representation records validated migration authority and default ACL semantics. |
| `zasp_workflow_replay(text,text,text,text,text,text,jsonb)` | `aclexplode` must produce exactly three entries and three distinct grantees: PUBLIC, the validated owner and `zasp_discovery_api`. Every entry must be EXECUTE, have that owner as grantor and have no grant option. Only that validated shape receives the fixed representation. |

This does not grant either helper new privileges. The owner retains its ordinary implicit ownership rights; the canonical token's `grantable:false` describes the checked ACL entries, not removal of those rights. No helper body, owner, ACL or saved historical row is rewritten by the correction.

At line 153, `ready` requires exactly two successful validations and retains its original raw saved-to-live definition/owner/ACL comparison at line 154. At line 930, only those two saved-row identities use the projection; their full saved definitions remain in the fingerprint. Every other signature retains the prior representation. Invalid helper identity produces a distinct invalid marker and cannot pass the explicit ready check.

The projection code is itself bound by the schema-wide function catalog at line 922. The existing owner/revoke loop at line 941 gives it the nonlogin authority owner and removes PUBLIC execution; none of the following application grants names the new helper. The correction does not add a callable normalization service for application principals.

## Why all seven pins changed

The 72 SQL checksum changes from `3e20d5ea41a47ae8e03540ecd08264748faea58fedf78544cc5f334e23e19d8c` to `e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940`. Its saved-identity representation and pinned helper/readiness implementation change the independent 72 fingerprint. The next builder embeds that checksum and fingerprint into 73's installed readiness function. The dependency continues through 78.

| Version | Frozen metadata source | Candidate fingerprint | Reviewed dependency |
| --- | --- | --- | --- |
| 72 | `A/migrations/production_temporal_discovery.go:14` | `b5d7f17f5350c89b337c6c875975402ab67b10ffc6facc2ea34c042342e9f07e` | Validated two-signature projection and its own catalog-bound code. |
| 73 | `A/migrations/production_temporal_admission.go:14` | `09895c8411beabd971e2425c3382a1152df3d224334ded17433fa80ae243b115` | Bound 72 checksum/fingerprint. |
| 74 | `A/migrations/production_temporal_test_executor.go:41` | `0be1a2bfe93c30928eb03eae744993df6ec6c4db692b909aed9b7c486de6aca5` | Bound 73 fingerprint. |
| 75 | `A/migrations/production_temporal_test_selector.go:14` | `507b909dd0a59c2ffe8c664d8e70c40d120f63ad215a96fc002141c22687b873` | Bound 74 fingerprint. |
| 76 | `A/migrations/production_temporal_human_admission.go:14` | `606fefa6b41a7627fa6c58687a837b9dc3d0185cabeb761cc420f9933026b079` | Bound 75 fingerprint, with existing saved 74 function projections. |
| 77 | `A/migrations/production_temporal_automatic_sources.go:44` | `8cac13406a1886a98cd327065e5525be28997add7a9bd359d12e7b4ed219f5ef` | Bound 76 fingerprint and unchanged predecessor projections. |
| 78 | `A/migrations/production_temporal_finding_response.go:50` | `11b999b767465c01389f4482f9196852905866873e585574888281220538d1d4` | Bound 77 fingerprint plus saved/effective ancestor definitions. |

The builders hash unbound source before substituting predecessor pins. So the six 73–78 source checksums do not change, while their installed function identities do. I checked the retained 76 projection of 74 at `A/migrations/sql/0076_production_temporal_human_admission.up.sql:170` and 78's saved/effective ancestor handling at `A/migrations/sql/0078_production_temporal_finding_response.up.sql:137`. Those projections were not widened. No replacement registered61 or SQL80 acceptance pin is introduced.

Each descendant derivation log records the new fingerprint at the first stale-pin refusal, with the prior boundary accepted and the disposable PostgreSQL process joined. The values match the candidate constants. Those six commands failed, as expected for derivation; they are not successful installation evidence on their own.

## Roles, old registrations and actual test assertions

`A/migrations/production_temporal_discovery.go:25` retains transactional installation and its locks. An existing schema skips DDL and registration insertion, then must satisfy the exact current checksum/fingerprint. There is no UPDATE that silently converts an old registration.

`A/apiserver/temporal_policy_response_lineage_postgres_test.go:471` exercises clean60/`zasp_test` and registered61/`zasp_e2e`. The corrected equality assertion captures the two helper definitions, owners and ACLs immediately after71, compares them after72, checks the two raw saved records against live catalog values, then reinstalls. It opens the actual registered discovery API login for a positive principal check. The security-agent API receives `42501` for 72 readiness.

Both profiles run nine rollback mutations: helper source, SECURITY DEFINER flag, live owner, extra replay ACL, grant option, saved owner, saved ACL, matching wrong saved/live owner, and unrelated canonical-id volatility. Each requires readiness to return false without accepting an error as a passing result. This covers the new validation boundary and guards against normalizing unrelated catalog drift.

The old-checksum case writes the actual old checksum into the disposable current registration, requires reinstall refusal and verifies the checksum was not changed. This is a refusal test, not an upgrade test of a retained old-schema database. The implementation and evidence do not authorize rewriting a persistent installation.

## Keep the failed records visible

| Retained evidence | Supported conclusion |
| --- | --- |
| `pin-derivation1.log` | FAIL34.179s. Both disposable profiles derive the same new72 fingerprint; the stale compiled pin refuses. |
| `owner-green1.log` | FAIL33.869s. Its combined before/after inequality did not isolate72 because capture began at55. It does not identify the differing field by itself. Later stage logging records the existing58 replay-body change. |
| `owner-green2.log` | PASS48.078s, case46.94s. Both profiles install/reinstall72, preserve exact helper identity, pass the role assertions and all nine tamper cases, then refuse the old checksum. PostgreSQL 3092/3199 joined normally. |
| `descendant73-derive.log` through `descendant78-derive.log` | Six retained failures at the successive stale pins: 20.516/22.704/25.712/28.387/32.871/33.735s. No readiness result was substituted to advance. |
| `composed-green1.log` | Aggregate FAIL. Supported profile passes through78 and registered API78 readiness in 36.24s. Canonical profile also reaches installed78/API readiness, then installs79 and fails at80 in 33.48s. Both owned PostgreSQL processes joined. |
| `composed-diagnostic1.log` | FAIL38.27s, PostgreSQL 6778 joined. The final 80 registration/catalog and 79 readiness/operator checks pass, but effective public61 readiness fails. The logged transition to false for ready61/68/72/78 already occurs after79. |

I inspected these records; I did not rerun their commands. Prebuild1's manifest matches all eight changed product sources, but its lineage test hash predates the added diagnostics. Prebuild2 matches all nine frozen sources. The earlier owner/derivation logs are retained checkpoints, not a claim that every final source byte ran in one green command.

The lineage adapter passes actual query results back to the installer. Its callbacks only collect diagnostics; they do not replace false readiness values. The supported-profile early return occurs after installed78/API readiness, not before it. The canonical failure occurs before the signed human80 finding-read/revocation assertions, so those assertions provide no passing evidence here.

## Still blocked beyond this correction

The diagnostic records ready61/68/72/78 changing from true after78 to false after79 while scope67 remains true and the 68 fingerprint remains unchanged. The 72 domain hash changes after79 and again inside80. This supports the separate domain-catalog compatibility investigation; this review does not claim the pending row-level diagnostic, accept a bridge or prescribe new pins. `base67=false` was already present in the working post78 composition and is not the new failure.

No policy81 implementation, current P7 worker/signer/effect proof, automatic77 unresolved retry, provider execution, deployed registration migration or full production composition is accepted. Earlier component packets remain evidence for their original hashes only.

Accept the bounded unpublished72 correction. Keep 79/80 composition and policy-family preflight open.
