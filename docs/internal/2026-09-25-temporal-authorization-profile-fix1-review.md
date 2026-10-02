# Temporal authorization profile F1 fix review

Date: 2026-09-25. Independent scoped SPEC and QUALITY re-review.

## Verdict

SPEC: PASS. QUALITY: PASS. Original Important finding F1 is resolved. New findings: 0 Critical, 0 Important, 0 Minor.

This accepts only the four-file F1 correction in `p7-temporal-profile-fix1`. It does not reaccept the broad authorization foundation, hierarchy or audit work, other Temporal families, or full P7.

## Scope and source identity

The authoritative comparison is the packet's frozen dirty-baseline `before/` against `after/`, not Git HEAD. I read the original review, fix instructions, proposal, report, manifest, complete scoped diff, relevant frozen source context, and all four raw RED/GREEN logs. I independently verified all 91 packet hash entries, all eight before/after candidate identities, and all 69 frozen context identities with zero mismatches. Both GREEN source manifests match all four candidate hashes. I did not rerun tests, launch services, or change product files.

Packet root: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-temporal-profile-fix1`.

| Artifact | SHA-256 |
| --- | --- |
| `manifest.json` | `fe3d08e1bfd5f797af3ec428e71858aec40697e5de6b96511304edb7f820e0c9` |
| `scoped.diff` | `26b401fce7ee733fd954b89e0867d9410423705c5ebf1265050c55e36a9454c0` |
| `hashes.sha256` | `e34092bbfd9741aa8b89ef6ea2fcc5aa60cbed470f0d30bcc70d208e343b5b5d` |

## F1 resolution and SPEC assessment

The original defect was not a missing hash. The profile hashed the actual 72 wrapper, but the only runtime guard was inside that replaceable wrapper. Returning the expected 72 fingerprint could bypass admission while the profile itself was unready. The correction adds independent enforcement at both relevant entry chains.

| Boundary | Frozen source and assessment |
| --- | --- |
| Native API admission | `after/migrations/sql/0080_production_authorization_enforcement.up.sql:65` makes `80.ready` require `runtime_profile_ready()`. The resolver at line 134 and fence at line 188 already require `80.ready`. Lines 24–39 dispatch only the two closed profile names; composed mode independently calls the private catalog, outside either Temporal fingerprint delegate. Missing composed dependencies cannot fall back to base. |
| Temporal admission | `after/migrations/sql/0080_authorization_temporal_profile.sql:109` adds `catalog_ready()` to the saved `68.ready(text,text)` predicate while preserving its original checks. The retained `context/migrations/sql/0078_production_temporal_finding_response.delivery.sql:14` entry calls `78.current_ready()` before delivery scanning, through the existing predecessor chain to 68. A constant 72 return no longer skips the independent 68 admission check. |
| Actual source identities | Profile SQL line 76 now hashes the actual 68 admission and fingerprint definitions alongside the actual 72 wrapper and domain function. Its own projectors, delegates, catalog guard and saved definitions are included. The 68 projection at lines 41–46 substitutes saved definitions only for the exact `68.ready(text,text)` and `68.fingerprint()` signatures. The full retained query, other function definitions, owner/ACL metadata, relations, RLS, policies, triggers and constraints remain live. |
| Protected profile selection | Main80 SQL lines 7–22 create a closed singleton selector with forced RLS and a statement trigger covering INSERT, UPDATE, DELETE and TRUNCATE. After registration, even the registered migration principal cannot mutate it through those operations. Lines 44–51 bind its value, trigger, columns, functions and surrounding security catalog to the registered 80 fingerprint. The profile catalog additionally requires the exact composed selector at profile SQL line 91. |

The readiness graph is finite. `80.ready` and composed `68.ready` call the private `catalog_ready`; that guard checks registered catalog equality, `79.ready`, the live 80 fingerprint, selector and exact triggers. It does not call `80.ready`, `68.ready`, full Temporal readiness or profile `ready`. The latter can safely compose full 78 and 80 readiness. Neither projected fingerprint output is used as the sole independent admission guard.

Standalone base mode does not require absent extension 78 or the private profile. Its selector branch requires those namespaces to remain absent. Composed mode explicitly requires them, so removal, renaming or attempted selector downgrade fails closed.

## QUALITY assessment

`after/migrations/production_authorization_temporal_profile.go:89` checks both projected historical pins before activating the changed entry points. Lines 94–119 install 80, bind the composed selector before registration, activate the wrappers, recheck both projections, then register the actual 80 and profile catalogs within the existing single transaction and schema lock. The final full-readiness check remains mandatory. There is no committed intermediate state with an active selector but unregistered catalog.

The fresh and exact-79 paths remain distinct. Exact replay requires the compiled profile checksum and full readiness at line 58; unknown existing 80 state is refused at line 61. The fix does not adopt arbitrary catalogs, alter historical 68–78 source/pin files, relax registration authority, or turn a projected fingerprint into a constant. Retained fault injection covers rollback from both supported starting shapes, including preserving an existing exact 79 installation. The old-checksum test exercises checksum refusal; it is not evidence of an upgrade from an old deployed binary.

The new test principal is registered through the existing 68 registration mechanism. `after/apiserver/authorization_temporal_profile_postgres_test.go:72` checks the real executor session identity and calls the granted `78.pending()` entry. It does not depend on granting a private readiness helper to the executor. Lines 169–177 add allow-valued 72, constant 68 delegate/projector, allow-valued 68 admission, selector and missing-dependency cases. Each case establishes working signed API and native Temporal entry preconditions, applies drift, requires actual entry rejection, and restores the source. Lines 239–249 also test all four selector mutations from owner, API and executor connections.

## Retained execution evidence

| Evidence | Result and interpretation |
| --- | --- |
| `constant72-red.log` | FAIL, package 43.774s. The probe fixture fails before drift because it attempted a private readiness helper. This is not the security regression proof. |
| `constant72-red-2.log` | FAIL, package 45.166s. With the probe corrected, the signed native API read and actual `78.pending()` entry both incorrectly succeed after allow-valued 72 replacement. This demonstrates original F1 at both entries. The recorded drift is an unrelated, unselected rejection-test file, not one of the four candidates. |
| `combined-green-1.log` | PASS: migration CLI package 1.088s; API package 129.328s; profile test 128.40s. Fresh install, exact-79 intermediate, replay/refusal/rollback assertions, standalone base and all 25 drift cases pass. The installed hierarchy test is explicitly SKIPPED; its checked-statement test passes. `source_drift=[]`. |
| `hierarchy-green.log` | PASS, package 24.183s; installed test 23.20s and all 11 subcases. Same four-file candidate, `source_drift=[]`. This supplements only the skipped base-profile hierarchy check. |

The raw logs record normal joins for their owned PostgreSQL processes. No reviewer rerun was needed for an unresolved in-scope risk.

## Limits and remaining gates

The profile test uses controlled local Check decisions and real signed SQL execution, not live OpenFGA authorization or deployment evidence. Its native Temporal probe is an empty `78.pending()` admission call, not execution of worker effects, worker FGA checks, compensation, phase transitions or full worker authorization. Replacing `68.ready` itself with true is tested through the surviving API/78 entry guards; this is not a claim that a directly replaced admission root must itself return false, nor universal resistance to arbitrary privileged catalog tampering or coverage of legacy writer paths.

The separate hierarchy test uses canonical61+79+80 without 78 and retained local OpenFGA with controlled credentials/signing. It establishes same-source base compatibility, not mounted hierarchy execution on the composed profile. Existing hierarchy additions in the main80 baseline are not independently accepted here. Production installation, deployment, all operations, full P7 and release readiness remain unverified by this review.
