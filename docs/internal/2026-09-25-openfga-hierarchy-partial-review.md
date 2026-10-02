# Spec compliance: partial, full scope incomplete

The delivered create/four-table checkpoint matches its released contract. Full hierarchy/P7 acceptance remains blocked by the already recorded audit-isolation, current-profile regression, public getEnvironment/scope-switch and environment-class-selection gates. None is waived by this review.

Task quality: **Approved for this frozen partial checkpoint.** New findings: 0 Critical, 0 Important, 0 Minor. This is not merge, deployment or full-spec approval.

## Reviewed bytes

Review date: 2026-09-25. I reviewed `p7-hierarchy-create-brief.md`, the implementer's complete report, manifest and 916-line scoped diff. The review uses the eight frozen files under:

`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-hierarchy-create/after/`

Call that directory `A` below. Every `A/file:line` reference names the frozen file, not the concurrent live candidate. I independently verified all eight SHA256 values against `manifest.json`. The main80 candidate is `fce8eb86ad369ce3cbed187c8f59918929d4a91250981c8bd8dd3f702ae2d802`; the new fragment is `936d7d092fec23560498c7747f80826eccf2f6f90dbae5abaa939f620dda5940`. The resolver snapshot is unchanged.

No product edits, tests, service calls or agents. The only new file is this report. Later profile-F1 changes to live80 are outside this review.

## What holds up

The current route preserves the selected-scope contract. `A/administration_repository.go:173-192` sends each checked create to its nine-argument SQL statement and literal `[]`; the old constants/non-enforcing branches remain intact. Foreign requested workspace still returns the existing not-found result before SQL. `A/authorization_statement.go:22-23,71-80,140-165` normalizes the different positional layouts into organization/workspace/environment and actor, checks the exact operation and selected-environment target, and leaves the actual SQL arguments unchanged. `A/authorization_targets.go:19` still maps both creates to the selected environment.

Native admission does not borrow legacy permissions. `A/0080_authorization_hierarchy_create.sql:65-85` checks source readiness, the actual API principal, exact operation/scope/actor, BrowserSession, manage_identity, freshness, selected-environment allow and current identity fence. It rejects any compatibility value other than JSON `[]`. The active-membership/direct-selected-scope restriction is separate from FGA allow. That matches the controller's explicit group-only policy.

The writes preserve the old result and audit shapes (`A/0080_authorization_hierarchy_create.sql:87-139`). Workspace creation includes its Development environment; both paths insert a direct scope, bootstrap correlation payload, default controls and the appropriate audit in the same SQL statement. Workspace audit stays in the old scope, environment audit uses the new environment. There is no receipt invented for these creates, internal retry, creator-admin grant or session/default-scope update.

Four-table isolation is narrow. The invoker trigger checks actual current_user and the installation-bound registered owner, with only the retained source19 direct-scope DELETE exception (`A/0080_authorization_hierarchy_create.sql:7-35`). The readiness helper validates exact trigger arguments/type/enabled state and function security/ACL (`37-63`). The owner loop exempts only the two added exact wrapper signatures alongside the existing controls wrappers (`A/0080_production_authorization_enforcement.up.sql:258-261`). The fragment does not grant raw API control insertion or ownership. Main80's new catalog rows cover the four relations, their triggers, columns, constraints and policies (`21-25`); its existing function selector covers the new guard/wrapper bodies (`9`).

Embedding is present in the right order. `A/production_authorization_enforcement.go:41-54` includes the fragment after controls, and `A/0080_production_authorization_enforcement.up.sql:247-248` places the corresponding marker before ownership finalization. All released files have their required hunks; the resolver was deliberately unchanged.

## Evidence I checked

The full retained `terminal/hierarchy-create-integrated-2.log` ends with exit0 and package PASS23.598s. Its eleven installed subtests pass, followed by the focused routing test. The log records committed NOSUPERUSER/NOBYPASSRLS demotion on the original registered owner session, verified restoration and normal join of owned PostgreSQL PID15997. No warnings or unexplained output appeared in that GREEN log. I did not rerun it.

The assertions support a bounded claim:

- Mounted creates and atomic effects: `A/authorization_hierarchy_create_postgres_test.go:220-247,282-312` check exact response fields, ETag1, persisted hierarchy/grant/bootstrap/control/audit rows and unchanged stored/default selection. Raw hierarchy INSERT/UPDATE/DELETE and TRUNCATE refusal is separate at248-281.
- Actual projected tuples and official OpenFGA Checks are used at78-109 and215-218. The membership/group/direct-row matrix at313-365 proves that selected group-admin authority does not become admin authority on the new direct scope, and group-only allow does not bypass the direct-row restriction.
- Refusals and rollback. Lines366-502 cover mounted credential/CSRF/freshness/scope failures, revoked credential, stale revision, fresh Check with stable prepared IDs, native wrong-purpose/actor/organization/environment/array calls, late audit collision and duplicate ID/name. The snapshot at199-211 includes all six table counts and desired revision.
- Lines503-555 prove projection-pending rejection and the current stored-selection boundary through getDataControls. The test explicitly uses controlled selection at534; it does not prove a public scope-switch or getEnvironment implementation. Source56 helper, source19 deprovision and source14 cutover checks are at557-593. Six catalog/owner/ACL/RLS drift cases are at594-613.

The signer/browser identity boundary is controlled. These are local mounted-handler, real registered PostgreSQL and owned-store FGA results, not live Stytch or deployed evidence.

## Named risks checked outside the diff

The classifier and repository hunks stop mid-function. I read their frozen surrounding functions to check normalized scope/actor positions, target comparison and the pre-existing BrowserSession requirement; references are above. I also read the unchanged frozen resolver entry for the risk of accidentally substituting organization identity for the selected environment. No such substitution is present.

For the risk that new statement guards break retained writers, I checked source19's actual deprovision DELETE and owner finalization (`services/platform/migrations/sql/0019_identity_administration.up.sql:296-315,374-383`) and source14's invoker cutover DELETE (`services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql:618-624`). Their identities match the guard's two permitted paths; the frozen installed test exercises both.

I read the unchanged controls-source helper to check that the new hierarchy readiness does not merely trust its own permissive helper. `services/platform/migrations/sql/0080_authorization_data_controls.sql:18-29` calls80 readiness and checks source7 registration, registered controls owner, forced RLS, wrapper security and retained audit ACL. Its live hash matches the retained pre-test source capture. Source19/source14 are historical source inspections, not entries in this packet's capture; the relevant installed assertions are frozen. This was a dependency inspection, not a re-review of accepted controls/foundation work. I also verified the retained integrated2 log and source-capture hashes against the manifest.

## Issues and limits

Critical: none found in the delivered diff. Important: none new. Minor: none.

Full-spec gaps remain explicit:

1. Audit isolation is unfinished. The wrappers' audit insertion and rollback are tested, but raw API audit writes remain open. `A/0080_authorization_hierarchy_create.sql:108-110,132-134` cannot establish native isolation of that sixth effect table. The separate audit compatibility/rejection work must finish before claiming full isolation.
2. This GREEN is not the required combined current-profile regression. Its fixture installs canonical61/79/80 (`A/authorization_hierarchy_create_postgres_test.go:49`); it does not install the Temporal78 composed profile. The separate profile-F1 owner must supply current-source combined evidence. This review neither approves nor reopens that owner's implementation.
3. Public getEnvironment, public scope switching and original environment class selection remain incomplete. The controlled getDataControls check at503-555 does not replace those requirements. The development-only insert at122 is the approved bounded contract, not satisfaction of original M2-46b production/staging/development selection.

Keep this verdict attached to the frozen eight-file checkpoint. Do not use its23.598s result to certify later shared80 edits.
