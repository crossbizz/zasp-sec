# Automatic sources: audit checkpoint, September 24

Status: grouped implementation in progress after controller design and execution-plan approval. The original audit below is preserved as the pre-edit checkpoint; later decisions and tests are recorded at the end. No deployment or completion claim. The original 728 requirements remain binding.

All source paths below are relative to `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`. I preserved the existing overlay. No commits, pushes, provisioning, shared database mutation or authoritative ledger edits.

## The baseline is recoverable

`p4c-automatic-source-baseline` under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan` contains a copy of all 4,865 tracked/nonignored regular files: 78,129,330 bytes. It includes API, UI, deployment and both platform/runtime-gateway modules. `manifest.json` contains each file's SHA256, size and mode, plus HEAD and capture time; `status.txt` and `tracked.patch` preserve Git state. The capture script refuses an existing destination.

HEAD: `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. Baseline manifest SHA256: `10520ea82d415bc4e9d9b35cf8e2df8f545cc93a0f68f7953be5f1d140452137`. The controller independently checked all 4,865 copied hashes and sizes. Ignored build outputs and earlier evidence packets are not claimed as copied by this snapshot; their originals remain untouched.

The accepted 76 report/review and remaining-trigger brief were read. The accepted source and its evidence packet are unchanged. Historical SQL is unchanged.

## What the current product can express

The public closed definition schemas expose `trigger_kind` and `trigger_source`, with kind limited to finding, attack_path and runtime_decision (`openapi/openapi.yaml:3660`, `:3681`). There is no severity, runtime count/window/risk, cooldown or manual-only setting. The strict Go definition decoder reconstructs `securityagent.Trigger{Kind, Source}` (`services/platform/apiserver/security_agent_repository.go:226`, `:248`; `services/platform/securityagent/types.go:12`).

The builder fixes sources to finding=`credential`, attack_path=`verified`, runtime_decision=`block` and submits that map (`app/features/securityagents/SecurityAgentsView.tsx:239`, `:343`). It displays the template trigger, but has no rule editor. Editing a definition saves a disabled draft; the SQL mirror bumps the resource version and records a versioned body (`0018_security_agent_execution.up.sql:338`). This is not user-configurable matching.

The ordered definition/context validators also use closed property lists, limit triggers to finding/path and limit paths to observed/verified (`0062_production_security_agent_public.up.sql:60`, `:66`, `:116`, `:120`). A new field cannot be added only to the browser or Go struct. Any extension must carry through persisted validation, readback, activation, copied authority functions and their exact compatibility pins.

The durable path table supports `potential`, `observed`, `verified`, `blocked` (`0009_production_risk_projection.up.sql:63`). The component matcher supports only potential/verified (`securityagent/triggers.go:35`), while production selectors support observed/verified. Potential must remain potential; treating it as observed would change meaning.

## Requirement-by-requirement evidence

| Requirement | Actual evidence | Missing boundary or limit |
| --- | --- | --- |
| M7A-35 | 75 copies the scoped persisted-source query: open findings matched by rule, enabled definition, tenant/environment and current binding. Retained finding schedulers also match rule/source. | No public or persisted minimum-severity rule. Component `MatchFinding` has severity but is not the registered product matcher. |
| M7A-36 | 33 and 55/75 require exact observed/verified state and `zasp_risk_attack_path_valid`. A potential path does not match verified. | Builder fixes verified. Existing public ordered validators reject potential; no complete user-configured state contract across routes. |
| M7A-37 | 24 and 55/75 use persisted gateway decisions with current device/credential checks, blocked decision and a fixed five-minute window. | No configured count/window/risk. Latest-event selection is not aggregation. Gateway event contract has no risk field. The ordinary proxy outcome differs from the builder default, detailed below. |
| M7A-38 | Durable source ID/version receipts and canonical run IDs prevent repeated admission of the same occurrence. | No configured cooldown. Permanent source-version dedup is not a bounded cooldown. Component dedup is an in-memory map. |
| M7A-38a | Durable source tables and trigger receipts have organization/workspace/environment scope and canonical source identity. Memory `TriggerEvent` validates scope and ID. | The source writers inspected do not insert an internal automatic-source event. A run receipt is a later admission record, not a source event. |
| M7A-38b | 75 Temporal Schedule -> scoped selection -> 73 admission/start -> 74 execution is an accepted local path. Retained 18/22/23/24/33 selectors queue their supported families. | No verified common one-source-event dispatcher with configured matching/cooldown across enabled responder families. Memory dispatcher takes `MemoryRepository` and injected enqueue. |
| M7A-38c | Real finding, path and runtime mutations exist, and periodic selectors read committed state. | Inspected real writers finish without a matching source-event record. Need atomic source-to-event capture and registered consumption, including rollback and replay checks. |
| M7A-38d | Accepted selector tests cover local actual Temporal execution; component pipeline covers three synthetic sources and replay. Historical combined E2E cited by the ledger covers a verified path. | Neither packet proves all three actual durable writers reach configured responders with duplicate-safe admission. |

Historical ledger rows 514-521 mark these requirements production-available. Their evidence descriptions identify real v27/v33 scheduler behavior. I am not demoting or rewriting them. The descriptions do not cover the entire original deliverables: for example, 38c cites a scheduler reading canonical path authority, while the original deliverable requires events emitted by three durable source writers. These are distinct evidence claims.

## The actual source boundaries

Finding changes have multiple callers. `apiserver/risk_repository.go:29` calls `zasp_risk_mutate`, whose update/audit/receipt are in one SQL transaction (`0009...up.sql:354`). Discovery's registered `DiscoveryExecutionRepository.ApplyRiskProjectionInput` calls `zasp_execution_apply_risk_projection` (`discovery_execution_repository.go:625`, `:655`). Its 14 implementation validates projection authority and applies inventory findings. `zasp_inventory_refresh_posture_findings` and `zasp_inventory_apply_findings` write the same canonical finding table (`0014...up.sql:756`, `:794`, `:871`, `:891`). Response actions also change finding state (`0018...up.sql:865`, `0021...up.sql:172`). An emitter added only to one Go repository would miss these writers.

Path state/evidence is written by `zasp_inventory_apply_findings`. It updates state/version, then replaces nodes/evidence and updates finding links within that transaction (`0014...up.sql:943-975`). A row-trigger callback must not call the matcher before those child writes finish. Capture immutable source identity in the transaction, consume only after commit, and re-read final evidence under current scope. This writer creates observed paths and preserves blocked paths. The audit has not yet identified a registered production writer that promotes a path to verified; the existing verified fixtures must not be called real verification-source proof.

Runtime: `services/runtime-gateway/production_runtime.go:75` sends the actual event through gatewaycontrol. `gatewaycontrol.PostgresRepository.Record` uses `zasp_runtime_gateway_record_event_v27` with fallback only for undefined function (`gatewaycontrol/postgres.go:120`). The v27 writer authenticates the current credential, validates scope and event digest, checks exact replay, advances the replay floor and inserts `zasp_runtime_gateway_events` atomically (`0027_production_recovery.up.sql:42-69`). The source has event ID, device ID, credential ID, session classification, sequence, decision, action_kind, policy IDs and occurred/recorded timestamps. Replay returns its original recorded time.

Two concrete runtime gaps:

1. The real proxy sets classification outcome to `requested` (`services/runtime-gateway/proxy.go:288`). Runtime stores the evaluated decision separately and copies the classification unchanged (`runtime.go:389-397`). 55/75 requires decision=`block` AND classification outcome equal to `trigger_source`; the builder chooses source=`block`. Ordinary proxy events do not satisfy that default. Other authenticated callers can supply a different allowed outcome, so this is not proof that every runtime trigger is absent.
2. Gatewaycontrol's closed event validator and v27 SQL classification list contain no risk (`gatewaycontrol/contract.go:82`; `0027...up.sql:46`). Policy IDs and action_kind exist. `MatchRuntime`'s free string Risk in the component package does not supply production risk provenance. A policy-derived risk field, or an explicitly approved interpretation based on existing authoritative policy attributes, is needed. Unknown historical risk must not become a fabricated value.

## Existing periodic behavior stays visible

75 copies the 73/55 candidate query into `select_body`, scopes it to a definition, disables legacy delegation there, and keeps retained delegation in a separate `retained_body` (`0075...up.sql:125-149`). Its durable checks include current service authorization, all-owner capacity and immutable 73 start capture. Its Schedule reconciliation scans definitions/configuration, not source events. `TestSelectorWorkflow` calls `AdmitTestSelector`, which invokes `zasp_temporal75.admit` (`orchestration/test_selector.go:138`; `agentsec-worker/temporal_test_selector.go:115`).

The Schedule skips overlaps and has a 10-second Temporal catch-up window (`orchestration/test_selector.go:83`). Each tick queries current persisted finding/path state and runtime events in the fixed window, so source catch-up is different from replaying missed Schedule ticks. Changes return definitions to draft; desired state pauses disabled definitions, and admission reauthorizes current version/grant (`0075...up.sql:53`, `:159`). Activation74 binds a service grant to exact version/body digest, not the creator's browser-session lifetime. Historical timestamps, receipts and run IDs must remain unchanged.

## Proposed design for controller ruling

This is architectural work inside the approved plan because the missing requirements cross the definition, source-ingest and admission contracts. I recommend one additive, versioned automatic-trigger authority with three grouped stages. These are implementation stages, not a replacement scope.

First, add optional versioned `trigger_rules` to the current definition body and strict public schemas. Omission retains exact legacy behavior. New UI-created rules explicitly select automatic or manual-only; finding minimum severity and family; path evidence state including potential/observed/verified; runtime decision, action, risk filter, count 1-100 and window 1-86400 seconds; cooldown 1-86400 seconds. Keep current kind/source values for compatibility and canonical human routes. Manual-only suppresses automatic dispatch without inventing human provenance or a new trigger kind. Saving rules creates a disabled draft and requires activation again. The rule's exact body participates in existing immutable definition digests.

Second, record immutable, tenant-scoped source-event identity in the same transaction as canonical mutations. An additive AFTER-row capture on finding/path/gateway tables covers registered writers and future callers without making network calls or acquiring run/budget locks inside source updates. Path child evidence is resolved only after commit. Persist source kind, canonical ID/version or event ID/sequence, original occurred time, capture time and payload digest; source update rollback also rolls back capture. Duplicate source input gets the same event. Keep source events distinct from per-definition delivery and admission receipts. No generic external webhook.

Third, use a bounded Temporal dispatcher for source events and the same matcher/admission rules for periodic catch-up. A minimal immutable delivery receipt and pending-outbox scan can bridge committed events to deterministic Workflow IDs; no claim lease engine or custom scheduler. Temporal owns retries and work progression. SQL owns current scope, enabled/version/grant/source checks, shared capacity, cooldown serialization, canonical run/start receipt and duplicate suppression. Two identities are needed: permanent event+definition occurrence dedup and a definition+canonical source/pattern cooldown key. A new source version inside cooldown is suppressed; replay of an old event never creates a run after cooldown. A later genuinely new event may create a run once cooldown expires. Runtime aggregation counts distinct authoritative event IDs in an explicit bounded window and retains its matched evidence IDs/digest.

Runtime risk needs a ruling before implementation. My recommendation is an optional, versioned policy-evaluation risk annotation derived by the authenticated gateway from its authoritative policy result, carried in the existing signed/digested event contract and persisted without rewriting historical events. Missing risk is unknown and does not match a configured risk. This needs a source-contract and evaluator change, not a definition-only field. The exact product risk vocabulary/source is still under audit. Do not alias outcome, action_kind or block to risk.

Focused follow-up found that the policy result has no current risk value: `policy.Policy` has no annotation (`services/platform/policy/policy.go:31`), `CompiledPolicy` has no risk (`:60`), and `Decision` contains only Action and Matched (`:86`). The actual evaluator loops over signed compiled policies, records matched policy IDs and chooses block/monitor (`services/runtime-gateway/runtime.go:333-351`). A risk annotation must start in the versioned scoped policy input/API validation, survive compilation and the signed bundle, then be aggregated only from matched policies. The gateway's event wire/codec, replay persistence, gatewaycontrol HTTP/client/SQL validation and canonical digest must all preserve it. Expired-policy fail-closed block has no matched policy and must remain unknown risk. Proposed vocabulary: low/medium/high/critical, with the highest explicitly annotated matched policy risk; absence is unknown, never inferred from block. The controller must approve this product annotation.

A narrower alternative joins authoritative scoped resource/finding risk during dispatch. That would describe resource risk, not policy-evaluation risk, and changes the meaning of the requirement. Leaving risk unimplemented is also possible only as an explicit unfinished M7A-37 dependency. I recommend the annotation path, with old event and bundle contracts accepted unchanged and new annotations protected by a versioned signed contract.

For definition enable/update catch-up, retain today's explicit current-state scan for legacy definitions. New rules should use the same configured matcher on current canonical state and bounded runtime evidence, with source-event identity reused when present. Activation itself must not fabricate a source mutation or rewrite its time. Whether a newly enabled responder intentionally catches a still-open pre-activation finding is a product choice; preserving current behavior is my recommendation. Definition version belongs in receipt provenance but should not reset an unexpired cooldown for the same definition ID/source pattern.

Alternative A: change only75's query and periodically reconstruct events. Smaller patch, but it misses atomic emission and cannot prove 38c. I do not recommend it.

Alternative B: emit from individual Go callers. That keeps table catalogs quieter but needs every discovery/action/runtime path to participate, and a post-commit publish failure loses delivery unless each writer also inserts an outbox record. The canonical-table capture covers the actual shared boundary and costs fewer writer changes.

## Responder families cannot disappear

| Current family | Existing owner/admission evidence | Design consequence |
| --- | --- | --- |
| Single run_test/rerun_test | 75 ->73 immutable admission/start ->74 service execution;76 separately preserves human routes | New source dispatch can reuse this authority with configured source checks, preserving75 catch-up and76 human semantics. |
| update_finding_response | Retained18/21 finding scheduler and retained worker; accepted76 report has actual retained coexistence proof | New matcher must cover this family too. Do not label a retained run74-owned. Preserve its current queue/executor until explicitly migrated. |
| create_temporary_policy | Retained22 finding and33 path schedulers, supervised approval path | Apply configured rules through the actual authority; retain approval/control/cleanup. Potential-state support must not bypass existing path validity. |
| revoke_integration_connection | Retained23 finding scheduler and approval/destructive-action authority | Include in matching/admission inventory, preserving its action-specific authorization. |
| isolate_session | Retained24 runtime scheduler using canonical session/event receipt | Requires the new bounded runtime evidence contract and explicit owner delivery. No copied worker loop inside an Activity. |
| Ordered multi-action | Public62 canonical finding/path IDs; Temporal68 execution for its migrated boundary | No automatic service provenance may be manufactured from a public human receipt. Needs a dedicated automatic-authority route that preserves ordered IDs and current service delegation. |
| start_attack_lab, create_evidence_export, send_response_webhook | Separate action/link/receipt families exist; source-to-automatic admission was not fully traced in this checkpoint | Enumerate actual enabled definition support before choosing an adapter. Lack of a verified dispatcher route remains a dependency, not permission to silently exclude these definitions. |

The new rule schema should not pretend that the specialized test route covers all enabled responders. Before production edits, the controller should choose whether this group installs the shared rule/event contract plus all existing automatic family adapters, or stages those adapters with explicit per-family acceptance. Full M7A-35..38d cannot be closed by the single-test stage.

## Grouped RED checks once the design is ruled

Use actual selected HTTP definition create/update/readback and UI form submission to prove persisted rules, strict refusal, disabled draft and reactivation behavior. Include manual-only and the potential/observed/verified distinction.

An owned registered PostgreSQL fixture should exercise real risk mutation/projection, path evidence update and gatewaycontrol.Record, inspect the committed canonical event, then invoke the registered Temporal dispatch boundary. Check rollback, exact replay, tenant mismatch, missing scope/ID, configured positives/negatives, distinct runtime count/window, cooldown expiry versus permanent replay identity, disabled/version/grant/source revocation and shared capacity. Source writers must not wait on Temporal or run/budget locks.

One connected composition test should consume a real committed event, reach the correct current admission owner, execute through Temporal and return typed/HTTP readback. Retained adapters need their own registered ownership/delivery checks; reuse accepted unchanged execution evidence where it actually applies. Tests target our integration, not Temporal/OpenFGA internals. Freeze source during nested builds and join all owned processes.

Existing evidence to cite without rerun: `TestTemporalTestSelectorAdmissionPostgres`, `TestTemporalTestSelectorLivePostgres`, `TestCanonicalTriggerSourcesDispatcherAndReplayE2E` (component only), `TestProductionDiscoveryExecutionPostgresSchedulesSnapshotsAndMonotonicProjection`, and the accepted76 native/connected/retained packet. Existing test names are coverage leads, not fresh results from this audit.

## Commands and honest limits

Ran the baseline script once: `node .superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/capture-automatic-source-baseline.mjs`; exit0, 4,865 copied files. Read-only `rg`, `sed`, `cat`, `git status`, `git rev-parse` and `git ls-files` traced the sources above. No successful suites were repeated.

Some initial source guesses did not exist: root/worktree `writing-style.md`, `securityagent/definition.go`, `securityagent/validation.go`, `securityagent/triggers_test.go`, `apiserver/discovery_projection_repository.go`, `services/platform/runtimegateway`, and a guessed27 filename. Those read attempts failed, then the registered paths were located with `rg`. The applicable style file was found at `/Users/manishmaheshwari/.codex/writing-style.md` and read. These were file-discovery errors, not product test failures.

Self-review: this checkpoint separates component matches, real periodic selection, canonical mutation and source-event delivery. It does not infer universal absence from constructor searches. It does not prove an installed event-capture deficiency with a RED test yet. Runtime risk semantics, registered verified-path production promotion, complete responder adapter ownership and exact compatibility object changes still need resolution. Accepted75/76 source is untouched.

The initial broad read-only file search was joined successfully with exit0. No owned process remains from this audit. PRD11.3:651 explicitly lists family/severity, path state, runtime pattern and Manual only; SA-1:776 explicitly requires the template or bounded builder. Both were read directly.

Overlay-relative changes at the audit checkpoint were this report and ignored baseline capture script/data only. No deployed-source, real-provider, Stytch or full FGA enforcement claim; P5-P7 and the original broader gates remain open.

## First rule-contract RED/GREEN group

The controller approved `2026-09-24-temporal-automatic-source-design.md` and checked `2026-09-24-temporal-automatic-source-execution-plan.md`. The risk ruling supersedes the preliminary highest-known suggestion above: contributors are the matched policies with the winning block/monitor action, any unknown contributor makes risk unknown, and no-match/cache fail-closed has unknown risk. More than25 matching definitions require durable Workflow continuation; an outbox acknowledgment is not dispatcher completion. Predecessor75/76 SQL and evidence stay unchanged; narrow Go integration is allowed with affected tests.

Evidence directory: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-automatic-source-evidence/logs`. `run-automatic-check.mjs` records command arguments, start/end time, output and exit code without replacing an existing log.

| Log | Command and result |
| --- | --- |
| `rules-http-red.log` | `go test -C services/platform -count=1 ./apiserver -run '^TestTemporalAutomaticRulesHTTPBody$' -v`: valid manual/finding rules rejected by the actual body-parser function. Two failing cases; legacy omission and invalid forms passed. Package1.045s, exit1. |
| `rules-ui-red.log` | `npx vitest run apps/web/api/security-agent-trigger-rules.test.ts app/features/securityagents/SecurityAgentsView.test.tsx -t 'trigger rules|Trigger rules|configured trigger'`: seven configured decoder forms rejected and Builder lacked Trigger mode. Eight failed,11 passed,99 intentionally unselected;1.38s, exit1. |
| `rules-http-green1.log` | Same Go command: all12 cases pass, package1.026s, exit0. |
| `rules-ui-green1.log` | Same selected Vitest command:19 pass,99 intentionally unselected;1.51s, exit0. |

These are parsing/client/UI behavior checks, not mounted authentication or installed SQL proof. The UI test uses the actual public client with controlled fetch. Node emitted existing module.register deprecation and localStorage environment warnings; the logs retain them. Both RED and GREEN process groups were joined. Source was not edited while each group ran.

The first implementation adds a strict optional rule decoder, public rule schemas, TS validation and Builder controls. The actual HTTP body parser retains rules in its canonical output; duplicate keys, case aliases, null, extra fields and kind mismatch are rejected. Legacy omission remains omitted. No new definition becomes automatically runnable on this evidence alone. Detail editing, installed persistence/current authority and full source dispatch are still being implemented.

`npm run openapi:generate` completed with openapi-typescript7.13.0 and regenerated the client. The installed persistence RED and typecheck commands started next; no result is claimed until their logs finish.

## Installed create/readback checkpoint

`rules-typecheck1.log` failed on two new test typing mistakes (unknown JSON spread and tuple inference). Both were corrected; `rules-typecheck2.log` is exit0. Later detail changes still need their own typecheck.

The installed attempts exposed a separate composition issue before persistence. `rules-postgres-red1.log` failed on missing handler ID-factory configuration, not product behavior. `rules-postgres-red2.log` returned503 in both selections. Diagnostic1/2 proved74 readiness true and replay `{found:false}`, with no mutation reached. Diagnostic3 traced `public.zasp_sa_attack_lab_readiness` to false for both the unchanged omitted-rule control and configured single-test input. The handler unconditionally probed57 for a request that only needed74. Each PostgreSQL process was joined normally; these failed attempts remain in the evidence directory.

The controller approved checking the entire bounded, unique requested-action list, probing each included family. No worker readiness substitute was used. `rules-capability-red.log` showed legacy/configured single-test requests wrongly failing503. `rules-capability-green1.log` passes all6 cases in1.027s: unrelated57 no longer blocks single-test definitions, while requested unavailable74, requested57, a mixed list containing57 and invalid lists still fail. This does not repair57 attack-lab readiness or prove that family's automatic adapter.

`rules-postgres-red3.log` reached actual74 configuration writes. Both configured creates returned201 and retained rules in body/history with matching digest; typed activation readback rejected the new field. **This corrects the preliminary SQL assumption:** the single-test74 writer accepts and preserves extra rule data. It is not evidence that every ordered/specialized writer does.77 still needs strict SQL rule validation, raw-caller refusal and capability-checked activation so new rules cannot execute through a selector that ignores them.

After adding the field and strict rule decoding to typed activation readback, `rules-postgres-green1.log` passed39.933s (fixture38.90s), both production handler selections. It proves configured finding draft create, persisted/history equality and digest, disabled draft/version1 and typed activation readback. Owned PostgreSQL10390 was joined with pg_ctl0/server Wait0. Authentication is supplied at the handler boundary. No installed77, activation, dispatch, real provider or deployment proof is claimed.

Saved-definition editing now uses the shared rule editor and the actual public PATCH client. `rules-detail-red.log` and `rules-detail-red2.log` were test setup failures (empty/wrong list envelope). `rules-detail-red3.log` is the meaningful absent-editor failure. The first GREEN attempt exposed an incorrect test expectation of PUT; the client uses PATCH. `rules-detail-red4.log` then caught dirty-state comparison depending on JSON key insertion order. Draft normalization fixes that without treating PostgreSQL's reordered JSONB keys as an edit. `rules-detail-green2.log` passes1 selected test/100 intentionally unselected in1.03s: configured values read into controls, an unedited rule remains clean, a manual-only edit blocks activation until save, and PATCH sends the disabled draft with explicit manual rule. All source was frozen while each owned test group ran.

The latest checkpoint leaves no owned process running. Group1 is not complete: raw-SQL validation/activation safety, update/history coverage and the final schema/typecheck remain. Groups2/3 have not yet been implemented. Accepted75/76 SQL is untouched; no ledger, shared service, commit or publication was changed.

## Guard-stage checkpoint, still private

`rules-authority-red.log` (48.619s) proves three raw74 SQL calls accepted malformed rules: null, unknown mode and zero cooldown. In that same run both selected public handlers passed the expanded exact semantic submitted/response/body/history comparisons and PATCH roundtrip: version2 manual rule, disabled draft, immutable version1 rule/digest. PG10912 joined normally.

Private77 now adds only its own schema/tables/functions and the named BEFORE INSERT/UPDATE `zasp_temporal77_definition_guard` trigger on canonical definitions. `rules_valid` checks optional version1 rule shapes/bounds; omission is unchanged. The guard checks77 readiness on configured writes, rejects malformed input and refuses configured validation/activation until an explicit family adapter replaces the staged `rules_capable` refusal. Installation rejects preexisting malformed or non-draft configured rows. No existing effective function or ACL was changed in this guard stage. No migrate CLI command exposes77 yet.

The first compile attempt `rules-authority-green1.log` intentionally failed registration with the zero development fingerprint; rolled-back DDL compiled and predecessor76 readiness stayed true. Its preliminary fingerprint was2fd3f424b23bed44973ccc79435ffabff0f045608cceb1b17001363780e00944. After adding guard readiness, preexisting-row checks and strict integer version parsing, `rules-authority-compile2.log` again compiled independently and kept76 ready. The guard-stage pin is `bfe6b61986368c1d8e7b4671a6bc207c5893fb9183c294fe7a942ebfd379d177`. Both owned processes were joined normally (PG11516 and11829).

`rules-authority-green2.log` passes56.616s (case55.65s), PG12141 normal join. Both selected public create/update cases pass, all3 malformed raw SQL writes are refused with22023 and no definition row, and the actual74 activation of a potential-path draft is refused with the named unsupported-capability error without changing version1/draft. The pin covers the new schema catalog and exact guard trigger. The configured family capability remains disabled pending groups2/3; this is not an accepted/installable publication stage.

`rules-typecheck3.log` and `rules-openapi-check.log` both exited0 after the detail changes. No processes remained at this checkpoint. No unaffected guard-suite repeat is needed before later SQL changes affect it. Group2 risk provenance is next; the full three-group review and all deployment/provider gates remain open.

## Risk contributor and durable-codec checkpoint

`risk-policy-red.log` failed all four annotation cases plus unknown-risk validation: compilation discarded the annotation and accepted an unknown label. `risk-runtime-red.log` stopped before tests because the runtime module's existing indirect dependency pins needed synchronization with the platform module. A read-only tidy diff identified no new requirement names; the applied module/sum changes update Go1.25.4 and existing OTel/x package pins. `risk-runtime-red2.log` then reached all six actual evaluator cases and failed because evaluation provenance was absent (0.627s).

The expanded real-disk test initially failed on macOS's symlinked temporary path (`risk-runtime-red3.log`,0.825s). Resolving that path as the existing evidence-store fixtures do yielded the intended missing-provenance failures in `risk-runtime-red4.log` (1.201s). Both setup failure and meaningful RED are retained. `risk-contract-red.log` showed the authenticated event decoder rejecting valid known/unknown evaluation objects (0.759s).

`risk-runtime-green1.log` passes all six cases (1.365s): losing unknown monitor, unknown winning block, maximum fully annotated block set, monitor winner, no match and expired fail-closed. Each uses real compiled/signed policy cache evaluation, the real disk evidence store, close/reopen and exact evaluation replay, then verifies the delivered event wire retains the same evaluation and leaves classification.outcome=requested. Control-plane IO is substituted. This is not registered HTTP or PostgreSQL ingestion proof.

`risk-policy-contract-green1.log` passes five policy subcases (0.596s) and twelve evaluation contract cases (0.862s). Omitted policy risk retains the exact original SHA256(Rego) digest; annotated digests bind a policy-risk-v1 domain separator and the annotation. Signed bundle validation rejects annotation tampering. Shared evaluation parsing rejects unknown/null/empty risk, wrong version, extra/case fields, foreign/unsorted contributors, unattributed known risk and mismatched session. Risk is unknown when any winning contributor lacks annotation; the losing monitor does not contribute. No-match/cache failure contributes no policy.

The actual proxy supplies normalized action/agent/session attributes; transport http/mcp and request classification remain distinct. Sparse legacy internal Evaluate calls without that normalized context omit evaluation rather than inventing provenance. Configured runtime matching must exclude missing annotation/context as appropriate. All processes joined. Group2 still needs policy API/UI coverage, signed HTTP transport and atomic installed annotation persistence; group3 is pending.77 remains private, configured activation remains disabled, and no publication or deployment is claimed.

## Installed risk boundary, still not a completed77

`risk-api-red.log` exposed actual null/empty/duplicate/case annotations accepted201. Its known-response assertion used a repository stub's empty return and was corrected to inspect the canonical mutation, not claimed as product field loss. `risk-api-green1.log` still failed duplicate input because workflow canonicalization erased duplicate keys. Raw policy validation now runs before that canonicalization; `risk-api-green2.log` passes all7 cases in1.000s, including typed readback and exact known annotation in the mutation. Policy JSON validates present annotation before the empty Go value can erase null/empty input. Signed compilation remained passing in the affected first GREEN run.

`risk-ui-red.log` failed four annotated decoder cases and the missing production form field. `risk-ui-green1.log` passed all9 decoder cases but the form test incorrectly supplied PUT instead of the existing PATCH client. `risk-ui-green2.log` passes the selected form test in0.896s: load high, edit critical, then clear to omitted unknown. API methods are controlled at the client boundary; this is not mounted authentication or database proof. Actual create/edit policy forms and public schema include the optional annotation. OpenAPI7.13.0 generation completed177.9ms and `risk-typecheck1.log` exited0.

`risk-record-red.log` caught the real PostgreSQL repository selecting27 for annotated events and falling back after missing77. `risk-record-green1.log` passes both routing/refusal cases in0.789s. Omitted events keep the prior27 path; present evaluation selects only77 and cannot downgrade on an error.

`risk-postgres-red.log` failed fixture setup because no runtime principal was bound; owned PG16048 joined normally (30.221s). Six fixture-local runtime roles were then registered through the existing runtime binding API. `risk-postgres-red2.log` reached the actual annotated gateway-role SQL call and failed42501 on schema77 (30.091s, PG16291 normal). `risk-postgres-red3.log` also proved installed deployment compilation rejected all4 annotated policies40001 while omitted SQL/Go output and signed consumption passed (30.127s, PG16676 normal).

The controller approved the exact installed compiler amendment described in the execution-plan addendum.77 saves original `zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)`, owner/ACL and hash26cafd835aeb6e7203b913753d39cf9390c29cb6a20594edc637db862d3f9767. The omitted branch calls the exact copied predecessor. Annotated output adds risk and hashes bytea with the same NUL separators as Go; monitor rollout override and trigger mapping remain in that predecessor. Only67.base_fingerprint and67.fingerprint are projected to their saved definitions for compatibility, and77 binds all three effective objects. Historical SQL is unchanged.

`risk-postgres-compile1.log` independently compiled the candidate DDL, deriving fingerprint `f3d87ea55d88221809d615641fd3663c5d55ef2ec64f0e421234e6a93f3eb529`; the old guard-stage pin correctly refused registration (31.755s, PG17342 normal). Base/domain projections exactly equal accepted68 pins c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a and499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf.

After binding that derived pin, `risk-postgres-green1.log` passes31.003s (case29.98), PG17752 normal. Five SQL/Go compiler and signed-consumer cases pass, malformed annotation and signed tampering fail. The actual gateway-role database writer persists exact evaluation atomically with the unchanged27 event, binds the combined digest to evaluation, preserves original timestamp/floor and legacy digest, accepts exact replay, refuses changed evaluation and historical27 backfill40001, rolls back event/annotation/floor together, denies the API principal and rejects revoked credential28000. This is gateway-role database evidence, not yet the signed HTTP path. The companion table has immutable rows/RLS/FK; the gateway role receives only77 schema usage and its exact writer function, no table rights.

The next signed HTTP RED found an existing empty-policy-list clone bug and the new provenance pointer's shallow copy (`risk-http-red.log`,0.853s): no-match and expired fail-closed signed requests reached503 while known-risk block passed. `risk-http-green1.log` passes all three real Ed25519 HTTP scenarios and clone independence in0.763s, including signed-body risk tampering refusal. Persistence is controlled in this focused HTTP test; group3 will connect the authenticated handler to the actual77 repository.

The affected regression batch passes: `risk-regression-platform.log` policy0.836s/gatewaycontrol0.485s, covering legacy policy compilation, signed envelope/cache,27 readiness and signed HTTP authority; `risk-regression-runtime.log`1.414s covers disk restore, drained replay and all six risk-contributor scenarios. No unrelated successful suites were repeated.

`risk-installed-green2.log` joined98.559s, overall exit1: rule persistence/guard passed55.53s (PG18551 normal), but the added foreign-credential fixture failed its enrollment timestamp constraint before the authority assertion (PG18799 normal). `risk-installed-green3.log` joined31.084s and exposed copied token-hash uniqueness (PG19729 normal). These are fixture failures, not authority RED. The fixture now preserves issued/consumed timestamps and distinct token/locator hashes; existing table constraints are unchanged.

`risk-installed-green4.log` passes35.311s (case34.26), PG20020 normal. The combined digest is independently recomputed from canonical event plus evaluation and differs from the legacy digest. Foreign tenant credential with the original device is rejected22023 without writes; corrupting only the disposable77 catalog rejects annotated writes42501, restoring it returns both77 and76 readiness, and revoked credential fails28000. Previous compiler, no-backfill, replay, timestamp/floor, rollback and role-isolation assertions also pass. Source stayed frozen during each owned test process. Group2 local boundaries are covered; group3 canonical capture/dispatch and joined authenticated HTTP/database proof remain. Configured activation is still disabled. No availability promotion, shared-state mutation, commit or publication occurred.

## Canonical capture and finding-writer checkpoint

`sources-postgres-red1.log` (29.606s, PG22154 normal) did not establish capture RED. The actual finding repository reached the old public writer's55000 audit/export readiness refusal; projection prerequisite setup had an unused positional argument. `sources-postgres-red2.log` (29.644s, PG23186 normal) logged the exact current risk writer, confirming three global52 readiness calls and an additional local later-version>60 refusal on the61 graph. Projection prerequisites succeeded but duplicate principal registration failed23505. Reusing the already registered risk principal fixed that setup without new grants.

`sources-postgres-red3.log` is the meaningful capture RED:30.018s (case29.02), PG23885 normal. Actual registered `DiscoveryExecutionRepository.ApplyRiskProjectionInput` committed its final finding/path. The finding retained version1 after its same-transaction path_id update; the next assertion failed42P01 because77.source_events did not exist.

Capture now adds only three named AFTER-row triggers and immutable scoped references (source kind/ID/version/original timestamp/canonical event ID). It does not digest transient row images, perform network IO or take admission/budget locks. The occurrence insert tolerates the discovery writer's legitimate same-version finalization. Matching must still resolve final committed source/children. An initial eager backfill was removed on controller review before acceptance: installation contains no data scan/rewrite. Bounded durable worker catch-up remains to be implemented using the same canonical identities and original timestamps.

The controller approved a private77 invoker-security finding writer. Public `zasp_risk_mutate` and the global52 guard remain unchanged. The exact saved predecessor hash is b5366f9c295a2b46844dd6b04458cb706cef5e422f2c53c55b487b62bebbfdec, owner zasp_discovery_authority, ACL `{=X/zasp_discovery_authority,zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}`. The copy replaces exactly three guards and the local60→61 bound, preserves scope/visibility/audit/receipt/idempotency and grants execution only to the existing discovery API authority. Its guard checks77 and the current API principal, plus explicit live audit policy/worker/source-ACL/workflow-ACL predicates. No table privileges or SECURITY DEFINER mutation were added.

`sources-capture-compile1.log` compiled independently and derived ee5ebdf8dde44ca1599c79dc3c80879feacf64b0eceaf700543707ef0b6f262e, then refused the old pin (31.233s, PG25143 normal). After adding the finding copy and removing eager backfill, `sources-capture-compile2.log` compiled and derived current pin eae2a755a4a11f03111a9a2588596bf259730d135ddbf9ba8a92eda947edd3c3 (31.437s, PG26421 normal). Neither compile attempt is behavior acceptance.

`sources-capture-green1.log` passes41.980s (case40.96), PG27282 normal. The actual registered discovery API role proves finding rollback with no event/audit/receipt, commit with original timestamp, exact replay without duplicates, foreign-scope finding refusal, and private invoker/ACL preservation. All five logged release/live audit predicates are true. The registered projection role proves final valid path children, same-version finding occurrence and exact replay with only one finding and one path occurrence. Seeded snapshot/lease/inventory prerequisites are controlled; the production writer creates the finding/path/children.

Controller review caught the optional capability missing from the real API tracing decorator. `sources-wrapper-red.log` fails that exact boundary (1.091s); `sources-wrapper-green1.log` passes the decorator (1.147s) and typed mutation route (0.831s), including current repeated probes, omission compatibility, invalid77 refusal without SQL and no fallback after a77 SQL error. Signed HTTP→actual77 runtime capture is the next running affected check. Matching, bounded catch-up, dispatch, cooldown/admission and family adapters remain pending; no automatic rule is activatable yet.
# Connected gateway boundary checkpoint

The first signed HTTP source fixture failed before requests were signed because
the test clock had fractional seconds (`sources-runtime-http1.log`,29.960s).
Both fixture clock and signature now use the existing whole-second contract.
HTTP2 then returned503 with zero writes (29.854s). Diagnostic1 joined29.552s,
PG29354 normal: actual gateway principal=true, public recovery readiness=false,
SQL error=nil. Effective public27 readiness delegates28/29. Credential authority
also rejected the seeded fractional expiry; the fixture now uses whole-second
expiry without changing the production decoder.

Controller approved the narrow optional77 gateway readiness gate. No public
readiness function changes. Six routing RED cases failed meaningfully in
`sources-gateway-ready-red1.log`(.772s). GREEN1 exposed expensive recursive
metadata construction inside the request deadline: the valid stub exceeded1s;
the other routing and four legacy cases passed. The checksum-only accessor now
hashes the identical assembled77 source without binding ancestors. Database
readiness itself is neither cached nor weakened.

`sources-gateway-compile1.log` joined31.413s,PG29957 normal. Independent DDL
succeeded and derived catalog pin
`1a4cfd5a7dba3c589757fe9c3fe943ae3908130be205f7335385041bde878905`;
the old-pin installation rejection was expected, not behavior evidence. The
affected installed signed-route batch passed in `sources-runtime-http-green1.log`
(31.766s,PG30318 normal). It traversed the real signed handler, real gateway
principal, current credential authority, actual27/77 writers and atomic capture.
Assertions cover signed authority200, policy-no-update204, transaction visibility
and rollback, replay, omitted event without annotation, signature tamper401,
catalog-tampered77 refusal503 on all four route variants, and revoked
credential401. These are local seeded credentials, not deployed enrollment.

Gateway-control module compile1 stopped at stale module metadata. Compile2
passed .754s after Go1.25.4 and existing dependency pins were reconciled; no
requirement names were added. Checksum equality passed2.563s. That command's
apiserver selector matched no tests and is not coverage. The corrected
`sources-finding-route-green2.log` passed all three affected routing cases in
.753s. `sources-gateway-ready-green2.log` passed all six new and four affected
legacy readiness cases in7.745s. The new risk capability also uses the identical
checksum-only accessor. No group3
matcher, dispatch, catch-up or full requirement acceptance is claimed.

## Shared matcher in progress

`sources-matcher-red1.log` joined30.452s,PG31175 normal. All21 source cases
reached the absent private SQL matcher (42883); the runtime prerequisites used
actual77 Record/replay. Finding/path rows here are seeded canonical fixtures,
not another claim of registered writer coverage.

Compile1 failed42601 on reserved alias `window` (30.890s,PG31608 normal).
Compile2 compiled and derived pin4138b572...; expected old-pin rejection joined
31.169s,PG31803 normal. With that pin, RED2 passed the21 rule/source cases and
failed the two added same-version finding-title/path-child snapshot assertions
(30.492s,PG32031 normal). The source matcher now binds final row and ordered
children; legacy identity digests are separately named, not payload proof.
RED3 caught whole-result null stripping detaching the finding snapshot from its
digest (30.337s,PG32601 normal); the path snapshot case passed. Top-level optional
identity metadata is now merged without normalizing the hashed nested snapshot.
After compiled pin56a228e7..., `sources-matcher-green1.log` passed all25 cases
(30.589s,PG33230 normal): exact recomputation and same-version source/child
changes, plus unknown-risk and foreign-session count exclusion. This remains
private source-matcher proof, not admission or execution proof.
Enabled-definition grants, admission/cooldown receipts, paged Temporal
dispatch and bounded catch-up remain pending. New-rule activation remains closed.

## Bounded catch-up checkpoint

Catch-up RED1 reached a registered executor but stopped at missing77 schema
capability42501 (30.344s,PG33677 normal). Initial GREEN1 passed41.198s,
PG34404 normal:41 seeded preinstallation findings, a seeded path and an actual27
unannotated runtime event; no migration backfill, rollback, bounded25-row pages,
database reconnect/resume, original canonical identities/times, empty tails and
wrap, an overlapping uncommitted writer, and later committed-trigger dedup.
This proves reconnect, not an OS worker restart. Temporal restart proof remains
in the connected dispatch group.

Controller review identified that the first runtime cursor scanned lifetime
history before filtering24h. RED2 seeded40 expired historical rows in an earlier
scope and wrote31 same-timestamp recent events through actual27. It preserved31
recent/0expired sources and reconnected mid-page, but touched71 runtime rows,
failing the new31-row expectation (31.986s,PG34915 normal).

The approved correction reuses the existing27 scope/time index: bounded next
scope seek through gateway devices, then equal-time event IDs followed by older
timestamps with the remaining row budget. Runtime scope/time/ID are durable;
expired-only scopes advance without walking their historical rows. No public
index build, history rewrite, lease or retry timer was added. The revised
installed check passed in `sources-catchup-green2.log` (49.035s,PG35348 normal),
using catalog pin `c4fa6143b1aeed0f0329cef4176ac936f031251815cb969a8e05856b849e1df1`.
It examined exactly31 recent runtime rows, excluded the40 historical rows,
resumed across equal-timestamp pages and scope boundaries, and retained all
earlier atomic capture/catch-up assertions. SQL scan progress does not consume definition
occurrences, authorize actions, or replace Temporal delivery/retry ownership.

## Configured admission in progress

`sources-admission-red1.log` joined30.485s,PG37081 normal. Registered74 draft
creation and source capture succeeded; actual executor admission reached the
missing77 function42883. Compile1 independently compiled the new private
occurrence/cooldown authority and derived pinfb0ec533..., with expected stale-pin
refusal (31.448s,PG37548 normal).

GREEN1 failed36.068s,PG37847 normal on a mistaken test expectation: the old75
selector catches a rejected candidate and returns a created count, rather than
propagating42501. The corrected assertion reads that count and checks that no
run, trigger receipt or77 occurrence persisted. No historical75 SQL changed.

The initial adapter preserves75 admission/73 start/74 execution ownership for
single-test finding and observed/verified path rules. Runtime, potential and
other responder adapters remain unfinished and gated. The candidate captures
the final matcher snapshot in immutable per-definition occurrence receipts and
uses separate mutable cooldown state. Controller review identified that using
the current rule duration would shorten an existing window after an edit. The
next RED includes600→1 before implementing a stored admission-time deadline.
Legacy pre77 receipt interoperability and connected delivery are not yet proved.

RED2 joined43.231s,PG38143 normal: the shortened-duration edit reached existing
test concurrency40001 instead of cooldown. Shared capacity prevented an extra
run. The fix persists `admitted_until` when an admission succeeds; edits affect
future windows, not that deadline. Compile2 derived6455ba624ee035320ac60d32567557f211196d03425d9bfa22160f3831334c58
(31.533s,PG38487 normal). GREEN2 stopped at duplicate fixture role42710 after
actual pre77 admission (25.176s,PG38783 normal). The test helper now upgrades
after75 without recreating74 roles.

`sources-admission-green3.log` passed49.982s,PG39167 normal: registered API
draft/full activation; draft visit not consumed; raw75 created0 with zero run,
trigger receipt or77 occurrence side effects; first configured finding admission
and exact replay; shortened600→1 edit preserving cooldown; permanent suppressed
replay after a fixture-expired deadline; exact immutable final-snapshot digest;
and a real75 receipt created before77 installation, then a definition edit and
77 `consumed`/`replayed` result. The original run, trigger receipt and run audit
remain byte-identical. Cooldown clock advancement is a disposable-fixture edit,
not a production clock API. This proves the finding adapter's admission boundary,
not path delivery, Temporal continuation/restart or other-family completion.

Definition paging RED1 reached the absent dispatch function42883 after actual74
creation/full activation of26 configured definitions and an earlier admission
occupying the first definition (86.261s,PG40010 normal). The new25-visited-row
page reports transient capacity deferral without consuming the occurrence and
continues to later definitions. Compile1 derivedcb517163744778ca074c254d39e5561b762e24ef2479aed434d19092bf1f4ab1
with valid DDL and expected stale-pin refusal (31.719s,PG40394 normal). Its
behavior check is running; this is not Temporal continuation evidence yet.

`sources-pages-green1.log` passed154.083s,PG40715 normal:26 actual activated
definitions,24 admissions plus an unconsumed capacity deferral on the first
25-visited page, then the26th admission after reconnect; duplicate sweeps admit
zero and preserve25 receipts. Total elapsed does not establish the first page's
latency. A later affected batch adds per-call timing and25s request deadlines
before choosing the production work quantum. Read-only diagnostic attempts used
two wrong role names, then raced normal fixture shutdown; they did not produce
database activity evidence. Process inspection showed a CPU-active executor.

Configured-definition catch-up RED1 reached its missing entry point42883
(30.292s,PG41533 normal). Compile1 derivedfba1331fe0fe09317f8a67d2e62e0d967fd94ce68a4621af8847dc553d107a77
with valid DDL and expected stale-pin rejection (31.328s,PG41873 normal).
In the still-running `sources-pages-deadline1.log` batch, the catch-up case
passed43.96s,PG42076 normal: draft visit0 in271ms;25 current lower-severity
visits/0 admissions in9.384s; final2 visits/1 admission in2.863s; original source
time and same event replay receipt preserved. Source time is seeded at whole
seconds solely to avoid PostgreSQL microsecond-rounding fixture noise. The
26-definition timed page case remains pending at this checkpoint.

The deadline batch joinedFAIL160.076s. Catch-up passed as above; the first
26-responder test page hit25.001794667s and timed out (case115.14s,PG42189
normal). This directly measures an oversized local page, not production latency.
Per controller ruling, both admission page paths now use a five-visited work
quantum below the25-row maximum, keeping all authority/catalog checks and the
25s query deadline. Tests still traverse all26 responders, reconnect, finish
later pages before revisiting the deferred first definition, and verify duplicate
sweeps. Compile1 derived90d19951b05d208975bbad3f29a28b145fd66830ec5063fcd8d199cf85e5d33d
(31.964s,PG42778 normal). The affected quantum GREEN batch is running. Native
Temporal Activity deadline and worker-restart evidence remain pending.

`sources-pages-quantum-green1.log` joinedPASS205.535s. Configured catch-up
passed45.68s,PG43197 normal; fan-out passed158.83s,PG43324 normal. All26
definitions were visited across six pages,25 admitted, and the capacity-full
first definition remained unconsumed. Reconnect and the complete duplicate
sweep passed. Heavy five-admission pages measured11.51–11.99s; first four plus
capacity deferral9.72s; five-row replay pages2.05–2.27s. Catch-up five-row
nonmatches measured1.98–2.18s and its final two-row admission2.76s. All calls
met the25s local query deadline. This supports choosing five as the initial work
quantum without changing the25-row contract maximum or caching/relaxing current
authority. It is not a production percentile or native Temporal Activity result.

Outbox RED1 reached missing `pending_sources`42883 (29.594s,PG44249 normal).
Compile1 installed valid DDL and derived5a7a36c2ed766c0882ccfe79feaba06972001275e5175554ffe80de4bb6dbf8e
with expected stale-pin refusal (31.381s,PG44676 normal). Outbox GREEN1 passed
37.401s,PG45068 normal: bounded25 pending enumeration, attempt rotation across
reconnect, failed first delivery revisited after other attempts, exact canonical
Workflow ID ACK and duplicate receipt, capture/pending rollback, pause/resume,
and API refusal. A populated second tenant proves wrong-scope attempt/ACK leave
its pending row and acceptance count unchanged; the global relay intentionally
enumerates both scopes. ACK here is the database contract only, not proof that
a Temporal RPC was accepted. The indexed pending table has attempt ordering,
not a lease, completion flag or alternate workflow timer.

Schedule selection RED1 exposed the configured rule marker being ignored by
the actual reconciler's action mapping (.815s). GREEN1 passed .757s with the
affected legacy reconciliation/refusal cases: configured rules select the new
AutomaticCatchupWorkflow on the same stable Schedule, omission remains legacy,
and configured work has no two-minute execution cap truncating continuation.
This uses a controlled Schedule transport. Installed desired routing, both new
Workflow/Activity registrations, lifecycle draining and native connected proof
are still pending. The next workflow RED1 is an absent-type compile result,
not page-loop behavior evidence.

Workflow RED2 (.749s) reached the new fail-closed function stubs and failed
sweep/continuation assertions. GREEN1 (.822s) exercises the production event
and catch-up page loops through controlled Activities: later-page progress
before deferred retry,30s StartToClose,100-page Continue-As-New with cursor and
deferral retained, resumed retry sweep, and invalid-page/root-progress refusal.
These are application Workflow tests, not native worker restart proof.

The exact-start adapter's new-type RED1 is a compile gap. Its GREEN1 (.751s)
covers18 controlled transport cases, including fresh acceptance, exact completed
root, and continued execution bound to described root/current identity plus the
previous run's immutable Continue-As-New close input/type/queue/new-run ID.
Missing history, wrong identity/type/queue, nil/wrong handle, cancellation after
RPC and generic conflicts fail closed. Relay new-type RED1 is also a compile
gap; GREEN1 (.763s) uses the production relay/store/start adapter with controlled
database and Temporal transports. It proves attempt-before-start, exact ACK only
after acceptance, malformed pending refusal, and later-row delivery after a
failed prefix. Installed outbox reconnect proof remains separately reported.

Installed desired RED1 reached missing77.executor_ready42883 (31.255s,
PG48326 normal). The candidate adds exact77/current-executor readiness and
77 desired/references wrappers, leaving75 source bytes unchanged. Omitted rule
desired output remains75's contract; configured rules select automatic catch-up
and manual mode pauses it. The definition index still covers only the staged
single-test family. Other responder-family migration is not claimed.

Desired compile1 derived049b5e66bc74abcdb8d5caf228f35e2d84f2e6a9e8eb9015b28a564613ceaac7
(31.506s,PG48574 normal). Bound-pin GREEN1 passed33.495s/32.67s,PG49416
normal: actual executor readiness, omitted75 equality, configured draft then
activated desired output, catalog-tampered readiness false and desired refusal.
Worker new-API compile RED1 is preserved; GREEN1 passed1.222s with controlled
database boundaries for absent/invalid/error/null readiness, closed page payload
and25s query budget, and runtime.Close retaining clients until the automatic
Activity joins. Both Workflows and Activities are wired in the production
constructor; selector sessions require current77 capability to match startup
registration. A pre77 running worker fails closed after installation instead of
switching to an unregistered workflow. Native constructor consumption remains
pending, so this is not registration acceptance yet.

`risk-envelope-red1.log` (.874s) is meaningful authenticated raw-envelope RED:
explicit evaluation:null and three duplicate evaluation variants returned204.
Omitted and valid annotated controls returned204; unknown outer field returned
400. GREEN1 (.795s) passes all seven raw cases plus the three existing evaluated
signed-event cases and clone isolation. The new outer decoder preserves omission
and strict unknown-field rejection while refusing null/duplicates before Record.
These use real signatures and controlled persistence, not installed writes.

Native preparation: `sources-native-runtime-identity.log` records read-only
Docker inspection of the existing `zasp-runtime-services-temporal-1`, running
`temporalio/server:1.32.0@sha256:c3e752127759616bb1615e0f9ba0e21635aeb5fdeb922de4f371c350955f46ae`.
Its Compose labels point to this worktree's checked-in local project, with only
loopback7233/9090 publications. The test borrows that retained server using a
unique namespace. No server/container/volume was started, stopped or replaced;
there is no server-restart claim or dev-server substitution. Native compile1
passed worker1.257s/API.839s with no tests selected, so it proves compilation
only. `sources-native-red1.log` is running the connected fixture. Two separate
child worker processes test ambiguous accepted Start then production execution
recovery, not yet a process replacement after a middle dispatch page. Controlled
provider validation now has an explicit77-only branch requiring an admitted
occurrence and nonrevoked matching service grant; previous74/75/76 fixture
conditions remain unchanged outside77. Current readback is typed repository,
not mounted HTTP; that assertion and native middle-page recovery remain open.

The first connected attempt, named `sources-native-red1.log`, joinedPASS
153.326s/case152.45s,PG51459 normal. It is not a failing RED. First child2.375s
left the actual accepted native source pending. Replacement child109.397s
consumed the production source relay and exact configured Schedule; native
history confirms AutomaticCatchupPage's30s StartToClose. Event/periodic replay
preserved one execution. After its actual74 settlement, the registered finding
writer produced a later version4 occurrence and a second execution settled
after the configured1s cooldown, with no fixture cooldown edit. Two actual74
parent receipts, provider/native call counts2/2 and all-null lease fields passed.
The signed HTTP runtime source reached actual77 capture and native dispatch,
which completed without fabricating an eligible runtime responder. Typed
repository terminal readback passed. The production worker Close joined in
1.65ms; both child processes and owned PostgreSQL joined. A read-only pg_stat
probe raced normal PostgreSQL shutdown and got connection refused, yielding no
database activity diagnosis. Mounted HTTP and middle-page native restart remain
pending; no server restart or deployed-provider acceptance is claimed.

Raw-envelope casefold RED1 (1.533s) demonstrated three signed case variants
accepted through encoding/json's case-insensitive field matching. GREEN1
(.867s) passes all ten raw-envelope cases after requiring the exact lowercase
evaluation key whenever a case-insensitive match exists. Omission still works;
case variants cannot erase evidence. This remains controlled persistence.

`sources-native-expanded1.log` joinedFAIL241.677s. Middle-page setup failed
77 readiness under the owner principal (87.41s,PG53522 normal): pgx.ConnString
returns the originally parsed DSN, not a serialization of an edited User field.
The fixture now explicitly constructs the registered-executor URL and asserts
session_user. Source ACK and Activity use separate executor connections because
native dispatch can overlap ACK. No product readiness guard was weakened.
The native case's replacement child passed109.077s, but the new mounted HTTP
assertion failed after status200/exact parent/needs_human/verification shape
(case153.24s,PG53794 normal). This is not accepted HTTP projection evidence.
The composite link/verification check remains unchanged pending targeted
nonsecret field diagnostics in expanded2. All production/test source is frozen
while that affected two-case batch runs. Both failures and their setup limits
remain preserved; there is no server restart or completed middle-page proof yet.

Expanded2 joinedFAIL364.567s. Middle-page passed182.56s, replacement79.23s,
PG54997 normal. Exact owned PID55300 was killed/joined after five committed
receipts, source ACK and a completed native Activity. Replacement retained the
Workflow and run IDs, one root cursor and five later pages; all26 distinct
admissions and the26th definition passed. Completed-workflow Start replay also
passed. This is isolated page-worker recovery; no server restart occurred.

Its Native case failed181.02s (replacement139.12s,PG55607 normal) before the
HTTP diagnostics. The later occurrence's SingleTest Activity exhausted retries.
`sources-native-history-diagnostic1.log` (.945s) is a read-only inspection of
the exact retained owned execution: planning Observe, completed Plan, test
Observe, SingleTest scheduled23/failed25 MaximumAttemptsReached, completed
Cleanup31 and failed Workflow35. It does not expose the first database error.
No second adapter subprocess output appeared, which narrows the investigation
but does not prove it never began. Native-only diagnostic3 retains redacted
phase/effect/link/count state and joined PostgreSQL ERROR/function-context lines,
omitting SQL statements/parameters. No product guard, retry or timeout changed;
the accepted middle-page case is not rerun. HTTP projection remains unaccepted.

Diagnostic3 joinedFAIL165.066s/case164.09s,PG57961 normal. Both actual native
executions completed, replacement child116.244s, but HTTP still failed only its
hardcoded reason expectation. Targeted diagnostics show identical parent test
link, definition/version1, needs_human outcome, nonempty equal proof digest and
`test_condition_persists` in both HTTP and repository. The fixture explicitly
sets TEST74_UNSAFE=true; its endpoint reports protected=false. The actual
comparison maps current verdict fail to condition_persists before consulting
baseline, so baseline_unavailable was the wrong fixture expectation. The next
assertion requires exact repository equality and condition_persists, leaving the
production comparator untouched. The earlier intermittent SingleTest failure
did not recur, which is not a fix or root-cause explanation; it stays unresolved.

The diagnostic3 ERROR-line filter was not guaranteed redaction: arbitrary
PostgreSQL messages may contain values. It printed no such lines in that run.
The next version allows only explicit static messages and function names, omits
other error text and never emits statements/parameters. First-adapter-acceptance1
groups Native HTTP with new manual/grant/path checks and an added pre77/75 versus
77 capacity assertion. Explicit grant revocation and canonical path prerequisites
are seeded; definition creation, activation, desired and admission use actual
registered roles. Source remains frozen during this group.

## First-adapter review freeze

`sources-first-adapter-acceptance1.log` joinedPASS286.060s: expanded admission
53.80s (PG59274), authority57.49s (PG59453), Native173.80s (PG59670), all
PostgreSQL processes normal. Active pre77/75 capacity blocks a new77 occurrence
without consuming it or rewriting old evidence. Activated manual rules produce
disabled automatic desired state and cannot bypass77 through75. Explicit seeded
grant revocation leaves no run/occurrence. Seeded canonical potential paths do
not admit observed/verified responders; observed then verified state/version
updates admit their matching enabled definitions exactly once, with final
snapshot/trigger receipt bindings. These state updates are fixture prerequisites,
not new proof of a public path-promotion API.

Native replacement child109.712s completed both real executions, configured
periodic duplicate and later post-expiry source. Mounted production HTTP now
proves the exact parent ID, needs_human state, linked test ID/definition/version,
needs_human/condition_persists verification and nonempty digest equality with the
typed repository. Identity, provider/storage and FGA boundaries remain controlled;
the local retained pinned Temporal server and actual product SQL/composition are
real. No SQL error diagnostics were emitted. Production worker Close joined in
3.57ms. No owned test/build remains active.

Read-only freeze checks reconfirm all216 preexisting migration SQL hashes match
the pre-edit baseline and `git diff --check` exits0. Source/evidence manifests,
copied current source and baseline-relative patch live in
`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-automatic-source-review-stage1/`.
The review brief there identifies boundaries and the unresolved failure below.

**Unresolved review risk:** expanded2's later-occurrence SingleTest exhausted
retries after planning and before observed second adapter output. Exact retained
history is preserved; the first application error is not known. Diagnostic3 and
acceptance1 success do not resolve this. The reviewer/controller must assess it
and may require focused first-error reproduction before local acceptance. It is
not silently classified as transient, accepted or deferred.

This is a staged first adapter, not completion of M7A-35..38d. Configuration,
risk provenance, source capture, matching and bounded delivery have local proof;
automatic run/rerun-test admission supports findings and observed/verified paths.
Runtime pattern responders, potential-path execution, other single-action
responder families and ordered multi-action configured admission remain gated.
Their retained owners/dependencies remain in the approved design and original
caller map.77 has no migrate CLI exposure and is not published/installable for
users. Remaining family migration, independent review, production OpenFGA and
real-provider/Stytch/deployment gates remain open. No commit or push occurred.

## Fix1 review response in progress

The stage1 packet stays immutable. Independent review found two Important
issues: configured activation before77, and the unresolved expanded2 later-run
SingleTest failure. Both remain acceptance gates. This round uses Superpowers
receiving-code-review, systematic-debugging and grouped test-driven development;
the controller approved the correction boundary in `p4c-automatic-source-fix1-brief.md`.

`fix1-rollout-red1.log` joinedFAIL61.346s, owned PG66173 normal. Both manual and
automatic configured creates returned201 and persisted drafts activated. The
update400 cases were wrong fixture path/body, not product RED. Corrected
`fix1-rollout-red2.log` joinedFAIL67.960s, PG66480 normal, shows both creates201,
updates200 and successful stored-draft activation.77 then rejects installation
with55000: the prior unsafe activation created a live configured row, which the
existing migration preflight correctly refuses. That guard is preserved.

The same actual registered executor login cannot read the definition table,
public definition_value, or74.definition (all42501).75 desired and74 authorize
do not return rule presence. The controller revised the worker correction to
require exact ready77 before current automatic-selector processing starts or
reports ready. This avoids a new grant or borrowed API credential. Omitted API
configuration remains available pre77, but replacing the automatic worker now
requires77 first. Operators must also retire old rule-blind automatic workers
before enabling configured definitions. Violating this order makes the new
worker unavailable; mixed-version old workers/direct historical SQL are not
claimed repaired before77.77 remains unpublished.

`fix1-composition-red1.log` joinedFAIL: agentsec-api1.508s and
agentsec-worker1.104s. Actual mounted API construction/decorator selected legacy55
instead of74 in all six controlled-IO cases; absent/invalid configured requests
returned201. Existing selector Activity admitted through75 in absent/invalid77
cases, with the ready case passing. These are application-boundary tests with
controlled SQL/session responses, separate from the installed-role regression.

The first candidate adds API-principal exact77 write checks, persisted scoped
activation checks across legacy and ordered invocation routes, missing74
definition-method forwarding through the actual tracing wrapper, and ready77
requirements for selector startup/current selection/retained Activity calls.
No SQL or fingerprint changed. The covering group is running in
`fix1-gates-green1.log`; no passing claim yet.

Finding2 remains unresolved. The controller approved a constructor-only,
unexported diagnostic decorator on existing workerExternalIO, default nil,
wrapping unchanged executor/product calls before registration. It will preserve
the same-process first/later-occurrence sequence, deadlines and retries. Only
Workflow/run/Activity correlation, static operation/phase identifiers, SQLSTATE,
allowlisted function/error identifiers and state booleans may be logged. No
live Product mutation, worker restart or uncertain-dispatch resend is allowed.

`fix1-gates-green1.log` joinedPASS: installed case67.80s/package69.561s,
PG67241 normal; mounted API2.319s; selector Activity1.141s. The two rule modes
now fail closed for pre77 create/update/persisted activation, omitted create
still succeeds, ready77 create succeeds, and invalid77 create refuses. This
does not yet cover the ordered activation route or actual selector startup;
those remain in the next covering batch. `fix1-diagnostic-compile1.log` passes
the default/decorated product identity check (1.189s). The same-process Native
first-error investigation is running separately in `fix1-first-error-native1.log`.

Prior `TestTemporalTestSelectorLivePostgres` and
`TestTemporalHumanAdmissionLivePostgres` fixtures install75 and construct this
automatic-selector worker without77. Their earlier connected constructor passes
are historical under the new prerequisite, not current rollout proof. Only
those affected fixture prerequisites need updating; pure SQL75/76 tests and the
retained non-test periodic repository test do not construct this selector.

`fix1-first-error-native1.log` joinedPASS165.968s (case164.74s, PG68177 normal).
The constructor diagnostic observed both first and later SingleTest calls on
attempt1, with successful linked dispatch, product and artifact operations.
Product.Test took24.030s and23.360s; the replacement child passed120.800s.
Exact mounted HTTP terminal assertions passed. This did not reproduce the
expanded2 failure and is not a fix. Important2 remains unresolved. The controller
authorized exactly one further same-sequence diagnostic after the rollout
extensions, with unchanged lifecycle, deadlines and retries, then scoped review
of the remaining uncertainty if that run also passes.

The diagnostic preserves underlying PgError where the existing database adapter
returns errors.Join. Existing conflict/operation/not-found classifications can
discard SQLSTATE; no driver observer was added without an actual failing category.
All emitted error labels are static, and SQL parameters/provider payloads are
excluded.

`fix1-rollout-extended1.log` joinedFAIL112.986s (case111.96s, PG70248 normal).
Public62 and legacy persisted activation refusals passed before a child-fixture
failure: changing pgx.Config.User did not change its cached ConnString. The child
used the owner DSN, so its absent77 refusal is not registered-executor proof.
The ready child failed readiness before omitted admission. The fixture now
constructs an explicit executor URL and asserts session_user before every mode.
`fix1-rollout-extended2.log` is the focused covering rerun. No product authority,
readiness predicate or SQL grant changed for this fixture correction.

`fix1-rollout-extended2.log` joinedPASS122.699s (case121.76s, PG72830 normal).
Each child first confirmed rollout77_executor. Absent and catalog-invalid77
refuse actual selector construction, readiness and current Schedule projection;
ready77 preserves omitted-rule desired semantics and creates one actual75
admission. Both stored configured drafts activate through ready77, while
pre77 legacy and public62/ordered activation calls and invalid77 activation
refuse. The unchanged draft/version assertions pass. The exact log was moved
from its accidental worktree-root location into the evidence directory after
joining; its bytes were not rewritten.

The final connected batch is running in `fix1-connected-compat-diagnostic2.log`:
only the two affected75/76 connected fixtures (now installing77 before worker
construction) and the one further authorized Native first-error sequence.
No source/test edits will occur before this owned command joins.

That batch's human-admission case passed125.17s, PG73429 normal. Its actual
production constructor now runs with77 installed, and the revoked-human native
adapter refusal, restored same-actor execution and terminal HTTP readback passed.
The selector case failed63.26s, PG73867 normal, at a fixture's advisory-lock wait.
Read-only diagnosis found assertSelectorSourceSerialization constructed its own
source with automatic=false, unlike the current installed77 production
constructor. The source refuses that state before acquiring the lock. After the
full batch joins, only this fixture initialization will change; the lock assertion
and deadlines stay unchanged, followed by a Selector-only check. The controller
confirmed this cause and correction. The final Native diagnostic is still running.

`fix1-connected-compat-diagnostic2.log` joinedFAIL435.211s because of that selector
fixture. Its Native case passed245.79s, PG74035 normal; replacement child passed
152.552s. Both first and later SingleTest calls completed on attempt1 with no
observed error. Product.Test took29.537s and30.234s; linked dispatch took2.250s
and2.028s with send_permit=true. The later execution was
01a0d46e-faf6-7a63-bde0-e479838857e5 in namespace
automatic-source77-1790270329338944000. Exact mounted HTTP/repository ID, version,
outcome, reason and digest equality passed. Close joined11.177ms.

Important2 is still unresolved. Two bounded same-sequence diagnostic executions
did not reproduce expanded2's first failure. Neither successful run establishes
a cause or a production fix. The controller explicitly capped reproduction at
these two runs and requested scoped rereview with this uncertainty intact. No
retry/deadline expansion, uncertain resend, midrun observer replacement or
driver-level error seam was introduced. The original failing log and retained
history remain part of the evidence manifest.

After the batch joined, the selector helper's source was initialized with
automatic=true, matching its installed77 premise. Its serialization assertion,
deadline, actual registered role and production constructor are unchanged.
Only `TestTemporalTestSelectorLivePostgres` is rerunning in
`fix1-selector-compat-green1.log`; the passing Human and Native cases are not
being repeated.

## Fix1 frozen handoff

`fix1-selector-compat-green1.log` joinedPASS198.509s (case197.50s, PG74877
normal). Child148.087s confirms the registered source waits for the advisory
lock then reads current revision2. Actual Schedule admission and native child/
parent execution pass under ready77. Selector disable preserves admitted work;
current grant revocation blocks prepared fresh IO and later-source admission.
The old75/76 connected evidence is now supplemented by these affected77 runs,
not reused as current constructor proof.

`fix1-static-checks.log` passes: git diff --check, all216 historical SQL hashes
unchanged, all88 frozen stage1 source copies unchanged. There is no active owned
test/build process. No source behavior changed after the covering checks.

Important1's current-app rollout correction is ready for scoped review, subject
to the explicit77-before-worker and old-worker retirement rules above. Existing
API readers and delete routing were not modified to require77; omitted writes
still pass the mounted and installed controls. Raw historical SQL and older
binaries before77 are outside this application correction, so mixed-version
rollout remains a release gate. No broader adapter availability is asserted.

Important2 is unresolved, with two bounded non-reproductions and the controller's
explicit stop-and-rereview decision. The diagnostic seam changes no default
product dependency, deadline or retry. Minor UI warnings remain deferred outside
this fix scope. Neither finding is silently promoted to accepted.

The fix packet is
`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-automatic-source-review-fix1/`.
It contains the19 changed source files, a stage1-relative diff, source/evidence
manifests and copied requirements/report/review. Its comparison merges the
unchanged original overlay with stage1's frozen overrides, not HEAD. Source is
frozen pending the controller's scoped reviewer. No commit, push, migration CLI
exposure, server shutdown or shared-volume operation occurred.
