# Current Ordered Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` for grouped implementation and review checkpoints. Root owns scheduling and the sole native database slot. Do not spawn additional agents, commit, push or edit the authoritative ledger under this addendum. Checkboxes describe work, not acceptance.

**Goal:** Replace recursive historical catalog reconstruction in the current Ordered execution path with a direct, freshly evaluated current-release structural contract while retaining every accepted authorization, drift and domain safety condition.

**Architecture:** A source-derived finite catalog manifest defines the current Ordered dependency closure. A private, non-recursive evaluator compares live structural facts with compiler-bound expected facts at the same existing entry/exit and post-wait boundaries; closed current-only native variants preserve live principal, revision, proof, source, time and domain checks. Historical functions, original migration bytes and unrelated families keep their existing paths.

**Tech Stack:** Existing pinned Go1.25.13, pgx5.10, PostgreSQL, Node generator, real local OpenFGA and Temporal integration; no dependency upgrades.

**Spec:** `docs/internal/2026-09-22-temporal-openfga-design.md`, its execution plan, and this root-selected option2 amendment. Evidence: P7 `ordered68-capacity-architecture-decision.md` and `ordered68-three-target-prefix-result.md`.

## Global constraints and explicit amendment

- Preserve original100-target admission,600s policy TTL,20m Apply, maximum5 attempts, original10s operation limits, cancellation and uncertain-effect/no-resend semantics. No new positive authorization cache, GUC, session-ready bit, automatic repinning or cross-call catalog cache.
- Keep every current structural-drift refusal property. The amendment changes the *representation and evaluation* of current integrity, not the allowed body/owner/ACL/RLS/trigger mutations. Historical fingerprint return bytes are no longer the active current evaluator's representation; their original public functions and migration records remain unchanged.
- Temporal/OpenFGA internals remain trusted dependencies. TDD tests our SQL/Go trust boundary and actual product wiring, not vendor conformance.
- No global81 migration, unrelated family rewrite, target-loop concurrency, batch signing protocol or runtime-ready activation. New functionality is a composed80 private Ordered module/version, selected only by the existing explicit current profile and fixed operation mapping.
- Development-only/no in-flight removes the need for a live-run migration service. Do not drop retained evidence or reset shared databases. Local predecessor capture is evidence, not a deployed allowlist.
- Parent must review the emitted concrete identity list and the semantic predicate partition before production implementation. Counts must come from source/build artifacts; this document does not invent a complete live catalog inventory.

## 1. The finite closure contract

The closure is not all `pg_catalog`, all customer objects, all functions matching a runtime prefix, or only functions found by a regular expression. It is a checked build artifact containing exact identities and field selectors. Use two finite inputs:

1. The exact compiled composed-profile SQL source and source map for the candidate, including Ordered writer/effect/signing/lifecycle/Test and raw69 retirement modules. Preserve its compiler checksum and source SHA. Use accepted7KoCcj/6frGMr production as the local predecessor, not the original14MB capture alone.
2. An explicit source-site inventory of structural facts read by the *accepted current* worker/runtime catalog and the68/69/78 readiness closure. The reviewed graph (`ordered-readiness-closure1-graph-complete.json`,177 nodes) is a starting cross-check, not proof of completeness: later modules and dynamic SQL must be reconciled against the actual compiled candidate. Every selector is expanded at build time to exact identities; every missing/extra live identity remains a runtime refusal. A prefix selector may define a release-owned namespace set, but its expected closed membership list must be emitted.

No reduction of the currently checked structural set is in this batch. In particular, dependencies that historical fingerprints happen to include remain structural facts even when they do not perform Ordered effects. We stop *executing their fingerprint recipes*, not detecting their drift. Future pruning requires separate authority and evidence.

### Active entry roots and route boundaries

All names below are fully qualified in emitted artifacts; `worker` means `zasp_authorization80_worker`. These are exact root families, not callable user-selected SQL:

| Current route | Root definitions / native children included | Existing Go consumers |
| --- | --- | --- |
| Apply effect reserve/start/read | `worker.ordered68_effect_source(text,jsonb)`, `require_ordered68_effect`, current effect entry and fixed `ordered68_effect_read` child | `authorization/worker_ordered_effects.go`; worker policy adapter; product Apply |
| Policy capture/source/sign | `prepare_ordered68_policy(text,jsonb)`, `ordered68_policy_metadata/source`, `ordered68_policy_begin/store`, `ordered68_signing_boundary` and its seven fixed inner copies, policy input/proof/purpose/time helpers | `authorization/worker_ordered_prepare.go`, `worker_ordered_policy.go`; worker policy signing adapter |
| Ordinary apply/cleanup/delivery | `ordered68_operation_source/session`, exact private children of `zasp_temporal68.application(jsonb)`, `cleanup(jsonb)`, `delivery(jsonb)` | `authorization/worker_ordered_operations.go`; product Apply/Cleanup |
| Existing Test and adapter | `ordered68_progress_facts`, `ordered68_test_source/exit`, `require_ordered68_test`; exact progress, linked, invocation, completion, settle, replay, stop, state and dispatch-readback children from `0080_authorization_worker_ordered_test.sql` | `worker_ordered_test_execution.go`, dispatch readback adapter, linked repository, actual runner and adapter journal |
| Captured lifecycle | `ordered69_source/finish`, `require_ordered69`, inspect/message/stop entries and status/reconcile/inspect/message/stop/stop_test fixed inner copies | `worker_ordered_lifecycle.go`; product inspect/stop/Notify |
| Ordered forward revision | New fixed reader of79 organization revision fields, selected only for the above forward operations; adapter role keeps its distinct principal | `authorization/worker.go` request-local revision reader selection; existing grouped revision helpers |

Use exact installed signatures from the compiled source map for names abbreviated in this table; do not guess overloads or infer parameter identity from `proname`. The generator must emit the complete root list, all overload-resolved outgoing edges and exact source sites. Unknown call targets, unclassified dynamic statements or changed copy anchors reject generation.

Planning/load/admit, API62 approval, Discovery, runtime ingestion, automatic jobs, ordinary non-Ordered SingleTest, and other worker families are not re-routed. Their *structural objects* remain in the preserved dependency set where previously bound. Current Test adapters and69 lifecycle are included because they share the changed authority/revision/native seams; their purpose distinctions do not change.

### Structural categories: exact emitted fields

For every category, keys use qualified identity strings and ordinal positions, not environment-dependent OIDs. OIDs are resolved internally and must be unique; unresolved objects refuse. The serializer is typed and canonical with explicit nulls, deterministic byte ordering and length-safe fields; no delimiter-concatenation ambiguity. Compare both complete key sets and values, not an expected-row inner join that ignores additions.

| Category | Required fields and closure rule |
| --- | --- |
| Namespace | Exact namespace identity, owner, ACL nullness and expanded grantee/grantor/privilege/grant-option tuples; exact member identities for release-owned closed sets |
| Routine | Namespace+name+ordered input type identities, kind, language, owner, full ACL/nullness, security-definer, volatility, strictness, parallel flag, leakproof, cost/rows, support-function identity, full ordered configuration, input/all argument types, modes/names/default expressions, return type/set flag, `prosrc` and `probin`; include transforms if present. Parsed SQL bodies require canonical body deparse, not omission; unsupported kinds/frames reject the build. Do not call `pg_get_functiondef` on aggregates |
| Relation | Qualified identity, kind/persistence, owner, ACL/nullness, row-security and forced-row-security, replica identity, tablespace/access method/options as applicable, parent/partition/inheritance identities and bounds. Include ordinary tables, views/materialized views, sequences and composite row types actually selected by the preserved set |
| Column/default | Relation+attnum, name, type+typmod, collation, nullability, identity/generated flags, dropped-slot shape, storage/compression, ACL/nullness, canonical default/generated expression with dependencies |
| Constraint/index | Exact relation/name/type, ordered local/referenced columns and referenced relation, expression/check, FK actions/match, validation/deferral/inheritance, backing index; full index definition/keys/predicate/expressions, unique/primary/exclusion/valid/ready flags. Do not infer an FK from matching column names |
| RLS policy | Relation/name, command, permissive, role identities, canonical USING and WITH CHECK expressions with dependency identities |
| Trigger | Relation/name, enabled mode, function identity, type/timing/event bits, args, WHEN expression, constraint/deferral/referenced relation, transition-table names; user trigger set exact. Internal FK/constraint triggers are covered explicitly by constraint/index/dependency structure, not silently ignored where an existing recipe pins them |
| View/rewrite | Canonical view definition, relation owner/ACL/security options; rewrite name/event/instead flag/enabled state, qualification/action and dependencies, not just a view SQL string |
| Type/operator/collation | Exact used domains/enums/ranges/composites, ordered labels/attributes, domain default/not-null/constraints, base/subtype/collation/support routines; exact operator/procedure/cast dependencies and extension identity where a selected expression uses them. Fixed built-ins are bound by the supported PostgreSQL/extension build contract; user-defined dependencies are manifest objects |
| Privilege defaults/roles | Scoped default ACL role/namespace/object-type/ACL; fixed authority roles' login/inherit/superuser/create-role/create-db/replication/bypass-RLS flags, fixed managed membership/admin/grantor options and security-relevant settings. Runtime registered login names/bindings remain live checks, not fixture-specific constants |
| Saved release definitions | Exact signature/key, full definition, original owner and ACL for every selected predecessor-functions table; saved views, saved constraints and saved trigger definitions, with count/key-set equality. These are structural evidence, not authority results |
| Static registration | Exact profile/schema/checksum/fingerprint/singleton shape for selected historical and composed registrations; canonical migration-version/checksum identities where currently checked. Distinguish the new module's own self-reference fields as specified below |
| Dependency edges | Exact selected-object class+identity+subobject to referenced class+identity+subobject+dependency kind, including shared ownership/ACL dependencies. Follow only explicit selected dependencies; reject unresolved dynamic object identifiers rather than capturing unrelated customer catalogs |

The fixed saved-table selector inventory starts from current exporter `workerUpgradeStaticSources` and compiled module INSERT sites, but the exporter is not trusted as the specification. Cross-check every original fingerprint fact branch, including exceptional schemas65/67/76 and raw69 saved rows. Exclude verifier bytes, encryption/signing keys, credentials, customer/product row values, session tokens, FGA tuples and provider bodies. Do not omit a needed category merely because current exporter serialization refuses it.

### Predicate partition: static does not mean every readiness predicate

Before replacing any readiness edge, emit a line-addressed partition table with one of three dispositions for every original predicate:

1. **Structural:** catalog identities/fields, fixed migration records, saved release definitions and closed extension/version contracts go into the manifest. Their values are checked freshly, not accepted once at install.
2. **Live:** principal/session membership/registration, role binding, current organization desired/applied/generation/store/model, proof/MAC/verifier/revocation data, associations/task/run state, approval/plan/budget/receipt/credential state, all input/evidence digests, clock/expiry, locks/isolation and in-flight/cleanup state remain native queries at the original points. Conditional foreign-schema63/64 checks retain exact branch/error semantics and dynamic contents; namespace absence must not be inferred from a historical artifact.
3. **Historical representation:** recursive hash-composition calls whose sole purpose is to serialize category1 may be replaced by the new current structural evaluation. If a function mixes category1 and2, extract only the static expression through a counted exact-source transform and retain every live predicate, including NULL/exception semantics and ordering around locks. A lexical call graph alone cannot classify it.

The partition is a required review artifact with no unclassified predicates. A predicate containing table data is not presumed static merely because it lives inside `ready()` or `fingerprint()`.

### Reviewed installation-dependent primitive exception

The source-contract review for Task2 identified eight occurrences of the same
original `EXISTS` expression comparing authorization80's compiled checksum and
registered fingerprint to `zasp_authorization80.fingerprint()`. That primitive
has no application callees. It includes raw policy/trigger fields containing
the actual registered migration login, so two supported installations can
legitimately have different raw fingerprints.

Retain exactly those complete comparison expressions freshly outside the
direct collector, with original caller frames, checksum, NULL behavior and
surrounding cardinality checks. Independently bind the primitive's unchanged
body/owner/ACL/config. The base67 caller is SECURITY INVOKER; it must not be
silently converted to a definer. No recursive readiness root, positive cache
or general fingerprint fallback is allowed by this exception.

The source-contract amendment must enumerate all eight exact spans and map
the affected raw fields/registration value to this obligation instead of
also comparing them with fixture-A portable constants. Remaining required
owner-dependent facts need their own original semantic accounting. This
exception does not prove portable release equality or native drift safety;
both remain acceptance gates. The direct collector itself still calls no
historical fingerprint or readiness function.

## 2. Expected baseline and evaluator trust

### Independent provenance

Expected values are generated in a reproducible **build reference**, not read from the installation target and blessed. Bind the exact compiler output/source SHA, generator source/format version, supported PostgreSQL/pgcrypto identity, all module source hashes and the final canonical manifest SHA. The checked build installs the exact compiler source in a fresh disposable database, verifies the existing pre-amendment source/pin/ACL admission, emits finite structural facts under the pinned owner frame, and cross-checks identities against the compiler/source-site inventory. The resulting artifact is reviewed and embedded in the release. A second independent fresh installation must produce the same canonical facts despite different OIDs and fixture login names.

The target installer accepts only this embedded artifact and its compiled hash. It may observe the live target to compare it, never to populate expected rows from `SELECT ...` or to overwrite the embedded expectation. A mutable target registration containing a matching-looking checksum is insufficient. Existing predecessor artifact ff7b2990 is local reference evidence only; fresh-retirement7KoCcj and the future amended target have different exact compiler identities. Do not fabricate a deployed allowlist or substitute the failed exporter payload for approved source provenance.

### Representation and non-recursive evaluation

New module lives inside composed80 but in the separate private schema `zasp_authorization80_ordered_current`. Do not append helpers to the old worker namespace: its existing catalog hashes the complete namespace, so that would silently invalidate retained compatibility gates. The following names are qualified by this new schema:

```text
registration(singleton boolean PK CHECK(singleton),
  format_version integer, profile_checksum text, manifest_sha256 text)
expected(kind text, identity text, fact jsonb,
  PRIMARY KEY(kind, identity))
catalog(expected_manifest text) RETURNS boolean
require(expected_manifest text) RETURNS void
revision(organization text) RETURNS jsonb
```

Expected rows are immutable owner-only release metadata with exact RLS/ACL/trigger structure and independently checked full content hash. No executable grants on the collector/catalog/require/inner variants to worker/API roles. Registration count must be1, correct format and compiled manifest; malformed/null/missing/duplicate/additional facts refuse.

`zasp_authorization80_ordered_current.catalog` reads catalog relations directly and compares the complete finite fact sets. It never calls predecessor readiness, historical fingerprint, current worker.catalog_ready or another current integrity evaluator. It may use PostgreSQL pure catalog deparsers required for expressions, but not a stored “ready” result. Produce each live object descriptor once per invocation using typed keyed materialization; the important change is direct current comparison instead of recursively re-hashing historical recipes. No shared temp table, statement-independent memo, privilege-definer result cache or external SQL input.

Native definition parity exposed frame-sensitive core deparsing. Root's accepted
P7 `ordered-current-transform-deparse-frame-decision.md` permits only the proposed
private `function_definition_public(oid)` core-deparser adapter: SECURITY INVOKER,
authority-owner-only, fixed `pg_catalog, public`/UTC, schema-qualified core call,
and independent exact body/full-frame admission before invocation. The collector
and canonical keys remain under `pg_catalog`. Represent its output as a distinct
source-frame-qualified descriptor, retaining original lazy/saved-branch demand;
do not reinterpret earlier raw references or strip schema prefixes. This adds
neither a historical application-helper call nor a ninth primitive exception.
Grouped native parity, admission-drift and old-universe compatibility remain
required; the accepted proposal is not implementation or installation proof.

Native4 and the root-run four-case frame-surface probe establish the same issue
for original identity-argument text and projected routine identity. The bounded
extension in P7 `ordered-current-transform-frame-surface-diagnosis.md` is approved
under the autonomous execution mandate: add fixed owner-only SECURITY INVOKER
`function_identity_arguments_public(oid)` and `function_identity_public(oid)`
adapters, each containing only its schema-qualified core deparser or regprocedure
cast, with the same fixed frame and independent complete admission as definition.
Only original projection leaves use these adapters. Collector keys, selectors,
rosters and object resolution stay canonical under pg_catalog; no global
descriptor rewrite, caller-selected frame, qualifier stripping or eager
definition evaluation is allowed. Version source-framed provenance; old raw
argument values cannot become original-frame expectations. Grouped controls and
one native thirteen-recipe/nineteen-case batch must cover all three adapters,
admission drift/non-invocation, immediate caller-frame restoration, original
NULL/error and lazy saved-branch behavior, and old-universe compatibility.
Original budgets and independent expected-source requirements remain unchanged.

### Evaluator self-pin without a hash cycle

Reuse the existing independent compiled-body/frame guard pattern rather than trusting the evaluator to report its own honesty. Every closed current SQL entry contains a fixed inline query that checks the exact evaluator OID, language, owner, ACL, security-definer, volatility/strict/parallel flags and config plus its body digest before calling it. The expected evaluator body digest is compiled into those entries. The evaluator itself compares live caller/child definitions against the embedded manifest. Thus changing only the evaluator refuses at entry, and changing another bound entry/helper refuses at evaluation. The typed Go preflight independently checks the exported entry's exact compiled definition/frame before invoking it; it does not trust a success JSON from a forged entry.

Break build cycles explicitly: evaluator source does not contain its final manifest hash or caller-body hashes; the trusted expected manifest hash enters only as the compiled literal at each fixed entry/typed caller. In the manifest's own entry-definition facts, normalize **only one exact compiler-declared manifest-literal span** to a fixed token. Compare all other definition bytes and raw actual literal separately to the compiled expected hash. Expected-row/registration content hashes use a typed exclusion of only their own manifest-hash field; no namespace/body wildcard or arbitrary string replacement. Two-build tests must prove fixed-point determinism, changed literal/body/ACL refusal and no attacker-selected normalization.

This defends the accepted single-object drift/forged-helper cases; it is not a claim to withstand an adversarial PostgreSQL superuser rewriting the whole database and every independent client trust anchor. Schema-lock protocol and trusted migration-owner assumptions remain explicit. Runtime principals gain no DDL, direct table writes or expected-manifest maintenance rights.

For only the newly introduced private PL/pgSQL routines, build the immutable
expected body from exact template `prosrc` bytes plus the complete independently
pinned routine frame instead of predicting `pg_get_functiondef` formatting
before installation. Bind qualified identity, ordered input/all argument and
result types, names/modes/defaults, binary and parsed-body absence, language,
owner/full ACL and nullness, definer/volatility/strict/parallel/leakproof flags,
ordered configuration, set-return/cost/rows/support/transforms as applicable.
Independent entry/client admission checks the evaluator before trusting its
result. This changes no original selected definition fields and permits no
target-derived expected values or omitted frame fields. Native mutation/parity
checks remain required; source-based generation alone is not installation proof.

The new private evaluator's manifest hash uses core
`pg_catalog.sha256(convert_to(canonical_payload,'UTF8'))`, not a replaceable
`public.digest` extension routine. The supported PostgreSQL build is part of
reference provenance; native verification must prove canonical-byte/hash
parity on that build. Original fingerprint recipes and their pgcrypto usage
remain unchanged. This avoids trusting an application-owned hash function
before the expected-table content has itself been authenticated.

## 3. Closed current execution routing

Add new private current native variants by exact-source copy of the accepted effective definitions, not original unmodified historical SQL. All copy transformations must have pinned source body/frame and exact occurrence counts. Keep the complete live-predicate partition. Materialize write results before the unchanged final fences; no `RETURN child(...)` escape. Fresh checks after organization/device/budget locks and clock rereads remain in the same positions. No DB transaction spans FGA, Temporal RPCs, artifact I/O or provider requests. Preserve the existing bounded local policy key-load/sign callback inside the original READ COMMITTED policy-begin/store transaction: those locks, raw-input MAC, revalidated expiry and rollback are part of the accepted signing boundary. This narrow local-signing exception does not permit remote signing/KMS/provider calls inside that transaction.

Existing public68/69 and all historical routine bytes/grants remain as installed in the accepted fresh-retirement predecessor, including raw69 grant retirement. New current entry functions keep closed request shapes and compiled fixed operation names. No generic native dispatch, caller-provided schema/signature/checksum selector, fallback on absence, or widened EXECUTE. Allocate executor/compensation/adapter EXECUTE only for their existing fixed purposes; all inner copies remain authority-owner-only. Historical both-nil application composition retains its accepted route; partial current bindings refuse.

Go routing is request-local, not a global change to `WorkerExecutor.Revision`. For the exact current Ordered operation set, use a private `RevisionReader` implementation calling `zasp_authorization80_ordered_current.revision`; supply it to the existing grouped Check helper and final revision reread within the same Authorize invocation. Preserve all CheckRequests, HIGHER_CONSISTENCY, pending/conflict/drift-before-denial behavior, two source reads and final revision. Other operation families and the public Revision method remain unchanged. Adapter keeps its own principal identity; captured operations do not gain a forward Check or permission requirement.

Source preparation found that only the four-phase Ordered Test helper currently
closes its revision interval before returning denial; the shared worker helper
returns denial early. For the new explicitly selected current Ordered route,
the stated drift-before-denial contract remains required and needs grouped
coverage plus a current-scoped implementation. Do not silently change the
shared helper for planning, Discovery or other families. Preserve existing
Check ordering, denial short-circuit, cancellation and checker-error handling,
then close the revision interval before deciding conflict versus denial on
the new route. Both source reads and the final revision reread remain on the
successful path; denied requests never reach signing or a mutation.

The old worker binder detects its historical worker namespace. That is not a
selector for the new addendum: Task3 must introduce explicit pinned composition
and fail partial bindings before SQL. `workerOperationSpec.current` describes
forward authorization, not a release version. Include a valid
compensation-only lifecycle client in the partial-composition refusal cases;
an empty executor that fails internally does not prove the boundary itself.

Route exact source, signing and final mutation SQL via the existing fixed `workerOperationSpec`/typed adapters for this composed profile. Current and historical selection remains explicit configuration; never infer it from schema existence. The real linked-dispatch readback uses the same original opaque decision, complete artifact validator and unchanged deadline before final Execute. Captured adapter Complete still records the observed response after revocation; first Test settlement remains forward-only, replay/stop remain narrow compensation.

## 4. Version/install and supported local transition

Use a distinct composed80 Ordered addendum source checksum, format/version and expected manifest. Keep the accepted worker component's existing compiler checksum and registration separately unchanged: the combined current readiness identity is the pair of that component and the new addendum, not an overwrite of old registration. No global schema81 and no runtime-enabled flag change. Historical checked migration files are not edited. Every copied current function is created in the new schema; source public/worker functions are read-only predecessors.

Fresh install: assemble the accepted modules first, add current-only definitions/metadata with closed owners/grants, validate the exact expected old structural baseline and final current artifact in one transaction, and register the new addendum identity only after all checks pass. Invalid shape/order/source aborts atomically. Prove the old component's baseline fingerprint and required gates remain unchanged/true after the addition; source-site inventory must expose any old namespace-universe selector that would see the new schema. If such a selector rejects the addition, stop for a specific compatibility decision rather than silently project or repin it. Existing historical wrappers remain on their old fingerprint path.

Local predecessor→target: require the exact independently compiled predecessor source identity plus its fully accepted effective structural manifest, no active runs or outstanding cleanup before changing runtime selectors, and the schema-migration exclusive lock. Apply additive current module/route grants in one transaction; preserve product rows, evidence, approvals, outbox and effect identities. Repeat with the exact target is a verified no-op; wrong predecessor, drift or interrupted partial state fails closed without registration rewrite. Native upgrade acceptance waits for a successful predecessor export; failed serializer evidence is not a valid predecessor manifest. No live-run migration/dual-worker service is built.

## 5. Files and ownership

Create focused units; do not grow the existing readiness generator into a generic SQL compiler:

- `migrations/tools/build-ordered-current-integrity.mjs` and `.test.mjs`: finite source-site inventory, predicate partition validation, deterministic typed manifest and closed copy emission.
- `migrations/sql/0080_authorization_worker_ordered_current_integrity.sql`: metadata and direct collector/evaluator/self-pin admission.
- `migrations/sql/0080_authorization_worker_ordered_current_calls.sql`: fixed entry and owner-only domain variants with exact copied anchors.
- `migrations/production_authorization_worker_ordered_current.go` and `_test.go`: embed/checksum/assembly admission. Modify only the explicit integration insertion in `production_authorization_worker_ordered.go` and the existing compiler registration boundary as separately owned spans.
- `authorization/worker_ordered_current.go` and `_test.go`: closed operation routing, compiled pins and request-local revision reader; narrow hooks in `worker.go`, operation/spec and signing paths. No unrelated checker or model changes.
- `agentsec-worker/authorization_worker_ordered_current_test.go`: actual typed current/historical/partial composition and signing/dispatch decisions; only tiny production adapter hooks where an existing literal statement cannot come from the closed spec.
- `apiserver/authorization_worker_ordered_current_integrity_postgres_test.go`: one grouped structural/live/upgrade acceptance fixture reusing the accepted producer and owned PostgreSQL lifecycle.
- Generated release artifacts under `migrations/ordered_current/`: exact roots/edges, predicate partition, fact manifest and source provenance. These are release inputs, not a generic dump or customer-data export.

Existing affected consumers retained for grouped acceptance: the three-target parent/helper; Test dispatch native boundaries; actual Test runner/settlement/no-send;69 settled/post-adapter/cleanup recovery; policy convergence; current worker constructors. Do not edit exporter files owned by Worker or unrelated dirty API/discovery files.

## 6. Grouped execution

### Task1 — freeze the source-derived contract before implementation

**Consumes:** accepted6frGMr production hashes, compiled source, exact effective catalog reference when available; existing accepted structural selectors and approved design. **Produces:** deterministic exact identities/field selectors and complete predicate partition; no executable runtime change.

- [ ] Write generator contract tests that refuse unresolved overloads/dynamic calls, omitted source branches, extra identities, ambiguous normalization and a mixed live/static predicate without classification. Consume actual pinned source bytes, not mocked names alone.
- [ ] Run the focused generator group and retain meaningful mismatch RED; a missing module compile error is labelled setup evidence only.
- [ ] Implement the closed inventory and partition emitter. Emit fixed roots, every outgoing edge, every structural selector/source anchor, every retained live predicate and all source hashes. Include fixed63/64 conditional-tail behavior explicitly.
- [ ] Run deterministic generation twice and compare artifact bytes. Root reviews the complete emitted closure and partition. No production evaluator work precedes this gate.

### Task2 — direct integrity representation and trust, one behavior group

**Consumes:** Task1 reviewed inventory. **Produces:** typed manifest schema, new SQL module and reproducible build artifact; still no production routing.

Use an independent expected fixture to test the serializer and comparison contract. Define the named mutation helpers in that test to change exactly one declared fact field; they must never call the production normalizer to manufacture expected output. Required assertions include:

```js
assert.equal(compareFacts(expected, structuredClone(expected)), true);
for (const mutate of [changeBody, grantExecute, changeOwner, disableTrigger,
  addRlsPolicy, removeConstraint, changeSavedDefinition, addUnexpectedObject]) {
  const live = structuredClone(expected); mutate(live);
  assert.equal(compareFacts(expected, live), false);
}
assert.throws(() => normalizeEntry(twoManifestLiteralSites));
assert.throws(() => buildManifest({ ...release, expectedFromTarget: true }));
```

- [ ] Add grouped RED for each category, explicit NULL versus empty, additions/removals, nonowner frame, wrong compiled pin, forged evaluator and copied entry. Bind actual SQL result behavior in the eventual native group; serializer tests alone cannot establish it.
- [ ] Implement direct keyed catalog queries and exact immutable expected rows with owner-only privileges; no call to old readiness/fingerprint from the evaluator. Add code admission that rejects any such generated edge.
- [ ] Resolve the declared self-reference spans in two deterministic passes and verify the normalized manifest is a fixed point; emit both payloadSHA and fileSHA distinctly.
- [ ] Compile affected migrations/API/worker once with `go test -p=1 ... -run '^$'`. Review complete module/artifact/trust boundary together before a native run.

### Task3 — current-only native and Go routing, retaining all live checks

**Consumes:** Tasks1–2 contracts. **Produces:** fixed current variants and typed operation routing, historical routes unchanged, runtime-ready false.

- [ ] Add consuming route tests for every fixed operation purpose and all8 Test subjects/targets; unknown sibling operations, malformed shape, both partial configurations and wrong pins must refuse before SQL. Actual both-nil historical calls must still consume their original statements.
- [ ] Test a request-local current revision reader with unchanged initial/closing/final reads. Pending fails, changed revision overrides denial, cancellation stops, no other family routes to the new statement.
- [ ] Emit closed copies with exact anchored substitutions only. Review a machine-produced before/after predicate/lock/effect diff: every original live check and lock must remain accounted for, all inserted new checks visible, no arbitrary rewrite of public historical routines.
- [ ] Route sources/begin/store/readback/final Execute through the same current profile; test unchanged original context deadline and same opaque decision through dispatch validator. Test callback refusal prevents final mutation.
- [ ] Run affected authorization/worker/repository/migrations groups once; review the complete application batch and exact overlay closure before capture.

### Task4 — one coherent installed trust and application group

**Consumes:** one immutable reviewed candidate with full hash inventory. **Produces:** local component evidence, never deployment activation.

- [ ] In one owned fresh fixture, prove original/current structural verdict parity for unchanged state and representative body/ACL/owner/config/defaultACL/RLS/constraint/trigger/saved/registration mutations, additions/missing dependencies, wrong expected pin and forged evaluator/entry. Use actual registered executor/compensation/adapter logins, exact refusal classes and bounded restoration; no timeout-as-denial.
- [ ] Exercise dynamic63/64 absent/orphan/valid conditional semantics and static/live separation with real revision/session/verifier/credential mutations. Preserve post-lock principal and expiry controls, entry/exit checks, source equality and pending-convergence behavior. Failure must roll back effects, not merely return an error after persistence.
- [ ] Consume actual checked approval→Apply→real Test dispatch/readback/engine/journal/artifacts/settlement and settled no-send replay, then69 captured recovery. Include response-after-revocation Complete versus forbidden first forward settlement, plus disconnected uncertainty and preserved Block cleanup debt when affected by the shared seam.
- [ ] Consume the reviewed actual100/three-target prefix once on the same candidate, unchanged600s/10s/2m limits. Require3stored/97planned,3acks,9scopes,6signatures,0finalreceipt and no fourth capture. Record all target walls, SQL phases and whole-prefix self time. Structural parity alone is not a performance pass.
- [ ] Only with credible measured600s margin, run the actual Temporal full100 Apply integration under original20m/max5/heartbeat/cancellation; require actual100 acknowledgements/final receipt and cleanup. If still too slow, stop this candidate's capacity claim—do not extend TTL or run an unchanged doomed loop.

### Task5 — local supported transition and handoff

- [ ] Once the independent predecessor capture is actually accepted, run one data-preserving exact from/to fixture with meaningful retained rows and no active work. Prove mismatched/drifted predecessor refusal before mutations, exact-target idempotence, rollback and record preservation. This does not authorize a deployed upgrade or generic rollout framework.
- [ ] Run affected package regressions and existing UI typecheck/build before shipping only changed accepted scope. No unchanged vendor/internal suite repetition.
- [ ] Record local accepted versus external/deployed gates, final artifact identities and remaining capacity/activation blockers. Root owns ledger and shipping decisions; no automatic commit or push in this plan.

## Critical self-review and remaining approval gate

- **Coverage:** live checks are explicitly excluded from the static baseline; mixed functions require a reviewed predicate partition. No claim that177 lexical nodes or the failed exporter is a complete structural manifest.
- **Trust:** expected facts are independent build inputs, not target-discovered truth. Evaluator and entries have separate pins; self-reference normalization is exact, bounded and tested. The trusted migration owner is not treated as an untrusted SQL adversary with arbitrary ability to rewrite every independent client pin.
- **Scope:** only fixed current Ordered routes change. Historical definitions and unrelated runtime/API/planning families remain; structural dependencies are retained even when their original hashing implementation is removed from this path.
- **Semantics:** no authority value persists across calls/waits; all current proof/revision/source/time and narrow compensation semantics remain. Full predicate/lock accounting is the production-code review prerequisite.
- **Economics:** this removes recursive representation work, not merely repeated deparsers. There is still no honest replacement cost prediction until native evaluation; runtime performance and full100 remain hard gates.
- **Versioning:** the module80 addendum has its own checksum/format while the old worker component identity remains unchanged. A separate namespace prevents the obvious old namespace-catalog drift; installer acceptance must still prove no closed-universe selector is invalidated. Admission is fail-closed without automatic repin. Local no-in-flight transition preserves evidence; live migration service is out of scope.

The design is concrete enough to execute Task1 now, but it deliberately does not invent the exact post-amendment manifest hash or object count. Root's next review consumes Task1's complete emitted closure/predicate partition before approving the evaluator/call transformations. No native run or implementation has occurred in this planning turn.
