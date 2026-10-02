# Existing-test execution implementation plan

Registered stopped-work settlement (2026-09-17): grouped owned session80184 passed all12 mode cases and registered worker checks; independent review found no actionable findings. See [composed-stop evidence](2026-09-17-existing-test-composed-stop-checkpoint.md). Production scheduling/restart and live gates remain open; M7A-21 remains component-only/disabled, unshipped.

Generation-fenced ownership checkpoint (2026-09-17): the reproduced maximum-version stranding defect is fixed with DB-generated claim generations, bounded counter cycling and saturating release/settlement. Owned rollover/cancellation/fingerprint/rollback48778 and corrected SQL settlement/max-expired-replay/recovery50482 passed; worker/migration race and independent re-review passed. UI build88795a passed, not live UI proof. See [generation evidence](2026-09-17-existing-test-generation-plan.md), including failed mixed-harness runs and their correction. Runtime/restart, leased composition and live gates remain open. M7A-21 stays component-only/disabled; no promotion, commit or push.

Cancellation retry/drift checkpoint (2026-09-17): owned20833 passed direct and stopped leased/retryable cancellation, four modes each (c47ebd/fd3d63), including rollback after an observed blocked-write release change. Worker/actual Node race5a370d passed9.859s. The test fixture timestamp correction and independent review are recorded in [cancellation evidence](2026-09-17-existing-test-stopped-cancellation-plan.md). Leased settlement composition, version exhaustion, runtime/restart and live gates remain open. M7A-21 stays component-only/disabled; no promotion or push.

Stopped leased cancellation checkpoint (2026-09-17): owned22034 passed existing human/worker cancellation and stopped-parent cancellation, four modes each (10cfaa/10e97b). Known partial and unknown outcomes, terminal no-op preservation, late callbacks and observed blocked-write expiry rollback are covered. A test-only parent lease setup error was reproduced and corrected; independent re-review found no new findings. See [cancellation evidence](2026-09-17-existing-test-stopped-cancellation-plan.md). Retryable/drift, leased settlement composition, exhaustion, runtime and live gates remain open. M7A-21 stays component-only/disabled; no promotion or push.

Stopped queued cancellation (2026-09-17): owned session75577 passed normal and stopped-queued reconciliation in four modes each (bb9020). See [cancellation evidence](2026-09-17-existing-test-stopped-cancellation-plan.md), including the earlier enclosing harness failure and correction. Leased cancellation, direct human/worker cancel compatibility, expiry/drift, runtime and live gates remain open. M7A-21 stays component-only/disabled; no promotion or push.

Registered remediation composition checkpoint (2026-09-17): available before/after artifact bytes now pass through the real comparator, registered client and SQL settlement. Owned four-mode completion/pending530a5c/052846 and grouped worker race4b6ada pass; parent asserts remediated proof, saved baseline, verified effect and single audit. In-flight cancellation coverage also passes. See [settlement evidence](2026-09-17-existing-test-settlement-checkpoint.md). Controlled storage/Node producer is not live engine/cloud or deployed-worker proof. Runtime scheduling, restart/shutdown, SQL exhaustion/queued cancellation and live gates remain open; M7A-21 is component-only/disabled, unshipped.

Registered settlement client checkpoint (2026-09-17): immutable exact-proof submission/replay and receipt validation implemented; grouped worker race and owned registered completion/pending checks pass across four modes. See [settlement checkpoint](2026-09-17-existing-test-settlement-checkpoint.md). This proves unavailable/unknown-evidence settlement, not successful artifact retrieval/remediation, restart persistence or live deployment. Worker-loop composition, exhaustion/cancellation gaps and A-D/live gates remain open; M7A-21 is component-only/disabled, unshipped.

Settlement candidate checkpoint (2026-09-17): guarded atomic settlement and exact replay are implemented with grouped owned acceptance. See [settlement evidence](2026-09-17-existing-test-settlement-checkpoint.md). Version exhaustion, queued cancellation, missing outcome cases, client/worker composition and live gates remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Settlement in progress (2026-09-17): [settlement plan](2026-09-17-existing-test-settlement-plan.md) records exact-byte proof hashing, snapshot/lease fencing, lost-ack replay, stopped-parent preservation and expired-uncertain crash recovery. New owned actual Node acceptance RED58abb9 reaches missing settle function42883; no SQL settlement or passing acceptance yet. Review corrected step success versus needs_human parent semantics against the original design. M7A-21 remains component-only/disabled; no promotion, UI/full release gate, commit or push.

Registered reconciliation client checkpoint (2026-09-17): exact guarded claim/read/heartbeat/release routing, compiled pins, local tokens and bounded receipt checks implemented. Actual Node/owned DB group passes complete and pending client decoding through eight registered-role child checks; grouped worker race and independent review pass. See [client evidence](2026-09-17-existing-test-client-checkpoint.md). Durable settlement, worker-loop/composed artifact acceptance and A-D/live gates remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Worker snapshot decoder checkpoint (2026-09-17): guarded envelope identity/expiry checks and complete-attempt conversion implemented. Persisted unknown outcome survives late journal completion; regression reproduced and fixed. Grouped worker/actual Node race passes and independent re-review found no remaining Important findings. See [decoder evidence](2026-09-17-existing-test-snapshot-decoder-checkpoint.md). Registered DB client/composed acceptance, settlement/reconciler and live gates remain open; M7A-21 stays component-only/disabled. No UI/full release gate, commit or push.

Reconciliation lease checkpoint (2026-09-17): guarded registered-worker claim/read/heartbeat/release implemented, including final authority and expiry checks after waits. Grouped owned actual Node/DB completion, dispatch, baseline, reconciliation, fingerprint and rollback checks pass; independent review found no remaining Critical/Important issues. See [lease evidence](2026-09-17-existing-test-reconcile-lease-checkpoint.md). Go wiring, settlement/reconciler and A-D/live gates remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Database evidence checkpoint (2026-09-17): private scoped link-derived attempt/journal loader and immutable enqueue categories implemented. UTC snapshot defect reproduced and fixed. Grouped owned actual Node/DB completion, baseline, dispatch and rollback checks pass; independent review found no Critical/Important issues. See [database evidence](2026-09-17-existing-test-database-evidence-checkpoint.md). Registered guarded lease wrapper, Go wiring, settlement/reconciler and A-D/live gates remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Evidence verification checkpoint (2026-09-17): scoped immutable input/output retrieval, strict artifact/journal association and fail-to-pass comparison implemented; grouped worker/actual Node race35197f passes5.906s. Independent review found no Critical/Important issues. See [evidence checkpoint](2026-09-17-existing-test-evidence-checkpoint.md). DB attempt binding, claim/lease settlement, reconciler/UI and A-D/live acceptance remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Baseline candidate checkpoint (2026-09-17): enqueue-time immutable attempt/input/output receipt snapshot implemented and independently reviewed; transaction-start cutoff defect reproduced and fixed. Grouped owned database and race checks pass. See [baseline evidence](2026-09-17-existing-test-baseline-checkpoint.md). Full artifact retrieval/comparability, settlement/reconciler and A-D/live gates remain open. M7A-21 stays component-only/disabled; no UI/full release gate, commit or push.

Target-comparison carriage checkpoint (2026-09-17): linked invocation now validates the stored comparison before target I/O, attaches its typed redacted tuple to fresh and replayed HTTP observations, checks replay equality and deep-copies category slices. Raw observation JSON excludes internal provenance. Node and Go artifact validators require exact comparison fields, matching tenant/test/version/target/ordered categories, valid binding identity/digests and consistent tuples across category records. SQL completion matches each artifact tuple to its own durable journal, refusing rehashed endpoint/configuration/safety/credential-binding digest substitutions. RED766f40 (HTTP),3a88fa (Node),ca5f4d (Go) and ownedNodeSQLd95206 preceded implementation. Owned calibration4ec93a pins55 ata9168c37253da88ef7a7299d52048b5459cdc0ce37fd037bf099e84570784142. Final grouped fdaed2/a0f13a/5245bf/ce4916/7d99d3/9039a7 passes actualNodeSQL completion37.67s, registered knownHTTPS17.02s, unknownHTTPS13.72s, journal client20.90s, fingerprint3.30s and release8.43s. HTTP comparison is asserted equal to stored DBJSONB on fresh/replay, with no resend. Actual pinned Promptfoo361bc6 passes v1/v2 pass/fail/engine_error/cancellation36.99s. Initial engine1df2e3 false-positive leak failure came from a repeated test digest matching the test lease; test-only digests now hash descriptive fixture strings, with leak assertions unchanged. Final Node2250bc passes16 tests including per-field duplicate/null/missing/alias cases; worker/actualNode race995de2 passes5.855s; adapter/migrationscf752b pass2.203s/4.898s; repository2a3c63 passes5.449s. Independent review found no Critical/Important findings. These are controlled engine/provider/database proofs, not live provider/S3/IAM/KMS acceptance. Full settlement-time input/output retrieval and native/evaluation identity verification, comparable baseline selection, settlement/reconciler and composed A-D/live gates remain open. M7A-21 stays component-only/disabled. No UI/full release gate, commit or push.

Stored target-comparison receipt checkpoint (2026-09-17): started and completed registered journal receipts now return the immutable target_resolution.comparison tuple; the client requires exact15-field comparison shape, scoped tenant/target/kind, valid test/credential IDs and versions, ordered valid unique categories, nonzero digests and endpoint SHA256 matching the actual binding. Canonical JSON is retained on InvocationReceipt. Missing/null/changed/aliased/duplicate fields are refused. RED550997 and owned DB REDdba595 preceded SQL carriage. Review found an invalid assumption equating credential_binding_digest with SHA256(reference); registration0026 defines it as opaque. Distinct registered-style digest REDf53879 reproduced the rejection; the decoder now preserves that digest without inventing its derivation. Reviewer confirmed the Important issue resolved with no new findings. Owned calibration42b83d pins55 atda9775176ea58f8af3ddfef6ee719bb5c2963a62b9ef469e6ef43acb35c8e95a. Grouped646f7f/baf315/2bbfa0/23d2ca passes completion36.78s, real registered journal client20.59s, fingerprint3.22s and release8.24s. SQLJSONB equality asserts returned tuple equals the stored row; replay preserves canonical identity. Adapter race181326 passes2.030s; migrations0dc1c3 passes4.690s; worker/Node528b12 passes5.685s. This is the source-receipt part of the active comparison batch: HTTP observation, Node/native artifact carriage, DB completion comparison binding, baseline/settlement/reconciler and A-D/live gates remain unfinished. No activation, production promotion, UI/full release gate, commit or push; M7A-21 stays component-only/disabled.

Concrete artifact readback checkpoint (2026-09-17): inspection confirmed production s3driver.Put already reads back the exact returned object version via HEAD/GET and validates scoped metadata, owner, KMS, content length and checksum; no redundant network read was added. Runner receipt validation now also requires application/json and exact returned body bytes for input and output. RED7c9651 reproduced acceptance of missing/changed body or wrong media type. The actual Node runner contract now uses the real artifactstore and S3 driver with controlled provider responses, requires both scoped/version/owner-pinned GETs and compares returned completion bytes with uploaded output. Worker/actual Node race2c4b37 passes5.542s; artifactstore and s3driver race3d8507 pass1.518s/1.423s. Independent review found no Critical/Important issues. These are controlled-provider retrieval proofs, not live S3/IAM/KMS acceptance or later settlement-time retrieval. Full target-comparison artifact identity, comparable baseline selection, settlement/reconciler and composed A-D/live acceptance remain open. SQL55 unchanged; M7A-21 remains component-only/disabled. No UI/full release gate, commit or push.

Actual producer/SQL contract checkpoint (2026-09-17): the owned completion fixture can invoke Node via ZASP_LINKED_FINISH_NODE and ZASP_LINKED_FINISH_RUNNER, using database-read scoped run/definition/target identities. Actual product configuration, summary and native-artifact producers now feed full bundle bytes unchanged into registered SQL completion for pass, fail and adapter503/engine_error. Owned run06aa1b/27260c passes all four action/autonomy cases37.21s; repository race0f524f passes5.024s. A response-digest tampering test now targets the response_digest key exactly; its prior broad replacement modified the input-artifact checksum, so prior evidence did not independently prove that negative case. New run proves the corrected rejection. Initial attempt22b402 failed before Node execution because the PostgreSQL image lacked the pinned runtime's musl loader; file/ldd identified dependencies, then three libraries copied from the pinned Promptfoo image were mounted read-only. All task-created extraction containers were removed. Production source and SQL55 pin are unchanged. This closes actual Node-produced shape acceptance by SQL, not real engine execution, live storage receipt/retrieval, full native/target identity validation or baseline/settlement/reconciliation. M7A-21 remains component-only/disabled. No full release/UI gate, commit or push.

Exact-artifact completion checkpoint (2026-09-17): runner and linked runtime now carry the exact uploaded evidence bytes into the registered 21-argument completion call. Go rejects absent, oversized, malformed or checksum/size-mismatched bytes before database access. SQL independently checks byte length/SHA256, rejects duplicate JSON keys/depth overflow, binds bundle summary/input/run to completion, and matches ordered category observations, credential-version and response digests, HTTP status and protected flags to its durable journal. Engine errors remain inconclusive. RED d454a8 and owned DB RED800545 preceded implementation. Owned calibration11f16a pins55 at56f48f130e76b6725b6ded05527b84f3ebfcb7b49f98e186f54e712516691157. Final grouped owned dd1e15/a8f42b/e50c71/9e4f3d passes cancellation27.75s, completion36.92s across four action/autonomy modes, fingerprint3.27s and release8.37s. Rehashed credential/response/category/protected substitutions, wrong byte size and duplicate keys are refused without persisted mutation. Repository raceec51ed passes4.854s; actual Node/worker race556833 passes5.543s and asserts returned bytes equal the upload body; migrations44c24c passes4.791s. Independent review reconfirmed zero Critical/Important findings. The DB fixture uses a controlled minimal native document: actual Node-produced bundle acceptance by SQL, full native/target-comparison identity, immutable storage retrieval, baseline/settlement/reconciler and A-D/live acceptance remain open. M7A-21 remains component-only/disabled; no fresh UI build/full release gate, commit or push.

Credential artifact-carriage checkpoint (2026-09-17): authenticated linked adapter responses now include an explicit credential_version_digest from the completed journal observation; missing/nonzero-format failures are refused. Raw observation JSON still excludes internal provenance, target requests do not receive version identity, and no credential reference/secret bytes are exposed. Node's exact-key linked parser and Go native-artifact verifier require the digest and retain it with each category in v2 evidence; missing/null/zero/aliased/duplicate values are refused, legacy v1 is unchanged. Node REDecbcfb and GoRED0a47b2 preceded implementation. Nodee33063 passes14 tests; final worker race0c0f03 passes5.836s with actual Node producer/Go consumer across configured categories; adapter race8d1d82 passes1.883s. Actual pinned Promptfoo334bbb passes v1/v2 pass/fail/engine_error and cancellation38.39s against controlled TLS. Owned registered DB/HTTPS508a3c passes known17.80s and unknown14.15s with exact digest retained on durable replay and no resend. Independent review found no Critical/Important issues. This is evidence carriage, not proof that an arbitrary artifact's digest matches the database: completion/settlement cross-checks, full target-comparison tuple in artifacts, baseline selection, reconciler and A-D/live acceptance remain open. SQL55 pin7b26bd267f843e701cbcb6cfcdfceb5bbcaa387c84ab05077578f074aa4a7679 unchanged; previous DB release group remains separate evidence. M7A-21 stays component-only/disabled. No fresh UI build/full release gate, commit or push.

Durable credential-journal checkpoint (2026-09-17): completed invocation rows now require a non-null32-byte nonzero credential-version digest; started/unknown rows requireNULL and never invent provenance. The unpublished55 guarded completion entrypoint accepts the digest, stores it atomically with the response and refuses a changed digest on replay. Completed receipts return it; Go validates exact13-field terminal shape, digest format and submitted/acknowledged identity, and sends14 completion arguments. Missing/null/zero/duplicate/aliased/substituted receipts fail closed; old unversioned terminal receipts cannot become comparable evidence. Invalid-client REDecd0cf and owned DBRED8c5281 preceded implementation. Controlled source signing digest now reaches real registered database completion/replay; direct persisted-value assertions and conflicting-version refusals pass. Owned calibration4fdda4 pins55 at7b26bd267f843e701cbcb6cfcdfceb5bbcaa387c84ab05077578f074aa4a7679. Grouped owned7659f8/db7ae9/eb5335/4722a4 passes claim47.83s, HTTP5.20s, known HTTPS17.12s, unknown HTTPS14.44s, legacy8.50s, terminal8.58s, journal client20.59s, fingerprint3.25s and release8.12s; affected cancellation7c5f9e28.93s and finish083e2636.85s pass. Adapter racea0613b passes2.007s, repository3a22b4 passes5.059s, migrationsb4720c passes4.651s. Independent review found no Critical/Important issues. Registered-role ACL/private-core restrictions, scoped lease/request/category association and late-known completion remain intact. These are controlled component/HTTPS/DB proofs, not deployed-provider proof. Artifact association, full comparable baseline/settlement, reconciliation and A-D/live acceptance remain open. Update55 and coordinated clients before rollout; M7A-21 stays component-only/disabled. No fresh UI build/full release gate, commit or push.

Credential-source checkpoint (2026-09-17): Secrets Manager resolver now requires bounded printable32..64 returned VersionId and derives a domain-separated SHA256 over credential reference plus that exact version from the same response as signing bytes. Missing/malformed version metadata fails closed and clears provider bytes. Credential material copies signing bytes and version digest under the destruction lock; Destroy removes both. Authorization and successful HTTPS observation retain the digest internally with json exclusion; no target header or public response field exposes version identity. API RED54c036/7756bf preceded implementation. Controlled rotation fixtures assert independent digest literals and exact HMACs; local TLS verifies actual invocation attribution, header non-disclosure, JSON exclusion and post-destruction refusal. Full redteamadapter race68ceb6 passes1.927s. Independent review found no Critical/Important issues; its JSON/destruction Minor coverage was added. This is in-memory provenance only: the journal/artifact formats do not yet retain this digest, old replay is unversioned, and no baseline/remediation proof is claimed. Durable credential association, full comparison tuple, reconciliation and A-D/live acceptance remain open. SQL55 pin424eec2de02e3a0506f3b505663d623d38641511c07daa66bee997767d010810 unchanged; no database or UI release rerun claimed. M7A-21 stays component-only/disabled; no full release gate, commit or push.

Adapter composition checkpoint (2026-09-17): production adapter now composes exact legacy /v1/evaluate and linked /v1/linked/evaluate paths. Linked resolution and invocation use the same pinned Postgres journal; no fallback or redirect on failure. Startup and recurring probes require legacy readiness plus exact55 readiness and registered adapter principal. Journal Ready API RED89091b and composition API REDd60cea preceded implementation; registered DB readiness REDd4c7a2 drove only a read-only client_ready grant to zasp_red_team_adapter, with grant-revocation drift coverage and no private-core grants. Owned calibration70fbc7 yields compiled55 pin424eec2de02e3a0506f3b505663d623d38641511c07daa66bee997767d010810. Grouped owned233eae/b2af64/43e792/626505/bf2e13 passes HTTP4.80s, known HTTPS16.21s, unknown HTTPS13.63s, legacy8.07s, journal client20.60s, fingerprint3.36s and release/rollback8.60s. Actual adapter composition child passes all four registered-login cases8428ec22.19s; strengthened owner-denial connection/context control8bd42b passes8.58s. Component racee45dd9 passes adapter1.774s/journal1.743s; final adapter race3d5b8d passes1.945s; migrations7693c6 passes4.476s. Loopback TLS sandbox refusalb4e51e was retried with scoped permission, not treated as a test pass. Independent review found no Critical/Important issues; invalid-path no-redirect/no-DB and owner-control Minor feedback was addressed. Release55 must precede the worker/adapter rollout with coordinated rollback. This proves controlled protocol composition and database/HTTPS boundaries, not deployed-cloud or complete end-to-end execution. Reconciliation, full artifact/actual secret-version association and A-D/live acceptance remain open. M7A-21 stays component-only/disabled. No fresh UI build/full release gate, commit or push.

Worker routing checkpoint (2026-09-17): production execution composition now selects a dual-protocol repository using persisted scoped database classification for each operation; outbox composition is unchanged. Unknown protocol/query errors never fall back. Linked retry/legacy cancellation are refused; distinct linked cancellation remains explicit. Controlled constructor/RunOnce terminal-delivery and mutation-routing tests cover both protocols and commit-ack failures. Registered PostgreSQL child initially failed (526c4b); diagnostics a154e3 showed recovery readiness true, then identity assertion78ce3a proved the child connected as owner zasp_e2e because pgx ConnString retained the original DSN after ConnConfig.User changed. The fixture now connects directly as existing_test_red_worker and asserts session_user; no production readiness checks or grants were weakened. Final owned registered-worker group b4a2c0 passes all four supervised/autonomous run/rerun cases in10.91s, including real router construction, artifact readiness and linked/legacy reads. Worker race7c68d6 passes5.738s with Node enabled. Independent follow-up review found no Critical/Important findings. Release55 pin8f0fd342aa1ea24c593fbf070ddb84887957ef92b91c9fd1adcb8a6a7d704e00 is unchanged; migrate before worker rollout and coordinate rollback. This is component evidence, not full production execution: adapter production composition, reconciliation, full artifact/actual secret-version association and A-D/live acceptance remain open. M7A-21 remains component-only/disabled. No fresh UI build/full release gate, commit or push.

Worker protocol-selection checkpoint (2026-09-17): SQL RED7a3800 and Go API RED112a15 drove a read-only scoped worker_protocol function and strict RunProtocol client. Classification uses the persisted scoped run/link, not queue input; only registered Red Team workers with exact55 pins can read linked/legacy. Unknown/foreign runs, null/malformed inputs, stale pins and unregistered roles fail; client duplicate/alias/null/extra/trailing/oversize values never select legacy. Classification grants no lease; actual legacy/linked mutation fences remain mandatory against races. Real Go-client fixtures prove both protocols and unchanged run state. Initial grouped7569a3/2ce519 failed because a fixture-only dispatch grant was still present; the test now asserts55000 for that drift and revokes it before client construction. No production permission was widened. Final owned grouped03e2b6/f8fc30/5f1ee3/1ca498/5a50fb/073028 passed cancellation28.20s, finish35.56s, claim/heartbeat47.03s, HTTP4.78s, known HTTPS16.02s, unknown HTTPS13.51s, legacy8.02s, journal client20.11s, fingerprint3.24s and release8.20s. Repository race14a48e passed4.937s; migration race327dff passed4.940s; worker race4a244b passed4.606s with Node enabled. Independent source and fixture-correction reviews found no Critical/Important issues. Owned calibration848cc0 pins55 at8f0fd342aa1ea24c593fbf070ddb84887957ef92b91c9fd1adcb8a6a7d704e00. Production still composes the legacy repository: dual-protocol routing/composition, reconciliation, full artifact/secret-version association and A-D/live acceptance remain open. These are controlled component fixtures, not production execution proof. M7A-21 stays component-only/disabled; unchanged UI inputs were not rebuilt this batch, and no full release gate, commit or push occurred.

Linked worker cancellation checkpoint (2026-09-17): missing-client RED04de4e and processor RED7783d7 drove CancelLinkedRedTeamRun plus explicit cancellation finalization. The client validates exact bounded outer/nested JSON, run/outcome consistency, positive attempt and cancellation flag, exact scope/input/raw lease and release55 pins; malformed responses cannot convert uncertainty to confirmed cancellation. A distinct optional worker method prevents legacy fallback. Only a valid nonrenewed cancellation heartbeat under the last confirmed live lease stops execution and enables finalization after joined heartbeat work. Finalization retains root shutdown and min(last lease,5s); lease loss, generic failure, contradictory heartbeat, missing capability and failed acknowledgement stay unacknowledged. Matching durable cancelled or failed/outcome_unknown permits queue acknowledgement without claiming external rollback. Unit clientc935a6 passed2.683s; actual Go client/registered DB cancellationb8e92c passed25.30s. Final grouped repository raceafda41 passed4.631s and worker race526098 passed4.595s with Node enabled, including renewal-before-cancellation and no-legacy-capability coverage. Independent client/lifecycle/final-delta reviews found no Critical/Important findings. Linkerfc6601 hit disk exhaustion; only the owned generated Go cache was cleared, recovering about35GB, then tests rebuilt successfully. SQL55 pin94433fa087b9a7a23bc11a796aeadc18ac86282508b637a41b4088ab3c064a0c and UI inputs are unchanged; previous database release group and UI build remain separately recorded, not rerun claims. These are controlled boundaries/DB fixtures, not a composed production worker or live-provider proof. Production selection, linked retry/reconciliation, full artifact/secret-version association and A-D/live gates remain open. M7A-21 stays component-only/disabled; no full release gate, commit or push.

Linked cancellation checkpoint (2026-09-17): shared private SQL cancellation preserves journal history and records before-execution, partial-execution or outcome_unknown classification. Human HTTP cancellation retains version/idempotency/audit semantics and works after parent lease expiry; exact-lease worker cancellation requires a requested cancellation. Unknown execution stays failed/outcome_unknown, never confirmed cancelled. Go/web validators now consume that bounded shape; consumer RED8dceac/35542e and DB RED084bf3/8ecd7b exposed rejection, nullable receipt and post-write expiry defects. Explicit outcome/time pairing and original-lease post-check now enforce rollback. Owned grouped20082b through ae81f9 passed cancellation26.45s, finish35.02s, claim/heartbeat45.02s, HTTP5.20s, known HTTPS13.60s, unknown HTTPS11.07s, legacy5.25s, journal client17.65s, fingerprint3.45s and release8.36s. Real HTTP->repository->registered DB, persisted reads, replay/no duplicate audit, late completion without erased uncertainty, private grants and rollback identity are covered. Repository race69767a passed3.974s; migrations967bc0 passed5.410s; web719a4a passed52 tests. UI builda8aca4 and compiled import985629 passed. Independent consumer and SQL reviews found no Critical/Important issues; explicit unlinked human cancellation positives remain a Minor coverage opportunity. Controlled calibration482670 pins55 at94433fa087b9a7a23bc11a796aeadc18ac86282508b637a41b4088ab3c064a0c. These are component fixtures, not live execution. Worker cancellation client/processor integration, reconciliation, immutable artifact/actual secret-version association, production composition and A-D/live acceptance remain open. M7A-21 stays component-only/disabled. Full release/advisory authorization remains open; no commit or push.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.
> Execute inline in feature batches with independent Superpowers review. Keep
> the original microtask ledger; these batches do not replace its requirements.

**Goal:** Complete M7A-21 run_test/rerun_test with actual durable execution and
linked verification, without target/prompt overrides or false success claims.

**Architecture:** A version-bound definition feeds deterministic planner and
worker admission. A private shared Red Team enqueue core creates the exact
linked test transactionally; a separate reconciler settles verified evidence.

**Tech Stack:** Go, PostgreSQL, TypeScript/React, existing Red Team workers,
versioned OpenAPI, compiled migration fingerprints.

**Spec:** `2026-09-16-security-agent-existing-test-design.md`.

## Global constraints

- Full original728-task scope; M7A-21 stays component-only until acceptance.
- IDs are canonical Product IDs; definition versions are1..1000000.
- No prompt, URL, target, credential, category, scope or safety overrides.
- No worker API-role membership or direct private-core EXECUTE grant.
- Organization admission lock precedes run/step and prerequisite locks.
- Check wall-clock lease/authority/budgets after blocking locks.
- Enqueue acknowledgement never means verification or remediation.
- Existing non-test definitions remain readable without existing_test.
- Retain all user-owned/recovered changes. Do not rewrite published migrations.
- Publication requires runnable UI and the full release gate. The unresolved
  fresh advisory scan authorization is not bypassed by a push or alternate host.

## Batch A: versioned definition and database authority

Files:

- Create `services/platform/migrations/sql/0055_security_agent_existing_tests.up.sql`
  and `.down.sql`, `security_agent_existing_tests.go` and
  `production_security_agent_existing_tests.go` in the migrations package.
- Create `services/platform/migrations/sql/fragments/security_agent_existing_tests.sql`
  for link, core and guarded entrypoints; keep release pin/rollback wiring in55.
- Modify `apiserver/security_agent_existing_test_reference.go`,
  `workflow_handler.go`, `security_agent_repository.go`,
  `security_agent_budget_release_database.go` in `services/platform`.
- Modify `openapi/openapi.yaml`, generated API types, web strict decoders and
  `app/features/securityagents/SecurityAgentsView.tsx` together.
- Extend `apiserver/security_agent_existing_test_binding_postgres_test.go`;
  add `security_agent_existing_test_release_postgres_test.go` and
  `security_agent_existing_test_definition_test.go` beside it.

Interfaces:

```go
// Existing closed reference syntax validator, retained as the wire boundary.
func decodeSecurityAgentExistingTestReference(json.RawMessage) (securityAgentExistingTestReference, error)
// New migration package surface, following release54's runner convention.
func ProductionSecurityAgentExistingTests() Metadata
func SecurityAgentExistingTestsFingerprint() string
func (runner *Runner) UpProductionSecurityAgentExistingTests(context.Context) error
func (runner *Runner) DownProductionSecurityAgentExistingTests(context.Context) error
```

The shared core has the existing human enqueue's nine argument types and
returns its existing mutation envelope. Name it
`zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text)`.
Keep fixed search_path and discovery ownership; only the two authorized definer
wrappers call it. Preserve the human wrapper's principal/intent/replay checks.

- [ ] Add failing real API/DB tests that create/update/read a draft with exact
  `existing_test`, reject absent/null/duplicate/extra/versionless references on
  test actions, and reject a reference on other actions. Verify stored body and
  row versions, not merely status200. Include stale/foreign/disabled test,
  same-organization different workspace/environment and legacy definition reads.
- [ ] Run only the new `TestSecurityAgentExistingTestDefinition` tests to capture
  the missing-contract failure before implementation.
- [ ] Add55 exact predecessor guards, saved original functions/ACLs, compatibility
  and compiled-pin wiring. Add scoped link FKs and unique step/run association.
  Preserve54 rollback behavior before use. Rollback must refuse if any new test
  link, invocation or history exists, including terminal records; retain all
  data and require a forward repair. Never restore legacy retry over used55.
- [ ] Extract the shared enqueue core from current safety-aware enqueue logic;
  delegate the human wrapper while retaining its API principal guard. Test a
  valid human enqueue/replay, denied worker direct call and no duplicate outbox.
- [ ] Wire strict public contracts and persist the selected test reference.
  Resolve it under current DB authority at mutation/activation; reject the
  entire transaction on failure. UI options come from real scoped tests and
  display the selected version; never fabricate an available action capability.
- [ ] Add helper ACL/body/owner/search_path drift tests, old-client refusal at55,
  warm-client upgrade/rollback tests and atomic rollback refusal for terminal,
  cancelled, partial and uncertain retained history. Empty unused55 rolls back.
- [ ] Run definition/decoder/release checks once as a batch; calibrate only in
  the owned DB and pin the result. Obtain independent review before Batch B.

## Batch B: planner, preparation and atomic dispatch

Files:

- Extend the55 fragment and `apiserver/security_agent_worker_repository.go`.
- Modify `agentsec-worker/security_agent_runtime.go` and the existing planner
  adapter/validation files under `services/platform/agentsec-worker`.
- Add `apiserver/security_agent_existing_test_admission_postgres_test.go` and
  `agentsec-worker/security_agent_existing_test_runtime_test.go`.

Interfaces preserve existing planner candidate `{index, action, target_id}`.
The target is a TestDefinition ID, not the target endpoint. The selected version
comes from stored authority. Add version55 context/accept/prepare/execute
functions with the same argument/return envelopes as their currently selected
v33/v24 counterparts; repository selection occurs only behind55 readiness.

```sql
-- Expected test query after dispatch, against owner-only fixture inspection.
SELECT count(*) = 1
FROM zasp_security_agent_test_links
WHERE (organization_id,workspace_id,environment_id,run_id,step_id)
      = ($1,$2,$3,$4,$5);
```

- [ ] Write failing registered-worker tests covering configured reference in
  planner context, exact digest replay, rejected substituted definition/version,
  simulation with zero new test runs, and prepare with persisted test intent.
- [ ] Add context/preparation branches for both actions. Reuse existing trigger
  evidence checks and approval-floor enforcement; do not accept arbitrary
  candidate fields or a caller-selected version.
- [ ] Implement transactional dispatch: exact current worker lease, policy
  controls, budget reserve, private resolver, deterministic linked run ID, effect,
  link, Red Team enqueue and audit. Return existing `running/pending` envelope.
  The snapshot reference and planner digest must still match after locks.
- [ ] Keep intermediate dispatch private: no application EXECUTE grant and no
  production capability enablement. Readiness/admission must refuse linked
  execution until C's claim/retry/invocation protocol is installed and pinned.
  Test direct registered-role dispatch denial independently of UI flags.
- [ ] Test response loss after commit, rollback before commit, second worker
  restart, duplicate concurrent dispatch and expired public replay receipt.
  Assert exactly one linked run/outbox and unchanged test-definition/target rows.
- [ ] Test lease loss, action/time/cost stop and target/credential expiry while
  waiting on each prerequisite lock. Observe the actual blocker before expiry.
  All negative cases must create zero effects/links/runs/outbox entries.
- [ ] Test control revocation and foreign-scope requests using actual registered
  worker connections. No owner-only assertion substitutes for application denial.
- [ ] Run the new admission/runtime tests plus existing budget start/stop/crash
  tests once; independent review of the complete atomic boundary precedes C.

## Batch C: evidence-backed settlement and cancellation

Files:

- Extend the55 fragment with link claim/settle/cancel authority.
- Create `apiserver/security_agent_existing_test_repository.go` and
  `agentsec-worker/security_agent_existing_test_runtime.go`.
- Extend worker composition and the existing Red Team completion/cancellation
  tests; add `security_agent_existing_test_completion_postgres_test.go` and
  `security_agent_existing_test_replay_postgres_test.go` in apiserver.
- Modify `agentsec-worker/red_team_execution_runtime.go`, `red_team_runner.go`,
  `red_team_artifact.go` and adapter invocation authority to persist the immutable
  execution comparison tuple and enforce linked-run unknown-outcome stops.
- Extend action detail projections and strict client decoders with linked test
  run, before/after evidence and safe verification reason.

The reconciler uses DB-owned link authority, not planner input. All calls include
scope, agent run/step, worker identity and lease. Claim through bounded batches;
release/settle through compare-and-swap link version and exact lease token.
Pending external runs are scheduled for later reconciliation, not busy-polled.

```go
// Behavioral expectations for the eventual registered DB completion tests.
// The fixture must complete the real linked Red Team attempt first.
cases := []struct{ baseline, verdict, want string }{
    {"comparable_fail", "pass", "remediated"},
    {"absent", "pass", "needs_human"},
    {"comparable_fail", "fail", "needs_human"},
    {"comparable_fail", "engine_error", "inconclusive"},
}
```

- [ ] Write failing settlement tests with exact persisted artifacts: valid
  fail-to-pass, no baseline, incompatible baseline, fail, engine error, missing
  artifact/version/checksum, substituted run/attempt/digest, foreign evidence,
  replay and stale reconciler lease. Assert step/effect/run/audit states together.
- [ ] Snapshot the comparable baseline at enqueue, not at settlement. Require
  identical scoped test/version/target and compatible engine/curated-check
  identity from artifact evidence before claiming change. An engine upgrade or
  unavailable baseline yields Needs human, not remediation.
- [ ] Add versioned comparison receipts from pinned adapter resolution: endpoint,
  target configuration, safety and credential binding/version digests; engine,
  runner image and pack identity; ordered check/prompt/assertion identities.
  Match the entire design tuple and each baseline failed check's protected
  result. Add fixtures where endpoint, credential version, assertion or one
  category changes despite an aggregate pass; none may yield Remediated.
- [ ] Implement settlement according to the design table; persist the full
  before/after provenance and verification digest. Do not mutate finding status.
- [ ] Share a private scoped cancellation core with the human Red Team wrapper;
  preserve API principal checks. Test before-dispatch cancel, queued cancellation,
  in-flight cancellation, completion racing cancellation, restart and uncertain
  provider outcome. No fabricated rollback or cleanup success.
- [ ] Add durable linked-run per-category invocation reservations. Commit started
  before network I/O; replay terminal receipts without another request. On
  started-without-terminal, deny retry/claim/re-invocation in SQL and settle
  Inconclusive. Test process crash, lease expiry, old-worker retry, cancellation
  during a request and duplicate category delivery. Count actual target requests.
  Distinguish confirmed unstarted cancel, known partial execution and unknown
  external execution in link audit/UI; legacy cancelled alone proves neither.
- [ ] Wire the reconciler into actual worker composition with bounded polling,
  heartbeat ownership and joined shutdown. Reuse existing queue/storage/runner
  paths; do not substitute the component fake backend.
- [ ] Run C's tests and existing Red Team execution/cancellation suites once.
  Review evidence semantics and cancellation races independently.

## Batch D: user workflow, release and ledger

Files: `scripts/production-combined-e2e.mjs`, its tests, action readiness and
production catalog, feature UI/decoder tests, release contract and docs/internal
status/availability/batch ledgers.

- [ ] Extend the composed browser test with a real scoped existing test and
  controlled target. Exercise builder selection/version, simulation, activation,
  trigger, planner, worker enqueue, pending UI, actual runner completion and
  linked before/after evidence. Reload and inspect exact scoped URLs.
- [ ] Include foreign-user read/control denial with a positive control, no-baseline
  pass, unsafe result and engine-error cases. Verify zero new test definitions or
  arbitrary target/prompt changes through the workflow.
- [ ] Enable both production action capabilities only after A-C and composed
  acceptance pass on the exact release. Grant only guarded wrapper EXECUTE once
  the complete invocation protocol is pinned; never grant the private core.
  Review the feature as one unit. Do not publish intermediate Batch B dispatch.
- [ ] Run generated-contract checks, affected UI tests, lint/typecheck, standalone
  UI build and full release gate before publishing. Reuse unchanged expensive
  results only when their covered inputs are unchanged; changed55 needs fresh
  compatibility/drift/rollback evidence.
- [ ] Update all original task evidence without promoting controlled fixtures
  to live production proof. Commit/push verified main integration only when
  release authorization/gates allow; record deployment/canary separately.

## Execution checkpoint

Linked completion checkpoint (2026-09-17): SQL RED55edf2 and Go API RED1ce68f drove a pinned registered-worker finish wrapper and strict Go client. Completion holds parent-before-child/current lease and pinned target authority; every journal row must match attempt/input/lease/target/category. Pass/fail requires all configured categories completed with HTTP200 and exact ordered evidence, aggregate verdict and objective/behavior. Engine error remains inconclusive and preserves unresolved starts. Private predecessor persistence retains immutable input/output artifact receipts; post-write readiness plus original lease and parent deadline checks roll back expired writes. The Go client sends raw lease bytes/exact release pins, requires input receipt, and rejects duplicate/aliased/null/extra/mismatched response fields. Real Go-to-SQL completion tests cover pass, mixed three-category fail, engine-error uncertainty and observed INSERT waits crossing lease/budget with unchanged run/attempt/journal; snapshots are ordered. Final owned group53742f/1dc03b/ddc014 passes finish33.53s, claim/heartbeat45.08s, HTTP5.07s, known HTTPS13.26s, unknown HTTPS10.83s, legacy5.06s, journal client17.32s, fingerprint3.41s and release7.88s. Exact repository race092d0e passes4.440s, full migration race4.425s, worker racee65e93 passes3.362s with Node enabled. Independent review has no Critical/Important findings. Calibrationb1004b pins55 at98c44a65fe04073bda1e26c243128555ad0be7cb5e04c8d61e0ccf0c00959470. Initial SQL CASE parse failure4d21a2 was fixed; an over-broad local selector652165 attempted host initdb and failed shared-memory setup, which is not verification evidence and caused no host-service/shared-memory cleanup. Final database evidence comes from the owned offline container. Artifact references here are controlled receipts, not live uploads/content retrieval. Full artifact comparison/secret-version association, linked cancellation/reconciliation, production composition and A-D/live acceptance remain open. M7A-21 stays component-only/disabled; no UI release gate, commit or push.

Linked processor checkpoint (2026-09-17): behavioral REDd9ac63 exposed dropped claim version and legacy retry handling. The processor now routes exact red-team-v2 claims to a separate linked lifecycle, propagates evidence version to Run, rejects unknown versions/expired leases, and leaves reconcile_required unacknowledged. A deadline monitor stays active during serialized heartbeat I/O; only valid live renewal plus queue visibility success replaces the prior local deadline. Visibility uses whole seconds rounded down to the DB expiry. Run errors, cancellation, missing input evidence and lease loss never call legacy retry/cancel or acknowledge; completion uses the live cancellation context and only acknowledged durable completion permits queue acknowledgement. Initial focused racef7d6c5 passes2.964s; final grouped worker race82e154 passes3.500s with explicit Node contract enabled. Seventeen controlled-boundary cases include renewal past initial expiry, deadline before first heartbeat, blocked heartbeat, malformed/contradictory expiry, visibility failure, missing input artifact, failed completion acknowledgement and deadline-blocked finish. Independent re-review has no Critical/Important findings. Authority/queue/runner lifecycle boundaries are controlled here, not actual database finish, external cancellation or live execution. Production still composes the legacy repository; linked database completion/cancellation/reconciliation, full artifact comparison and exact secret-version association, A-D acceptance and live gates remain open. M7A-21 stays component-only/disabled; no UI release gate, commit or push.

Linked runner-input checkpoint (2026-09-17): API REDb1ddd2 and behavioral REDab81ae exposed missing version selection. Explicit red-team-v2 execution requests now persist v2 input with the configured immutable runner-image digest and invoke the same fixed adapter host at /v1/linked/evaluate. Empty version preserves v1; unsupported values fail before artifact persistence/execution. Actual Run feeds actual Node configuration/summary/native producers and the Go bundle verifier across six mixed-verdict categories, preserving the image and excluding authority secrets. Controlled command/storage and native responses are not live engine, provider, upload or image-attestation proof. Initial grouped882583 caught fixture output permissions; the fixture now uses the real producer's exclusive0600 files. Final grouped worker racec19c71 passes2.430s with ZASP_TEST_NODE explicitly enabled. Independent review has no Critical/Important findings. Production processor still does not propagate/select linked claims: deadline-aware execution, finish/cancel/reconciliation, exact secret version, comparison settlement and A-D/live gates remain open. M7A-21 stays component-only/disabled. No fresh UI release gate, commit or push.

Linked heartbeat checkpoint (2026-09-17): missing Go API826a05/a6e59a and SQL RED3fa587 drove registered-worker renewal plus strict Go consumption. Renewal holds parent-before-child authority, exact worker/token and linked definition/current pinned target; expiry is capped by parent budget. It retains the original expiry and rechecks it after UPDATE waits and full release verification, so a fresh expiry cannot resurrect an expired lease. Cancellation returns renewed=false/cancel_requested=true without run cancellation or lease mutation. Invalid/expired leases do not renew. The client requires a bounded future expiry only on successful renewal, rejecting duplicate/case/null/extra/contradictory response fields; legacy heartbeat consumers retain nil expiry. Actual Go->SQL tests cover stopped budget/control/discovery, observed UPDATE waits crossing original lease and budget deadlines, cancellation without mutation, started-journal renewal and configuration drift refusal with unchanged run/journal. Grouped owned PostgreSQL83a127/7e76dd passes claim+heartbeat44.66s, HTTP4.81s, known HTTPS13.03s, unknown HTTPS10.37s, legacy4.98s, client16.83s, fingerprint3.28s and release7.35s. Repository race df1ede passes3.575s, worker compatibility8dcd4c passes2.314s, migration racecdd3a5 passes5.032s. Controlled calibration385544 yields pin2ca53c90989ce66033d5cbf0b701b3fb925187fa2d5ed1d0a5f10f674d64309d. Independent re-review has no Critical/Important findings. These are component tests, not live provider/cancellation proof. Production worker selection and deadline handling, linked completion/cancellation/reconciliation, exact secret-version association, comparison settlement and A-D/live gates remain open. M7A-21 remains component-only/disabled; no fresh UI release gate, commit or push.

Linked Go claim client checkpoint (2026-09-17): missing-API test8ecf36 drove a dedicated Go claim repository with compiled55 readiness/role checks, per-call scope and release pins, raw lease bytes, no legacy fallback, bounded exact JSON decoding (including nested duplicate/case/null rejection), v2 evidence version, immutable input digest, exact run/definition association and bounded future lease. Non-claim dispositions carry no execution authority; provider errors are sanitized. Shared RedTeamRunClaim now carries EvidenceVersion; legacy callers leave it empty. Real registered-worker integration REDac90b7 exposed missing readiness permission and retained rate_limited on a fresh retry lease. Read-only client_ready permission and clearing error_code only after uncertainty checks fix those issues. The positive PostgreSQL fixture now uses the actual Go constructor/client for initial claim, expired-unstarted and rate-limited reclaim, reconciliation and terminal acknowledgement, followed by real adapter journal operations without target I/O. Grouped offline DBbb28d7/94436d passes claim24.10s, HTTP4.83s, known HTTPS13.12s, unknown HTTPS10.65s, legacy5.13s, client17.26s, fingerprint3.38s and release7.52s. Client/legacy repository racebd4cf7 passes2.399s; worker compatibility race087bc7 passes2.318s; full migration race79b389 passes4.446s (the earlier filtered migration command selected no tests and is not migration evidence). Controlled calibration1bbcc4 yields pinf78810f52a3383e678dde93bfda17c99509a8aabb8adb5be337b7d2c158e78d0. Independent re-review has no remaining Critical/Important findings. This does not select the new repository in production workers or prove uploaded artifacts/live invocation. Linked worker selection, heartbeat/completion/cancellation/reconciliation, exact secret-version association, comparison settlement and A-D/live gates remain open. M7A-21 remains component-only/disabled; no fresh UI release gate, commit or push.

Linked worker claim checkpoint (2026-09-17): REDc78ae5 drove a release-pinned registered-worker claim entrypoint. It locks organization/parent/budget/step before child state, requires exact linked definition and current target provenance, caps the lease at the parent deadline, and rechecks wall-clock authority after UPDATE waits and release verification. Live duplicate leases return retry_later; expired work with any journal history, exhausted attempts or outcome_unknown returns reconcile_required without mutation; only unstarted work can receive another attempt. Review found terminal acknowledgement unnecessarily required live parent authority; REDf1cefd and a separate scoped read-only terminal path resolve that issue. All three terminal states acknowledge even with stopped budget, without granting execution. Registered-worker tests also cover wrong roles (including unregistered owner), scopes, null/malformed values, stale pins, parent/budget/control/definition/discovery stops, observed UPDATE-blocked deadline expiry, exact v2 claim identity/digest/capped lease, unstarted reclaim and started/known-terminal reconciliation. Real claim-to-adapter journal calls are covered without target I/O; separate HTTPS fixtures still use controlled discovery and owner-seeded leases. Grouped offline PostgreSQL047884/5930b8/cd03dc passes claim22.75s, HTTP4.88s, known HTTPS12.90s, unknown HTTPS10.39s, legacy4.98s, invocation start49.60s, terminal5.25s, client17.11s, fingerprint3.23s and release7.17s. Migration racece24bb passes4.999s. Final offline calibration12fd9f yields pin0bc4e09fbec8b4b99b78b2074dddddd69105cc3feebd8ae1d47ec522ad63fd02; drift tests cover claim ACL/search path and private worker grants. Independent re-review has no remaining Critical/Important findings. The Go repository/worker does not yet consume/select this claim response. Linked heartbeat/completion/cancellation/reconciliation, exact secret-version association, comparison settlement and A-D/live gates remain open. M7A-21 remains component-only/disabled; no fresh UI release gate, commit or push.

Legacy completion checkpoint (2026-09-17): RED1d8512 reproduced linked complete/pass without linked journal evidence through the legacy18-argument completion function. Release55 now guards that callable overload; the17-argument overload retains unconditional rejection and privatev38 remains inaccessible to workers. Registered-worker tests use valid controlled receipts, assert unchanged linked run and attempt rows on refusal, and positively claim/complete an unlinked run with exact input-artifact retention. Grouped owned PostgreSQL a83e5d/9055bc passes HTTP5.14s, known HTTPS14.18s, unknown HTTPS11.68s, worker lifecycle6.18s, journal client17.77s, fingerprint3.89s and release7.01s. Migration raceb40f9a passes5.321s. Controlled calibration7cd0d8 yields pin af585ed5f4d96c5ada4b853916429c1919e6a9f952a94c30ac7a20e01b6248fd; rollback comparisons include overload identities/privatev38 and new drift cases pass. Independent source review found no Critical/Important findings. Unchanged lease-expiry tests were not rerun in this batch; their prior evidence remains separately recorded. Artifact references are fixture inputs, not uploaded-object or production execution proof. Linked worker claim/heartbeat/completion/cancellation, exact secret-version association, comparison settlement and A-D/live gates remain open. M7A-21 remains component-only/disabled; no fresh UI release gate, commit or push.

Legacy worker lifecycle checkpoint (2026-09-17): grouped RED8ea3ff reproduced both linked heartbeat renewal and claimed cancellation through old registered-worker entrypoints. Release55 now fences both through the scoped link guard, saves private predecessors, and restores their exact body/owner/ACL on eligible rollback. Registered-worker tests assert refusal without linked run mutation and positive unlinked heartbeat/retry/reclaim/cancellation. Owned offline grouped PostgreSQL verification7e143e/fedc60/5b5b58/56ad42/b467c1 passes HTTP lifecycle5.20s, known HTTPS13.46s, unknown HTTPS10.96s, legacy fence5.17s, invocation start49.62s, terminal5.45s, client17.49s, fingerprint3.52s and release7.04s; migrations race9ee60c passes5.211s. Offline calibrationf47b9b yields compiled pin9faacbb4fbdb27ebaa6be1f0efec3db753a6350f0d351e9262188a56dbe0b4a9. Independent source review found no Critical/Important issues. This closes two legacy mutation bypasses, not linked worker execution: finish-overload fencing, linked claim/heartbeat/completion/cancellation, exact secret-version association, comparison settlement and A-D/live gates remain open. M7A-21 remains component-only/disabled. No fresh UI release gate, commit or push.

Runner image declaration checkpoint (2026-09-17): RED runtime b90d84/rendered8b8472/Node5fd17b/Go27dd39 drove immutable-image declaration validation. Helm supplies ZASP_RED_TEAM_RUNNER_IMAGE from the same value as the red-team worker container image; runtime config and runner construction reject absent, mutable, malformed or zero digests. Production composition passes the validated image declaration. V2 input requires runner_image_digest, Node retains it in evaluation identity and Go rejects mismatches/invalid declarations; v1 wire format remains unchanged. Node16 plus focused rendered release65090f pass, final affected Go race2e88a6 passes2.423s with actual six-category Node contract enabled, pinned controlled enginece48c5 passes37.30s. Full release-rendering89db18 passes45 tests after its owned filesystem watcher failed in sandbox7423f0 and succeeded on scoped retry. Independent review has no Critical/Important findings. Compatibility: non-Helm red-team deployments must set ZASP_RED_TEAM_RUNNER_IMAGE to their immutable configured image before adopting this change. This proves configuration/wire declarations, not deployed-image attestation: production still selects v1, config-to-v2-input and DB/artifact association remain unwired, and the image proof uses an explicitly controlled declared digest. Actual secret version, linked claim/selection, cancellation/settlement and A-D/live gates remain open. M7A-21 stays component-only/disabled. No UI release gate, commit or push.

Evaluation identity checkpoint (2026-09-17): RED Node814134 and Go162b96 captured missing linked evaluation identity. V2 native artifacts now retain engine/version, curated-pack version and ordered category/check IDs with SHA256 prompt/assertion identities. The assertion identity includes the exact JS grade, canary and versioned adapter criterion. Node validates the actual native testCase.assert before retaining it; Go independently derives and requires exact identity and per-record assertion. Missing/changed pack, check, prompt/assertion hash, substituted or extra assertion fields are refused. No-native engine-error artifacts carry attempted identity only. Node component30e63d passes16 tests; actual pinned Promptfoo2fd899 passes v1/v2 pass/fail/engine-error and cancellation39.08s against controlled TLS. Final Go race9342e4 passes2.464s with ZASP_TEST_NODE explicitly set: actual Node producers and Go consumer agree for all six categories, mixed verdicts and reordered-identity refusal. Independent review has no Critical/Important findings; its multi-category coverage note is resolved. This does not pin the built runner image, actual secret version, or associate database comparison with immutable input/output artifacts. Those gates, linked DB claim/selection, cancellation/settlement and A-D/live acceptance remain open. Compiled55 pin remains844aa23ab89501c6c5da3864be6c6368d0c58c66f3104029a6c39aae861e2261. M7A-21 stays component-only/disabled; no UI release gate, commit or push.

Scoped test/safety comparison checkpoint (2026-09-17): RED ce8da6 reproduced completed receipt reuse after same-version safety-policy and category changes in all four handler/DB/TLS modes. The private invocation_target helper now takes exact test ID/version from held link/run authority, joins the matching enabled scoped definition/target under NOWAIT share locks, and adds organization/workspace/environment, test ID/version, target ID/kind, ordered categories and safety SHA256 to the durable comparison snapshot. Resolve/start reject drift without rewriting the journal or sending again. Direct stored-field assertions verify scope/test/safety identity. Independent review reports no Critical/Important findings. Grouped owned suite f65199/bea132/bffe91/bca5f5/e46f4b passes HTTP5.04s, known TLS13.16s, unknown TLS10.90s, legacy5.18s, start49.50s, terminal5.30s, client16.93s, fingerprint3.21s and release/rollback6.52s. Migration race db1756 passes4.901s. Compiled55 pin844aa23ab89501c6c5da3864be6c6368d0c58c66f3104029a6c39aae861e2261 was calibrated in owned fixture aee71d; ACL/drift tests use the new private seven-argument identity. Engine/image/pack/check identity, actual secret-version association, immutable artifact association, linked worker claim/selection, cancellation/settlement and A-D/live acceptance remain open. M7A-21 remains component-only/disabled. No UI release gate, commit or push.

Target/credential comparison checkpoint (2026-09-17): RED fac0d2 reproduced completed receipt reuse after credential-version rotation in all four owned handler/DB/TLS modes. The private target resolver now pins a versioned comparison object in durable target_resolution: endpoint and winning-configuration SHA256 digests plus exact credential binding ID/version/reference digest. It joins the active unexpired exact scoped binding and retains NOWAIT row locks; existing resolve/start snapshot comparisons reject version, digest or configuration drift without another target request. Complete still records known late observations. Independent review has no Critical/Important findings; added its Minor stored-value/unchanged-journal assertions, final four-mode a0f670 passes13.08s. Grouped owned suite fbe792/0aa8a4/f8f65d/a873e8/6ffd6d passes HTTP lifecycle4.98s, known TLS12.71s, unknown TLS10.59s, legacy4.95s, start49.44s, terminal5.33s, journal client17.34s, fingerprint3.22s and release/rollback6.48s. Migration race f540f0 passes4.783s. New compiled55 pin is 371e8aa7e93e59c44105ee0a1230c488feb8dedd423b0a5cf1c4b9b87fb3f259, calibrated only in the owned fixture8f7d2c. This pins database authority, not the actual transported secret version. Safety/test/engine/image/pack/check comparison members, artifact association, DB-owned claim/runner selection, cancellation/settlement and A-D/live acceptance remain open. M7A-21 stays component-only/disabled. No UI release gate, commit or push.

Handler/database/TLS checkpoint (2026-09-17): The owned integration now enters actual NewJournaledHandler.ServeHTTP with registered Postgres resolution/journaling, then actual HTTPSInvoker against controlled TLS. Wrong bearer, valid foreign organization/workspace/environment/run and wrong lease all refuse before any target request. Exact redacted HTTP observation fields, no-store, committed-start visibility and lost-completion-ack replay pass. An additional four-mode malformed target response case retains started/no completed_at and returns503 on both initial call and fresh connection/handler replay with exactly one request. Final grouped run b420fb/afab09 passes known11.03s and unknown10.37s; both owned PostgreSQL processes joined normally. Independent review found no Critical/Important issues; its Minor exact-response-shape suggestion was added before the final run. Direct ServeHTTP, seeded discovery/lease, controlled routing/credentials and fresh connection/handler are not worker composition, production transport, full process restart or live-provider proof. M7A-21 remains component-only/disabled; next production work is the immutable comparison tuple and DB-owned linked claim/runner selection, followed by cancellation/settlement and A-D acceptance. No UI release gate, commit, push or status promotion.

Database-to-HTTPS checkpoint (2026-09-17): TestSecurityAgentExistingTestJournalHTTPSPostgres runs the owned redteamadapter test binary against the same isolated PostgreSQL fixture. Actual registered PostgresInvocationJournal resolution/start/complete compose with HTTPSInvoker and controlled TLS. A separate owner connection observes the exact committed started/request digest before the target responds. All four run/rerun and supervised/autonomous cases pass; rerun cases deliberately drop acknowledgement only after real completion commits. Fresh registered database-connection replay retains the actual unsafe response digest/protected=false and makes exactly one target request. Final owned run afd8fb passes9.58s; adapter race fd59bd passes1.610s after sandbox listener denial4a5123 was retried with scoped permission. Independent review reports no Critical/Important findings. This is seeded discovery/lease and controlled routing/credentials, not a full process restart, production transport, worker-to-handler or live-provider proof. No product transport bypass added. M7A-21 remains component-only/disabled; full comparison tuple, DB-owned v2 selection, claim/retry/cancellation/settlement, A-D acceptance and live gates remain open. No UI release gate, commit or push.

Linked engine/evidence checkpoint (2026-09-17): Node v2 grades the exact linked observation envelope and retains its response digest without synthesizing target text. Pinned Promptfoo controlled-adapter image proof 9e31df passed v1/v2 pass/fail/engine-error and v2 cancellation, with exact per-category call counts and peak concurrency one for successful linked evaluations. This is controlled TLS evidence, not live provider or journal-backed execution. Fresh Node component group d28f1e passes 15 tests. Go v2 artifact verification binds schema/run/category/status/digest/protected to the summary; RED ca83b6 exposed conflicting duplicate protected values, now rejected with case aliases by exact recursive key validation. Review found the summary decoder also accepted ambiguous keys; RED eba987 reproduced it. The shared v2 decoder now checks summary and native bytes. Added protected-pass, adapter503 and missing-native engine-error positive cases. Final focused Go race 937470 passes (2.232s). Independent re-review reports no remaining Critical/Important component findings. Production launcher still selects v1, linked execution stays disabled/component-only. Full comparison tuple, DB-owned v2 selection, claim/retry/cancellation/settlement, A-D acceptance and live gates remain open. No UI release gate, commit, push or production promotion.

Linked HTTP-handler checkpoint (2026-09-17): RED4ef5d2 reproduced missing
linked routing and accidental acceptance of the legacy path. NewJournaledHandler
now serves only /v1/linked/evaluate with existing token/scope/lease checks and an
exact four-key bounded JSON body. After resolution it calls InvokeJournaled and
returns red-team-linked-observation-v1 (run/category/redacted observation), never
raw or fabricated provider output. NewHandler retains its legacy path/response;
production composition still uses NewHandler, so the linked route is NOT enabled.

Controlled journal/resolver with an actual owned TLS target verifies lost complete
acknowledgement503 then unsafe replay200 with one target request, fresh safe
success/replay equality, malformed target response remaining unknown with no
resend, and malformed/auth/ambiguous request refusal before resolution/network.
Legacy and linked handlers reject each other's paths. Adapter race9d331b passed
1.999s. Owned runtime group0dd5ec/93efb7 passed configuration, DB concurrency0.49s,
failed-commit acknowledgement0.41s and shutdown0.44s. Independent review found no
Critical/Important issues; its fresh-success/legacy-path coverage suggestions
were added. This is HTTP/HTTPS component evidence, not composed SQL-to-HTTP proof.

M7A-21 remains component-only/disabled. Next integration must make the worker
consume the versioned observation contract and wire the real journal/resolver,
then count requests through real DB-to-HTTPS flow. Full comparison/credential
version, claim/retry/cancellation/settlement, A-D acceptance and live production
proof remain open. No UI gate, commit, push or production promotion.


Versioned target-resolution checkpoint (2026-09-17): client REDe48cfa and
registered DB RED9f0e34 identified missing resolution. PostgresInvocationJournal
now implements TargetResolver through the pinned invocation_resolve wrapper.
It returns only an exact five-key valid binding for the requested target/kind.
SQL checks registered adapter, exact release, parent/current safety, locked live
Red Team lease and scoped linked definition/category. Winning provenance stays
under the existing NOWAIT locks; a prior journal resolution cannot be substituted.
Final parent and held-lease deadlines are checked after the release scan. This
read grants no execution permission; durable Start is still required before I/O.

The registered client fixture resolves the binding before start/complete/replay.
It refuses wrong organization/workspace/environment, target/kind, category, lease
and release pins. Owned group792655/983057/768341 passed HTTP lifecycle4.95s,
legacy fence5.04s, resolver/journal client16.89s, fingerprint3.30s and release6.51s.
Adapter racebf7e37 passed1.925s; migration raceb95ed1 passed5.080s. Calibration
a63b0c pins55 at `3ef421c5120ccc443d06411894152a564b646cd562157addcef536d4f724bebf`.
Independent review found no Critical/Important issues. Delayed-readiness expiry
instrumentation currently exercises Start, not ResolveTarget; resolver-specific
post-readiness delay coverage remains an explicit test limitation.

This is registered DB/client evidence using seeded discovery and lease authority,
not live discovery or a provider request. M7A-21 stays component-only/disabled.
Actual adapter/worker route composition, DB-to-HTTPS request counting, complete
comparison/credential-version tuple, claim/retry/cancellation/settlement and A-D
acceptance remain open. No UI release gate, commit, push or production promotion.


Versioned journal-wrapper checkpoint (2026-09-17): RED0a36f8 reproduced missing versioned starts in all four action/autonomy cases. New start/complete wrappers check registered adapter identity and exact release readiness before/after private cores. Only zasp_red_team_adapter gets wrapper EXECUTE; private cores and dispatch remain inaccessible. The registered PostgresInvocationJournal now performs real DB start, unresolved refusal, completion and immutable unsafe replay without temporary core grants. Discovery and lease prerequisites remain owner-seeded, with no provider request.

Independent review found post-core release scans could outlive admission expiry. Timing RED1d7076/3e4c5e reproduced a parent-deadline bypass. The start wrapper now rechecks parent/current safety and the already-locked Red Team lease after readiness. The owned readiness-delay hook is scoped to the current run and restored before the real positive flow. Its expiry checks are timing instrumentation, not release verification. Completion keeps late-observation semantics. Reviewer accepted the repair with no remaining blockers.

Owned calibrationb7ceff pins55 at `722056f6e02de1c63db53f342017093a39f1d464811a3e85077e851f2793ae95`; initial wrapper pinae0ab731 from03ff17 is superseded. Migration race3ae85e passed5.279s; adapter racee9d227 passed1.970s. Initial group3939fc/a980dc passed but preceded the timing repair and does not clear final acceptance.

M7A-21 remains component-only/disabled. Versioned target resolution, adapter/worker route composition and real DB-to-HTTPS request counting remain unverified; full comparison/credential-version tuple, claim/retry/cancellation/settlement and A-D acceptance are open. No UI gate, commit, push or production promotion.

Final owned group7c46ac/f5cb2e/f0cc94/8775f8 passed: HTTP lifecycle4.95s,
legacy fence4.97s, invocation start49.33s, terminal5.35s, registered journal
client15.41s, fingerprint3.30s and release6.30s. This supersedes the pre-repair
group; all four action/autonomy modes reject post-core parent/lease expiry and
leave no started row before the restored real-readiness positive flow.


PostgreSQL journal-client checkpoint (2026-09-17): initial compile8fd32d
identified the missing client; behavioral RED7dcda3 refused a valid started receipt
before implementation. New PostgresInvocationJournal constructs scoped, checksum/
fingerprint-pinned calls to the planned versioned start/complete wrappers, never
private cores. It validates canonical inputs/body digest before DB access and
strictly decodes stored binding/provenance, category/digests, attempts and terminal
run/verdict/time. Duplicate, aliased, extra and mismatched receipt fields fail;
completion acknowledgements must match the submitted observation exactly.

Adapter race9d7a90 passed1.972s. Owned no-network PostgreSQL groupba4fa9/1ef41e
passed concurrency0.94s, deferred-commit acknowledgement0.39s, shutdown0.47s and
runtime configuration checks. The deferred FK test produces a RETURNING row but
rejects its failed commit with no receipt/no persisted row; a successful write is
visible from another connection. This verifies the concrete driver's autocommit
boundary, not full journal SQL integration. Independent review has no remaining
blocking findings after exact-key membership and negative coverage improvements.

The versioned invocation_start/complete SQL wrappers are not implemented yet;
the client is not composed into a live route and cannot execute against release55
as-is. No private-core grants or fallback were added. Wire the wrappers, receipt
association and real database-to-HTTPS flow before enabling this path. M7A-21
stays component-only/disabled; full comparison tuple, credential version,
claim/retry/cancellation/settlement and A-D acceptance remain open. No UI release
gate, commit, push, provider call or production promotion is claimed.


Outbound binding checkpoint (2026-09-17): RED1fa70b reproduced seven
accepted mismatches (endpoint, credential reference, target ID/kind, version,
missing binding and completed replay). InvocationReceipt now carries the stored
TargetBinding and InvokeJournaled requires exact equality with the invocation
before sending or replaying. The journal contract forbids echoing the request
or resolving a replacement on replay. The controlled fixture retains its original
binding/digest; a changed endpoint after lost completion acknowledgement is refused.
Adapter package race checks6465dc passed1.853s. Independent review found no
Critical/Important findings. This is coordinator coverage over controlled journal
and owned TLS, not concrete database-client or live provider proof. M7A-21 remains
component-only and disabled; concrete journal client/route, credential version,
full comparison tuple, claim/retry/cancellation/settlement and A-D acceptance remain
open. No UI release gate, commit, push or production promotion.


Durable target-resolution checkpoint (2026-09-17): RED7ce8e8 showed the
missing endpoint binding in four started receipts. The private resolver now
uses the winning source/snapshot/evidence joins with wall-clock target freshness.
A started journal row stores its binding (target/kind/endpoint/credential
reference/inventory version) and provenance (integration/snapshot/evidence/
source/generation). Later categories and replay must retain that exact resolution.
Terminal receipts expose the stored resolution, never a newly resolved substitute.

Independent review found an observation/entity lock-order risk against typed
discovery apply. Contention REDbb36d4 held the source row and timed out in all
four cases. Provenance row acquisition now uses NOWAIT, removing that wait cycle;
the test requires55P03 while busy, then proceeds after release. Review accepted
the repair. This reproduces contention, not a full live discovery deadlock.
The earlier green group202239/702d41 lacked this contention test and is superseded.

Owned calibration8268f4 pins55 at
`4283cbb381dd5c07b19027f28fd4fb6b002619603c6d02d0ccd4f2a767e405f8`.
The prior6c080c pin from840c72 is superseded. Tests also refuse a non-last-good
snapshot and a substituted endpoint on terminal replay without changing journal
history. Concrete journal client must still compare the pin to the actual signed
request. Credential binding version, engine/runner/pack/check identities and
complete comparison evidence remain unfinished. Owner-seeded discovery is not
live sync proof; no real provider request is claimed.


Final grouped verification84a3fa/4e46e2/c7e346 passed: HTTP lifecycle4.99s,
legacy fence5.05s, invocation start49.41s, terminal5.15s, fingerprint3.28s,
and release6.07s. Migration race checksfe6e76 passed5.131s.
M7A-21 remains component-only and disabled, with A-D acceptance open.
No fresh UI release gate, commit, push or production promotion is claimed.

Verification cadence: group related microtasks into feature batches. Keep focused
regression tests during implementation, run affected integration checks and
independent review once per stable batch, and run full release/UI gates before
push. Retain per-task evidence and all security boundary coverage. The terminal
suite's duplicate expiry waits were removed; dedicated admission tests retain them.


Invocation authorization checkpoint (2026-09-17): RED49ada6 showed starts
accepted after disabling the parent definition in all four action/autonomy
cases. A private invocation authorization function now reuses the dispatch
contract with exact-count checked substitutions only for the function name and
expected post-dispatch states (running/executing). Original dispatch authority
is unchanged. Parent admission checks current definition enabled/autonomy/action,
exact stored plan hash and step tuple, and supervised approval identity/hash/
expiry or autonomous absence of approvals, before and after journal work.

Owned calibrationc4cd27 sets55 pin
`0977197c90d4305810a55d8cbd96bdc8fdaed1590c060723075fe406c9eaa552`.
Independent review found no Critical/Important issue; outdated pending-approval
comment was corrected. Tests cover disabled definitions, substituted supervised
approval plan hash, and observed journal INSERT blocking through plan expiry
in all modes and approval expiry in supervised modes. Temporary fixture grants,
owner mutations and seeded leases are controlled component evidence only.

Grouped2fc143/5044b7/bf9e85/416ef6 passes HTTP5.05s, legacy fence5.10s,
start49.32s, terminal5.11s, fingerprint3.26s and release/drift/rollback5.95s.
Migration racefd5e55 passes4.610s with clean diff check. New private authorization
ACL and search_path drift are rejected. The terminal suite still avoids duplicate
start-expiry waits. Endpoint/config/provenance/comparison pinning, concrete SQL
journal client, adapter/worker routing and end-to-end settlement remain open.
M7A-21 stays component-only and disabled. No UI release gate, commit, push or
production promotion.

Current-target invocation checkpoint (2026-09-17): RED0b5028 demonstrated
that a revoked credential still allowed a started receipt in the first joined
case. Later RED cases hit setup refusal because the shared credential remained
revoked; the test now restores shared authority before asserting the call result.
The private parent guard reuses the locked scoped test-binding resolver and
requires its exact definition/version/target/kind tuple to equal the link.
This checks current enabled selected test, non-production environment, active
target, matching active credential, safety class and wall-clock freshness.
The binding check repeats after journal writes/replay locks, followed by final
Red Team lease and parent deadline checks.

Owned calibration83a9a4 sets55 pin
`f0e7abd045473cff4fde73a0eeb60957395650822cd5d431b369d8fa05bc058e`.
Independent review found no Critical/Important issue. Actual endpoint/config
pinning, provenance/comparison tuple and final invocation approval authority are
still unfinished. Temporary grants, owner-seeded leases/discovery and authority
mutations remain controlled evidence, not live provider or discovery proof.

Grouped3f4296/ac0862/add0c8/4e113e/1700ec passes HTTP4.98s, legacy
fence4.99s, start37.31s, terminal37.40s, fingerprint3.25s and release6.03s.
Migration racef489f2 passes5.252s. The start suite observes journal INSERT
blocking through target fresh_until and credential valid_until expiry, in
addition to lease/budget deadline waits, and rejects each transaction.

Test-only batching then removed duplicate admission-negative/expiry waits from
terminal mode. The dedicated start suite retains those cases; terminal mode
retains ACL, commit, reconnect, uncertainty and terminal assertions. Independent
review confirmed fixture independence and retained coverage. Recompiled terminal
d5a44a/b018dc passes5.26s versus37.40s, about32s saved in this suite.
Diff check2bcd66 passes. No UI gate, commit, push or production promotion.
M7A-21 stays component-only; final SQL wrapper, concrete journal repository,
adapter/worker wiring, comparison/settlement and composed acceptance remain open.

Parent invocation admission checkpoint (2026-09-17): RED758c28 showed all
four joined action/autonomy cases accepting a new start despite the parent
budget's sticky stop. The private parent guard now takes organization admission
before parent/run/budget/step locks, requires running parent, executing step,
pending effect, exact existing reservation/input digest and three enabled
kill-switch rows, and revalidates the discovered scoped link. Missing, stopped,
null or expired budget authority fails. Start rechecks the parent deadline after
blocking journal work and receipt replay locks. Terminal completion still
records late observations without granting renewed authority.

Owned calibrationfb50e4 sets55 pin
`6bfb702b7615482658d51d1f162290843c144fa02d49075e076b755dc0d8c877`.
Independent review found no Critical/Important issue in this prerequisite.
Current target/safety, approval and comparison authority still belong in the
unfinished final adapter wrapper. No private helper grants or route enablement
were added. Controlled owner mutations and temporary adapter grants are not
production execution or live provider evidence.

Groupedc195d9/60e623/93858f/480ca1/beea7c passes HTTP5.24s, legacy
worker fence5.22s, start21.44s, terminal21.49s, fingerprint3.47s and release/
drift/rollback6.23s. Start cases stop/recover parent run, sticky budget, action
kill switch and reservation digest. Actual journal INSERT blocking is observed
through both Red Team lease expiry and parent budget deadline, with rejection.
Migration race384ef1 passes5.511s; diff check9e7cff clean. M7A-21 remains
component-only; full SQL admission, real journal repository, adapter/worker
wiring, comparison/settlement and composed acceptance remain open. No UI gate,
commit, push or promotion.

Journaled HTTPS coordinator checkpoint (2026-09-17): RED63fd0f showed no
request/terminal observation from the missing coordinator. InvokeJournaled now
hashes the exact shared signed payload, requires a newly committed start or an
exact terminal receipt, sends once, and returns structured evidence only after
completion acknowledgement. Replay never invents raw output. The journal
contract requires full scoped admission and rejects unresolved starts, including
lost start acknowledgement; this interface is not yet a concrete SQL client.

Adapter race e33c9c passes1.813s with actual local TLS requests and a controlled
journal: commit-before-send, lost completion acknowledgement/replay with count1,
unknown outcome refusal, exact received-body/signing digest, malformed receipt
and cancellation zero-send, lost start acknowledgement zero-send, replay-copy
isolation, unsafe false result, malformed response/transport-close no completion
and no resend. Rebuilt command package d48d02/41e644 passes owned-container
config, DB concurrency0.58s, deadline/shutdown0.42s and TLS checks. Independent
review found no Critical/Important issue after contract/test strengthening.

Controlled journal state is not database durability or tenant admission proof.
Concrete SQL admission, journal repository, handler/worker wiring, comparison
evidence and settlement remain open. Coordinator has no HTTP route registration.
M7A-21 remains component-only and disabled; no UI gate, commit, push or promotion.

Ambiguous-response repair (2026-09-17): RED2a5957 demonstrated duplicate
output fields hiding an unsafe canary behind a later safe value. Struct decoding
overwrote the first field. Both invocation methods now require exactly one
case-sensitive output string and object/EOF closure. Duplicate/case-folded,
null, array, empty, unknown, missing, truncated and trailing responses fail
without output or a successful observation. Adapter race aec780 passes1.823s;
rebuilt command package passes owned-container3d93a6/2bee3d (DB concurrency0.62s,
deadline/shutdown0.41s, config/TLS checks). Independent review found no Critical/
Important issue. This closes a false-protected-result prerequisite; durable
admission/receipt wiring remains unfinished. No UI gate, push or promotion.

HTTPS observation checkpoint (2026-09-17): RED0bba2a proved the missing
observation boundary for all six curated categories, protected/unsafe cases.
InvokeObserved now uses the existing credential signing, bounded HTTPS transport
and strict response validation. It returns the raw response-body SHA256, HTTP200
and exact selected canary not-contains result separately from output. Legacy
Invoke delegates the same path. No raw output enters the observation object.

Adapter race groupd76e3e passes1.743s, including all12 local TLS observation
cases with one actual fixture request each and empty observations for rejected
responses. Initial sandbox27b422 denied loopback binding; approved loopback run
then captured the real RED. Overbroad grouped commande1b503 passed the adapter
package but failed two host initdb setups. The command package was rebuilt for
the owned no-network PostgreSQL container:49a7af/18efd2 passes configuration,
database concurrency0.69s, request deadline/shutdown0.41s and TLS-file checks.
No user PostgreSQL process or IPC was changed. Diff check595bae passes.

Independent review found no Critical/Important issue. Non-200 or malformed
responses currently yield no observation, so future durable integration must
retain uncertainty without inventing a protected result or retrying execution.
This is local TLS component evidence, not live customer, admission, durable
receipt wiring, comparison tuple or remediation proof. M7A-21 stays component-
only and disabled; no UI release gate, commit, push or production promotion.

Private terminal-receipt checkpoint (2026-09-17): repairs RED87deec,
which found no completion operation in four joined action/autonomy cases.
The private journal now stores immutable response digests, HTTP status and a
bounded protected observation. Completed receipts replay without another start;
an unresolved category blocks a new category. Conflicting association or response
fields fail without changing the receipt. Raw provider text is not stored.

Completion can record a known response after a cancellation request and lease
expiry, without changing the run or renewing execution authority. The fixture
does not prove a terminal cancelled run. A non-200 response cannot claim a
protected result. Independent review found no Critical/Important issue in this
private persistence boundary; full adapter admission, actual provider requests,
curated assertions, comparison evidence and runtime settlement remain open.

Owned calibration56ffee pins55 at
`c557cec07a3090b04327a099ea685103bd1ddd81d80e131da937f9079b5183ef`.

Grouped456936/eacfb6/f243f0/7d6414/fe28d2 passes HTTP lifecycle5.50s,
legacy-worker fence5.26s, durable start13.22s, terminal receipts13.43s,
compiled fingerprint3.63s and release/drift/rollback6.45s. Migration race9e995f
passes4.972s; diff checke9c68b is clean. Private completion/projection grants
and search_path drift are rejected. These are controlled DB/HTTP component
tests with temporary grants, seeded leases/discovery and fixture observations.
No target request, live discovery proof, UI release gate, commit or push.
M7A-21 remains component-only, execution disabled and A-D acceptance open.

Historical started-only checkpoint (superseded by the terminal slice above):
Private durable-start journal repairs RED35340a (missing invocation start core
in four joined action/autonomy cases). New scoped journal has a full link FK,
attempt/category identity, immutable input/request/lease digests, a started
timestamp and forced RLS with no application table grants. The private adapter-
principal persistence core locks the Red Team run, exact link and current test
definition; it checks lease/cancellation/category, refuses any prior unresolved
start across attempts/categories, inserts and rechecks wall-clock lease expiry.
A committed started row means unknown outcome, never successful execution.

Owned calibration43532f sets compiled55 pin
`432fcb4ea69aaafe527e5c39af61069e6119a24c4f3d54208ad4103d2ea7ad70`.
Fingerprint covers both tables and their columns/constraints/indexes/policies/
triggers with table identity. Down locks/refuses retained journal and removes an
unused journal before links. New release drift checks cover journal SELECT ACL,
forced RLS, default and core execute/search_path changes.

Grouped00e92a/e0f275/4a98da passes HTTP lifecycle5.04s, legacy-worker fence4.94s,
durable start13.21s, fingerprint3.33s and release/drift/rollback5.56s.
Migration race0672e1 passes4.784s; diff/gofmt checkdd01cb is clean.
The start cases cover private ACL denial, wrong lease/category refusal, observed
journal INSERT row-exclusive lock through lease expiry with zero retained rows,
exact committed digests, connection close/reconnect after commit, duplicate start
refusal and attempt2 refusal with exactly one original journal row. Independent
review's initial journal-lock-helper concern was resolved by the current explicit
invocation-table mapping and confirmed by the passing observed-lock tests.

This is private persistence only. Temporary fixture EXECUTE grants and owner-
seeded leases/discovery remain controlled evidence. Request digest is fixture-
supplied here, not yet a proven pinned adapter comparison tuple. Future versioned
admission must own organization, policy/budget and target authority. Started-only
schema has no terminal receipt operation yet; adapter/worker wiring, terminal
replay, cancellation, comparison evidence and settlement are still unfinished.
No target request was sent, and these tests prove no live discovery/provider
behavior. M7A-21 remains component-only; all A-D acceptance stays open and
execution stays disabled. No UI release gate, commit, push or promotion.

Legacy linked-worker gate repairs RED2d68e2: registered Red Team workers
claimed all four linked run/rerun supervised/autonomous cases before the durable
invocation protocol existed. Release55 now saves the genuine legacy claim/retry/
resolve functions and inserts a private registered-principal, scoped run/link
guard. Linked calls fail55000. Unlinked worker calls retain inherited behavior.
Adapter resolution uses FOR UPDATE NOWAIT: review found that a new blocking
wait would make inherited transaction-time lease/safety checks stale. Contention
now fails55P03 before delegation; this does not fix all pre-existing transaction-
age behavior or replace future wall-clock invocation admission.

Owned calibrationf6cd9b pins55 at
`81b9b5c99c833adc65eaa5fc9d232bba7d0ea34566d6672df7bdb4d5566b272c`.
Final grouped7921cb/ce3c8c passes mounted HTTP lifecycle5.23s, linked legacy-worker
fence5.07s (four action/autonomy paths), fingerprint3.20s and release/drift/
rollback5.31s. Migration race2c1d64 passes4.667s. The fixture uses registered
worker/adapter calls, real preparation/approval and private dispatch with temporary
fixture grants. It verifies linked claim/retry/resolution refusals, unlinked
claim/retry/resolution positive controls and immediate55P03 while an owner row
lock is held, followed by successful resolution after release. Retained old-worker
leases and winning discovery projection are owner-seeded, not actual discovery
sync, human enqueue or provider execution. Rollback compares original bodies,
owners and ACLs for all three inherited functions, including resolver volatility.
Private helper and predecessor ACL drift are rejected. Independent review accepted
the bounded gate after the NOWAIT correction; final grouped checks passed.

This is a prerequisite guard, not durable invocation implementation. Per-category
started/terminal receipts, claim/retry protocol, cancellation, comparative
evidence and settlement remain unfinished. M7A-21 stays component-only, all A-D
acceptance remains open, and execution stays disabled. No UI release gate,
commit, push or production promotion in this batch.

HTTP lifecycle retry batch repairs RED339039: a simulation retry one second
later returned409 because the handler-generated expiry was part of the inherited
receipt intent. Release55 reconstructs only that expiry from the durable receipt
under the idempotency lock. Goal, evidence, definition and version still bind the
digest; the saved plan and original receipt remain live and unchanged. The shared
Go result validator accepts a replay's original live expiry only when it is no
later than the new candidate. Fresh results still require exact expiry equality.

Owned calibrationcf9b5b sets compiled55 pin
`caf27869d2ce48f6702c3c6c0c34b38bb5f3ea4c0d61cb0d2d751b3c95375e4a`.
New mounted-composition HTTP lifecycle test passes5.02s (39663a), including
validation and simulation replay with new generated IDs/expiry, unchanged bodies,
receipt headers and durable snapshots, changed goal/evidence/version refusals,
read-only permission denial and stale fresh-auth denial. Owner-injected expired
request receipt cannot be revived by the newer candidate deadline. That setup
backdates both creation and expiry to respect the table constraint; first attempt
17f344 failed23514 during setup and is not counted as a pass. This specifically
tests request-receipt expiry, not elapsed expiry of the embedded plan deadline.

Final grouped c7076e/39663a/97082f/bd1463 passes corrected lifecycle HTTP5.02s,
existing draft HTTP5.92s, prepared dispatch14.78s and approval/read7.17s.
Unchanged production inputs also passed legacy activation4.83s, simulation3.78s,
replay4.19s, SQL lifecycle15.04s, fingerprint3.24s and release/drift/rollback5.01s
in run13b656 (whose aggregate failed only for the corrected fixture setup).
Focused API race da8ecd passes2.640s; migration race08d840 passes5.045s.
Independent review accepted the bounded fix and final negative assertions.

Identity/browser-security context is supplied at the router boundary. This is
not session-authentication, rendered-browser, provider or deployment proof.
M7A-21 remains component-only; execution is still disabled pending durable
invocation/claim/retry/cancellation/settlement and remaining A-D acceptance.
No UI release gate, commit, push or availability promotion in this batch.

Pinned validation/simulation batch repairs missing-entrypoint RED96adac and
repository-routing RED0b3808. Both repository operations probe release55 per call
and supply compiled pins; drift errors do not fall back. Owned calibration772dca
sets fingerprint `a49445c0fcd7a31ec00973f83743d0f52150dd266c0a8bdb53f9dab0263b9550`.
Grouped owned PostgreSQL run18377c/56ab0c/a0cd53 passed: legacy activation4.45s,
simulation3.59s, replay4.05s; positive lifecycle14.79s; prepared dispatch14.95s;
approval/read7.19s; fingerprint3.18s; release/drift/rollback4.92s.
Migration race27b154 passed4.938s; focused non-PostgreSQL routing race90478d
passed2.738s. Independent review accepted this bounded slice.

Actual repository validation and simulation now have component evidence for both
test actions, including observed audit-lock waits through authorization expiry,
immutable validation receipts, current-binding simulation replay, consistently
rehashed plan-tamper refusal, inventory entity/evidence positives and no execution
enqueue. Identity is supplied at the repository boundary, not authenticated HTTP.
Inventory fixtures are raw seeded evidence, not completed discovery sync. Missing
evidence IDs are not populated foreign-tenant proof. The reviewer retracted an
inventory-permission concern after ownership inspection and actual API-role tests;
no new grants were needed.

One overly broad host test selector (4cdecf) included a PostgreSQL test without
Postgres in its name and failed during initdb from shared-memory exhaustion. This
is an environmental failure, not a pass. Read-only checke14bed found no remaining
task-owned process; existing user PostgreSQL servers and IPC were untouched.
The corrected anchored non-PostgreSQL selector passed; database checks used the
owned, no-network Docker fixture.

M7A-21 stays component-only. Supervised/autonomous execution is still disabled.
Mounted HTTP/browser lifecycle proof, remaining cross-scope/concurrency coverage,
durable invocation/claim/retry/cancellation/settlement and full A-D acceptance
remain open. No new production proof, availability promotion, UI release gate,
commit or push. Fresh advisory authorization is still an external release gate.

Legacy lifecycle fence repairs RED90138a: original API-callable activation and
simulation accepted both test actions without exact-reference authority. Release55
now refuses new test intent after inherited definition locks, and refuses replay
when current or immutable input-version history contains test intent. Saved private
release54 bodies retain53 cost checks; published migrations are unchanged.
Owned calibrationf566c6 pins55 at
`0a21019e2c028fe9c38649b3d3419f88e4b029020d1cd679436fd75d16c8387c`.
Groupb4c81f completed PASSdc28ad: six activation refusals4.14s, two simulation
refusals3.63s, legacy-positive/historical-replay3cases4.10s, joined private
dispatch15.14s, approval/read7.33s, fingerprint3.20s and release4.54s.
Full migration race2d8b6b passes4.737s. Independent review found no blocking issue.
Historical replay setup uses temporary fixture-only private-function grants and
owner same-version current-body changes, not a normal user update. Positive legacy
activation covers draft-to-validated only. Snapshots compare definition/history,
request receipts, agent audit/runs and Red Team runs/outbox, not all durable tables.
Private-function denial, ACL/search_path drift, removal of fixture grants and
exact unused rollback body/owner/ACL restoration pass. No public test dispatch,
capability enablement, production proof or push. Next: pinned55 lifecycle entrypoints,
exact-reference validation/simulation and replay, post-lock/write clock checks,
per-operation repository routing, then invocation/settlement and composed acceptance.

Catalog reconciliation repairs REDf36f5f: both test actions now report
non-reversible in the built-in catalog, readiness metadata and product manifest.
The component catalog response test also preserves supervised approval,
autonomous domain authorization and disabled production capability. Full
securityagent race b346e9 passes1.495s. Affected non-Postgres API/worker race
a13bde passes2.553s/8.005s. Independent four-file review found no issues.
SQL identities and compiled55 pin are unchanged.
Activation/simulation and invocation/settlement remain the next critical path;
all A-D acceptance boxes stay open.

Private dispatch and link enqueue now share exact hashed authorization after
joined RED821387. Supervised requires an approved exact-scope run/step/plan-hash
approval, same requester, separate approver, fresh-auth receipt and unexpired
approval. Autonomous requires the hashed autonomous marker and no approvals
anywhere in that scoped run; review-found other-step bypass REDc938f4 is fixed.
Recheck after enqueue, link INSERT and audit INSERT while authority stays locked.
Final groupb4bbba/4bf07c passes14 joined cases14.91s: four actual preparation/
approval/claim flows plus10 refusals, including observed outbox/link/audit
INSERT waits through approval expiry. Refusal snapshots prove full run/step
preservation and unchanged counts of effects/reservations/links/audit/test runs/
outbox/receipts; they do not prove byte-identical prior rows in count-only tables.
The same group passes prior candidate link/dispatch regressions, registered
approval/read7.15s, fingerprint3.21s, release4.20s and candidate rollback3.17s
each. Migration race4d93dc passes4.989s; independent source review is complete.
Owned calibration2d19e2 pins55 at
`6f2b71ca7ce85bf8a952b6010fe165ee160f6be335a519a897dd03b78927ed4c`.
No public dispatch grant or capability enablement. Next connect the guarded
activation/simulation paths and finish invocation/claim/retry/cancellation/
settlement with actual target request evidence, then composed UI acceptance.
Reconcile catalog reversibility before enablement and retain all remaining
A-D checks. The four positive enqueue cases are not provider execution proof.

Go display/routing slice repairs decoder REDf24097, routing RED46a9a7 and
duplicate-argument REDd997d7. Run/approval/page/decision now probe55 per call,
append exact compiled pins, preserve legacy only when55 is absent and fail
closed on drift. Arguments require test ID and integer expected_version1..1000000;
test rollback is not_supported and approval is non-reversible with zero TTL.
Final9b3b6a passes7.38s through actual registered DB/repository reads, fresh
approval and immutable replay for both actions. Affected non-Postgres race
e47424 passes2.312s. Independent review accepted the bounded slice. SQL inputs
and compiled55 pin8ec833e7f26847fcf74638a9b571430254cd380c97027f693ff8ac9ef202c89b
are unchanged, so prior release checks remain applicable. Next: coordinated
private dispatcher/link authorization. Also reconcile original catalog
Reversible:true with non-reversible test invocation before capability enablement;
retain the agreed low risk/approval-floor-none and supervised approval rules.
Mounted auth/UI, populated-scope collisions, mixed pagination, autonomous read
acceptance and invocation/settlement remain unfinished. No batch promotion.

The55 database read/context slice repairs six missing-entrypoint RED3fcf65
cases. Private clones preserve24 base read guards and54 context assembly while
adding exact test-action projections. Public approval, approval-page and run
context reads require registered API authority and compiled55 readiness. Only
test ID and pinned expected_version enter argument displays. Published54 bodies
remain unchanged. Group91874d/c8bf2d passes registered approval/read tests6.68s,
fingerprint3.31s and release4.48s; migration race72d91d passes5.015s.
Owned calibrationbc4ddc yields current55 pin
`8ec833e7f26847fcf74638a9b571430254cd380c97027f693ff8ac9ef202c89b`.
Independent review found no blocking issue. Tests cover API denial of three
private context cores, each public read's stale pin, and nonexistent foreign
organization/workspace/environment scopes followed by positive reads. They do
not prove populated-scope collisions, mixed legacy pagination, all-core worker
ACLs or secret-sentinel omission. Go decoders, per-operation routing and actual
repository round trips are the next step, before private dispatch/link repair.
No public HTTP/UI acceptance or production availability follows from SQL reads.
Final test-only assertion tightening requires empty arrays and null cursors on
foreign pages; focused7c9a94 passes6.30s. Release inputs were unchanged, so the
group's release/fingerprint results remain applicable. Ledger369245 validates
all728 rows without promotion. All owned PostgreSQL processes exited normally.

Approval-decision slice is implemented after missing-function RED294069 and
review-found fractional-version RED34e92d. New private55 projection binds exact
approval/run/plan/step/hash and safe test-effect fields. Gated decision delegates
the original controls, enriches the receipt atomically and replays that immutable
receipt without projecting changed approval fields. Legacy actions preserve24.
Every successful branch reaches the final55 readiness check. Independent review
found no remaining blocking issue in this bounded slice; observed mid-decision
release drift remains additional coverage to add with the read/routing batch.
Grouped51aa6a/17b788: approval4.78s, fingerprint3.42s and release4.37s PASS;
joined dispatch remains FAIL5.50s, now after real approval/claim for supervised.
Migration race93ae86 passes4.678s. Owned calibrationa78dfe produced compiled55
pin `ec899395ab280a146de92eb9a8276b41e97107b5828e6f8cfd77a0bf349819dd`.
Next implement gated55 read/context projections and Go per-operation routing/
validation, then coordinated private dispatcher/link authorization. Decision
SQL alone is not API/UI or end-to-end acceptance. All A-D boxes remain open.

Joined preparation/approval/claim/dispatch regression now reaches actual
registered-role boundaries for both actions and autonomy modes. RED837c21
(4.92s) confirms supervised decisions fail with22023 in the legacy approval
projection; autonomous runs reach private dispatch and fail40001 on its old
allow-only check. Run/plan/step/approval/planner-receipt/audit snapshots prove
supervised decision failure rolled back those rows. The final test also checks
approval-decision request receipts. Finalcb3074 reproduces all four failures
in4.99s with decision request receipts unchanged too; the owned PostgreSQL
server exited normally. Its positive oracle requires exactly one
queued Red Team run, pending outbox, runTest receipt and matching step reservation;
that oracle is not yet reached and is not passing execution evidence.

Independent review expanded the next coordinated batch: add private55 test
approval projection and gated list/detail/run-detail/decision wrappers, plus
55 context projections and Go routing/validators. Current context SQL still
calls unsupported v24 projections at its run, approval and approval-page paths.
Calling v24 and replacing the result cannot repair a statement that already
throws. Preserve decision principal/fresh-auth/requester/CAS/idempotency checks;
store enriched decision receipts atomically and verify replay after later state
changes. Bind projected approval/run/step/plan/hash exactly. Keep published54
identities unchanged. Then coordinate both dispatch and link authorization as
below. Do not use owner-approved rows to bypass this missing user workflow.

Versioned planner failure handling now repairs RED6c321e/560c2d. The registered
worker function serializes replay, retains the lease through receipt/audit
writes, rechecks exact55 context and rolls late failures back before persisting
budget stops. Final direct14casesed39fb passes18.78s; actual repository4cases
e25b6f passes5.49s. Affected repository race92de6a and full migration race8c642d
pass. Compiled55 pin is `1425713045dbec3f5c20014d606007597bf72ca7f2f75c4e68d5f7dc305c7f9d`.
Next coordinate BOTH private dispatcher and link enqueue with hashed
approval_required/autonomous markers. Supervised must resolve an approved,
unexpired exact-scope run/step/plan-hash approval; autonomous must have no
approval rows. Recheck approval expiry after enqueue/audit waits, atomically
rolling back step reservation, effect, link and enqueue on expiry. Add actual
prepare -> approve where supervised -> claim -> private dispatch tests for both
actions/autonomies. Keep dispatch ungranted until invocation safeguards finish.

Versioned preparation/acceptance now repairs REDd3ebea. The private preparation
core retains the lease through plan/step/approval/audit and acceptance-receipt
writes. A private exact-context clone removes only the prior-plan refusal;
finalization rechecks current evidence, binding, clock, lease and budget before
clearing the lease. Nested rollback removes authority on late expiry; deadline
stops are persisted outside it. Final5125ff passes14 acceptance cases19.40s and5
preparation cases4.80s. Per-operation Go routing repairs REDa3d61d; affected race
57f83a passes2.016s. Full migration racef0e3fa passes4.643s. Compiled55 pin is
`307db3d85183348a1821b6f0f2e12c479f6b6815c043635a0bd3e08abfccf729` from owned4f54ae.
Independent source review is complete for the slice. Next: versioned planner
failure handling and coordinated private dispatch authorization/approval
compatibility, then activation/simulation and invocation/settlement. Direct
registered-role tests and controlled repository tests are not a composed
repository/DB or live worker proof. All A-D acceptances remain open.

Preparation/acceptance now have initial registered-worker RED contracts in
`security_agent_existing_test_preparation_postgres_test.go` and
`security_agent_existing_test_acceptance_postgres_test.go`. Groupd3ebea confirms
all12 cases reach the missing55 functions (SQLSTATE42883), not a fixture error.
This is incomplete test-first work, not passing acceptance. Independent review
identified the existing supervised approval requirement: approval floor none
does not bypass it. Four preparation cases cover both actions and autonomy
modes; eight acceptance cases cover valid candidates, replay and substitutions.
Assertions bind approval/step/plan state and compare replay authority snapshots.
Use the <=63-byte name `zasp_production_security_agent_existing_tests_accept_planner`.
Next implement preparation and acceptance together: retain the current lease
through plan/step/approval/audit/receipt writes, revalidate time-dependent
authority before final transition, and roll those writes back on a late stop.
The private dispatcher currently accepts only `allow` and must be adapted to
the real supervised/autonomous authorization and approval contract. Do not
change the legacy approval semantics to fit that unexposed candidate.

Versioned55 reservation and repository/worker reference wiring are implemented
as another partial Batch B slice. Missing-function REDfc5e5b, routing REDbd7386
and request/processor REDf7c66e preceded their repairs. Final PostgreSQLba89c4
passes20 reservation cases15.29s, including actual repository round trips for
both actions and observed insertion-lock expiry with zero late reservations.
Final focused racecaa8c8/f9b807 and full migration race951bed pass. Independent
reviews found no remaining blocking issue in these slices. Current55 pin is
`c9910c1e6940608fadaf8468221c88c633564cd8fbb413b435ee41e8174c3de7`.
The adapter now carries the exact stored reference and retains the existing
explicit-target restriction. Next: versioned preparation/acceptance and planner
failure handling (both current33 paths still resolve33 context), then activation/
simulation and remaining invocation/settlement acceptance. Controlled request
bounds are not verified production model prices. No public dispatch, capability
enablement, release publication or A-D acceptance follows from these tests.

Registered55 context slice now passes20 actual worker-role casesfb637d11.49s
after missing-function RED65bc43. It returns pinned test ID/version with canonical
digest, preserves legacy33 context, and checks current finding/path/runtime
authority, lease/budget and post-wait expiry without enqueue. Reviewed context
and tests are partial Batch B, not full planner acceptance. Release/HTTP/write/
cutover/consumer checks passed in group68a3d5; the group's prior-plan fixture
parameter-type failure was repaired and only the affected context test rerun.
Full migration race16c7f9 passes. Current compiled55 pin2ed2d497687e88d618f9c6c37d3759f1d73c1eec21210bd6bc827f0452fec245
supersedes earlier pins. Next: pinned55 planner budget reservation that recomputes
this exact context, strict repository/runtime routing, preparation and acceptance.
Do not weaken the old33 reservation digest comparison to accommodate55. No
public dispatch grant, action capability enablement or publication is authorized
by this component evidence. All A-D acceptance boxes remain open.

Mounted production wiring now passes focused race1a904a with controlled session/
SQL boundaries: healthy draft201, permission/CSRF403, edge Origin400, expected
scope409 and invalid55 replay503, with no denied mutation attempt. Independent
review confirms the bounded evidence. Separate actual PostgreSQL handler16e029
passes6.38s with PATCH update. Composed live browser/authentication/database
acceptance remains open; do not combine these into a live-proof claim. Next
implementation slice is Batch B's versioned planner context/preparation/acceptance
while retaining private dispatch and disabled execution capabilities.

Real handler/repository/registered55 draft integration now passes88e7476.57s:
create/update/get, replay before/after update, stale/missing/null reference and
activation refusals, exact submitted persistence, cancellation, warm rollback/
re-upgrade capability and drift refusal. Production tracing forwarding was
repaired after review/RED0c1215; full API race cdecd2 and focused handler race
23c805 pass. Shared warm/fresh consumer groupaa033a passes. Draft capability is
now context-aware and current-release-gated; execution capabilities remain off.
Next acceptance: composed tracing/database/authenticated tenant paths, then the
remaining activation/planner/invocation/settlement requirements. Separate tests
are not mounted/browser proof. No batch or production promotion.

Newest registered55 slice passes actual versioned API-role create/update/read,
immutable replay, scoped refusals and actor history. Cutover tests pass completed
rollback-first, lock-held refusal and mutation-first retained-history scenarios.
ReplayWorkflow now uses its own compiled55 SQL authority after RED4eec9d/81c0cb;
independent review accepted the wrapper and exact-key routing. Focused workflow
and full migration race406efb pass. Group3ebd72/a321d0/a0744f/e9ce4b records real
PostgreSQL candidate, release, versioned definition/replay and cutover results.
Next: real HTTP handler/repository acceptance and release-aware draft capability.
No production capability bypass, activation or execution acceptance is claimed.

Versioned55 draft-write guard is implemented but not yet acceptance-complete.
Repository routing RED979681 and review-found case-alias RED24cb82 are repaired;
affected workflow/routing race d858f1 passes. Real DB missing-entrypoint RED5d0830
now passes stale-pin refusal in group33b826/97ebdf/4c9558, with refreshed owned
compiled pin, release rollback and consumer checks. Source review accepted the
API-only guard and lock ordering. Next: positive versioned mutation and two-order
rollback races; explicitly gate/review ReplayWorkflow before enabling actual HTTP
draft capability. Full Batch A and all later acceptances remain open.

Registered55 groundwork now passes the owned PostgreSQL group21b9c6/b67893/6842ce:
compiled pin, saved-function empty rollback, retained definition-history refusal,
RLS-authority rejection, private dispatch and eight warm/fresh consumers through
upgrade/drift/rollback. Audit configuration routing is55-aware and full migration
race37b7e9 passes after REDb7462d and independent review. This is partial Batch A,
not batch acceptance. The next draft-write path must use versioned55 SQL authority
so rollback between a capability probe and mutation cannot invoke legacy54 writes.
The production draft capability stays off until that path is implemented and
verified through real HTTP/DB tests. All A-D acceptance boxes remain open.

Definition authority now has real owned PostgreSQL18.3 evidence through the
network-isolated container route. RED408eb0/0c8a4e exposed actor provenance and
missing-reference acceptance; candidate-only repair resolves the persisted
reference atomically and binds the new history version to its operator.
Grouped d6d914 passes binding and enqueue/dispatch/definition tests, including
legacy mutations and old replay after later update. Independent review covered
the repair. This is partial Batch A groundwork; registration/pins/rollback,
cross-scope mutation and composed HTTP acceptance remain open. See authority doc
for exact image, restrictions, failures and final evidence.

Group707b6a adds registered-API cross-organization/workspace/environment reference
refusal with own-scope positive controls and candidate-only rollback groundwork.
Unused rollback restores compiled54; retained definition history refuses without
mutation. Registered55 migration identity/RLS, pins, cutover/invocation fences and
all retained execution-state rollback cases remain open. No HTTP readiness bypass.

Parser, private54 resolver and role/expiry/release tests exist as groundwork.
Shared enqueue extraction is now an unregistered candidate with test-first
98c31a and final5.560s greenf5fffa plus independent review. It covers the extraction
substep of Batch A, not55 migration integration or complete Batch A acceptance.
Private link persistence now passes9b31b4 in10.395s, including atomic rollback,
receipt-independent replay, observed duplicate contention and post-lock expiry.
Owner-seeded intent/effects do not prove the guarded admission/planner path.
Private guarded dispatch now has grouped ef0e2d (16.412s) for registered-worker
calls over owner-seeded preparation, initial refusal cases and observed late
audit-lock lease/budget/target expiry. Independent review confirms digest and
late-write repairs. Runtime groupc70661 passes18.353s for current credential,
revocation/expiry, persisted rotation-state refusal, digest binding and late
audit-wait expiry. Review retracted the proposed latest-credential parity defect
after the real schema rejected its impossible two-live-v15-credentials fixture.
No rotation API, signed ingestion or target execution is proved here. It remains
unregistered/ungranted outside fixtures and is not complete Batch B acceptance.
All A-D batch acceptances remain open. Latest verified main and external gates
are recorded in `implementation_status_v1.5.md`; this plan grants no clearance.

Draft wire-contract groundwork now passes9973df (Go non-DB affected group),
499f94 (122 browser decoder/receipt checks), typecheck, OpenAPI lint/generation
checks and standalone UI build6f61a3. Raw HTTP duplicate validation runs before
canonicalization/replay; draft persistence remains gated by an unimplemented
repository capability. Database mutation resolution, real write/read acceptance
remain open. The existing PostgreSQL delete-regression setup
is blocked by host SysV shared-memory exhaustionc6d1b9, not a passing test.

Selector component groundwork now uses the real scoped paginated test-list API.
Grouped192 tests e52669 include explicit enabled selection, exact pinned intent,
catalog/permission refusal, reload failure, late removed-permission lookup,
frozen lost-response retry and replacement-API option invalidation. Review
regressiona2b797 proved the latter defect before repair; independent re-review
accepted the focused repair. Typecheck7d4345, lint/coverage33ea13 and standalone
build40e667 pass. These tests use controlled responses; no composed live selector
or worker execution acceptance is claimed. All A-D acceptances remain open.
