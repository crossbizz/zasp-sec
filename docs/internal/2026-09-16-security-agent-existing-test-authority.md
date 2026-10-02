# M7A-21: durable existing-test action authority

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

Independent review of the actual producer/SQL contract checkpoint found no new Critical/Important issues. The reviewer confirmed the keyed response_digest mutation leaves the input receipt unchanged and tests journal association after recomputing byte checksum/size. Final ledger validation536ff3 retains534 production-available/133 component-only/61 external/0 missing; no production promotion.

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

Status: implementation reconnaissance and verified privilege baseline. The
existing-test action is still component-only and unavailable in production.
This reconnaissance is not implementation acceptance. The selected end-to-end
design and feature-batch plan are now in
`2026-09-16-security-agent-existing-test-design.md` and
`2026-09-16-security-agent-existing-test-plan.md`; all four execution batches
remain open.

## Original requirement

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

Catalog reconciliation checkpoint: REDf36f5f caught the false reversible flag
for both test actions in the component HTTP catalog and readiness metadata.
Both sources and the product TSV now report false. Grouped securityagent race
b346e9 passes1.495s, including unchanged supervised approval, autonomous domain
authorization and disabled production execution. Affected non-Postgres API/worker
race a13bde passes2.553s/8.005s; independent four-file review found no issues.
This repair does not enable either action or
prove mounted production HTTP, activation, target execution or settlement.

Latest private authorization checkpoint: initial joined RED821387 (four modes)
and review-found other-step approval REDc938f4 preceded the shared helper repair.
Private dispatch and fresh link enqueue bind exact plan/step hashes, current
definition autonomy and approval authority. Autonomous exclusion is run-wide.
Clock/authority checks run after enqueue, link insertion and final audit writes;
the lease stays held until the final state transition. Dispatch remains private.
Group442777 completed with PASS in4bf07c: joined14 cases14.91s (b4bbba), prior
candidate enqueue/link/dispatch cases (142715), registered approval/read7.15s,
fingerprint3.21s, release4.20s, empty candidate rollback3.17s and retained-history
refusal3.17s. Migration race4d93dc passes4.989s. Compiled55 pin from owned
calibration2d19e2 is
`6f2b71ca7ce85bf8a952b6010fe165ee160f6be335a519a897dd03b78927ed4c`.
Independent review found no remaining blocking issue in this bounded slice.
Registered-role joined tests use actual preparation, supervised decision and
claim but temporary fixture-only dispatch grants and owner-seeded admission.
Older component fixtures now seed hashed autonomous plans, not synthetic allow.
Four positive cases prove one queued run/pending outbox/receipt/reservation.
Ten refusals include observed outbox, link and audit lock waits through approval
expiry. Snapshots compare run/steps fully and other execution authority counts;
approval expiry itself is deliberately changed by the wait fixture.
All owned PostgreSQL processes exited normally. No target request, invocation
receipt, live deployment, UI acceptance or production readiness is proved.
Activation/simulation, durable invocation/retry/cancellation/settlement, catalog
reversibility reconciliation and remaining A-D/live gates stay open. No push.

Latest Go integration checkpoint: final9b3b6a passes7.38s with actual repository
approval/replay and six registered detail/page/run reads across both actions.
Decoder REDf24097, routing RED46a9a7 and duplicate-key REDd997d7 preceded repairs.
Four operations probe full55 readiness per call and use compiled pins; warm
false/true transitions preserve legacy absence and block invalid releases.
Strict test arguments reject null, extra, duplicate and invalid-version fields.
Affected non-Postgres racee47424 passes2.312s; independent review accepted the
slice. An earlier broad race selector was interrupted993bad before completion
and is not evidence; process inspectionbbd6bb found no remaining owned test
process. Existing unrelated host PostgreSQL servers were untouched. Final DB
verification ran in the owned no-network container and exited normally.
SQL/pin unchanged8ec833e7f26847fcf74638a9b571430254cd380c97027f693ff8ac9ef202c89b.
Identity is supplied by the fixture, not authenticated browser middleware.
The original catalog still says test actions are reversible; reconcile it with
truthful no-rollback projection before enabling capabilities. Dispatch/link,
invocation/settlement and composed/deployed acceptance remain open. No push.

Latest read/context checkpoint: six registered SQL read cases RED3fcf65 are
repaired by private55 clones plus compiled-release-gated public reads. Exact
test ID/version projection, stale-pin refusal, API denial of three context
cores and nonexistent org/workspace/environment refusal pass in91874d6.68s
alongside decision/replay/version checks. Fingerprint3.31s/release4.48s pass
in91874d/c8bf2d; migration race72d91d5.015s passes. Independent review found no
blocking issue; populated-scope collisions, mixed legacy pagination, all-core
worker ACLs and raw secret-sentinel cases remain additional read coverage.
Current55 pin is `8ec833e7f26847fcf74638a9b571430254cd380c97027f693ff8ac9ef202c89b`
from owned calibrationbc4ddc. Published54 bodies are untouched. Go decoding and
routing are not yet updated, so this is not repository/API/UI acceptance.
Dispatch/link authorization and all later A-D requirements remain unfinished.

Latest checkpoint: versioned approval decisions are component-verified, not
production available. Missing entrypoint RED294069 and fractional-version
RED34e92d preceded fixes. Private projection binds approval/plan/run/step/hash;
decision preserves original controls and stores enriched receipts atomically.
Replay returns the saved response even after controlled approval changes.
Fresh group51aa6a/17b788 passes approval4.78s (both actions plus six malformed
version subcases), compiled fingerprint3.42s and registered release4.37s.
Joined workflow still fails40001 at private dispatch for all four modes5.50s;
supervised approval and claim now succeed before it. Group exit remains1.
Migration race93ae86 passes4.678s; independent review found no remaining blocking
issue in this slice. Current compiled55 pin is
`ec899395ab280a146de92eb9a8276b41e97107b5828e6f8cfd77a0bf349819dd` from owned
calibrationa78dfe. No worker/provider invocation or public HTTP proof is claimed.
Read/context wrappers, Go routing/validators, dispatch/link authorization and
the remaining invocation/settlement/browser/deployed acceptance are still open.
All owned PostgreSQL processes in the group exited normally. No push occurred.

Register run_test/rerun_test against an existing TestDefinition. An action must
not create arbitrary target or prompt content. Preserve the dependencies on
M7A-20/M5-35 and the later Attack Lab/export/webhook tasks, without reducing
scope to this admission boundary.

## Preparation and acceptance RED contracts

Superseded by implementation and evidence below; retained as TDD history.

Registered-worker tests now cover both test actions in supervised/autonomous
preparation and eight candidate acceptance/replay/refusal cases. Final group
`d3ebea` failed all12 cases at the expected missing55 entry points with42883
(acceptance4.35s, preparation3.44s). The owned PostgreSQL servers exited normally.
No assertion after those missing calls has passed yet; these are initial RED
contracts, not preparation or acceptance proof. Test compilation28b120 passed.

Earlier8dfba6 also exposed an owner-fixture update matching a same-ID definition
in another scope. The fixture now filters organization/workspace/environment;
rerun2551a2 reached missing functions for all cases. The acceptance function
name was then shortened to `existing_tests_accept_planner` to avoid PostgreSQL's
63-byte identifier truncation. Finald3ebea uses that unambiguous name.

Independent review checked `securityagent/planner.go` and published21 authority:
supervised preparation must create waiting_approval/approval_required and a
pending exact-plan approval. Autonomous preparation creates queued/authorized
with deterministic authorization and no approval. The private dispatcher still
expects allow and must be updated before integration. Approval floor none is
not permission to bypass supervised approval. Review also strengthened exact
approval bindings and immutable replay snapshots in the new tests.

Next implementation must retain the lease through plan, step, approval, audit
and planner-receipt writes, then check current binding/credential expiry, lease
and budget before clearing it. Use a subtransaction for late-stop rollback.
The current context function refuses existing plans, so it cannot be reused
unchanged as post-write validation. Production SQL and compiled55 pin are
unchanged in this checkpoint. No new grant, activation, execution or push.

## Registered preparation/acceptance, partial Batch B

The later failure-settlement checkpoint below supersedes this release pin.

The55 planner fragment now includes private preparation and finalization plus
worker-only prepare/accept entry points. Supervised plans retain the existing
approval requirement; autonomous plans queue authorized steps without approval.
Plans bind the test/version/target and authorization into hashed step intent.
The planner lease stays held through every plan/step/approval/audit/receipt write.
Private recheck clones the exact context authority with only prior-plan refusal
removed. It validates held prerequisites, current credential/target clock,
lease, budget and digest before final transition. A late stop rolls back the
inner writes and persists the durable stop outside that savepoint.

Initial12 contracts passed96d9fb (acceptance5.88s, preparation4.54s), together
with compiled fingerprint3.28s and release/rollback4.22s. The exact clone guard
first rejected mismatched newline c0df00; its needle was corrected without
weakening occurrence checks. Owned calibration4f54ae yielded compiled55 pin
`307db3d85183348a1821b6f0f2e12c479f6b6815c043635a0bd3e08abfccf729`.

Expanded group3e5b1e/e46370/5278d4/6e5e09 passed acceptance19.01s,
HTTP6.07s, context11.41s, preparation4.66s, reservation14.96s,
versioned definitions6.06s and cutover4.26s. Final affected rerun5125ff passes
14 acceptance cases19.40s and5 preparation cases4.80s. Six cases observe exact
audit/receipt relation blockers before lease, budget or target expiry. Lease
and target refusals leave zero new plan/step/approval/audit/receipt; deadline
cases retain only needs_human and its stop receipt. Other assertions cover
registered-role private-helper denial, immutable replay, conflicting model
replay and refusal without mutating an owner-seeded newer attempt/lease.
No Red Team run/outbox or provider/step reservation is created. The newer
attempt is a controlled fixture, not an actual reclaim-flow acceptance.

Go preparation/acceptance now probe complete55 availability on every operation,
select versioned SQL when ready, preserve legacy absence and refuse release
drift before SQL. Routing REDa3d61d preceded implementation; racea809f1 passed
the initial routing group and final affected57f83a passed2.016s. Full migration
racef0e3fa passed4.643s. Independent reviews found no remaining blocking source
issue in these slices and verified the stronger replay/ACL/no-execution oracles.
Final changed-release warmed-consumer groupb5cc04 passes18.15s on the same
registered connections through55 drift, restoration and rollback. All owned
PostgreSQL servers exited normally; no test process remains from these groups.

Still open: actual repository/DB preparation acceptance, autonomous acceptance,
full trigger/credential late-expiry coverage, planner failure routing and
private dispatch's supervised approval/autonomous authorization compatibility.
Execution capabilities remain off and dispatch private. A-D feature acceptance,
composed user workflow, full release, publication and live production proof
remain open. No original task was promoted by this component evidence.

## Registered planner failure settlement, partial Batch B

Missing-function RED6c321e covered unavailable/rejected/rerun before the new
versioned function. SQL now preserves predecessor error/output-digest and
tagged budget-stop replay semantics, serializes receipt lookup with organization
then run locks, and retains the exact lease through receipt/audit writes.
Post-write context recomputation checks test binding, evidence, credential/target
clock, lease and budget. A late deadline rolls failed authority back and records
only needs_human plus its stopped receipt. Exact replay does not repeat writes.

Routing RED560c2d preceded per-operation full55 availability selection in Go;
absence retains legacy SQL, while present-invalid55 stops before SQL. Four
actual repository/registered database round trips cover unavailable/rejected,
rerun and tagged stop. They use controlled admission and no provider execution.

Owned calibrationa5343e yielded compiled pin
`1425713045dbec3f5c20014d606007597bf72ca7f2f75c4e68d5f7dc305c7f9d`.
Initial groupe25b6f passed14 direct failure cases19.01s,4 repository cases5.49s,
fingerprint3.32s and release/rollback4.27s. Review requested stronger lease
oracles; final directed39fb passes18.78s, checking all lease fields and version
after terminal/stop/refusal. Six cases observe audit/receipt blockers before
lease/deadline/target expiry; rejection leaves no failure receipt/audit or
external work, while deadline retains a replayable stop receipt. One legacy
finding case passes; this is not exact old-release parity across every trigger.
Affected repository race92de6a passes2.085s and full migration race8c642d4.581s.
Independent source review found no Critical/Important blocker in this slice.
Final changed-release groupe5c8d0/ed39fb/8825be also passes acceptance19.17s,
preparation4.75s and warm-consumer upgrade/drift/rollback17.93s. All owned
PostgreSQL servers exited normally; no verification session is left running.

Next dispatch work must update both the dispatcher and link enqueue, which
still require allow. Preserve preparation's hashed approval_required/autonomous
markers, real approved plan-bound supervised authority, autonomous no-approval
rule, and post-wait approval expiry. Full A-D, actual provider invocation,
settlement/cancellation, composed browser/deployment and release gates remain
open. Dispatch stays private and production action capabilities stay off.

## Current source evidence

- `securityagent/builtin_actions.go` has ID-only component actions backed by the
  component backend. `securityagent/action_readiness.go` deliberately marks both
  unavailable; toggling that flag would not implement a durable adapter.
- `migrations/sql/0025_red_team_execution.up.sql` defines
  `zasp_red_team_run_test(org,workspace,environment,actor,idempotency,definition,
  definition_version,run,correlation)`. It checks the registered API principal,
  exact scoped enabled definition/version, persists a run/outbox and replay
  receipt transactionally. Migration37 replaces target validity with current
  safety authorization; reuse must retain that later guard.
- `migrations/sql/0032_production_security_agent_planner.up.sql` limits planner
  context to four existing actions and derives its allowed target from stored
  authority. The adapter therefore needs durable definition binding and planner
  context integration, not merely a BuiltinBackend method.
- `agentsec-worker/security_agent_runtime.go` submits one validated step and
  routes prepared work through the worker authority. It cannot impersonate a
  browser principal or call an API-only enqueue function.

## Chosen direction and rejected shortcuts

Use a worker-specific lease/step/budget-bound admission with a private shared
enqueue core, retaining the existing human/API wrapper and all scoped target,
definition-version, credential and safety checks. The private core must have
no application-role direct EXECUTE grant. Keep worker role membership unchanged.
Persist the exact agent run/step to Red Team run association before returning
pending; verification must inspect the durable linked outcome/evidence, not
treat enqueue acknowledgement as a successful security response.

Calling the public API from the worker would require invented browser authority
or widened grants. Copying Red Team enqueue logic would duplicate the safety
and idempotency rules. Neither is the implementation direction.

The operator's existing-TestDefinition selection must be persisted and version
bound before planning. A planner-supplied UUID is not that authorization.
Source tracing found the definition is a closed JSON object in
`apiserver/workflow_handler.go:securityAgentBody`, the activation reader and
the web decoder. The builder currently submits only template actions and limits.
There is no existing per-action test configuration to reuse.

Chosen definition field: optional `existing_test` object containing exactly
`definition_id` (canonical Product ID) and `definition_version` (integer1 through
1,000,000). Keep old definitions without the field readable. For run_test or
rerun_test, require one matching test reference and verification_kind=test_run;
reject this field on other action definitions. Do not allow prompt, URL, target,
scope, credentials or an unversioned lookup in this object. Resolve current
authority again at activation, planning and action admission; persisted intent
alone grants nothing. Public acceptance remains gated until the database path
and client contracts are wired, so this internal parser does not enable drafts
or execution prematurely.

The first internal component is `decodeSecurityAgentExistingTestReference` in
`apiserver/security_agent_existing_test_reference.go`. It uses the existing
duplicate-aware bounded object parser and rejects malformed/extra/trailing
data. The test-first missing-function build720e27 is setup evidence, not a
reproduced product defect. Public handler/reader, OpenAPI/client/builder,
durable binding/admission and action availability are not changed by this slice.

Grouped parser/cost-contract checks passb28a43 in1.041s after independent review.
The24 reference cases include unknown overrides, duplicate keys, missing/null
fields, noncanonical ID, fractional/exponent/string/overflow versions, the
size limit and trailing JSON. Every rejection requires the fixed operation
error and a zero reference. Existing explicit cost allowance cases also pass.
This remains an internal, currently uncalled component awaiting durable binding
integration; it does not authorize or expose a new public workflow.

## Executed boundary evidence

`TestSecurityAgentExistingTestPreservesAPIEnqueueBoundaryPostgres` passesc4a6cb
in5.787s against the registered migration54 fixture. Direct enqueue as the
Security Agent worker returns42501. The API role reaches the missing-definition
check and returnsP0002, providing a positive control for function availability.
Definition/run/outbox counts remain unchanged for both calls. The test catches
accidental worker EXECUTE grants or API-role inheritance; it is not a test of
valid test execution, browser authorization or a deployed provider. Independent
review found no blocking issue. Count equality does not assert byte-identical
table contents or unchanged audit/replay receipts.

## Required implementation acceptance

### Private resolver checkpoint

The unpublished migration54 now includes a private scoped test-binding resolver.
It reads persisted agent version/intent, locks the enabled exact-version test,
environment, target and credential, and returns only definition ID/version and
target ID/kind. Fixed table-owner lock helpers avoid broad UPDATE grants to the
discovery role. Neither application role nor PUBLIC receives helper EXECUTE.
Final wall-clock checks reject target or credential expiry after lock acquisition.
This resolver is not yet called by activation, planning or action admission.

Owned calibration674237 produced compiled fingerprint
`3e4569f4bc5aec90dfa17fe6c4124e45a0c2b281b475369695c7c2ada773dffb`;
the fresh compiled-pin and API/worker boundary checks passed in c229f6. That
group failed one expiry fixture before reaching the resolver because observed_at
was newer than fresh_until. The fixture now preserves the table's time ordering.
Binding plus release group409c15 passes15.908s, including12 unsafe-reference
cases, retained row locks on five authorities, target/credential expiry during
a lock wait, application/PUBLIC denial for all three private helpers, helper
grant drift refusal and rollback removal. Independent source review found no
Important blocker. Its exact-blocker observation improvement passes dba5d2 in
10.222s: pg_blocking_pids identifies the credential lock holder while database
time remains before expiry, then release after expiry returns40001 in both cases.
These are local database checks, not worker execution or deployed safety proof.

### Remaining acceptance

Shared enqueue extraction now exists as unregistered55 candidate SQL in
`migrations/sql/fragments/security_agent_existing_test_enqueue.sql`. It requires
the exact compiled54 predecessor, saves its safety-aware API function privately,
extracts a private core and keeps the API principal guard on the public wrapper.
No runtime caller or55 registration uses the candidate yet; applying it changes
the predecessor fingerprint, so it is not a usable54 release or a55 cutover.

Test-first98c31a failed with missing-core42883. The final owned database test
f5fffa passes5.560s: real API enqueue and exact replay create one run/outbox/
receipt, changed-version replay conflicts, stale/foreign/disabled/revoked new
requests fail without work, definition and target rows are byte-equivalent as
JSON, API/worker direct core calls and worker public enqueue are denied42501.
Saved predecessor body equality and private owner/search-path/ACL checks pass.
Independent review found no Critical/Important extraction blocker; its minor
safety/count/identity assertions were added to this final run. This proves the
shared-core component, not lease-bound admission, actual worker execution,
registered55 rollback or deployment.

Private link persistence now exists in `security_agent_existing_test_links.sql`:
forced-RLS owner-only table, full-scope run/step/effect/test-run foreign keys,
one linked test per agent step, deterministic test-run identity and durable
stored response replay. The caller must already own organization admission,
lease/control/budget validation and effect creation. This helper deliberately
has no application EXECUTE grant and is not a worker entry point.

Test-firstd3ccbc failed missing link function42883. The initial fixture lacked
the exact definition-version actor row (e8ce6a/5a08a2); supplying real version
history fixed the fixture, not the production actor refusal. Regression0a265e
then reproduced adoption of a preexisting API test receipt. The helper now
requires a fresh core result when no agent link exists. Regression78f283
reproduced stale-target enqueue after observed actor/advisory waits; it now
locks actor and the exact core advisory key before test resolution and rechecks
authority after enqueue. Independent review confirmed both source fixes.

Grouped47325a passes9.885s: collision refusal, actual role/table denial, replay
after API receipt removal, changed-step conflict, exact blocker expiry and
rollback absence of link/run/outbox/receipt/audit. Final9b31b4 passes10.395s
including observed two-connection duplicate contention: the second request waits
on the first transaction and returns the same stored link after commit, with one
outbox entry. Prepared intent/effect rows here are owner
fixtures, not planner, lease, budget, invocation or production proof.

Full-scope binding and current enabled/version checks; no arbitrary prompt,
target or URL; foreign/missing/stale/disabled definitions; revoked credentials;
lease loss and action/time/cost stops before enqueue; deterministic durable
association and restart-safe replay; real controlled test execution with linked
evidence; no new definition or target rows; safe cancellation and ambiguous
outcomes. Migration fingerprint/role drift/rollback, public API/builder wiring,
worker composition and real-browser acceptance all remain required. Keep the
action unavailable until those prerequisites are implemented and verified.

### Guarded dispatch candidate, still private

The unregistered55 candidate now includes a private dispatch function. Its
fixture grants only the registered test worker temporary access and seeds
preparation as owner; this is not public planner or production worker proof.
Initial fixture28f27a had an unused argument and did not exercise dispatch.
After fixture repair, ea1be7 reproduced ambiguous result_digest assignment42702;
renaming the local fixed that failure. Groupd346c3 passed10.448s, including
run_test/rerun_test pending dispatch, stale lease, changed plan/step/evidence,
disabled control, prior budget stop and step-limit refusal.

Independent review identified late audit waits and missing runtime credential
rotation parity. The initial conflicting-row fixture held organization admission
before setup and was not a late-write regression. Live pg_stat_activity proved
that wait; only the blocked setup queries were cancelled and the owned database
exited cleanly. Corrected regressionc6c7f3 uses an observed audit relation
maintenance lock and reproduces dispatch after lease/budget/target expiry.
The candidate now rechecks binding, plan/runtime expiry and lease/budget after
the audit write, before clearing the lease. Negative work counts directly query
the deterministic test-run identity, independent of surviving links.
Grouped ef0e2d passes16.412s, including all three late-audit expiry cases.
Independent source review confirms the digest and post-audit fixes; it does
not approve the full dispatch candidate. Follow-up assertions also inspect
persisted stop reason/state and absence of reservation and both audit types.
Those strengthened assertions pass final2bdc10 in15.854s: late budget expiry
persists needs_human/budget_deadline_exceeded; lease/target refusals leave the
run planning; no reservation, agent audit, Red Team audit or enqueued work
survives any of the three late-expiry cases. Owned PostgreSQL cleanup passed.

Runtime review correction: the initial unrevoked-predecessor/replacement fixture
37bc2b failed23505 on zasp_gateway_credentials_live_v15_idx, not on dispatch.
The registered schema prohibits two unrevoked current-format credentials per
scoped device. Credential authority requires current format and rejects revoked,
expired or superseded credentials before event ingestion; rotation revokes the
predecessor. Independent review retracted the Important parity finding because
the proposed defect was not reachable through the supported flow. No constraint
was weakened and no production fix is attributed to that finding.

Runtime groupc70661 passes18.353s: current credential dispatches; revoked,
expired, persisted rotated-predecessor and changed request-digest evidence are
refused. Observed audit-table wait through runtime credential expiry leaves
zero enqueued work/reservations/audits and the run planning. These use real
registered-worker dispatch over owner-seeded credential/event/preparation rows,
not enrollment, rotation API, signed ingestion or external execution proof.
Independent review found no Important blocker in this test-only addition.

Attack-path dispatch fixtures remain open. So do registered55, public contracts,
planner/preparation, invocation
receipts, reconciliation, evidence comparison and end-to-end browser acceptance.
No batch acceptance or task availability is promoted by this candidate.

Reference deployment, external provider/credential and release-advisory gates
remain separate from local fixtures. No production promotion or push.

### Draft wire contract groundwork

Go REDa1b6f4 rejected valid run/rerun references as unknown fields. The parser
now retains the exact closed ID/version intent for disabled drafts with a
separate durable-definition capability gate. No production repository implements
that capability yet, so grammar support does not enable public writes. RED2eba1a
proved that an absent capability previously reached mutation; the HTTP gate now
rejects it. Enabling these actions remains refused; activation metadata is unchanged.

Review regression389c17 reproduced case-insensitive JSON aliases and omitted
enabled being accepted. Canonical required/optional-key validation now rejects
them. HTTP regressioncb1b8e then proved canonicalization erased duplicate outer
and nested keys before parsing. Raw validation now precedes canonicalization
and replay lookup. Capable-stub HTTP tests verify rejection before replay and
mutation, not just direct parser behavior. Independent re-review found no blocker
in these focused repairs. Group9973df passes1.020s for definition contracts,
cost contracts and non-database workflow-handler regressions.

The browser decoder, optional OpenAPI reference schema and generated types retain
exact references, reject malformed/action-incompatible references and bind them
to receipt intent/results. Legacy reads and historical receipts can omit the
field. TS REDf1c702 became green499f94:122 tests across receipt and Security Agent
decoders. Typecheck7666ca and focused ESLint passed; OpenAPI lint657e1f and26
schema/generated-client checksbe680f passed. UI build6f61a3 produced standalone
output. No test selector UI or database mutation/resolution wiring is claimed.

The existing PostgreSQL nonempty-delete workflow regression did not reach its
assertions: initdb failed with SysV shared-memory exhaustion (c6d1b9), after
adding captured bootstrap diagnostics. Read-only IPC inspection5e00b9 confirms
32 segments. No unrelated process or segment was removed. This verification
gate remains open; the non-database group explicitly excluded that one test.

## Existing-test selector component checkpoint

The builder now loads enabled existing tests via the real Red Team list adapter,
with expected-scope headers and bounded pagination. A transport-boundary test
exercises two pages through that adapter, not a custom list-method stub. User
selection pins only definition_id/definition_version. Unsupported catalog or
missing red-team.read authority blocks lookup/save. Reload clears selection;
unmount aborts lookup; failed save retains the exact payload/idempotency key and
locks selection. Full scope/generation keys remount the production view.

Initial selector REDdcff36 became green ee7de7. Lint653d59 found a redundant
synchronous loading reset in the effect. Removing it passed lint but review
identified API replacement retaining old selectable options. Regressiona2b797
reproduced that issue; result-to-API identity binding renders loading/empty until
the replacement lookup resolves. Group e52669 passes192 tests including explicit
reselection of the replacement version. Independent re-review closed that issue.

UI/API coverage1625e7 rejected a duplicate listTests mapping; the canonical Red
Team mapping remains the single entry. Coverage-test REDd40b9a also found stale
counts for three already-recovered operations: getSecurityAgentAuditEvent,
listSecurityAgentActivityRuns and listSecurityAgentRunActivity. Expected counts
now reflect152 public operations (142 available,10 api_available), with4 planned.
Focused lint and10 coverage tests33ea13, typecheck7d4345 and standalone build40e667
pass. Browser component/transport fixtures are not live service proof. Production
action capabilities and durable-definition capability remain unavailable; real
database persistence, planner, invocation/evidence and composed acceptance remain
required before enabling these actions or promoting M7A-21.

## Stored activation reader and current database gate

RED1e3aa2 reproduced valid disabled run_test/rerun_test definitions being rejected
by GetSecurityAgentActivation. Its stored-body reader now uses the strict raw
definition grammar, retains required id, and validates optional existing_test.
The alternate readable-action branch requires one test action, test_run and
disabled draft/validated state. The existing scope, definition/row version,
budget and general agent checks remain. Enabled test execution is still refused.
Eleven cases cover both actions, missing/null/zero/extra/duplicate references,
wrong or mixed actions, wrong verification and unavailable enabled execution.
Focused group0c0fc0 passes; independent source review found no Critical/Important
issue. Stubbed stored payloads do not prove database persistence or availability.
The wider repository/draft-contract/cost group also passes under the race detector
(3df3d9,2.060s); affected-file whitespace check96248b is clean. UI source is
unchanged from the prior standalone build40e667.

The fresh owned integration attempt647afb still fails in initdb before any test
assertion: all shared-memory IDs are occupied. Read-only IPC3f82e8 reports30
detached56-byte segments and2 live attached PostgreSQL servers. Narrow cleanup
permission was requested asynchronously, requiring fresh zero attachments and
absent creator processes. No cleanup or process stop has been performed.

## Definition visibility and lookup lifecycle follow-up

REDe8af07 found that API identity alone allowed an old result to reappear after
A-to-B-to-A switching while B remained pending. Results now carry a distinct
memoized request identity (API, reload revision and callback), with abort cleanup
on every change. The regression verifies no old choice or late B result appears;
fresh A results still require explicit selection. The same red group exposed
missing pinned-reference detail. AgentDetail now shows the persisted test ID and
version as read-only text. A reopen/name-edit test verifies the exact reference
and disabled state survive and unavailable catalog support still blocks activation.

Group061b26 passes194 UI/API/receipt tests; lint62c103, typecheck116dc2,
whitespacefb1b59 and standalone build309578 pass. Independent review found no
blocking issue in these edits. These remain controlled component/transport tests,
not database persistence or live execution proof. Backend and external gates
are unchanged; no production capability, availability count or push changed.

## Pending registered-role definition acceptance

`security_agent_existing_test_definition_postgres_test.go` adds the next database
contract to the owned candidate fixture, after dispatch subtests so its additional
definition cannot change their setup queries. It calls the actual public mutation
function as the registered API login, asserting draft create/replay, stored body,
version history and receipt count; malformed/stale/missing/absent-reference updates
must preserve authority. A valid rerun update is read through the registered API
function and checked against persisted version/digest/receipt history.

This test is prepared, not verified. Compile6e1992 passes, but execution7d8da6
fails at the same initdb shared-memory gate before any assertion. It is not an
observed product RED and does not authorize a production implementation claim.
Source tracing also found the predecessor mirror trigger records session_user
as history actor_id; the contract intentionally requires the operator principal
passed to mutation. That provenance repair belongs in guarded55 mutation wiring,
not an owner-only test fixture rewrite. Foreign-scope/disabled-test and real HTTP
acceptance remain to be completed with the database path. No55 capability enabled.
Review requested a positive update control, isolated other-action refusal and
full scoped row snapshots. The final harness contains all three, including
ordered receipt/audit/idempotency bodies. Independent re-review found no remaining
blocking harness issue; compile-only7dee80 passes. No database assertions ran.

## Isolated PostgreSQL recovery and definition authority

The host remains at32 occupied SysV slots (read-only c73b52); no segment or live
server was removed. An isolated container now runs the real fixture with no
network, read-only source/binary mounts and disposable tmpfs data as postgres.
The cached PostgreSQL16 image correctly refused the18 migration fingerprint
(587475). No pin was changed. Official postgres:18.3-bookworm was downloaded
and executed by digest
`sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`.
The Go test binary is cross-compiled linux/arm64 with CGO disabled, downloads
disabled and existing modules. This is not a race-detector run.

Real RED408eb0 reached stored-definition history and rejected its session_user
actor. The unregistered55 candidate now saves the exact mutation predecessor,
preserves its role/ACL/search path and binds only the newly inserted exact scoped
version to the canonical operator principal inside the original transaction.
Replay returns before any provenance change. RED0c8a4e then exposed accepted
missing-reference updates. The candidate now calls the private54 resolver for
every test action/reference, with atomic rollback of workflow/history/audit on
refusal. Published migration files and production capabilities are unchanged.

Focused9413c0 passes create/replay/update/read and13 malformed/stale/disabled
refusals. Negative subtest failure now stops the parent, preventing a mistakenly
accepted write from making later cases pass on stale CAS. Independent review
added legacy create/update/read/delete, a second operator with unchanged earlier
history and exact old replay after a newer version. Review and runtime f2d86d
identified a fixture correlation collision; fresh mutations now have distinct
correlations while exact replay retains the original one.

Final grouped d6d914 passes both TestSecurityAgentExistingTestBindingPostgres
(7.28s) and TestSecurityAgentExistingTestEnqueueCorePostgres (15.40s), including
resolver expiry, durable links, guarded dispatch, current credential authority,
all definition refusals and legacy/replay checks. Both owned PostgreSQL processes
were joined with normal exit. Independent review found no blocking product SQL
issue. This supersedes the earlier compile-only definition checkpoint and removes
host cleanup as a prerequisite for this container test route. It does not prove
registered55 compatibility/rollback, actual HTTP definition writes, same-org
cross-workspace/environment mutation denial, activation/planning/invocation or
live production acceptance. All A-D acceptance boxes remain open. No push or
production promotion; fresh advisory authorization still gates publication.

## Tenant-bound definition and candidate rollback batch

Definition groupdac153 passes three additional scope-substitution cases. Each
varies exactly one organization/workspace/environment coordinate, with the other
scope IDs reused. A real registered-API creation against an enabled scoped test,
target and credential is the positive control. Substitution into the primary
definition must return40001 and preserve full primary/foreign authority snapshots.
Independent review found no blocking harness issue. These tests use distinct test
and target IDs: they prove full-scope reference binding, not same-test-ID collision
behavior or a foreign browser principal's authentication/authorization.

Candidate rollback REDb3ac22 proved unused rollback was absent; restoration of
the two exact saved public functions plus removal of candidate-only objects now
passes the compiled54 readiness check (a17561). RED84c33e proved a retained
noncurrent test-bearing definition version allowed unsafe downgrade. The owned
candidate down fragment now locks workflow/definition/history/link tables and
refuses before DDL if any links or test-bearing current/historical/workflow body
remain. Refusal preserves version rows, metadata, mutation/enqueue bodies and
candidate schema/table identity.

Grouped707b6a passes resolver, enqueue/link/dispatch/definition, empty rollback
and retained-history rollback fixtures. Both new rollback tests run in existing
CI's Test.*SecurityAgent lane. Whitespace and728-row ledger validationa35824 pass.
No UI source changed; no push or production promotion. Superpowers review found
no blocking issue for this explicitly owner-run disposable rollback. It is NOT
the registered55 down migration: forced-RLS-safe migration identity checks,
bounded dispatch/invocation cutover fences, retained invocation/terminal/partial
history cases and full55 pins/compatibility remain required before reuse there.
The production repository still refuses the unregistered changed fingerprint;
no readiness override was added to fabricate HTTP acceptance.

## Registered55 local compatibility checkpoint

Release55 now has a compiled migration identity, exact predecessor checks and
runner upgrade/down operations. Nine saved public functions are restored on
unused rollback. Private fingerprint ancestry preserves the published53/54
identities; old54 clients refuse55. The compiled55 fingerprint is
`460915bbf82c08d92cbeab4bdc49a65d9f728718953944653d5b3110bd10b81c`.
The new client checks installed55 on every read and refuses invalid55 without
falling back to54. Dispatch remains private and production actions remain off.

Fresh grouped PostgreSQL18.3 verification21b9c6/b67893/6842ce passes calibration
(3.38s), registered release (4.22s) and eight warm/fresh API, ingest, planner and
action consumers across53->54->55->54->53 (18.08s). Tests reject ACL, forced-RLS,
search_path, predecessor metadata and mutable-pin laundering drift. Registered
rollback refuses retained noncurrent version99 definition history and preserves
the55 version and history. NOINHERIT membership is rejected with42501 and the
explicit authority error before retention reads. An unused55 returns to exact54.
All owned PostgreSQL processes exited normally. The pinned, network-isolated
container uses read-only source mounts; this binary is not race-instrumented.

Audit configuration/worker/API registration orchestration originally rejected55:
fresh REDb7462d reproduced six failures. Exact55 state selection and compiled
pre/post readiness now pass the full migration race suite37b7e9 (4.799s), including
wrong predecessor and selected-release checksums, initial/final drift and unknown
future versions. Independent review found no Critical/Important issue; its
selected-checksum coverage suggestion is included. This orchestration coverage
uses a controlled query adapter, not actual55 audit configuration operations.

This supersedes the earlier registration and host-initdb blockers for these
owned fixtures only. Batch A still needs real HTTP draft write/read acceptance
and atomic versioned write authority across rollback. Planner integration,
invocation reservations, cancellation/settlement, retained execution-state
rollback coverage and composed browser/worker acceptance remain open. Do not
publish this intermediate55 or promote M7A-21. Fresh advisory authorization,
full release verification and live operational evidence remain separate gates.

## Versioned draft-write guard groundwork

Repository routing RED979681 proved test-bearing writes still used legacy SQL.
They now call the versioned55 mutation entrypoint with compiled checksum and
fingerprint, with no retry through the older entrypoint. Independent review found
an alternate-cased action key could hide the lowercase PostgreSQL action from
Go's struct decoder. Regression24cb82 reproduced this; exact-key object routing
now preserves PostgreSQL semantics and rejects duplicate keys/null values before
any database call. Legacy non-test writes retain their previous route.

Registered API-role DB RED5d0830 proved the versioned entrypoint was absent.
The new API-only, fixed-search-path definer checks the registered principal,
locks workflow/definition/history tables in ROW EXCLUSIVE NOWAIT mode, then
checks compiled55 authority before and after the inherited mutation. These
transaction-held locks conflict with registered rollback. The55 fingerprint and
automatic down removal include the new entrypoint. Independent source review
found no remaining Critical/Important issue in this bounded implementation.

Owned calibration06e136 updated the unpublished55 pin to
`1b0b0a833388b6303cca5229dc0df3e1ba336c74304ba9cc2cd6ea8fd706f8c1`, superseding
the preceding checkpoint's pin. Group33b826/97ebdf/4c9558 passes calibration3.39s,
registered release/stale-pin refusal4.27s and warm/fresh consumer checks19.22s.
Owned PostgreSQL processes exited normally. Full migration race c0ec95 passes
4.401s; affected workflow/routing race d858f1 passes2.199s. No UI input changed.

This is not successful versioned-write or HTTP acceptance yet. Required next:
positive create/update/read persistence, mutation-first and rollback-first race
characterization, and the pre-mutation ReplayWorkflow path. Capability remains
off. M7A-21 stays component-only; no push or full Batch A acceptance.

## Registered write, replay and cutover acceptance slice

The versioned55 API-role test now exercises actual create, exact replay, update,
read, scoped reference refusals, disabled/stale/malformed references, actor
history and legacy update/delete. It verifies stored bodies, row versions,
receipts and unchanged refusal snapshots. Three foreign positive controls vary
only organization, workspace or environment. This is SQL/API-role acceptance,
not an authenticated browser or mounted HTTP-server acceptance.

Cutover tests cover completed registered rollback before a stale55 call (42883,
no legacy fallback or rows in six mutation tables), an already-held rollback
relation lock (55P03 and no partial writes), and a real API write held in an open
transaction. All three required RowExclusiveLocks are observed; registered
rollback refuses while the transaction is open. After commit, exact draft and
actor history survive and retained history prevents downgrade. Observing locks
after a write alone would not prove early fencing; the separate held-lock test
provides that evidence. Independent review accepted this characterization.

Pre-mutation ReplayWorkflow had its own gap: Go RED4eec9d used legacy SQL, and
DB RED81c0cb found no versioned replay function. Test-bearing replay now uses a
separate API-only55 entrypoint with principal and compiled pre/post readiness
checks. It admits no work and does not acquire mutation locks. Shared exact-key
routing rejects duplicate/null objects and prevents case aliases from hiding the
lowercase action. Review-requested outer-envelope cases cover reference-only,
rerun, duplicate body/actions, null body and legacy empty body.

Owned calibration3c9897 set the unpublished compiled55 pin to
`1a1e68bb0e15f216227a1d90ea0491ce2f0c231a34c3220c39fc87fd924e5bb6`; earlier pins
above are historical. Focused workflow/write/replay race and full migration race
406efb pass2.216s and4.479s. PostgreSQL grouped3ebd72/a321d0/a0744f/e9ce4b passes
candidate regression15.73s, calibration3.29s, release and stale write/replay pin
checks4.23s, versioned definition/replay6.02s and cutover4.31s. Both new wrapper
ACLs are API-only; private dispatch is still not granted.
Final group output795cfb also passes eight warm/fresh consumer checks18.24s.
All six owned PostgreSQL processes exited normally. The group used the pinned
network-isolated PostgreSQL18.3 container and a non-race Linux test binary.

Remaining Batch A work includes the HTTP handler using the real repository and
its release-aware capability. No capability bypass was added. Activation,
planner, invocation/cancellation/settlement and composed execution remain open.
M7A-21 stays component-only and all A-D batch acceptances remain open. No push.

## Real handler and release-aware draft capability

HTTP RED494b66 reproduced create400 with the actual registered55 repository:
no draft capability was advertised. The handler now passes its request context
through repository and database capability checks. The database probes current55
and verifies compiled pins without caching presence/absence. Missing55 returns
false; invalid55 and cancellation return errors. SQL write/replay guards remain
the atomic authority, so capability lookup is not a substitute for write fencing.
This enables only disabled drafts, not action execution or activation.

Real handler/registered-API database integration a0085b first passed create,
update and replay. Extended group80767f/068b20/aa033a passes warm55->54->55
capability changes, cancellation, exact submitted/stored bodies and actor
history, immutable create replay after update, drift503, restored replay and
unchanged history/receipt counts (HTTP6.80s; shared warm/fresh consumers20.21s).
Final HTTP88e747 passes6.57s with GET readback plus stale/missing-test409,
null-reference400 and activation400, checking each refusal preserves the current
draft/version. Counts establish no extra history/receipts, not a full snapshot
proof that every existing audit/idempotency field remained unchanged.

Independent review found production tracing hid the capability. Decorator
RED0c1215 reproduced it; forwarding now preserves context, legacy absence,
current errors and warm capability changes. The actual decorator regression
passes in full agentsec-api race cdecd2 (2.966s). Initial4383a7 was a sandbox
loopback-listener denial, not a product failure; the authorized local-fixture
rerun passed. Focused handler/contracts/repository race23c805 passes2.145s.
Independent re-review closed the forwarding issue with no new blocking finding.

These are separate actual handler/database and decorator tests. They do not
prove a composed tracing+database+authentication stack, live login, a browser
workflow, worker execution or deployment. No source UI inputs changed and no
push occurred. Current55 SQL/pin are unchanged from the previous checkpoint.
M7A-21 remains component-only. Remaining acceptance includes mounted/authenticated
tenant paths, planner/activation admission, invocation/cancellation/settlement,
and full composed execution. All original728 requirements remain in scope.

## Mounted API wiring and refusal checks

Actual production composition now has a focused mounting test through edge
validation, session middleware, tracing, repository and handler. A controlled
session/SQL boundary checks exact tenant/principal arguments and compiled55 pins.
Healthy create returns201 with the pinned disabled-draft reference; missing
manage_workflows and wrong CSRF return403, expected-scope mismatch409, corrupt55
503. Wrong Origin returns the established edge-layer400. Initial7bb538 failed
only because that case incorrectly expected403; existing edge contract tests
confirmed400, so the test expectation was corrected without changing product code.

Independent review requested counting mutation attempts before the controlled
database's checks. This now proves negative cases never attempt mutation SQL,
not merely that the fake accepted no write. Grouped mounted/decorator race1a904a
passes2.100s. The echoed boundary body proves transport preservation, not SQL
validation or persistence. No live login or real database is used by this test.

Separate actual PostgreSQL handler acceptance16e029 passes6.38s after aligning
its update method with the real PATCH route. Stored-body, replay, refusal and
capability assertions remain intact; the owned process exited normally. Together
these are useful separate wiring/persistence checks, not a single authenticated
browser+database proof. UI/product SQL/pins are unchanged. No push or production
promotion. Planner context/preparation/acceptance and durable invocation remain
the next implementation work; full composed browser acceptance remains open.

## Registered55 planner context, partial Batch B

Added worker-only `zasp_production_security_agent_existing_tests_planner_context`
to the unpublished55 assembly. Full compiled readiness brackets its test branch;
the organization budget guard precedes run/prerequisite locks. The private54
resolver supplies the exact stored test ID/version. Finding, attack-path and
runtime evidence are revalidated under locks, followed by time-dependent binding
and lease/budget checks. Budget stops return the durable stop envelope. Context
includes one configured test target, no caller-selected parameters or version.
Non-test definitions retain the33 context. No plan or execution is created.

The corrected real worker-role regression failed at missing function42883 in
65bc43 before implementation. Initial83562c also exposed unused fixture arguments;
those were repaired before that RED. Owned calibration467ea6 observed compiled
pin2ed2d497687e88d618f9c6c37d3759f1d73c1eec21210bd6bc827f0452fec245,
now pinned in source. No live fingerprint was adopted at runtime. The new prefix
is fingerprinted and removed by unused55 rollback; dispatch is still private.

Initial grouped50f57a passed context12 cases, fingerprint and release checks.
Expanded95d079 passed19 cases. Finalfb637d passes20 cases in11.49s: run/rerun,
stale/disabled test, disabled agent, stale evidence/lease, foreign scope, durable
budget stops, observed finding-lock waits that expire lease/deadline/target,
valid and revoked/expired/digest-changed runtime evidence, valid/stale attack
path, byte-identical legacy context and prior-plan refusal. Successful contexts
are repeatable; Go SHA256 independently checks the complete PostgreSQL canonical
context, and changing the stored test version changes its digest. Oracles assert
no plan/step/effect/link, provider/step reservation, Red Team run or outbox from
context calls. The separate prior-plan case proves a healthy test context first,
then refusal without changing an owner-seeded, canonically hashed stored plan.
It does not prove production plan acceptance.

Final grouped regression68a3d5 passed HTTP6.16s, compiled fingerprint3.33s,
release4.23s, versioned definition5.94s, cutover4.28s and consumers18.12s. The
group was not globally green: prior-plan fixture setup483a3d had an untyped JSON
parameter42P18. Explicit text casts repaired test setup only, followed by the
affected context rerunfb637d. Other covered inputs were unchanged, so their
successful results were retained under feature-batched verification. All owned
PostgreSQL processes exited normally using the pinned, no-network18.3 container.
Full migration package race16c7f9 passes4.673s. Independent review accepted the
context and coverage extension; two stale-prefix findings were retracted after
fresh source inspection, and the prior-plan positive control was strengthened.

This remains component-only over owner-seeded admitted runs. No activation,
model invocation, preparation/acceptance, simulation, dispatch, settlement,
authenticated browser or live provider execution is proved. The old planner
reservation recomputes33 context and cannot admit these new test contexts. Next
is a matching pinned55 reservation/recomputation path plus strict Go repository
and worker routing, then preparation/acceptance. No relaxed digest comparison,
public execution grant, count promotion or push. The original728 scope remains.

## Registered reservation and planner reference wiring, partial Batch B

Added a private55 clone of the existing planner reservation authority, changing
only its function identity and context resolver with exact occurrence checks.
The published53 function is unchanged. A worker-only55 wrapper checks compiled
readiness, retains core accounting/replay stops, and recomputes context after
reservation insertion. A late deadline stop rolls back the new reservation
inside a savepoint, then persists the stop outside it. Late lease/target expiry
aborts the reservation. The private core is not granted to application roles.

Real worker calls for both actions failed at missing function42883 in REDfc5e5b.
Owned calibrationd62d15 produced the current compiled55 pin
`c9910c1e6940608fadaf8468221c88c633564cd8fbb413b435ee41e8174c3de7`.
Groupedcc6a2e/a36ace/29b25e/717948 passed context20cases11.66s, compiled fingerprint
3.41s, release4.25s and the initial18 reservation cases13.35s. Exact role denial,
private-core ACL and drift refusal, recomputed digest/version, configured token/
cost bounds, replay and unknown-usage stops are covered. Insertion-wait cases
observe an actual ungranted RowExclusiveLock on the reservation relation before
expiry, then require zero new reservation for expired lease, budget or target;
the budget case retains its durable stop. Returned reason and expiry are checked
against authoritative state. No step reservation, plan, effect, link, Red Team
run or outbox may be created by reservation.

Repository REDbd7386 proved missing55 selection, existing-test decoding failure
and release-drift fallback. Per-operation selection now uses the full compiled55
capability without caching absence; invalid55 fails before context/reservation
SQL. The typed reference survives decoding and is bound to the sole allowed
test target. Duplicate-aware validation covers envelope, context and reference,
not all nested objects; PostgreSQL JSONB canonicalization remains distinct.
Missing/null/extra/duplicate/mismatched references, invalid versions, old releases
and references on legacy actions are refused. Legacy paths remain available
when55 is absent. Warm cutover/drift/rollback routing has focused boundary tests.

Actual repository+PostgreSQL modes initially failedd46af3 because the owner-seeded
claimed run still had initial version1; validSecurityAgentRunClaim requires>1.
Only fixture setup changed to return version2. Finalba89c4 passes20 cases15.29s,
including exact context/reference and durable reservation round trips for both
actions. This is still owner-seeded admission, not scheduling/activation proof.
The surrounding27a38f group passed unchanged HTTP6.68s, versioned definitions
6.13s, cutover4.28s and warm consumers17.73s; the group itself failed until the
affected reservation rerun. All owned container PostgreSQL processes joined.

Worker REDf7c66e proved the processor dropped the reference and the real adapter
omitted it from requests or sent malformed test contexts. The processor now
copies it; the adapter serializes exact ID/version and validates one action,
target, evidence item and step, canonical ID, bounded version and supported
evidence kind. Candidate validation already used only explicit AllowedTargets;
that implementation is preserved. Controlled transport tests include environment/
evidence target substitution, absent/mismatched/out-of-range reference, mixed or
legacy actions, extra target/step/evidence and unsupported evidence kind.
The processor test has controlled budget and acceptance authority. It proves
propagation, not database acceptance or a real model response.

Final focused repository racecaa8c8 passes1.793s; worker racef9b807 passes2.199s.
Full migration race951bed passes4.298s. A combined package filter accidentally
included older host database suites and was interruptedaae137; it is not passing
evidence. Authorized process inspection1af6bb found no matching test binary or
owned temporary planner PostgreSQL process left alive. No user server or IPC
segment was stopped/removed. Separate corrected package filters passed. Reviews
accepted the SQL, repository and runtime slices; requested assertions were added.

No provider/network invocation occurred in these fixtures. Default production
PlannerBudget still lacks verified model-price bounds and fails closed; controlled
request bounds do not establish that gate. Preparation/acceptance and planner
failure still use33 authority and cannot consume the new test context end to end.
Those versioned paths are next, alongside activation/simulation and remaining
durable invocation/cancellation/settlement requirements. Dispatch stays private,
public execution capabilities remain off, and full composed/authenticated/browser
and live production acceptance remain open. No UI inputs changed or push occurred.
