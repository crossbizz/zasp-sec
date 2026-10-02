# Run action-details projection handoff

DONE_WITH_CONCERNS. This additive58 run-projection batch is verified and frozen for independent review. Approval SQL, export execution routing and manual-parent public provenance are separate open work. This is not M7A-23 or production acceptance.

Current pin: `46b69c98336c9a93c168e9b451ae8da69fb248ee1706d6d2c419f31707b6a998`.
Base pin after accepted P2/P3: `eb5d958fba7a720ad6f8d47c9f4cfb6a4193b10f4b48a4fb6bdcdc3b67ff0bf0`.
Worktree: /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917
HEAD: 8733b16f8d939d38a8157dd2519e57fc6f630542

Only three product files changed in this delta:
- migrations/sql/fragments/security_agent_export_links.sql adds private zasp_sa_export_public_step and saves/extends the predecessor run_context_core/public_step functions through the existing58 restore mechanism.
- migrations/security_agent_exports_release.go pins the resulting catalog.
- New apiserver/security_agent_export_projection_postgres_test.go exercises registered reads and actual dispatch/storage/settlement operations. No Go/TS implementation or renderer file was edited by this batch.

The private core projects exactly {target_id,evidence_ids}; target is the parent run and evidence_ids is the original ordered closed typed selection. The helper checks canonical plan/step digest, original parent definition/version, exact arguments, empty control/target metadata, and full-scope link/job/effect identities. It compares selection to the immutable link and original job request; it never recollects newer sources.

Pending effects bind their digest to the persisted original dispatch receipt. Settled effects bind their digest to the immutable settlement snapshot and verify the closed receipt's run/step/export/result identity. Cleanup may change the current job's storage state later; historical settlement facts remain historical. No provider locator, provider version, private package or storage snapshot is returned.

Public semantics agreed with root and exercised through root's public decoder:
- No effect: result null, verification unavailable/none.
- Pending and succeeded have verification pending/effect_record. Artifact completion is not verified security remediation.
- A known_failure result has failed/effect_record verification.
- cleanup_pending remains cleanup_pending with inconclusive/effect_record verification. It records a storage obligation; rollback is not_supported, unavailable, unavailable/none for every export state. No TTL or control expiry is added.

Only pending/succeeded/known_failure/cleanup_pending are accepted export effect states. Existing stopped parent states are preserved separately, including contained/remediated/inconclusive histories; export settlement did not cause those pre-existing outcomes.

## What actually ran

Superpowers TDD produced a registered behavioral RED before product edits: the pre-effect API wrapper rejected export at its predecessor allowlist. The grouped RED reached the same boundary for actual succeeded, known_failure and cleanup_pending settlements. Five owned PostgreSQL lifetimes joined normally; exit1. Both initial and grouped commands/output are retained in projection-red.log and projection-group-red.log.

The first affected batch at pin7d10566a passed:
ProofSources14.53s, Projection5.27s, ProjectionSettled19.66s, ProjectionRefusals6.40s, Release7.16s. Eight owned PostgreSQL lifetimes joined; no skips; exit0. projection-initial-green.log is the complete original run.

That original Docker handle initially stalled before any output and its daemon ping timed out. The same handle later completed without intervention, duplicate execution or shared runtime restart. projection-pending-runtime.md records that sequence and the held source/binary hashes. projection-draft.patch preserves exact source at the first GREEN.

Self-review then found a reader restriction: existing settlement preserves every stopped parent, but the draft reader accepted only needs_human/failed/cancelled. Root approved a focused correction. Three real-settle fixtures for already-contained/remediated/inconclusive parents failed against7d10566a (projection-stopped-red.log, three clean joins, exit1). The final SQL changes only that receipt-state allowlist, not parent mutation or four-state export semantics.

Final affected follow-up:
ProjectionSettled20.92s (all three terminal export results), ProjectionStoppedParent16.78s (three preserved parent histories), Release7.41s. Seven owned PostgreSQL lifetimes joined with pg_ctl/server Wait exit0, no skips, container exit0. Exact output: projection-final-green.log.

Offline compilation before each run exited0:
```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

Initial affected batch:
```sh
/usr/local/bin/docker run --rm --name zasp-export-db-projection-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport(Projection|ProjectionSettled|ProjectionRefusals|Release|ProofSources)Postgres$' -test.v -test.timeout 300s
```

Final affected follow-up:
```sh
/usr/local/bin/docker run --rm --name zasp-export-db-projection-final-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport(ProjectionStoppedParent|ProjectionSettled|Release)Postgres$' -test.v -test.timeout 300s
```

All PostgreSQL work for this batch ran inside the cached Linux/arm64 network-none, read-only container as postgres with owned tmpfs. No host PostgreSQL, installs, image pulls or provider calls. CGO-disabled binary is not race-detector evidence. Each calibration log records the expected rejection while SQL and pin differed; calibration failures are not promoted to behavioral regressions.

Tests cover original two-source ordering and reordered-link refusal; malformed/unknown-key selection; target-parent mismatch; each foreign scope/run dimension; pending link/input/job-request/digest drift; settled digest drift; real prepared/finished/settled success; real cancelled/no-intent failure and prepared/cancelled cleanup_pending; newer source version without changing original selection; no private provider/package/storage leakage; public decoder verification/rollback semantics. ProofSources checks existing-test and Attack Lab public-step delegation under58. Release checks actual Runner58 worker registration, live column/trigger drift refusal and exact predecessor57 catalog/ACL restoration through down/up.

## Exact bytes

projection.patch is the three-file delta on the accepted P2/P3 snapshot. SHA256:
`dbdf407fbd40356d1231270eb2812397d084399519df0ccc7dcdb372cf389ac3`.

Before bytes:
```text
f12e9b1dd97b6e1219e5b2f0ad613c0bc298c4f511a24896a59fdc36550954f1 projection-before/security_agent_export_links.sql.txt
e4d1fcc1ba47f22b54757a94f7164ab57004150d3f44b2eb54015fa3a1de3676 projection-before/security_agent_exports_release.go.txt
ABSENT services/platform/apiserver/security_agent_export_projection_postgres_test.go
```

After/source/evidence hashes:
```text
3ff1e314e35391de04af63a828213214ece386dcb0dd469c80fb52730f1c39aa  services/platform/migrations/security_agent_exports_release.go
43c704245a849a4699167f72690317a43cd217bf231bc972e31b47ac36fed5fd  services/platform/migrations/sql/fragments/security_agent_export_links.sql
83ab07aa465ddb8603455dfc5ed3430e88e647f3a036927804c372d5209bde5c  services/platform/apiserver/security_agent_export_projection_postgres_test.go
dbdf407fbd40356d1231270eb2812397d084399519df0ccc7dcdb372cf389ac3  docs/internal/security-agent-export-20260919/database/projection.patch
372db27efdfa47bb47c203782dfbc0cb052e4969283923104f12e8e46365b5e3  docs/internal/security-agent-export-20260919/database/projection-final-green.log
ed94dc7779590532b7718a840916b74e7d3e9e844c1c68a4622ed96edfda32f4  docs/internal/security-agent-export-20260919/database/projection-stopped-red.log
bb933859b4ba754f446e2cf4147371aea230eb3f1f244752446571d5caea1e04  services/platform/agentsec-worker/security_agent_export_render.go
0b541bee4e3639d54e85308d797abb59bdf5309aa694258442256eb7876cf2cf  services/platform/agentsec-worker/security_agent_export_render_test.go
9032865183eee8f45c245e9c0dfd8b6e0db444b25799488a4b776d2a565e8b73 projection-red.log
17f32eafd334d8324a3c502bd51a050e4f71e04174ee0c051e3578b98499efb9 projection-group-red.log
71915b4501912563f98338ef135e73c6fe502d2d2977a082ba0a3e15ad1c4959 projection-initial-green.log
8587a6fd88a7eb308206c23dd89e4722a062acd0f12705004a62de1c2c01149a projection-draft.patch
d272dd193c57de9699fa221bc66afaf0de9ea2fa4f9739119e5aa49ad8fdd62e /private/tmp/zasp-export-db-test-initial.test
```

Root-owned decoder dependencies used by the final binary, not edited here:
```text
3d5613759067df0ed110cf62e292388a6c6156362fad1998cfec1814794dae70 services/platform/apiserver/security_agent_action_projection.go
f59ceea33b094c9de94ab078d84acaa65a38d0385c37bbfc4ac5dd773639f90e services/platform/apiserver/security_agent_action_validation.go
```

Reverse apply check of projection.patch exited0. gofmt -l returned no files. Renderer hashes still match their accepted baseline. Original task-only.patch, review-p2.patch and review-p3.patch remain separate and unchanged.

## Still open

Approval value/decision/detail/page routing remains next connected SQL work. Run-context for a supervised export containing an approval is not claimed accepted by this autonomous finding-parent batch. Root owns the corresponding Go/TS/OpenAPI implementation.

Export run_kind routing is also pending. Attack Lab has an immutable parent dispatch worker/token receipt. Existing-test execute instead rejects a cleared lease before any replay branch; it has no equivalent parent dispatch token receipt. The controller must choose preserved predecessor refusal or a separately scoped receipt extension, not an invented false-route fallback.

Manual-parent public provenance is a required connected gap. Accepted manual receipts use a digest trigger_id while legacy run/approval evidence fields require ProductIDs. Root chose typed manual provenance and an explicitly empty legacy evidence list only when that provenance is validated; this requires connected run-page/claim/Go/TS/OpenAPI work. No digest-to-ProductID coercion or borrowed source is implemented. These tests use finding parents; supporting manual typed selections does not establish manual-parent public workflow acceptance.

No staging, commit or push occurred. This frozen projection needs its independent review before the next SQL edit.
