# P2 settlement claim review follow-up

Correction after review: the original terminal-winner test retained a live lease, so the independent settled_at coverage claim below was overstated. `review-p3-report.md` records the test-only correction, isolated settled-guard mutation RED and corrected GREEN. Product SQL and the P2 fingerprint are unchanged.

DONE. Reproduced the reviewer’s exact stale-candidate/updated-locked-row concern, then fixed it. Awaiting the same reviewer’s follow-up; this is not public-workflow or production acceptance.

Current release58 fingerprint: `eb5d958fba7a720ad6f8d47c9f4cfb6a4193b10f4b48a4fb6bdcdc3b67ff0bf0`.
Predecessor frozen fingerprint: `df4ba6cf13e1ae0312a1c46dc05895e8f83bd8b2b381ddc1162482e694a77ff2`.
Worktree and HEAD remain those in task-1-report.md. No root-owned product file or frozen renderer changed.

## Reproduction and fix

Receiving-code-review and systematic debugging required checking the hypothesis before changing product code. The initial unmodified-public-function table-lock characterization passed: PostgreSQL obtains a fresh candidate snapshot after that wait. It is preserved separately and is not called behavioral RED.

The controlled regression copies the installed settlement claim function using pg_get_functiondef into a fixture-only function outside the fingerprint namespace. The only alterations are its name and a correlated advisory barrier before row locking. Role checks, readiness, candidate predicates, row locking, loop, updates and receipts remain the installed production body. A separately connected registered worker calls the unchanged public claim and, for the terminal case, public settle. The fixture barrier forces the stale claimant’s statement snapshot to precede the winner’s committed lease/receipt. No production hook, built-in replacement, readiness exception, mock claim, or timing-only sleep establishes the interleaving; pg_blocking_pids confirms the barrier.

At the frozen SQL both cases failed behaviorally: the stale claimant returned the link and mutated its entire persisted lease/receipt row after the winning claim or settlement committed. Both owned PostgreSQL lifetimes joined normally. Container exit 1.

The product fix adds one CONTINUE guard to the existing locked-row loop: skip when its current row is already settled or has an unexpired settlement lease. The due alias can retain its old statement snapshot, but the locked outer row is current after EvalPlanQual. Lock ownership keeps the checked tuple stable until the update. No signature, envelope, grants, parent state, ordering or pending-poll behavior changed.

Both cases now return [] and preserve to_jsonb(link) byte-for-byte. The live-lease and settled-row guards are tested independently.

## Verification

Offline compilation completed with exit 0 before RED and after the fix/pin update:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

The complete exact Docker commands and raw outputs are retained in:
- review-p2-table-characterization.log: initial public-function characterization, exit 0.
- review-p2-red.log: both controlled interleavings fail before the product fix, exit 1.
- review-p2-calibration.log: changed SQL correctly rejected under the old pin; observed new catalog fingerprint, exit 1. This is pin calibration, not a product behavioral failure.
- review-p2-green.log: one affected feature batch at the new pin, exit 0.

Final grouped command:

```sh
/usr/local/bin/docker run --rm --name zasp-export-db-review-p2-green --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-export-db-test-initial.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExport(SettlementInterleave|SettlementTableGate|StoppedSettlement|Lifecycle|TwoScopes|Release)Postgres$' -test.v -test.timeout 300s
```

Six groups passed: Lifecycle 10.80s; StoppedSettlement 11.19s; TwoScopes 4.96s; SettlementTableGate 4.96s; SettlementInterleave 9.93s; Release 6.47s. Eight owned PostgreSQL lifetimes joined with pg_ctl exit 0/server Wait exit 0, no skips. Release includes actual Runner58 registration, exact57 down/up restoration and drift refusal. Lifecycle retains completed-child settlement, expired-budget/revoked-actor drain and replay checks. No unrelated source-family or public-worker process rerun was needed for this three-line SQL correction.

PostgreSQL ran only in the cached Linux/arm64 network-none read-only container, user postgres, owned tmpfs; no host PostgreSQL or image pull. CGO-disabled binary is not race-detector evidence.

## Scoped bytes

Original task-only.patch and checkpoint-df4ba6cf.patch remain unchanged, both SHA256:
4681b66ca882c046bc2f463ddf7d50cf450e804e3b7bd1067d7f1ca4bd852380

Apply review-p2.patch on that frozen snapshot. This delta changes only:
- migrations/sql/fragments/security_agent_export_links.sql: current locked-row eligibility guard.
- migrations/security_agent_exports_release.go: exact recalibrated fingerprint.
- apiserver/security_agent_export_postgres_test.go: table-gate characterization and two controlled interleavings.

Scoped patch SHA256:
67e6b52c31b51ef6a65983c07e8c5dfaf3314ba44c8be91a14cdc4a02d9da804

Before bytes are preserved under review-before/:
```text
0e37b4ace32342ca8c4ee17eb77812842600f155256373cbe397bbdfb4f8d7f0 security_agent_export_links.sql.txt
3af10ba2f7389083d617d30075a60d70f67315df634eade9f0809633d1a031e8 security_agent_exports_release.go.txt
4f88d075acb767769a8b8e3035d58e67ff5feb0610d58755c9113513da4e3b58 security_agent_export_postgres_test.go.txt
```

After source bytes:
```text
f12e9b1dd97b6e1219e5b2f0ad613c0bc298c4f511a24896a59fdc36550954f1 services/platform/migrations/sql/fragments/security_agent_export_links.sql
e4d1fcc1ba47f22b54757a94f7164ab57004150d3f44b2eb54015fa3a1de3676 services/platform/migrations/security_agent_exports_release.go
9d063164a1fcf0197bf0dd275bfddda81fb064740f8989be718a6a2aa87082ae services/platform/apiserver/security_agent_export_postgres_test.go
```

Evidence hashes:
```text
869f46f23295553921ce32bb9e61f7a8dd5ea5d61da3ac56d02d1254f974a97e review-p2-table-characterization.log
b858945477d01cef50044dff149272c8814ba567a03a86037e8f0e9fe9e9724d review-p2-red.log
ff7fbda514faf7cd92e2c321eb1f9a6b9f52c614528a7620497b3f116bb117d5 review-p2-calibration.log
a95005308e7303c2c581e0a046109eb9e97cd666979edc366a34f3fbf3707e39 review-p2-green.log
```

git apply --reverse --check review-p2.patch and scoped git diff --check exited 0. Renderer hashes remain bb933859… and 0b541bee….

The separate action-details/approval projection gap identified by the controller is not included or claimed fixed here. No further product edits will occur before this P2 snapshot is handed back.
