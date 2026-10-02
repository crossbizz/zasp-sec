# M2-33 connected GREEN implementation

The mounted versioned-update RED and the subsequently reproduced mapping/
rejection deadlock are fixed locally. Final connected backend tests, affected
Go race tests and pinned Node22 full UI/types/lint/build pass. Independent
review and root release classification remain outstanding. No commit/push.

## Exact source scope

Worktree `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`;
HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`.

Only two production files changed in this batch:

- administration_repository.go: zero-version INSERT ... DO NOTHING and
  positive-version UPDATE are separate, mutually exclusive CTEs. Their UNION
  feeds unchanged organization-wide session/PAT revocation, audit and response
  CTEs in one atomic SQL statement. Missing positive-version targets cannot be
  created; stale versions and duplicate creation keep prior conflict behavior.
- connector_rejection_transaction.go: browser final mapping locks now precede
  the credential lock; membership remains first. Registered mapping changes
  mutate mappings before revoking organization credentials, while resolve and
  deprovision start with membership. Fresh permission/readiness and final
  wall-clock expiry checks remain; no weaker authorization fallback was added.

Tests expand group_mapping_update_postgres_test.go and add
group_mapping_contention_postgres_test.go. Hooks and query tracing exist only
in _test.go. All actual writes still use registered repositories and mounted
HTTP routes. Owner SQL only supplies fixtures/read-only assertions and owned
blockers/cancellation, never a replacement product update or audit INSERT.

Fresh BEFORE and AFTER byte copies for these four files are in green/before
and green/after. source-manifest.log provides individual SHA256 values. The
320-line scoped.patch is against those fresh BEFORE bytes, not HEAD or the
inherited dirty tree. SHA256:
`e197026663391b17e290c51a19430cedb3ff7c10d6398a1abcc0059f0df764b7`.
The runtime-tested pre-comment patch was
`943bdbdfbda9856cbd854533919a8c5e5df00654e485229074a93808735609cd`.
Original M8-41 snapshots and original M2-33 RED evidence were not overwritten.
No migration, grant, RLS, public schema, CLI routing or ledger edits by this
implementer. cleanup.log verifies the other scoped source identities remain
unchanged, including all193 migration source files.

## RED → GREEN chain

1. Original red-observed.log: valid version1 replacement incorrectly returned
   HTTP409, no role/version advance, no second audit, no session revocation;
   real create and stale/tenant controls passed (see ../red-report.md).
2. mapping-first-green.log: split create/update makes that exact original
   regression PASS5.12seconds. Rejection lock order was still unchanged.
3. contention-red.log: actual registered mapper HTTP blocked by the real
   rejection transaction was observed with pg_blocking_pids. A test-only
   transaction-row wrapper pauses after actual credential FOR SHARE Scan to
   establish ordering. After release, pgx query tracing captured **40P01**;
   mapper returned409 rather than200 while rejection returned400. This is a
   demonstrated database deadlock, not a generic503 or timeout. Only the lock
   subtest failed; successive versions/group permissions/PAT and rollback
   checks passed. Log SHA256:
   `18ce7bfccd4a838c09c3c9804c960d3b2b1162fe3b95f74fec66c79919ddd236`.
4. Minimal membership→mapping→credential reorder. Connected-green.log passes
   both HTTP operations after the same observed mapper wait, with no40P01.
   The complete retained connector suite also passes against the new order.

The concurrency wrapper changes scheduling only: it neither manufactures a
result nor changes database locks, SQL, credentials, route or repository. Both
goroutines are joined, including cleanup paths, under bounded fixture contexts.

## Connected verification

All commands use the explicit worktree above. Go uses local1.25.6,
GOTOOLCHAIN=local/GOPROXY=off/GOSUMDB=off and retained offline cache. Real DB
tests use only cached image
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`,
network none, no pull/build, read-only, postgres user and owned tmpfs.

Final combined backend command:

```sh
bash .superpowers/sdd/2026-09-18-connector-rejection-plan/run-focused.sh apiserver '^Test(GroupMappingExpectedVersionUpdateMountedPostgres|ConnectorRejection(Classification|HTTPBoundary)|ConnectorRejectedAuthorityOverridesPostgres)$'
```

Named enumeration preceded execution. connected-green.log: PASS; mapping test
4.60seconds, connector mounted test14.23seconds. Parent binary SHA256
`05d68801f896abdc85f58cf31f179622f7c5f12c0dd81a22bfae36b514323dd3`;
log SHA256 `bd98edd966f7637b48f501ed66a23c39b85f95b99c6a478fc6e46325980a8681`.

Mapping assertions cover initial create, versions1→2→3, ETags, duplicate create,
stale positive version, missing positive-version mapping, foreign-tenant target,
safe fixed statuses, durable audit counts, session/PAT revocation, and unchanged
foreign mapping. A group-only member starts without manage_workflows under the
read-only mapping; real resolve/CreateSession/Authenticate after promotion now
returns manage_workflows, and the previous session is revoked. No live IdP.

An observed blocked audit INSERT is canceled via pg_cancel_backend. The mapping
role/version, audit count, existing session and PAT all retain their prior
state, proving SQL-statement rollback of update/revocation/audit together.

The connected run reuses every existing connector assertion: original10
override cases and four denial controls; GitHub/webhook success; retry/conflict,
real audit GET; browser and PAT after-INSERT revocation races; wall-clock expiry
after target wait; actual resolve/deprovision contention and group removal;
rollback/panic/cancel/closed/missing/unregistered cases; actual pgxpool and
production tracing child. It was run once after final backend edits.

Affected host **unit-only** race command:

```sh
go test -C services/platform -race -count=1 ./apiserver ./agentsec-api -run '^(TestConnectorRejection(Classification|HTTPBoundary)|TestWorkflowHandler.*|TestPostgresJSONDatabase.*|TestTracedDatabase.*|TestOperational.*|TestAdministration(TimeCursorCanonicalizesNumericOffsets|ExpiryAcceptsValidDateTimeInstantFormatting))$' -v
```

affected-unit-race.log:50 top-level PASS, apiserver4.965seconds,
runtime2.231seconds. An earlier overbroad administration-name regex was caught
during compilation and interrupted/joined130 before test output; the empty
affected-race.log is retained, not counted as verification. It could have
selected a host-PG test, so the exact two unit names above replaced it. No host
PostgreSQL fixture was launched; process checks showed no host test server.

Final feature-boundary UI command used PATH prefix
`/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin`:

```sh
node --version; npm --version
npm test && npm run typecheck && npm run lint && npm run build
```

ui-pinned22.log prints v22.23.1/npm10.9.8. Full224files/2136tests PASS in47.54s;
typecheck, lint and all5 build stages PASS. No UI source change or package
installation. No per-microtask full-suite reruns.

## Bounds and remaining review questions

Locks are bounded existing same-scope mapping rows, not table locks. Browser
group membership stability relies on registered resolve/deprovision membership
locks; mapping mutation relies on its atomic organization credential-revocation
protocol. Owner/bypass SQL omitting those protocols is outside the claim.
No new locked-reference/phantom filter was added: root ruled that unsupported
raw-SQL scenarios do not justify it absent a real product-writer counterexample.
Independent review requested narrowing an overbroad comment about revocation.
The final comment now makes only a lock-order claim and explicitly excludes
concurrent credential creation from its statement-snapshot claim. Independent review
should assess sessions created concurrently with the mapper statement snapshot,
which may not appear in that statement's revocation snapshot; this batch does
not claim to have tested that timing or all session-creation interleavings.

No live identity provider, browser/cloud deployment, external egress or whole
audit-table immutability claim follows from these local checks. Legacy API
audit CRUD remains unchanged. Release56 checksum/fingerprint remain the exact
values recorded in the connected log; no historical migration adapters.

## Cleanup

All handles joined:22734firstGREEN0,25452contentionRED1,18524connected0,
17479abortedcompile130,45587unit-race0,88313pinnedUIgate0. Owned PostgreSQL
servers in the connected run (pid24 and95) both logged pg_ctl0/serverWait0;
production child processes joined. Docker --rm removed all owned mapping and
connector fixtures. cleanup.log lists unrelated containers only (including
voxeval and independently owned daemon-replay containers, not touched).
No live handle remains. Behavior froze before final grouped checks and review.
The sole subsequent production edit is the requested comment clarification,
preserved as review-comment-only.patch against the retained
runtime-tested-connector_rejection_transaction.go.txt (SHA2566800aadd8cfbf7470d4d8161c5225db65deea74921fcf11efe2ebb32c5b85c3c).
Final file SHA256 is14610254ff3476a4cd4261d5d4d4a7f1bf3e739d4e4256af7b1ea8b6dd53af99.
Removing comment-only lines makes the compared files byte-identical; no
runtime logic, SQL, import, type or test changed. Existing runtime evidence is
explicitly reused as behavior-identical; broad tests were not repeated for
wording. Independent review completion remains root-owned.
