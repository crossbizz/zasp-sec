# Registered multi-tenant reconciler process acceptance

This continues M7A-21 without changing the original728 scope or promoting its
availability. Production code is unchanged in this batch; the new tests exercise
the actual registered client, database scope discovery and runtime scheduler.

The owned PostgreSQL fixture migrates through55, registers the worker principal,
and prepares three queued links across two tenant scopes. Target and definition
IDs are deliberately shared across scopes. Fixture setup temporarily grants the
private dispatch helper and revokes it before any reconciler process starts.
This controlled setup is not proof that the still-disabled user action is live.

One child discovers an eligible scope, commits a real claim and exits23 without
running cleanup. The parent waits for that process to terminate and observes its
durable live lease. A separate child composes the actual runtime and handles the
two remaining eligible links across both tenants, leaving the live claim alone.
The owner then expires only the abandoned lease timestamp. A third process
rediscovers, reclaims with a changed generation, and releases it to delayed
pending work. Exact other-link snapshots remain unchanged. Three queued test
runs and three outbox records remain; no invocation journal is created.

First owned acceptance30ec60 passes9.07s. Both child runtime invocations pass;
the fail-stop child must exit23, not merely fail or skip. The owned database is
joined and stops normally. Test executables are Linux/arm64:
`/private/tmp/zasp-reconciler-restart-api-r1` and
`/private/tmp/zasp-reconciler-restart-worker-r1`. Docker is offline/read-only,
uses a private tmpfs and the pinned PostgreSQL image. No host database starts.

Final grouped owned acceptance session42643 exits0 (862869/4f0c23): registered
lease23.41s, stopped-queued22.54s (four modes each), multi-tenant restart7.75s.
All three parent tests and their selected child tests pass with no fixture skips;
every owned PostgreSQL process joins normally. Ledgera9201b validates728 rows,
534 production-available,133 component-only,61 external and zero missing.
All compilation/test sessions for this batch are terminal.

Full worker/migration race840ab6 passes41.522s/5.842s with the local Go toolchain
and GOPROXY=off. This run's owned-only tests may skip without fixture variables;
the separate Docker acceptance supplies and asserts those dependencies.
CI now builds a race-instrumented child executable and exports its path within
the existing durable-runtime step before the broad SecurityAgent API test lane.
CI contract RED5d2dc7 caught the absent build/export. Final contract229ab9 passes
250/250. Independent review found no actionable issues in either acceptance or
CI wiring. The complete expanded GitHub Actions lane has not been run here.

## Completed settlement lost-ack process acceptance

The follow-up adds a test-only database wrapper that exits24 after the real
registered settlement query returns successfully, before the client receives
its acknowledgement. The parent independently reads committed rows, starts a
replacement composed runtime and compares exact link, parent, step, effect,
test-run, audit, invocation and outbox snapshots. Each case retains exactly one
test_reconciled audit. Existing outcome and saved-baseline assertions still run.

Control RED438af5 used the unmodified child: settlement completed but the child
exited normally, so the required fail-stop assertion failed. With the test-only
hook, owned session31108 exits0 (167e38), all four supervised/autonomous run and
rerun modes pass in51.58s with no fixture skips. The owned PostgreSQL process
joins normally. Full worker race session34010 exits0 (cba756),42.216s.
Independent review found no Critical or Important findings in this delta.

The first child calls ReconcileOne directly; the replacement uses the composed
runtime. This proves committed work is skipped after process restart, not
persisted-request replay by a restarted client. Artifact production uses the
actual Node runner and controlled storage, not a live target or AWS. The local
offline image fixture used saved Linux Node24.17.0 with its matching musl
libraries; this is not verification of the CI Node22 environment. Initial
loader/initdb harness failures were corrected before the meaningful RED run.
The Node library path is restricted to the Node wrapper, never PostgreSQL.

No production source changed in this acceptance delta. M7A-21 stays
component-only, disabled and unshipped. Counts are unchanged.

Post-batch UI verification002258 exits0: Node22.23.1 production build and
compiled production-import guard pass (7 client chunks,8 server chunks).
Standalone HTTP smoke161664 returns200 for the root and all7 emitted JS/CSS
assets. The owned loopback server on7896 is stopped (7ce2dc). This verifies
build/HTTP asset serving, not hydration or authenticated end-to-end behavior.
Ledgerf8a6a5 validates728 rows at534/133/61 with zero missing. These checks run
against the current dirty feature tree, not an isolated commit/push candidate.

## Overlapping replica acceptance

Two composed runtime children now hold separate committed leases in the same
tenant at the same time. A test-only query wrapper stops each after its real
claim returns and waits on stdin. The parent observes exactly two live leases,
distinct run IDs/generations, version2, and the exact two worker identities
before releasing both barriers. The complete other-tenant link JSONB snapshot
is unchanged across both claims and releases. A third runtime then processes
that tenant. All three links finish delayed pending at version3 with cleared
ownership; exactly three queued runs/outbox rows and zero invocations remain.
Child cleanup closes stdin, cancels the bounded context and joins each process.

Control REDb81acf: the prior child rejects the new concurrent mode and never
reaches the required claim barrier. This is harness fail-closed evidence, not
a reproduced production defect. No production code changed. The grouped owned
run31040 exits0 (51b7a0/2bb7c9): overlapping replicas9.97s, queued restart8.38s,
four-mode settlement restart52.30s; no fixture skips and all databases joined.
Worker racec77241 passes42.122s. Independent review identified two minor coverage
gaps (exact worker IDs/full other-tenant snapshot); both are tightened and
re-reviewed with no new findings. Final focused acceptance77d0b9 passes7.87s
using the recompiled parent, with normal owned database shutdown.

These tests prove overlapping durable ownership and tenant isolation. Claims
are acquired sequentially while both leases remain held; they do not prove
simultaneous transaction contention, sustained throughput, HPA behavior or a
live deployment. Cloud boundaries stay controlled. CI's existing broad
SecurityAgent lane selects the new parent test and builds the matching child;
the expanded hosted lane has not been run here. UI inputs are unchanged from
the build/HTTP smoke above. No new UI run or push clearance is claimed.

## Evidence limits and next acceptance

- Failure occurs after a client claim, not a forced crash inside the production
  worker executable or mid-settlement transaction.
- Expiry is controlled by the owner fixture. This does not measure real60s lease
  timing or prove clock behavior under load.
- Cloud readiness and the artifact storage boundary are controlled. Queued work
  must not read artifacts; this proves no authenticated AWS access.
- Completed-test lost-ack recovery is now covered above. Stale callback/replay
  across actual child processes, simultaneous claim-transaction contention,
  sustained load characterization and live rollout remain open. Overlapping
  replica acceptance above does not replace those proofs.
- No UI source change, push-candidate clearance, commit, push or production
  activation is claimed. Availability counts remain unchanged. The current
  tree's UI build/HTTP smoke evidence is recorded above.
