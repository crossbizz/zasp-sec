# Connected automatic discovery proof

Work in progress. This record does not claim completion or live-provider readiness.

Scope: existing public schedule API, real 300-second cadence, scheduler process
restart after committed admission and before advance, production pinned Kubernetes
HTTP client and parser, durable typed inventory, mounted browser reload, retained
last-good state, foreign tenant refusal, public disable/delete and clean joins.

No product changes are planned. Initial identity and authorized connector fixtures
are seeded; schedules, syncs, jobs, snapshots and inventory are not seeded or
backdated. Queue delivery, credential material and artifact storage are controlled
boundaries. Kubernetes TLS and DNS are owned by the collection test process.

The scheduler admission checkpoint wraps the real database call after its result
returns. On cancellation it does not synthesize a successful result or completion.
The second lifetime is the ordinary worker binary with a new worker identity.

## Initial RED / GREEN

- Mode selection RED: `node --test --test-name-pattern='automatic discovery proof' scripts/production-combined-e2e.test.mjs` failed with `false !== true` before the mode existed.
- Mode selection GREEN: pinned Node 22.23.1, automatic and export isolation selectors, 2 passed.
- Native DNS bound test: `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./agentsec-worker -run '^TestAutomaticDiscoveryDNS' -count=1`, passed.

Connected runtime and independent review are pending. Original M3 ledger credit
and external gates remain unchanged.

## Fixture transport checkpoints

Three attempts stopped before any scheduled-admission assertion. `connected-1.log`
records native macOS loopback443 permission denial. The controlled collection
process moved into the existing owned Linux PostgreSQL container, still using the
registered discovery login. `connected-2.log` records Docker cp refusing its
read-only root; a bounded tar extraction into the existing writable /tmp replaced
that copy. `connected-3.log` records executable permission denial, exit126.

Root inspected the same image/current owned container and found /tmp mounted
rw,nosuid,nodev without noexec. The approved ruling is to keep the helper in /tmp,
explicitly chmod0755, test executable access and record stat mode/owner. No change
to owned-browser-postgres or production endpoint constraints. If this hypothesis
is wrong, the cost is one failed fixture rerun before seeking a wider container
interface. All three failed owned roots were cleaned up; retained logs remain.

Focused native race gate for scheduler/DNS tests passed in2.168s. The first full
Node helper run found VM test contexts missing the two new mode/evidence globals;
their false/null defaults and the bounded Docker command allowlist were updated.

The fourth attempt failed `test -x` after successful chmod. A fresh instance of
the exact owned-PG helper settled the difference: `/proc/mounts` contained
`tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime`. Copying `/bin/true` to /tmp,
chmod0755 and stat gave `755 999 999`; executable access returned1 and exec126.
The diagnostic container was removed through the helper's joined cleanup.

Root then approved a narrow optional readonly collector-binary mount in
`owned-browser-postgres.mjs` and its tests. Host input must be an existing regular
mode0755 file; directories, symlinks, traversal, injected options and other modes
are refused. The container destination is fixed. Default arguments are unchanged,
root stays read-only and /tmp stays noexec. Test-first missing-mount RED became
GREEN across all16 owned-PG lifecycle cases.

Attempt5 reached the worker but our DNS responder rejected Go's empty EDNS OPT
record. A native real Go resolver test reproduced the timeout and retained the
actual question. Accepting only one bounded empty OPT record fixed it; scheduler,
DNS and discovery runtime race tests passed (2.190s final grouped worker run).

## Confirmed production defect

Attempt6 reached the pinned Kubernetes TLS handshake and failed with
`remote error: tls: bad certificate`, zero inventory HTTP calls and a correctly
retryable durable job. In `pinnedCollectionCertPool`, `x509.ParseCertificate`
retained slices into `block.Bytes`; `clear(block.Bytes)` erased them before
CertPool used the certificate. Go's parser assigns Raw, RawIssuer, RawSubject and
RawSubjectPublicKeyInfo directly from its DER input.

Root approved that product file and its focused test. The real-TLS regression
first proved a working independent CA pool on the same transport, then failed
the production pinned path. See `pinned-tls-red.log`. The fix gives x509 its own
DER copy, clears the decoder buffer and cloned PEM temporary, and clears DER on
parse failure. Hostname, CA, CIDR, pinned IP, TLS version and redirect checks stay
unchanged. The full Kubernetes package race gate passed in1.741s, including
foreign-hostname and foreign-CA negative controls (`pinned-tls-green.log`).

Attempt7 traversed all11 Kubernetes inventory HTTP phases but public Agents was
empty. Its helper acknowledgement alone did not prove a successful snapshot.
Attempt8 adds public sync-status assertions and retained registered-query trace
to locate that failure before the real cadence starts. No additional product
change has been made.

Current helper gate:102 Node tests,100 passed,2 existing opt-in skips. ESLint
passed for the four changed scripts. Connected acceptance remains pending.

## Snapshot rejection isolated before another connected run

Attempt7's exact assertion was actual0, expected1 AFTER the baseline collection;
its initial empty inventory assertion passed. Attempt8's durable public sync
finished `failed`, `last_error_code=malformed`, counts0, snapshot null. The
registered trace contained claim, input and failed finish, with no snapshot
apply. This was not a seed-count failure. Existing `seedPostgres` supplies
authorized connectors, identity, unrelated risk/workflow fixtures and inventory
backfill/cutover, but it does not insert this packet's agent or schedule.

The native `TestAutomaticDiscoveryAgentPageMeetsSnapshotGrammar` takes the exact
controlled Deployment response through the production Kubernetes HTTP parser
and then `collection.NewSnapshotCandidate`. RED: its posture attributes were
valid JSON but their nested keys were not canonical. Changing only attribute
key order made the reference candidate pass. See `agent-snapshot-red.log`.
Root approved the narrow emitter change. The private posture struct now uses
lexical JSON-key order, with every field and value retained. A second focused
RED found the same issue in optional Red Team binding attributes; its private
struct received the same ordering-only correction. The strict collection
validator is unchanged. `annotated-agent-snapshot-red.log` records that RED.

The worker fixture now records page number/counts/hash, artifact size/hash/version,
parser outcome, typed snapshot digest/counts and registered apply/finish calls.
It rejects a complete provider response that merely receives a queue ack without
a complete parsed snapshot and actual registered apply. Provider diagnostics are
saved before process-status assertions, including failed attempts.

The browser inventory check now isolates the collected target by name and ID.
It permits unchanged authorized prior rows but rejects missing/duplicate targets,
a target present before manual baseline collection, unrelated inventory changes
and replacement identity after the scheduled collection. Focused RED/GREEN logs
are `baseline-inventory-red.log` and `baseline-inventory-green.log`. The next run
will retain its public pre-collection inventory response.

Fresh verification: Kubernetes package race1.593s and collection contract
race2.259s (`agent-snapshot-green.log`); focused worker race2.371s. Node group:
103 tests,101 pass,2 existing opt-in skips (`native-node.log`). ESLint exited0 for
the four changed scripts. No connected attempt9 has started. Source is frozen
pending the root-owned webhook regression so the two proofs do not race hashes.

Frozen source SHA256:

| File | SHA256 |
|---|---|
| scripts/production-combined-e2e.mjs | dbd8bca43a71a1b12294a883d67b92ab999e808a8602de75fc1ec5e54e072da3 |
| scripts/production-combined-e2e.test.mjs | 54c8ee17592c7581833015f7769e833d5e6f9d5f80c8cf21f8a6b52a295f98ae |
| scripts/owned-browser-postgres.mjs | 2eb952ef1aa95ee717ab5ae64733f13646fe613680b6f11b9a9f681ea0959016 |
| scripts/owned-browser-postgres.test.mjs | 244ea31b7037200da10e03fac0d11f95e4dfbfdf10f3323b3f5d47b7a60e913a |
| services/platform/agentsec-worker/automatic_discovery_process_test.go | 92c34adacc7a615a01a1b69509bf3be340ce3918599394b9384a1662131d61e7 |
| services/platform/connectors/kubernetesdiscovery/collection_api.go | 3f22ee370ce3e28052f903c2785fd17095935136f837d6dd3b766e2fc9be35b5 |
| services/platform/connectors/kubernetesdiscovery/pinned_collection_api.go | 353e6c8c8b6eae785b41931d94310d0e802a7cb7873bf49002732a32752a6ec5 |
| services/platform/connectors/kubernetesdiscovery/pinned_collection_api_test.go | 9077e77eb303df352cc4c1422151a23fd8accaf2ea5432c4e6dedbdb01ff4b61 |

## Canonical boundary, superseding field ordering

Attempt9 still failed before cadence. Its retained boundary trace proved11
provider pages and12 persisted artifacts, then a malformed snapshot; cleanup
joined with zero errors. Evidence root:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-automatic-discovery-evidence-xHywgl`.
The complete native collection regression reproduced it without PostgreSQL or a
browser and identified namespace `stable_fields` in cluster,namespace,name order.

Root ruled that declaration-order encoding was the common defect. All individual
struct-order edits above were reverted. The final product diff adds one private
canonical object encoder at `marshalKubernetesEntity`, applied to stable fields
and attributes. It recursively sorts object keys, keeps array ordering, and uses
`json.Number` so large integers retain their exact value. There was no reusable
encoder in the connector packages, only private canonical validators. The
collection validator remains unchanged.

`canonical-boundary-red.log` proves full collection rejection and a noncanonical
nested value. `canonical-boundary-focused-green.log` proves the complete real
collector produced `collection.CompleteResult` from11 HTTP phases and12 artifacts,
with4 typed entities,4 relationships and4 evidence records. The value-preservation
case checks nested objects/arrays, null, booleans, strings,1.25 and integer
9007199254740993. All emitted entities also pass the strict snapshot constructor.
Full package races passed: Kubernetes1.767s and collection2.243s
(`canonical-boundary-green.log`); the verbose focused race passed1.300s.

Final changed hashes replacing the two corresponding rows above:

| File | SHA256 |
|---|---|
| services/platform/connectors/kubernetesdiscovery/collection_api.go | d2a28f46abff44070adcc1d0cb35058011ce2bf771d8ced1b53e5c9f5df48091 |
| services/platform/connectors/kubernetesdiscovery/pinned_collection_api_test.go | a839c554a3ed615362a86d5b23fdc8cbfd08de317bc04194ef99d52583d5b759 |

Connected attempt10 is running on these frozen bytes. Acceptance is still pending.

Attempt10 passed baseline collection, public schedule/replay/deletion, foreign
isolation and mounted inventory. It stopped120.14s into the first scheduler
lifetime, before the due time. Both the isolated bridge and its relay deliberately
close connections after120s; the fixture incorrectly made one transient RunOnce
failure fatal. The product polling loop retries and updates readiness. Root
approved using that exact production polling loop in the first scheduler fixture.
No relay timeout or product scheduler behavior changed. Resources joined with
zero cleanup errors; the failed worker exit remains a failed process assertion
in the manifest, not an accepted lifetime.

`scheduler-polling-red.log` reproduced one mapped transient failure stopping after
one attempt. `scheduler-polling-green.log` proves recovery on the next production
poll and grouped discovery/scheduler races passed2.694s. This focused test injects
the mapped error; actual120s relay rollover is still part of the connected gate.
New worker fixture SHA256:
`a4f8bbe9c2b6b4f90a5b95c291047e8a756e24f08c761376d60c02ff5965b323`.
Attempt11 now runs with that harness correction and the same product bytes.

## Attempt11 stopped; occurrence and owned-close corrections

Attempt11 is not accepted. Its first scheduler crossed the real due time:
300.070s from public schedule creation to committed scheduled admission. The
first scheduler joined, and its replacement polled successfully for about5.2s.
All four retained API/collector/scheduler lifetimes ended with status0 and no
signal. The manifest stopped at restart, before the durable-count assertion
result was retained. Cleanup then rejected an owned relay's SIGPIPE and hid the
original assertion diagnostic. Duplicate occurrence admission was a source-based
explanation, not a retained runtime count from this attempt.

Evidence remains at
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-automatic-discovery-evidence-O14kyb`.
The temporary root remains at
`/private/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-production-e2e-hpivq7`.
The owned container and observed process IDs were absent after cleanup; the
cleanup receipt still correctly says `joined=false`, one error, root retained.
The launcher had no timeout wrapper, its session exited1, and the harness's
SIGTERM handler would exit143. These observations do not support external
launcher SIGTERM as the cause. No evidence roots were deleted.

Root approved two narrow TDD corrections and one deliberately failing SQL
regression. No migration, registry, webhook or deployment file changed here.

The Go regression proved that claim version2 versus3 changed all three durable
IDs and the idempotency key for the same schedule and due instant. The product
change removes mutable claim version from the occurrence seed; its validity
check remains. The test also requires distinct identities for the next due
instant and refusal of version0. RED: `scheduler-occurrence-red.log`. Focused
race GREEN: `scheduler-occurrence-green-2.log`,2.810s. The earlier `green.log`
contains only a wrong-working-directory command failure, not a test result.

Bridge RED: an actual local socket closes, the controlled external relay emits
SIGPIPE, and cleanup fails. Spontaneous SIGPIPE and nonzero exits already failed
as required. The correction accepts SIGPIPE only when this bridge had already
set `closing`, before the child-close callback. The120s deadline is unchanged.
An added negative control keeps nonzero exit7 after owned peer-close rejected.
`bridge-sigpipe-red-2.log` is the behavioral RED; the first log records a test
setup race, which was corrected before the product edit. The test controls only
the external subprocess event boundary and exercises the real bridge/socket.

The registered PostgreSQL regression is intentionally RED. It uses the existing
execution13 migration/registration fixture and production schedule-admission SQL
with a due time of now. It seeds no job, receipt or lease. This is a SQL defect
reproduction, not the public300s cadence proof. Two separate connections use the
registered scheduler login and pass the real repository readiness constructor.
The first admission commits;5.053854788s of real lease expiry later, claim version
changes2→3 with the same due time. The same request keeps scoped sync/job/outbox/
receipt counts at1, but the intended replay-success assertion fails with
`SQLSTATE=23505 message=schedule run conflict`. PostgreSQL joined normally.
See `scheduler-occurrence-postgres-container-red.log` (test5.81s, exit1).
The first native attempt failed during initdb because macOS shared-memory IDs
were exhausted; `scheduler-occurrence-postgres-red.log` retains that setup error.
The behavioral RED used the pinned PostgreSQL image in an owned network-none,
read-only container, with only the test binary mounted read-only. Its exact
container name was `zasp-scheduler-occurrence-red-320vs5`; the post-run lookup
confirmed absence. The test binary remains in the owned temporary directory.

Fresh grouped verification: `occurrence-bridge-grouped-node.log` records115 tests,
113 passes and2 existing opt-in skips, zero failures. The affected worker race
passed2.940s and Kubernetes race2.492s (`occurrence-bridge-grouped-race.log`). Its
collection selector matched no tests, so a separate full collection race ran
and passed1.791s (`occurrence-collection-race.log`). The two browser process
fixtures remain opt-in skips in the native worker run. ESLint passed for both
bridge files. No UI source changed.

The SQL fix is still blocked on the next additive release slot after webhook59.
Root's target is atomic rebinding of only an incomplete exact occurrence receipt
to its currently validated live claimant, preserving every scope/identity/digest/
due-time match and stale-lease completion fencing. Migration13 and the shared
registry remain untouched. Attempt12 has not started. The original failure
diagnostic must also be retained before cleanup in the next connected run.

Frozen correction SHA256:

| File | SHA256 |
|---|---|
| services/platform/agentsec-worker/scheduler_runtime.go | 90484a03728f2693352d42449f1365ce943050e62fa414a781e5f4f389324eb1 |
| services/platform/agentsec-worker/scheduler_runtime_test.go | a489bae674ee92c1665acc8084ee60c8c44258f0bf6bfa575a2a888904b7f4f1 |
| scripts/isolated-postgres-bridge.mjs | 888f290b39f90540c59ca9a15b7345bc33a358c44eccf39d50a314d1d61d3f71 |
| scripts/isolated-postgres-bridge.test.mjs | f0b6d56bad8c2325acf863c32ca14c028ac009561ce3ce16deee054313593dcc |
| services/platform/apiserver/automatic_discovery_scheduler_postgres_test.go | ddd9674660d661f6288d41c417ea0498c18a7b86cdc7f275ec1971a21b61b57c |
| Linux arm64 apiserver.test | 56ec96510132363bbc25054024063c9337bb9d3f8e326a5d8185d77bad67ce68 |

The binary path is `/tmp/zasp-scheduler-occurrence-red.320vS5/apiserver.test`.
Evidence hashes: Go RED `766fec0984f1ba3fd5e8a06f44ac51c23f2f2ba4c9dc7a7ea8fdfee2fbb47571`;
Go focused GREEN `1cec7dc59fa26b99f45e7d1735acbf4073a33d6f9859339299f32ce622781276`;
bridge RED `05cc8f43fbe5c5464d9f4c9be6f0f0ff3366c9b0954fe704f2baaf2e02f9a468`;
grouped Node `79473b0315369fc7d913b5b948553df4cfbddfc750adf67dd32b50a087c5d82d`;
grouped race `b91364c4066aac0d772d5c3730d6efef54998a6e01df1f5fe6c1b61a05f8472c`;
full collection race `f4dbb026feec8f2310fc07e0bb626d71fd9e789cc4cd9737b5a713939cab3175`;
registered PostgreSQL RED `2b3e5708feacf5637b02b8c67393024c68cb31c691fc84b6a619fbb3f7f6ed7e`.

Commands ran from `services/platform` for Go, repository root for Node:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./agentsec-worker -run 'Test(ScheduledOccurrence|Scheduler|NextScheduled|AutomaticDiscoverySchedulerRecovers)' -count=1 -v
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./agentsec-worker ./connectors/kubernetesdiscovery ./connectors/collection -run 'Test(AutomaticDiscovery|ScheduledOccurrence|Scheduler|NextScheduled|Discovery|Kubernetes|CanonicalKubernetes)' -count=1 -v
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./connectors/collection -count=1
node --test scripts/production-combined-e2e.test.mjs scripts/owned-browser-postgres.test.mjs scripts/isolated-postgres-bridge.test.mjs scripts/owned-command.test.mjs scripts/bounded-signal-cleanup.test.mjs
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/zasp-scheduler-occurrence-red.320vS5/apiserver.test ./apiserver
docker run --rm --pull=never --name zasp-scheduler-occurrence-red-320vs5 --label zasp.test.owner=scheduler-occurrence-red-320vs5 --network none --read-only --user postgres --tmpfs /tmp:rw,nosuid,nodev,mode=1777 --mount type=bind,src=/tmp/zasp-scheduler-occurrence-red.320vS5/apiserver.test,dst=/apiserver.test,readonly --entrypoint /apiserver.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestAutomaticDiscoveryScheduledOccurrenceRebindPostgres$' -test.count=1 -test.v -test.timeout=60s
```

## Bridge review correction: stop must retain numeric failures

Independent review found that the preexisting global `!stopped` exemption still
hid numeric failures during `stop()`. The new behavioral test reproduced exit7
and unissued SIGTERM/SIGKILL being accepted after stop destroyed owned stdout.
All three failed with `Missing expected rejection` before the correction.
`bridge-stop-exit-red.log` SHA256:
`5cef5fac20e4509bb22e842f46bc7649da79a9b88f38f81a9dbe6190cc55f980`.

The correction removes that exemption. Per-child flags record successful
`child.kill` calls; only null-code SIGPIPE after owned close or matching
bridge-issued TERM/KILL are accepted. Numeric failures are rejected even during
stop. The250ms/1250ms escalation and120s deadline are unchanged. Existing
spontaneous SIGPIPE/nonzero and owned-peer-close exit7 controls still reject.
Two real Node subprocesses prove TERM and TERM-resistant KILL cleanup, including
process absence after join. No scheduler or SQL files changed in this round.

Final focused group: `node --test scripts/isolated-postgres-bridge.test.mjs
scripts/owned-browser-postgres.test.mjs`,30/30 passed, zero skips,1.654s.
`bridge-stop-exit-final-green.log` SHA256:
`39a35495ed34b4a87423696b764cabc96c90899ed3c8a292ba68dd573a0c2e75`.
Both bridge files passed ESLint. Source hashes supersede the earlier rows:
script `c6674ea4de730d4b047c582bcf60930650ccf90b90955cff58b210bb20a81f96`;
test `1a3bd9ecd0ee9b706e6749d02a46698397df9e2481bd17557d579d2c63a68083`.

Exact executable-code diff against the previously reviewed script:

```diff
     let resolve, closed = false, closing = false, terminate, kill, stderr = "";
+    let terminateSent = false, killSent = false;
-      terminate = setTimeout(() => { if (!closed) child.kill("SIGTERM"); }, 250);
-      kill = setTimeout(() => { if (!closed) child.kill("SIGKILL"); }, 1250);
+      terminate = setTimeout(() => { if (!closed) terminateSent = child.kill("SIGTERM"); }, 250);
+      kill = setTimeout(() => { if (!closed) killSent = child.kill("SIGKILL"); }, 1250);
-      const ownedPipeClose = closing && signal === "SIGPIPE";
+      const ownedSignalClose = code === null && closing && (signal === "SIGPIPE" || signal === "SIGTERM" && terminateSent || signal === "SIGKILL" && killSent);
-      if (code !== 0 && !stopped && !ownedPipeClose) errors.push(new Error(`owned relay exited ${code}/${signal}: ${stderr}`));
+      if (code !== 0 && !ownedSignalClose) errors.push(new Error(`owned relay exited ${code}/${signal}: ${stderr}`));
```

## Release60 schedule-replay design and execution packet

Root wrote the additive correction design and five-task execution plan while
webhook release59 remains under its assigned owner. This does not claim the SQL
fix exists and does not authorize overlapping migration edits. The packet locks
the occurrence key to tenant scope, schedule and exact due time; requires an
atomic immutable-match rebind of only an incomplete receipt; preserves stale-
token completion refusal; adds release identity, safe rollback and connected
attempt12 gates; and keeps the actual300-second public cadence proof separate
from the focused due-now SQL diagnostic.

Design: `docs/internal/2026-09-19-automatic-discovery-schedule-replay-design.md`
SHA256 `faefa7ac87b7693d93d448c5ee4559c52f618d917205d53ae1d53d78ff3f08c0`.
Plan: `docs/internal/2026-09-19-automatic-discovery-schedule-replay-plan.md`
SHA256 `32601c8b47a95397120105aed8c26ca7f4b907a4cc55393721ee0ac7fab994a8`.
Task1 cannot begin until release59 is frozen and independently accepted. Slot60
must be rechecked at that handoff. No release60 source, registry or CLI edit has
started.

## Release60 packet review correction

The first independent plan review rejected the packet before implementation. It
found one Critical and seven Important gaps: the release59/readiness ancestry was
under-specified; scheduled replay did not compare the returned outbox ID; the
connected harness remained pinned to58; mixed old/new scheduler liveness was
claimed without a supported mapping; down checked evidence before acquiring its
table lock; completion replay had no durable time boundary; negative tests could
miss provisional writes; and same-token replay incorrectly incremented rebind
generation. One ownership/command detail was Minor.

Ruling: use grouped verification at coherent feature boundaries, with focused
RED/GREEN during edits, one affected SQL/Go/Node group per task, and the full
UI/build/release gate once at publication. Every original microtask retains its
own evidence mapping, and tenant/security-negative cases stay in the grouped
matrix. If this ruling is wrong, rerun the affected group; do not weaken the
acceptance criteria.

The corrected packet now requires the complete compatibility inventory, exact
returned/proposed sync/job/outbox equality, provisional-write rollback counts,
generation changes only on authority transfer, table-lock-first down, durable
occurrence completion replay, maintenance-fenced old-scheduler rollout, explicit
old-first fail-closed proof and exact automatic-mode60 harness pins/source hashes.
Task1 still cannot start before the frozen, independently accepted release59
handoff.

The first re-review retained two gaps. The packet no longer promises that an old
version-derived scheduler can repair an expired legacy receipt; such a violation
stays blocked for a separately reviewed recovery. Task1 now carries both
same-key normalized-ID mismatch controls and different-key provisional-write
rollback controls.

Corrected design SHA256:
`5dd5fec8e32977a9558186bb73f959b2c35c4eeb418313a8a3184ab3350bc2a3`.
Corrected plan SHA256:
`238590c11a6d6013e0c9d717a37ba7efdd326baacc7d14a985e5ec4267502de5`.
The earlier packet hashes are superseded, not implementation evidence.

The second re-review retained installation-locking, state-value and ownership
details. The packet now drains live owners before stopping them, distinguishes
pre-install orphan from post60 old-first refusal, holds admission-compatible
locks through install preflight, snapshots freshness values/versions, requires
scheduled-only Go ID equality, derives `GOARCH` from the pinned image with
`GOOS=linux`, and assigns SQL versus Go completion ownership explicitly.

The third review cleared every prior finding but caught one new overclaim: locks
cannot identify an obsolete first writer for an empty occurrence. The final
packet says exactly what the database can enforce. Maintenance fencing remains
mandatory; an unsupported post-install old first write may persist a legacy
receipt, the next release60 replay must refuse without mutation or duplicates,
and progress stays blocked for separately reviewed recovery. No canonical-writer
fence is claimed.

The scoped GPT-6 Astra re-review approved the corrected architecture with no
remaining load-bearing finding. Its final Minor wording cleanup now says the
subsequent release60 replay fails closed; it does not claim the unsupported old
first write itself is rejected. Release60 implementation remains gated on the
frozen, independently accepted release59 handoff.

Release59 handoff is now accepted after its own fix round and clean scoped
re-review. Production migration/CLI sources contain no release60 registration;
the only `up-to-60` matches are release59 compatibility tests that deliberately
name the future boundary. The plan's Task1 slot probe now excludes those tests and
records Task2 ownership of moving them after60 exists. Frozen predecessor hashes:
release59 Go `5d309aed2177aa0f496d40a7ef0c57f4acee725393d045380309780f7ff32c36`,
test `3a5823d7ef124106f1ddea8f225deb070cc8adce409f2686a741eab15d204bb3`,
up SQL `213166dcb6ff9cd77e311dcc1e6c045d6d8606de04410f8d2e9a85e05773307d`,
down SQL `e9e9a809b6a70bbfd0c500874ca473fff4c2590f7f1987a5557a1871d01e3c49`,
registry `143e51e479e4b3cd907391362139a515a692a7c0e96c0ae4a9cbe72f22b2c544`,
CLI `c3c3cdc10c2ed7783f735e6cfe16f3d597cfad62565f21449e8411147869ff98`.
Task2's explicit allowlist includes the production bootstrap wrapper/tests and
the four release59 compatibility-test files whose future boundary moves from60
only after release60 registration. Task1 leaves all six unchanged.

## Release60 Task1 accepted RED

The registered release60 RED is frozen and independently accepted. The exact
Task1 selector ran against release59 in four isolated PostgreSQL fixtures for
39.36 seconds. It retained eight intended failing leaves: three scheduled
decoder ID mismatches incorrectly accepted, three exact reclaims rejected with
SQLSTATE23505 instead of rebinding, and two different-key provisional-write
cases that persisted state instead of rolling back. Forty-one existing controls
passed, zero tests skipped and all four databases joined cleanly. Production
migration/CLI sources still contain no release60 registration.

Independent GPT-6 Astra review reconstructed the 555-line test and179-line log
from the review package and reported no Critical, Important or Minor finding.
Task1 cannot prove a successful rebind on release59. Generation assertions,
post-rebind old-token completion fencing and durable completion remain mandatory
for Tasks2/3. Historical duplicate-install rejection remains mandatory in Task2.
The public300-second cadence and connected restart proof remain mandatory in
Task4 attempt12. No production behavior or availability classification changes
at this checkpoint.

Task1 report SHA256:
`787a191ccb164ff352901a630e4b88d16dea18190d9db56a7057f3bfafaed73c`.
Review package SHA256:
`c32540935f67ba29be79ea888d3d4c9d99066883e592ae9b72056f5b293b7a3e`.
Test SHA256:
`6def3b603e33167ea08a8f509916a259ab4a5bafe032b78ea646fe339e15ebdc`.
RED log SHA256:
`d5c75fcfb297041c66149866865f3bdabaf09cb3cfda0c63f539f3e8aa4628aa`.

## Release60 Task2 accepted migration authority

The additive release60 migration and production registry/CLI boundary are now
independently accepted at controlled component scope. Initial review found two
Important defects: readiness omitted outgoing membership drift on the scheduler
and projection authority roles, and lost-response retries for `released` and
`disabled` schedule completion failed after the first call cleared the lease.
Both were reproduced against PostgreSQL, fixed with direct regressions and
accepted by scoped re-review with no new Critical, Important or Minor finding.

Final grouped evidence contains312/312 migration/CLI run/pass records and50/50
registered PostgreSQL run/pass records, zero failures/skips and ten normal
database joins. It covers exact59→60→59→60 cycling, historical duplicate and
incomplete preflight, all19 saved definitions, compiled consumer pairs, tenant
and grant negatives, occurrence generations, stale-token refusal, advanced and
non-advanced completion replay, down refusal and down/rebind serialization.

Final release60 checksum:
`37956023196757f30a7ecb415e9d7d7e6f76cfa32a3ffa2d45445c172f6313ab`.
Final release60 fingerprint:
`1ed52fb5f9a83384e1d3fecbc3bc116d3981a36479e9b3b1f6ec04b5cd4f3b36`.
Final report SHA256:
`f5c84f07238deabdaa5b9e092b1007d25fd368f46f9a846746cf98f03d756b6f`.
Fix delta SHA256:
`b31b9ce1d24dcecbb87fc672b2b1e971ff43a4efb3a5f39bc1bd1ab6e39770bd`.
Migration log SHA256:
`fdc76101d76abacde0a72e61e35faf49fcc0f22abd1e6ddb46a00addb15b7107`.
Cycle log SHA256:
`ff35a6ae2129f4d8237d1fcabd35042b4626688aa04dd5ab35bc6264dfc5c2e0`.

This does not prove repository/runtime integration, the public300-second cadence,
connected restart, live providers, deployment or publication. Task3 consumes
the exact final pair above; Tasks4/5 retain those remaining gates.

## Release60 Task3 accepted scheduler runtime

Scheduler repository/runtime integration is independently accepted with no
Critical, Important or Minor finding. The scheduler now requires exact release60
readiness with no release13 fallback, compares every scheduled returned/proposed
sync, job and outbox ID, and checks readiness before each claim batch. Discovery
worker, projection, outbox and manual-sync predecessor behavior remains intact.

Final grouped evidence is apiserver51/51, worker35/35, migrations289/289,
registered replay/predecessor58/58 and exact release-cycle34/34, with zero
failures/skips and eight normal PostgreSQL joins. The database matrix covers real
lease expiry, generations1/2, stable retry, stale-token completion denial,
durable completion replay after a later admission, completed same-due refusal,
tenant rollback, principal/RLS negatives and both legacy maintenance-fence cases.

Task3 report SHA256:
`ea0ceff318f4fc8af9d72b1aba3d93052eb4b21a6b72fb3edb44ab0c6279dcfd`.
Review package SHA256:
`d67cae60c9865d66a406b22af901e35d619bb456c07081075347289dab5e8ad9`.
Replay log SHA256:
`1cde148d7d071b486e9047d5c145babbdf3ef7b6bef88f92fcf6efa63a20aae0`.

The public300-second cadence, full connected restart/browser path, live providers,
deployment and publication are still unverified. Task4 owns exactly one connected
attempt12 and must inspect that same run rather than restarting it for status.

## Release60 Task4 connected attempt12

The automatic-mode harness now migrates to60, verifies its exact checksum,
metadata and live fingerprint plus readiness before API/scheduler startup, and
starts the API with expected schema60. Export mode stays on58. Direct harness
RED had22 failing records; the same focused group passed22/22. Grouped Node
verification passed141 of143 tests with zero failures and the two existing
opt-in skips. ESLint and scoped diff checks passed. The first grouped run caught
an existing inventory test's fixed extraction boundary including the newly added
hash helper; its boundary now ends at the next function and the full group was
rerun. No product, migration, runtime or UI source changed in Task4.

Attempt12 was launched once with Node22 and offline Go. Exec session54738 owns
Node PID70233, launcher PID70230. Owned PostgreSQL container:
`05b891fcbc86df2f044a4cf08c30bdad86753680255eb8a1ddb1696984876324`,
name `zasp-browser-postgres-fdf1fd3ab63528fed166b205541481c5`.
Its inspected image is the pinned arm64 PostgreSQL image; network mode is none
and root is read-only. Evidence directory:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-automatic-discovery-evidence-VsAJ33`.
Runtime root:
`/private/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-production-e2e-F02IjW`.

The same run reached baseline collection, public schedule create/replay/delete,
foreign denial and mounted inventory, then began waiting for the real due time
`2026-09-20T05:53:10.238646Z`. Acceptance and cleanup are not yet claimed.
The harness freezes all Go/SQL sources, harness scripts, built UI files and eight
compiled binaries, compares their final hashes, records stage errors separately
from join errors, and requires a unique rebound occurrence with durable
completion. The two real cadence windows and all existing bounds are unchanged.

Attempt12 stopped with exit1 at the new receipt-evidence query. Its manifest is
`completed:false`, stage `restart`. The real cadence passed300.325 seconds;
the first scheduler joined with status0/null signal, the replacement advanced
during its5.354-second lifetime, and the sync/job/outbox count assertions passed.
Receipt acceptance, changed collection, retention and withdrawal are not proven
by this run. All four recorded process lifetimes joined0/null. Cleanup records
`joined:true`, zero errors and runtime-root removal; exact container inspection
confirms absence. All1882 source/binary hashes stayed identical during that run.

The failure was introduced in Task4's evidence query, not the public API. The
public IntegrationSchedule response deliberately omits internal schedule `id`;
the query used `saved.body.id`, rendering `schedule_id='undefined'`. Its initial
test incorrectly invented that field. The corrected real-public-shape test
reproduced the exact0-row assertion before the query fix, with one failing leaf
and parent plus10 passing records. The query now joins the scoped schedule using
public integration identity and the exact original due timestamp. It compares
the internal receipt/completion IDs to each other and does not add an ID to the
public contract. Focused24/24 and grouped143/145 (zero failures, two existing
opt-in skips) passed, along with ESLint and scoped diff checks.

The parent authorized one new numbered attempt13 in the updated Task4 brief,
SHA256 `ef357b93e38f3722b9ec949bfc0564011316b16761557dfb722b42abe904fca2`.
Attempt12 and its manifest/log remain unchanged. Attempt13 is running once in
exec session67770, Node PID72461, launcher PID72458. Its owned PostgreSQL ID is
`9b36ec5a28b494de06ca83b63dba06b2c2f798cfecdecdf96e77ccaf76449a73`, name
`zasp-browser-postgres-df3305bce517365170534e504d5356ad`; evidence root is
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-automatic-discovery-evidence-dSI31M`.
It reached the real due-time wait for `2026-09-20T06:03:41.620497Z`.
New frozen harness SHA256:
`ff7c0704df5153c3d2720b821b6f805617a825c00b1794516bf9ec6fb05e0f2a`;
test SHA256 `5fa75d8f663885af9354aa62cde808d374fb3ba3c289d1907b007d05bc7ab9e1`.
No source was edited after attempt13 launch. Its acceptance remains pending.

## Release60 Task4 attempt13 disposition and authorized attempt14

Attempt13 has now exited0 and cleaned up. Its raw manifest is `completed:true`,
with1882 equal input hashes, no stage/join errors and seven lifetimes joined0/null.
Cleanup is joined, errorCount0, runtime root removed and exact container absent.
It proved300.342 seconds of real cadence, unique generation1 durable scheduler
replay, one sync/job/outbox, changed Kubernetes collection, mounted inventory
reload and failed/partial last-good retention. It is not accepted for withdrawal:
the old check observed06:08:42.856Z, past the pre-disable due but4.229 seconds
before the actual stored disabled due06:08:47.084951Z. The immutable log/manifest
are retained as otherwise-passing, withdrawal-incomplete evidence. Raw success
flags do not override this qualification.

The public disabled response has `next_run_at:null`. The corrected Task4 brief,
SHA256 `50f71993842a493a28e8491ae95042896e70feaacc21b13eb4197d37bb45850e`,
authorizes exactly one attempt14 after asserting that contract and reading the
scoped stored due through public integration identity plus returned disable
version/state. Direct RED reproduced the incorrect old deadline (five passing,
two failing records including parent). Focused32/32 and grouped150/152 passed,
zero failures, with two existing opt-in grouped skips. ESLint/diff checks passed.
The +10-second deadline and +1-second observation margin were not widened.

Attempt14 was launched once in exec session68680, Node75647, launcher75644.
Container ID `f19cb765016f78d6a91e2d4f2a9a376832bbd245e40ac39742612089f3500fdf`,
name `zasp-browser-postgres-38035116fe036f1a6a79bdd4a4ceb3ad`.
Evidence root:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-automatic-discovery-evidence-02halw`.
Runtime root:
`/private/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-production-e2e-RhNsrO`.
Frozen harness SHA256 `c64c19092e45cdb595aecf0e7ac105bd8392783012df4800119a590c9e4a34ac`;
test SHA256 `c11ffcdb89ea329af59588caa3fcccdba78f23d44b46ac6c7d40d70197f968b7`.
No source edits or restarted attempts are permitted during this run. Connected
acceptance, cleanup and independent review remain pending. No live-provider,
deployment or production-availability promotion is claimed.

Attempt14 completed once with exit0, without source edits or restart. Its manifest
has `completed:true`, `failure:null`, `inputsUnchanged:true` and no join errors.
All1882 input hashes match before/after; a fresh post-run verifier matched1874
current source files and all eight independently observed binaries. Exact
release60 readiness was checked before API/scheduler startup. Public cadence
was300.268 seconds. The first scheduler joined normally before its replacement;
one generation1 occurrence completed durably5.135 seconds after admission under
the real5-second lease, with exactly one sync/job/outbox. Changed Kubernetes
collection and mounted browser reload passed, as did failed/partial last-good
retention. The disabled version5 stored due06:27:21.869063Z was crossed, with the
scheduled count still1 at06:27:23.247Z,1.378 seconds later. No duplicate work was
admitted for the disabled/deleted schedules.

All seven API/scheduler/collector lifetimes joined0/null. Cleanup is joined with
zero errors; exact container, temporary runtime root and nineteen observed
process IDs are absent. Attempt14 log SHA256:
`0c11ab551b98edc76e6879535a34fc2918548fc6ffa84e2caf0cac283bcc7af2`.
Final manifest SHA256:
`87acabc4e395b7fe4aa80dce51f0c1d91e18e82f2bc5e87b8841d8c6581f76c0`.
Scoped review delta SHA256:
`cb7a0212ed3fc46de22f13cbdc9623e20f75dcd27b1007634c46478fdd4f8fe9`.

Task4 is ready for independent Superpowers review, not publication or production
availability promotion. Attempts12/13 retain their stated failures/limits. The
provider, IdP, credentials, queue delivery and artifact storage remain controlled
fixtures. No live customer/provider or deployment proof is claimed. Task5 retains
the main status/TSV and UI/publication gates.

Independent Task4 review now reports specification and task-quality PASS with no
Critical, Important or Minor finding. It verified exact60 startup, all1,874
current source hashes, all1,882 pre/post entries, cadence/restart/rebind/durable
completion, mounted inventory and last-good behavior, the actual stored disabled
due crossing, immutable attempt12/13 qualifications, seven clean joins and final
cleanup absence. Task4 is accepted at controlled-provider scope. Live provider,
deployment, scalability, full UI/publication and all-product readiness remain
open and are not inferred from this result.

Task4 report SHA256:
`2c58b87144a3de67ca4fe04debdc1fea0da4a417ca453572bb145c80137585e8`.
Final review delta SHA256:
`cb7a0212ed3fc46de22f13cbdc9623e20f75dcd27b1007634c46478fdd4f8fe9`.
Attempt14 manifest SHA256:
`87acabc4e395b7fe4aa80dce51f0c1d91e18e82f2bc5e87b8841d8c6581f76c0`.
