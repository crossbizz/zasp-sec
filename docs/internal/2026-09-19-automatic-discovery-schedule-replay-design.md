# Automatic discovery schedule replay design

Date: 2026-09-19. Status: selected correction, waiting for the reviewed release59 handoff.

## Outcome

One public schedule occurrence is identified by its tenant scope, saved schedule,
integration and exact `next_run_at`. A scheduler process that commits admission
and dies before advancing the schedule must let a later registered scheduler
reclaim that same occurrence after lease expiry. The replacement process returns
the existing sync, job and outbox. It must not create a second occurrence.

This correction preserves the public minimum300-second cadence. The focused SQL
test uses a due-now schedule only to reproduce the registered restart boundary in
about5 seconds. It is not evidence for public cadence behavior. Connected proof
still waits the actual300 seconds.

## Root cause and retained evidence

Release13 increments `zasp_discovery_schedules.version` on every claim. The Go
scheduler formerly included that mutable claim version in the deterministic
sync seed, so an expired-lease reclaim generated different sync, job, outbox and
idempotency identities for the same due instant. The reviewed Go correction now
uses schedule ID, integration ID and exact due time, while retaining positive
claim-version validation.

With stable identities, release13 still refuses the replacement claimant. Its
schedule-run receipt stores the first lease owner/token and requires those values
to match on replay. The retained registered PostgreSQL RED waits a real5-second
lease expiry, reclaims on a separate registered scheduler connection, proves
version2 to3 with the same due time and one stored sync/job/outbox/receipt, then
fails with SQLSTATE23505 `schedule run conflict`.

## Selected database correction

Release60 follows reviewed release59. It does not edit releases13 or59. The
migration adds one occurrence-unique constraint on
`(organization_id,workspace_id,environment_id,schedule_id,scheduled_for)`, a
nonnegative `rebind_generation` column and occurrence completion digest/result
columns on `zasp_discovery_schedule_runs`. Installation refuses pre-existing
duplicate occurrence rows and any incomplete schedule-run receipt.

The rollout is maintenance-fenced. First let each live old scheduler finish its
admitted occurrence, then stop and join every old process. Preflight refuses an
already expired/incomplete legacy receipt and stays blocked until a separate
reviewed recovery is designed and executed. With a clean preflight, install
release60 and start only a release60-pinned scheduler. This prevents a
version-derived process from becoming the first writer after release60. If that
fence is violated, the subsequent release60 replay fails closed and leaves the
old-first receipt unchanged. Release60 never guesses a mapping or deletes either
class of legacy evidence.

The migration advisory lock is acquired first. Installation then locks schedules
and schedule runs in the same order used by admission before checking duplicate
or incomplete receipts, and retains those locks through schema/function install.
An in-flight old admission either finishes before the predicate and is observed,
or the database locks exclude it during installation. An already executing
predecessor function can still resume afterward and become an unsupported old
first writer; the maintenance fence is mandatory. Its later release60 replay
fails closed without changing or duplicating the legacy receipt. The SQL does not
claim to identify canonical stable IDs for that empty-occurrence first write.

The release60 registered scheduled-admission function keeps the current schedule
row locked and requires the current unexpired registered lease before calling the
existing sync admission. Before any receipt insert or rebind, it requires the
returned sync, job and outbox IDs to equal all three caller-proposed IDs. The
general manual-sync replay contract stays unchanged. Its schedule-run insert uses
the occurrence key as conflict authority. An exact replay by the same lease
owner/token returns the stored receipt without changing generation. A different
current lease may update only `lease_owner`, `lease_token` and increment
`rebind_generation` exactly once, and only when stored sync ID, job ID, request
digest and exact scheduled time match and `completed_at IS NULL`. Zero rows after
insert/rebind raises SQLSTATE23505. Changed IDs, digests, scope, schedule, due
time, completed receipts and stale leases remain refused.

The transaction boundary matters. A deliberately started older binary can still
propose version-derived IDs after release60. The occurrence conflict rolls back
every provisional sync/job/outbox write in that transaction. It cannot duplicate
the occurrence. This is a safety net, not a supported mixed-scheduler rollout.
Under the required rollout, a release60 binary supplies stable IDs, rebinds the
incomplete stable receipt and completes with the new lease. The old token cannot
complete after rebinding.

Completion replay is occurrence-durable. The release60 completion wrapper checks
the receipt completion digest/result before current-time or live-lease checks.
The first replacement-token completion advances the schedule once and stores its
exact result atomically on that occurrence. A lost response can be replayed after
the next due instant or a later claim, returning the stored result without
touching the newer occurrence. A different completion digest or a pre-rebind old
token fails closed.

## Release identity and rollback

Release60 snapshots every predecessor definition it replaces and gates install
on exact release59 checksum, fingerprint and readiness. The compatibility set is
explicit: `zasp_compliance_readiness`,
`zasp_production_security_agent_existing_tests_readiness`,
`zasp_sa_attack_lab_readiness`, both attack-lab/export prior
`predecessor_ready` functions, `zasp_sa_export_readiness`,
`zasp_workflow_mutate`, `zasp_risk_mutate`,
`zasp_production_security_agent_attack_path_security_ready`,
`zasp_production_workflow_compatibility_security_ready`, the attack-lab audit
fingerprint, `zasp_execution_live_fingerprint`, `zasp_execution_readiness`,
`zasp_execution_security_ready`, scheduled admission/completion and every
release59 readiness/guard whose version count rejects60.

The release60 live fingerprint covers saved definitions, the new columns and
constraint, registered functions, owners, search paths and ACLs. Each old
compiled checksum/fingerprint pair is accepted only through a nonrecursive
wrapper that first proves full release60 readiness. Unknown pairs and drift fail
closed. API, worker, projection, export and webhook boundaries keep their prior
compiled arguments. The scheduler alone requires release60 checksum/fingerprint.

Down migration sets a bounded lock timeout, takes the migration advisory lock,
then takes an exclusive table lock on `zasp_discovery_schedule_runs` before it
checks rebind or completion evidence. It retains both locks through restoration
and schema removal. It refuses if any `rebind_generation` is positive or any
release60-only completion evidence exists, because removing that state would
erase restart evidence. With no such evidence it drops the new constraint and
columns, restores every saved definition/owner/ACL and exact release59 readiness,
deletes release60 metadata and permits a fresh59 to60 cycle.

## Verification boundary

Required component proof is a real registered two-connection PostgreSQL test,
not owner-side row mutation: first admission, actual lease expiry, second claim,
same occurrence replay, old-token refusal, new-token advance, one durable
sync/job/outbox/receipt, altered-input rollback and occurrence-durable
lost-response replay. Release-cycle proof covers59 to60 to59 to60, every affected
compatibility boundary, readiness drift, grants, down-versus-rebind serialization
and rollback refusal after release60 evidence.

Required connected proof is attempt12 of the existing automatic-discovery browser
packet: public schedule CRUD, actual300-second cadence, first process admission,
real process restart and lease expiry, one sync/job/outbox, Kubernetes collection,
typed inventory reload, last-good retention, tenant denial and disabled/deleted
withdrawal. Controlled Kubernetes/DNS/TLS and local identity remain disclosed;
this does not claim a live customer cluster or managed cloud provider.
