# Platform-global Security Agent execution control

Status: SQL Task1 is locally implemented and independently accepted after the
owned eight-test matrix. CLI Task2 is also locally accepted after real command
execution and independent review. Eight concurrency cases and the final local
feature integration review are accepted. Dependency-complete shipping verification,
external release evidence, publication and CI remain open. See the implementation plan and global operator transaction
report for exact evidence. No production rollout is claimed. Standing
authorization permits local decisions without routine approval pauses.

## Why the current path is insufficient

Release27's zasp_recovery_scope_mutable rejects non-ProductID scope before
checking holds. Its generic mutation guard applies to both kill-switch and
Security Agent audit tables. The global tuple is ('*','*','*','*'), so changing
the control and appending its audit event both fail. Release18's setter requires
the registered tenant API principal; release20 revokes direct API execution.
It is not a supported operator command.

The recovery fingerprint also includes every *_recovery_hold trigger definition
(0027_production_recovery.up.sql:652). Replacing two triggers without deliberate
versioned compatibility handling would invalidate predecessor readiness.

## Selected authority and behavior

Use an explicit operator command on agentsec-migrate and the existing registered
migration authority. Check both the session_user binding in
zasp_discovery_principal_bindings and membership of zasp_discovery_authority,
following the existing audit-export configuration boundary. Do not use
current_user inside a security-definer function as caller authentication.
No tenant API or runtime worker gains operator capability.

Entrypoint provenance uses an internal NOLOGIN role,
`zasp_security_agent_global_operator`, owning only the operator read/CAS entrypoints.
It has no steady-state membership in either direction and no credentials.
SECURITY INVOKER guards require that effective role plus the registered
session_user migration identity. Direct DML by the registered migration login
must refuse. Add narrowly scoped RLS policies as well as column/table privileges:
the existing tables force RLS and currently authorize discovery authority only.
Do not transfer their ownership or grant BYPASSRLS. A malicious superuser or
schema owner able to replace guards remains outside this entrypoint boundary.
Fingerprint role attributes, zero memberships, grants and global-only policies.

The command reads or compare-and-swaps the exact global control, with an expected
positive version, bounded request identity and audit correlation. Return only
enabled state, version and replay status. A repeated request must compare the
full persisted intent; a changed request at the same identity must refuse.
Changing the control, durable receipt and append-only audit is one transaction.
Missing global state is an error, not permission to create a new enabled row.

Keep tenant recovery checks exactly as they are for canonical tenant scopes.
The only wildcard exception is the exact global kill-switch UPDATE, plus an
INSERT of its exact global kill_switch_changed audit event by the authenticated
operator path. Reject mixed wildcard scopes, action-specific wildcard controls,
global row deletion, identity movement, audit UPDATE/DELETE and malformed event
associations. No generic wildcard acceptance in zasp_valid_product_id or
zasp_recovery_scope_mutable; no trigger disabling or replication-role bypass.

Take the existing global control row lock before the mutation and audit. New
execution admissions that share-lock it serialize with a stop. The stop does
not claim cancellation of already committed invocation authorizations, including
ones whose HTTP request has not yet been sent. The journal commits Start before
external invocation, so its row lock cannot cover the later network send.
Cancellation,
reconciliation and scoped history remain available while execution is off.
Re-enable does not alter tenant/environment/action settings or recovery holds.
Revalidate operator binding and exact release identity after blocking writes.

## Versioning and alternatives

Implement in the unpublished candidate release only after the mounted batch
stabilizes. Preserve published release27 bytes. Save exact predecessor trigger
definitions and every replaced function/ACL for unused rollback. Extend the
candidate fingerprint to cover both replacement triggers, their guard functions,
operator authority, receipt schema and grants. Handle the predecessor recovery
fingerprint explicitly using the repository's versioned compatibility pattern;
never accept an arbitrary fingerprint mismatch. The inspected existing private
55-to54-to53-to52 ancestry already reaches live recovery27 through the separate
release34 compatibility branch. Recalibrate only55; keep all historical pins and
their version-specific client refusal behavior unchanged. Used-history rollback must
refuse rather than discard operator audit/receipts.

Operator use and rollback must take conflicting relation locks before readiness
checks, then recheck after waits. Add receipt/control/audit relation coverage to
the down migration. Replay returns the original saved result without reapplying
an earlier stop after a subsequent re-enable. Guards validate the transaction's
full durable intent and matching receipt/audit association, not caller-set GUCs.

Rejected: direct owner UPDATE cannot produce the required guarded audit path;
granting the old setter to tenant APIs would expand tenant authority; disabling
recovery triggers breaks recovery isolation. A separate operator identity and
new credential distribution are unnecessary for this existing migration-level
operation, but would be required if an unprivileged operations service is added.

Ruling: retain the existing migration-level trust boundary and a narrow versioned
global exception. This avoids creating a second operations identity system.
Cost if wrong: operator command and release compatibility need rework before
publication. No production permissions change until tests and review pass.

## Acceptance required before release

One owned Docker PostgreSQL feature batch must prove registered operator stop,
exact replay, stale-version/conflicting replay refusal and re-enable; tenant API,
all worker identities, unregistered owner-role member and forged session identity
must refuse. Test every malformed wildcard scope and audit mutation above.
Failure after control update but before audit/receipt must roll back all writes.

Exercise stop racing blocked admission and invocation, including loss of operator
binding during a wait. Prove no new work after the stop barrier while existing
cancellation/reconciliation/history still work; do not equate process termination
with external cancellation. Run tenant recovery-hold positive/refusal controls
before and after operator transitions. Verify compatibility fingerprints, exact
ACLs, migration rollback before use and atomic rollback refusal after history.

CLI tests cover strict parsing, bounded timeout, safe output and parameterized
SQL. The actual command runs against owned registered candidate authority with
stop/read/re-enable evidence. Full release, runnable UI and independent
Superpowers review remain required. No live production result is inferred.
