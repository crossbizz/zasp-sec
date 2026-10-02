# M2-33 group-mapping update RED

Confirmed inherited product bug. No production fix implemented. The focused
mounted regression fails only at the valid positive-version replacement after
real authentication, initial creation and denied controls succeed.

## Reproduction

Worktree `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`;
HEAD `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Dedicated new test: `services/platform/apiserver/group_mapping_update_postgres_test.go`.
No frozen connector source was edited.

`red-observed.log` enumerates and executes exactly
`TestGroupMappingExpectedVersionUpdateMountedPostgres`. Registered
`security_agent_v33_discovery_api_login` is asserted non-superuser/non-bypass.
The real repository creates and authenticates fresh browser sessions for the
security_admin principal with manage_identity. Real composition, middleware,
Origin/CSRF/fresh-auth/expected-scope gates, identity handler and repository are
used. No direct product audit INSERT or raw mapping update replaces the route.
Owner SQL supplies membership/direct scope and one foreign-tenant mapping only.

Observed sequence:

1. PATCH initial mapping expected_version0: HTTP200, role security_engineer,
   version1, ETag1, one durable group_mapping.update event; current admin session
   is revoked. This positive control proves registration/setup/auth/dispatch.
2. Create a distinct real session; do not resurrect the revoked credential.
3. Repeated expected_version0:409 with no added event.
4. Foreign-tenant-only group reference:404, no added event or foreign-row change.
5. PATCH same local group, role read_only_viewer, expected_version1: **409
   version_conflict instead of200; stored role remains security_engineer,
   version remains1 rather than2; audit count remains1 rather than2; current
   session remains unrevoked rather than being revoked.**

The final combined assertion names all missing replacement effects. The
observed failure is not an authentication, CSRF, permission, migration or
configuration error. Test ran6.08seconds and exited1 as intended.

## Source cause

Actual dispatch is confirmed, with no schema-specific alternative:

- composition.go65 registers PATCH `/api/v1/admin/group-mappings` as
  updateGroupMappings, requiring manage_identity and BrowserSession.
- production.go696 decodes expected_version and sends it to the administration
  mutation; production.go803 calls the installed repository.
- administration_repository.go189-190 selects postgresUpsertGroupMappingSQL.
- administration_repository.go40 gates INSERT's source on `WHERE $6=0` but
  requires existing version=$6 inside ON CONFLICT UPDATE. Positive versions
  therefore produce no source row, so conflict update cannot execute. Version
  starts at1 and is constrained positive (release7). The query falls through
  to its existing-row conflict result without mapping/audit/revocation effects.

## Connected lock-order analysis — source-backed, not runtime proof

Production-writer search found postgresUpsertGroupMappingSQL as the mapping
INSERT/UPDATE writer. Its changed CTE acquires the mapping row before dependent
revoked_sessions/revoked_tokens mutate organization credentials; audit depends
on those revocation counts. A repaired positive-version branch retaining this
order can expose a cycle with the frozen rejection path:

```text
mapping update: mapping row → session/token write lock
rejection:      membership share → credential share → mapping share
```

If update holds the mapping and waits for a credential held by rejection while
rejection waits for that mapping, PostgreSQL must abort a deadlock participant.
This is a prospective source-derived contention finding, not an observed
deadlock or evidence of unauthorized successful audit. Existing final guards
fail closed on database errors.

Future fix must use compatible mapping-before-credential ordering for the
group branch while retaining membership-first: release19 resolve_session and
reconcile_deprovision take membership FOR UPDATE before credential revocation
and member-group changes. Preserve fresh final credential/permission/expiry
checks after waits and exact tenant/positive-witness semantics. A simple
unconditional INSERT is not sufficient: missing positive-version targets must
not be created, stale versions must not mutate, and revocation/audit must remain
atomic. Root chooses the connected implementation design after this RED.
No migration, grant, RLS or historical fingerprint change is needed by this
diagnosis. Any future fix needs actual registered-writer contention tests.

## Evidence and isolation

`run-red.sh` compiles locally with GOOS=linux/GOARCH=arm64,
GOTOOLCHAIN=local/GOPROXY=off/GOSUMDB=off, Go1.25.6 and retained offline cache.
It enumerates before running one anchored test in owned cached PostgreSQL
`postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba`,
network none, read-only, postgres user, no pull/build, owned tmpfs. No host PG,
provider/live call, package installation, staging, commit, push or UI rerun.

Final execution command:

```sh
bash docs/internal/group-mapping-update-20260918/run-red.sh --reuse-binary
```

The binary was reused unchanged after a transient Docker entrypoint visibility
failure; its identity is
`df184f1243688c395ec745803d2e3618213156534467c29510cd8c51ccf5dac5`.
Test source SHA256
`1a34d62d64c1b7588fc45b89a1ce7e8cf187b6e961e87b8f826540135dd03be9`.
Observed RED log SHA256
`19cd6de24b77c9d022405172e32e5cc29c2fa8bedee7bbff72b0370f88887053`;
scoped patch SHA256
`ca6861e0827d3c8a98c1ec90b1b721f930db624b6b8b822d6877c4fd43001f6f`.
Key production identities (unchanged): administration_repository.go
`7fde0beed3ebdb83d447156135776e8a3bec9ead4b51aaccb3a2923410bc2c94`;
production.go `5af42fcf2df4bfb8fdda1b0ea9e286be079584bb9a640f531166fbf9aa662ade`;
composition.go `373b7ddc43563c4ded96b9c4920cbc042c4b41123d91bc9006db9389b3004e89`;
connector_rejection_transaction.go
`fde240399ae4cdf39010645926c5a2cf1423f45e8c3a027dff88f3fff43b8e6c`.

`before-source.log` and `after-source.log` cover apiserver, agentsec-api and
migrations; their only difference is the new test. `red-scoped.patch` contains
only that test addition. Release56 checksum remains
`f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1` and fingerprint
`8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`.

Setup-only logs are retained separately: red-run.log is an initial foreign
fixture scope FK23503, corrected using real foreign workspace/environment IDs;
red-run-final.log is a container launch255 before enumeration, with a valid
static ELF on host. Neither is product RED. Same-binary fresh owned-container
retry succeeded; no speculative production edits or repeated compilation.

Handles44938,76645 and63799 all joined. Final owned PostgreSQL pid23 joined:
pg_ctl exit0, server Wait exit0. Docker --rm removed both owned enumeration and
test containers; explicit final name-filter query returned no rows. The ten
unrelated voxeval containers remain untouched in remaining-containers.log.
No active process handle remains. GREEN and independent review are deferred to
root authorization; this phase is diagnosis/test/evidence only.
