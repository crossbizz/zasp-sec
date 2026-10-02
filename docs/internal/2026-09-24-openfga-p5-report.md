# P5: the model is ready for review

September 24, 2026. DONE_WITH_CONCERNS: local component work and checks are done;
independent review belongs to the controller. Production enforcement is not done.
HEAD remains `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, branch
`codex/cached-runtime-ship-20260917`. No commit, push, shared deployment, dependency
change, migration edit or authoritative-ledger update was made by this lane.

The preexisting dirty overlay stayed in place. All source additions are under
`services/platform/authorization/`; that directory was absent at the start.
The only other owned outputs are this report and the plan workspace's `p5/`.

## What changed

The new package contains `checker.go`, `openfga.go`, `mapping.go`, `operations.go`,
`operations.json`, `model.fga`, `model.json`, `model.fga.yaml`, four Go test files
and `README.md`. The review patch contains those files and this report, against
their absent starting bytes. The manifest records their SHA-256 hashes, evidence
hashes and the current readonly dependency hashes.

`NewOpenFGA` consumes the existing official SDK v0.8.2 client and
`runtimeservices.Config`. Every Check overrides the configured store/model IDs,
requests HIGHER_CONSISTENCY, has a deadline and returns a redacted failure with
Allowed=false. It creates no client, cache, legacy fallback or readiness allow.
The runtime keeps ownership of TLS, credentials, transport and client lifetime.

Mapping uses canonical product IDs. Human subjects remain `user:<principal-ID>`;
Stytch provider references aren't FGA subjects. PATs use their owning user, with
token intersection still required at the application boundary. Agent and service
subjects are distinct types and cannot receive human roles.

Organization/workspace/environment ancestry has one emitted parent at each level.
Product resource IDs include all three scope IDs, resource kind and resource ID.
Organization/workspace API checks still target the selected exact environment;
they don't acquire tenant-wide inheritance. SQL must validate parent ownership.
OpenFGA cannot enforce single-parent cardinality for the projection writer.

## Policy decisions, kept narrow

The approved role decision supplies the six-role matrix. Security Admin retains
identity administration; Developer/Owner gets no integration mutations. Both
admin roles still need an exact environment grant and active organization
membership. Direct and verified-group scoped grants can combine within the same
scope. The unused identity-package permission map was not unioned into this one.

All eleven production permission names remain separate FGA relations.
`manage_workflows` keeps its current integration, policy, sensor, agent and
approval coverage. Every operation is explicitly mapped, so it isn't a lossy
alias for one of those domains. Direct human object grants are separate relations
and still intersect organization membership.

Delegations have distinct objects with conditioned machine assignees and an
attachment to one resource permission. The key includes exact scope, principal,
task, target and permission. A second task using the same machine/target has its
own independently revocable grant, and one task cannot borrow another's extra
permission. `DelegationGrant` returns both tuples for P6's desired-state unit.

An initial concatenated delegation key exceeded OpenFGA's 256-byte object limit.
The retained failure identifies that exact validation error. The fixed ID is the
organization ID plus SHA-256 of every canonical binding component; separators
cannot appear in validated components. It introduces no new SQL or Stytch
principal identity. Representative concurrent-task/revocation cases pass on the
actual local model.

## The operation surface

Re-extraction from current composition found 150 core operations, including seven
empty permission entries, plus two audit, five compliance and three Security
Agent export operations: 160 total. The AST inventory test follows core literals,
conditional operation arrays and explicit export append calls. It compares
method/path/permission and core credential/fresh-auth contracts to the registry.

| Permission | Composed operation count |
| --- | ---: |
| empty credential/bootstrap policy | 7 |
| view | 67 |
| manage_identity | 20 |
| manage_api_tokens | 7 |
| view_audit | 4 |
| investigate_sessions | 4 |
| revoke_sessions | 1 |
| view_compliance | 8 |
| manage_data_controls | 1 |
| manage_findings | 3 |
| manage_workflows | 30 |
| run_tests | 8 |

Empty relations aren't anonymous bypasses. Existing bootstrap/session handlers
and credential rules remain binding. `BrowserExpectedScope` is a header
precondition, not a credential; P7 must preserve it and CSRF.

The four routes with both fresh-auth flags and PAT admission remain unchanged:
`startRecoveryBackup`, `startRecoveryRestore`, `createSensorEnrollment` and
`rotateSensorToken`. Their PAT branch isn't evidence of fresh Stytch auth.
Audit/compliance/Security Agent exports keep `view_audit`/`view_compliance`/`view`
respectively, plus their stronger handler/SQL download, content and retention
restrictions. There's no `export_evidence` shortcut.

## Evidence that ran

Grouped RED failed on absent mapping/registry/checker behavior and the missing
product model. The initial implementation then passed its focused mapping and
Check tests and real model cases. After the concurrent-delegation requirement,
the affected RED group failed on the absent helper; a real-service validation
failure exposed the too-long object key. The fixed group passed.

Final commands, from `services/platform`:

```sh
ZASP_P5_MODEL_TEST=1 go test ./authorization -count=1 -v
go vet ./authorization
```

Both exited 0. Seven top-level tests and four Check-response subtests passed;
the opt-in real-service test executed 93 application permission checks, with no
skip. These cover all six roles across the eleven permissions, both admin roles'
scope limits, two organizations, another workspace/environment, direct audit
access and sibling denial, separate agent/service subjects, exact task/target
binding, concurrent tasks, cross-task permission denial, independent delegation
revocation and organization-membership removal. Error checks cover service outage,
malformed responses, invalid inputs and pinned model/store/consistency requests.

The final local store is `01M3A8BN006B8Z1BXM66KE5NJ4`; model
`01M3A8BN24RFAH6N9Q6QJ6VJPF`. It is P5-owned development evidence, not the active
runtime configuration. The final fixture intentionally removes one human
membership and one delegation per machine to exercise denial. Earlier owned
scratch stores were retained; no shared state was reset or deleted.

The pinned official CLI v0.8.0 transformed `model.fga`, and its parsed JSON
exactly matched `model.json`. The CLI container used the existing digest from
local Compose. `model.fga.yaml` is a development import descriptor; the single
application assertion matrix is in the Go real-service test. No vendor-internal
or graph-evaluator conformance suite was added. Store-file format was checked
against [OpenFGA's model-testing documentation](https://openfga.dev/docs/modeling/testing).

Exact final logs and failure evidence are in the `p5/` packet. Only affected
authorization checks were run; no unchanged repository-wide suite was repeated.

## What P6/P7 must wire

P6 owns desired-state SQL, an outbox, organization serialization and desired vs.
applied revision/model-generation fencing. Project active membership, validated
single-parent hierarchy, direct grants and verified group mappings. Project both
delegation tuples as one unit; remove the attachment and assignee on revocation.
Reconcile current state, don't replay stale grants over newer revocations.

Shared mutation seams include `apiserver/administration_repository.go`,
`identity_administration_repository.go`, bootstrap/grant writes and Stytch event
handling. SQL0019 `zasp_identity_admin_resolve_session` changes verified group
claims during login and revokes sessions/PATs; it is a permission write boundary,
not a read-only resolver. Historical migrations remain unchanged. The controller
must assign any new migration and shared-file ownership separately.

P7 must construct this checker from runtime clients in real API/worker composition
and invoke it in router, capabilities, list/search/export and pre-effect paths.
Server-loaded resources supply CheckRequest scope/type/ID. Check occurs outside
SQL transactions, followed by revision/model/resource-version revalidation under
the grant-change lock for sensitive commits/effects. Keep immediate SQL identity
deactivation, PAT intersection, CSRF/fresh auth, tenant isolation, query counts,
pagination, approvals, runtime policy and budget guards. Compensation needs its
separate narrow authority. An FGA allow cannot replace any of those gates.

No live Stytch delivery, deployed tenant isolation, production Check enforcement,
SQL revocation-race proof, provider effect or original-task availability change is
claimed here. All 728 original tasks and their deployment/external prerequisites
remain under the authoritative ledger. Send this frozen packet to the one
independent reviewer before accepting P5.
