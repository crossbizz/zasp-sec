# Before wiring this into a request

This is the P5 model/checker component. It isn't active API or worker enforcement.
The production caller must finish P6/P7 before treating a Check allow as usable.

`NewOpenFGA(clients.FGA, runtimeConfig)` borrows the official SDK client already
created by `runtimeservices.Connect`. It keeps immutable store/model pins, gives
each call a deadline, requests HIGHER_CONSISTENCY and returns redacted errors.
It has no allow cache. Don't close the borrowed client here.

`CheckRequest` is server-owned. Authenticate first, retain immediate SQL session,
PAT and membership deactivation, then load the resource and its exact scope from
SQL. The caller must verify desired/applied authorization revision and model
generation before Check; sensitive commits/effects revalidate them under the
same lock used by grant changes. Never hold that transaction during Check.

## Subjects and parents

Human subjects use `user:<product-principal-id>`. Stytch references remain in the
existing verified identity mapping. A PAT checks as its owning user and still
intersects its current token permissions, scope, expiry and revocation state.
There's no PAT or synthetic Stytch-member type in the model.

`agent:<product-id>` and `service:<product-id>` are different subjects. Their
delegation assignee tuples require `task_bound`; tuple context pins `bound_task`
and Check supplies only the server-loaded `task`. The exact object and permission
are part of the delegation object's canonical key. `DelegationGrant` emits two
tuples: the conditioned machine assignee and its `delegation#assignee` attachment
to the exact resource permission. The key contains organization, workspace,
environment, target kind/ID, principal kind/ID, task ID and permission. Each task
has its own independently revocable grant, including concurrent tasks using the
same machine and target. Permissions from another task cannot satisfy its Check.
P6 must reconcile both tuples as one desired-state unit and fence activation until
the full revision is applied. Revocation removes both; removing the attachment
alone also denies access immediately in the model.
The object's ID is `organization-ID/SHA256(canonical-binding)`. The full binding
is too long for OpenFGA's 256-byte object limit; hashing keeps every binding
component and avoids generating a new SQL or provider principal identity.

Object encoding:

| Object | ID |
| --- | --- |
| organization | organization product ID |
| workspace | organization/workspace |
| environment | organization/workspace/environment |
| resource | organization/workspace/environment/resource-kind/resource-ID |

`Hierarchy` emits one parent at each level. It doesn't prove database ancestry,
and OpenFGA doesn't enforce single-parent cardinality for us. P6 must validate
one SQL parent and replace obsolete edges under the desired-state revision lock.
Never grant from caller-supplied organization IDs or contextual parent tuples.

Organization and workspace API operations still check the selected exact
environment. Their resource IDs must match that scope. Lists/creation check the
selected environment too; P7 must retain authorized SQL counts/pagination and
validate returned resources. A route check alone doesn't authorize every row.

## What the policy keeps

The six role grants live only on environments. Each effective permission also
requires organization membership through the workspace/environment parent chain.
An organization role label or membership alone grants no environment access.
P6 projects direct grants and verified group role mappings at their exact scope;
the union is permitted only within that scope.

The approved production baseline is in
`docs/internal/2026-09-22-openfga-role-policy-decision.md`. Security Admin retains
identity administration. Developer/Owner gets no integration mutations.
`manage_workflows` keeps its full existing meaning across integrations, policies,
sensors, agent mutations and approvals. We don't alias it to one domain.

`operations.json` explicitly covers all current core and optional routes.
`Permission` and `Relation` are the same eleven production permission names.
Seven empty relations retain credential/bootstrap contracts; they are not
anonymous bypasses. The credential list excludes `BrowserExpectedScope`, which
is a header precondition added by composition, not a credential. P7 must retain
that check, CSRF, the current browser/PAT fresh-auth branches and every stronger
SQL/handler gate. The four fresh-auth routes currently admitting PATs remain
listed; this does not assert fresh Stytch authentication for PAT calls.

Audit exports use `view_audit`, compliance exports use `view_compliance`, and
Security Agent exports use `view`. Retain their download-grant, content, retention
and target/version restrictions. A broad `export_evidence` alias doesn't exist.

`ResourceGrant` (human) and `DelegationGrant` (machine) only encode already
authorized desired state. They don't authorize issuing a grant. Current grantor authority,
approval, runtime policy and budgets still apply before machine effects.
Compensation needs its separate narrow authority, not the initiating user's role.

## Local checks

From `services/platform`:

```sh
ZASP_P5_MODEL_TEST=1 go test ./authorization -count=1 -v
```

The opt-in example test inspects the retained loopback OpenFGA container, reads
its existing credential only in memory and creates a new P5-owned store/model.
It keeps those IDs as evidence and never changes runtime model configuration.
Without the flag, Go reports the real-service test as skipped. Don't count that
as model acceptance.

`model.fga` is the readable source. `model.json` is its SDK publication artifact;
the pinned official CLI transform must agree (empty relation metadata can differ).
`model.fga.yaml` is a development import descriptor, not a second fixture suite.
