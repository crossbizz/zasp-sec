# Connected preflight operator contract

This component observes intended AWS targets through official SDK APIs. It is
not a launch acceptance receipt. Its current report always keeps readiness false
because the original IRSA, OpenSearch, EKS/private network and selected
EC2 sensor checks are not all connected. Queue metadata does not prove send,
receive or delete authority. S3/KMS metadata does not prove artifact write rights.

After the CLI build passes, invoke the read-only inspector with an absolute,
operator-owned config file having no group/other permissions:

```sh
agentsecctl preflight run --mode before-install --config-file /absolute/private/preflight.json
agentsecctl preflight run --mode installed --config-file /absolute/private/preflight.json
```

Both modes retain all eight original sections. A blocked evaluation writes the
bounded JSON report to stdout and exits nonzero. Missing credentials do not fall
back to another source. Configuration and credential errors do not print paths,
credential values or raw provider errors. Failure details contain a fixed SDK
operation, exact target digest, closed outcome and fixed remediation hint.
SDK operation names and IAM permission names are deliberately distinct.

The strict `agentsec-preflight-config-v1` config contains `deployment` (account,
partition, region, supported profile and release), product-ID `scope`,
`credentials`, `features` and `aws` resource bindings. The executable declarations
in `services/platform/preflight/contract.go` and validation in `config.go` define
the accepted fields. Unknown/duplicate fields, observed Boolean attestations,
arbitrary endpoints, cross-account or cross-region resources and unsafe files
are rejected. Targets are operator intentions, not verified tenant enrollment.

Select exactly one credential source: `operator_file` (private owned JSON),
`operator_environment` (explicit standard AWS variables), or
`workload_web_identity` (the fixed EKS projected token path and expected role).
No profile, IMDS or operator fallback is attempted. Workload exchange uses STS;
identity is checked before resource reads. It does not establish the remaining
IRSA trust or Kubernetes binding observations. No permissions are installed.
Secret values are transient and never reported. Mutable buffers are cleared;
immutable Go/SDK strings cannot be guaranteed erased from memory.

Optional `neon` config selects `credential_file`, `expected_host`,
`expected_database`, `expected_principal` and compiled `profile_recipe`
(`worker-v1` or `audit-identity-worker-v1`). The private credential JSON contains
only `host`, `port` (5432), `database`, `user` and `password`. Host must be the exact
Neon pooled endpoint; database and principal must match the intended values.
Nonempty `PG*` environment settings are rejected before parsing; there is no
service, passfile, host, TLS or credential fallback. The bounded pool verifies
TLS hostname and authenticated principal, then uses a read-only transaction and
fixed SELECTs for the complete compiled canonical61 and selected private78/79/80
metadata. Missing schema before installation is `not_installed`, not current
schema compatibility. No migration, DDL, role change or grant is performed.

Optional `stytch` config selects fixed test/live `origin`, `credential_file`, exact
`organization_id`, `member_id` and `member_session_id`. The private credential JSON
contains only `project_id` and `secret`, matching the selected environment. The
observer GETs the exact organization and the member's active sessions, requires
the selected session and expiry, and never creates, exchanges, authenticates or
renews a session. These provider observations do not establish product tenant
enrollment or fresh product grants. Unknown optional vendor fields can be null;
authority aliases, duplicate bindings and replacement sessions are rejected.

Neon and Stytch use independent authorities and run before AWS credential early
returns. Their success cannot clear another original prerequisite. Missing config
stays explicitly unobserved. Actual provider credentials, metadata-read access,
approved target bindings and working network routes remain prerequisites.

Use `agentsecctl preflight evaluate --offline` for the original Boolean policy
evaluator. Bare `preflight` retains this compatibility mode. Its report states
`source: offline-evaluation`, `ready: false`, and records the policy decision in
`evaluation_ready`. Offline success is not installation readiness.

Production acceptance still requires the documented target, least-privilege
workload bindings, real Stytch/provider integrations and deployed end-to-end
flows. No original task is promoted by this component.

Selected-node sensor observations use explicit `kubernetes` authority (HTTPS
endpoint, CA file, cluster UID, and existing service-account or private bearer-file
credentials) and a `sensor` selection. The selection binds the exact cluster UID,
enrollment binding, source profile, Node label selector, and both deployed
sensor/Tetragon DaemonSet identities, container images and service accounts.
Both charts require the same explicit cluster UID and Node selector; no default
cluster identity or invented fleet coverage is supplied.

The reader lists actual selected Nodes, reads each exact named DaemonSet and its
namespace Pods, and joins current UID/boot/generation-bound reports from Leases.
It repeats the Node observation and applies a final freshness fence. Selecting
Nodes requires cluster-wide Node metadata LIST permission: a label selector is
not an RBAC restriction. Named DaemonSet GET and namespace Pod LIST bindings are
explicit. No secret read, exec, TokenReview or provider mutation is added.

The lineage producer writes a protected sibling observation witness through its
existing writable state mount; the consumer reads it through its existing read-only
mount. Original observation time is retained. New pending coverage records bind
exact payload, selection and freshness; legacy, copied or expired pending records
are preserved and refused, without rewriting sequence history. The old unconfigured
coordinator remains for compatibility; deployment of the selected-coverage profile
and retirement acceptance remain required. Host kernel/BTF, root-owned mounted
witness, actual Helm rendering and real Kubernetes coverage are separate acceptance
gates. Component fixtures do not satisfy them.
