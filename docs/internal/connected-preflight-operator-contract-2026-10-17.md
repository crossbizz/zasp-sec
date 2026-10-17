# Connected preflight operator contract

This component observes intended AWS targets through official SDK APIs. It is
not a launch acceptance receipt. Its current report always keeps readiness false
because original Fargate, network and data-plane permission
acceptance remains incomplete. OpenSearch metadata/schema observations do not
prove workload-origin reachability or write permission. Queue metadata does not prove send,
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
identity is checked before resource reads. A selected identity alone does not
establish the full IRSA inventory or Kubernetes bindings described below. No
permissions are installed.
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

Optional `aws_authority` selects separate explicit operator inspection credentials,
the exact EKS cluster ARN/name/VPC/issuer/endpoint/CA digest/cluster UID, and exact
role purpose-to-ARN bindings. Its compiled inventory retains all 38 original IRSA
purposes and three infrastructure service roles, including optional Attack Lab
selection rules. A partial supplied inventory cannot establish full coverage.
Read-only EKS DescribeCluster and IAM GetRole/GetOpenIDConnectProvider observations
require the intended EKS 1.34 private-only endpoint contract and exact trust shape.
No inspection permission is added to workload roles.

The shared explicit Kubernetes authority reads the selected cluster namespace,
compiled ServiceAccounts and selected Pod specification through exact GET paths.
It binds the EKS endpoint, CA digest and cluster UID. Auxiliary API role trust is
checked separately from the primary role annotation on its shared ServiceAccount.
A configured selected workload is proved against the subject, audience and issuer
returned by the same successful STS web-identity exchange that supplied its actual
credentials. Unverified JWT claims and a second exchange do not supply proof.
Current Pod specification is separate evidence: it cannot prove token ownership
of a Pod UID, ServiceAccount recreation or token revocation. No TokenReview grant
or mutation is added. Per-run private proof is never cached in the Runner.

The report exposes required/observed role and trust counts and separate selected
exchange/specification booleans. A selected-role identity success cannot clear an
incomplete original inventory. Failure outcomes and exact Kubernetes read actions
remain bounded and redacted. Fargate, network reachability, OpenSearch and actual
write/consume permissions remain separate original requirements; metadata and
trust inspection do not establish them.

Optional `opensearch` config binds the exact domain name/ARN, private regional
HTTPS endpoint, VPC/subnets/security groups, KMS key, expected session-search
phase and selected container/image digest. Separate explicit inspection
credentials perform STS identity and DescribeDomain reads; local credential
prerequisite failure stays unobserved, without fabricating an attempted STS call.
The domain must meet the original OpenSearch 2.19 private/encrypted/TLS contract.

Schema reads require the same verified selected workload exchange and fresh
cluster/Pod/container/environment bindings. Runtime-index observes its raw-event
and actual configured session index; projection-search observes its inventory
index. Only fixed canonical schema GETs are allowed, using the existing Ready
validators. Unsupported workload purposes remain unobserved. No index creation,
initialization, document write, fallback identity or new workload permission is
introduced. Expected phase is configuration, not an observed deployment phase.
Inspector-origin reads do not prove workload network origin, global deployment
phase, index write authority or full installation readiness.
