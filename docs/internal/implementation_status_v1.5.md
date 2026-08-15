# Agent Security Platform Implementation Status

**Source plan:** `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`  
**Source PRD:** `docs/internal/agent_security_platform_PRD_v1.5.md`  
**Last updated:** August 15, 2026
**Execution branch:** `codex/zasp-implementation`

This file is the authoritative execution status for the 728 microtasks in the
v1.5 technical implementation plan. The plan remains authoritative for scope,
dependencies, deliverables, and verification. A plan task not listed under
In progress, Complete, or Blocked is Pending.

## Status summary

| Status | Count |
| --- | ---: |
| Pending | 705 |
| In progress | 1 |
| Complete | 19 |
| Blocked | 2 |

## Milestone summary

| Milestone | Total | Pending | In progress | Complete | Blocked |
| --- | ---: | ---: | ---: | ---: | ---: |
| M0 | 27 | 4 | 1 | 19 | 2 |
| M1 | 68 | 68 | 0 | 0 | 0 |
| M1A | 10 | 10 | 0 | 0 | 0 |
| M2 | 72 | 72 | 0 | 0 | 0 |
| M3 | 75 | 75 | 0 | 0 | 0 |
| M4 | 82 | 82 | 0 | 0 | 0 |
| M5 | 42 | 42 | 0 | 0 | 0 |
| M6 | 36 | 36 | 0 | 0 | 0 |
| M7 | 62 | 62 | 0 | 0 | 0 |
| M7A | 113 | 113 | 0 | 0 | 0 |
| M8 | 141 | 141 | 0 | 0 | 0 |

## Execution invariants

- Update this file in the same commit that starts or completes a plan task.
- A task moves from Pending to In progress before implementation begins.
- A task moves to Complete only after its required verification and task review pass.
- A task moves to Blocked only with the exact missing external dependency and evidence.
- Tests, type-check, lint, and production build must pass before a branch push.
- The UI must remain runnable and use product APIs as those contracts become available.
- Existing demo UI is reusable design input, not evidence that a plan task is complete.
- Security-sensitive behavior follows test-first implementation and fails closed.

## Prerequisite work

| ID | Status | Purpose | Verification |
| --- | --- | --- | --- |
| PRE-01 | Complete | Restored a clean, reproducible UI quality baseline before M0 work. | Node 22.23.1/npm 10.9.8 install, tests, type-check, lint, and production build pass without errors. |
| PRE-02 | Complete | Added a push and pull-request quality gate that enforces the runnable-UI invariant. | CI uses Node 22.23.1/npm 10.9.8, performs the locked install, and runs the root verification command. |

## Temporary waiver work

Temporary items are tracked execution work but are not part of the 728
source-plan microtasks and cannot satisfy their deferred provider gates.

| ID | Status | Purpose | Completion gate |
| --- | --- | --- | --- |
| PROV-01 | Blocked | Exercise IAM/STS assume, allowed-read, explicit-deny, and exact cleanup behavior in an isolated disposable LocalStack target without weakening the real-AWS harness. | Exact-pinned LocalStack 4.7.0 does not forward SourceIdentity into the assumed session and does not enforce the required SourceIdentity trust condition. Resume with an isolated provider version or build that proves both behaviors, then repeat cleanup, audit, gates, scans, and review. |

Repository commands, contract coverage, cleanup, audit, and zero-finding review
are in place. PROV-01 is Blocked on the exact LocalStack 4.7.0
SourceIdentity/trust-condition capability dependency. Official LocalStack
v4.14.0 source retains the same unsupported forwarding path; this was source
review only, not live testing. Its tagged STS provider accepts `source_identity`
but delegates the response without adding it to the returned session or stored
session configuration. The 728 source-plan counts are `705/1/19/2` because
PROV-01 is excluded from those counts.

## In progress

| Task | Started | Current work |
| --- | --- | --- |
| M0-19 | August 15, 2026 | Building the real EKS Security Groups for Pods egress proof with exact EC2 rule/ENI evidence, direct-deny and proxy-allow canary checks, and fail-closed cleanup. M0-18 remains Blocked and LocalStack cannot authorize success. |

## Complete

| Task | Completed | Evidence |
| --- | --- | --- |
| M0-01 | August 13, 2026 | Fourteen external/OSS proof gates have objective PASS/FAIL criteria and initial `Not run` status; task review approved after two fix rounds. |
| M0-02 | August 13, 2026 | A disposable password-only Stytch Test Organization produced a real authenticated 60-minute Member session/JWT and was confirmed deleted; 33 black-box lifecycle/security tests, full verification, a pinned full-history Gitleaks scan, and independent review passed. |
| M0-03 | August 13, 2026 | The exact-pinned official Stytch Node SDK validated a fresh B2B JWT locally and the same JWT through forced remote authentication; 49 focused tests, a live disposable proof, full verification, dependency audit, full-history secret scan, and independent review passed. |
| M0-04 | August 13, 2026 | An exact-pinned Go/pgxpool proof derived and validated the effective Neon pooler destination, completed ten overlapping reads with zero acquired connections, closed cleanly, passed live hostname-verifying TLS, full gates, secret scan, and independent security re-review. |
| M0-05 | August 13, 2026 | A disposable Neon branch accepted one versioned up/down migration through a direct hostname-verifying pgx connection, returned exactly to its baseline fingerprint, and was absent from the active branch list after cleanup; 34 Go race tests, all repository gates, a full-history secret scan, and two independent security-review fix rounds passed. |
| M0-06 | August 13, 2026 | LocalStack created a uniquely owned Standard queue and DLQ, round-tripped exact redrive attributes and one two-event Organization-scoped batch, deleted the message, proved the source empty, and removed both queues; 22 Go behavior groups, live SDK proof, full gates, secret scan, and independent security re-review passed. |
| M0-07 | August 13, 2026 | An exact-digest disposable LocalStack target proved direct KMS encryption/decryption, an Organization-scoped SSE-KMS S3 object, and a KMS-backed secret; exact cleanup, prefix-wide current-SDK audit, container absence, full gates, secret scan, and final independent security re-review passed. |
| M0-08 | August 13, 2026 | A disposable exact-image OpenSearch target indexed one metadata-only Organization A session event; the scoped session/environment query returned exactly that event for A and zero hits for B, followed by exact index/container cleanup, full gates, secret scan, and final independent security re-review. |
| M0-10 | August 14, 2026 | Two exact-pinned disposable Cartography/Neo4j fixture runs loaded two synthetic Organizations and proved eight normalized nodes, four relationships, collision isolation, customer-label safety, exact cleanup, pinned gates/scans, two consecutive live passes, and zero-finding independent review under the fixture-only waiver; no AWS/GitHub authorization-parity claim. |
| M0-11 | August 14, 2026 | The exact-pinned Prowler fixture-only evidence proof produced one reviewed open/high finding and one linked normalized evidence record for the canonical M0-10 Organization-scoped role, proved exact cleanup and shared-target non-mutation, passed pinned gates and license/secret audits, and received a zero-finding independent re-review without claiming real-AWS parity. |
| M0-12 | August 14, 2026 | Two consecutive final-code exact-pinned disposable Tetragon/Kubernetes runs produced process, file, and outbound TCP signals with one shared Kubernetes workload identity, explicit sensor health/capability and zero drop/loss counters, exact full-ID cleanup and zero-resource audits, pinned gates/license/secret scans, and zero-finding independent review. |
| M0-13 | August 14, 2026 | The exact-pinned local OTLP ingest proof delivered one bounded trace and span with all six Organization/agent/session/task/tool/sandbox identity attributes through a real Collector into the product-owned ingest adapter, disabled remote export, proved exact cleanup in two final-code live runs, and passed pinned gates/scans plus zero-finding independent review; R-12 remains Not run until M0-22 proves bounded remote-export failure behavior. |
| M0-14a | August 14, 2026 | The two consecutive final-code exact-pinned Nango/PostgreSQL runs proved minimum free self-hosted boot and exact database-backed readiness from a one-shot client on a private internal product network, with no host ports, exact cleanup, zero-resource audits, pinned gates/scans, and a zero-finding independent review; R-08 was deferred to M0-15. |
| M0-14b | August 15, 2026 | Two consecutive final-code exact-pinned Nango OAuth runs completed one private synthetic provider authorization-code and PKCE flow, retained only the Organization-scoped durable connection reference, proved exact wrapper/fixture/Nango/PostgreSQL/network/workspace ownership and zero cleanup, and passed pinned gates, license/secret scans, and a zero-finding pre-landing review; R-08 was deferred to M0-15. |
| M0-14c | August 15, 2026 | Two consecutive final-code exact-pinned Nango runs created one private `1password-events` API-key connection, verified the generated JWT-shaped provider key exactly once against the private TLS fixture, retained only the Organization-scoped durable connection reference, proved product-state secrecy and exact zero-resource cleanup, and passed pinned gates, license/secret scans, and a zero-finding whole-range review; R-08 was deferred to M0-15. |
| M0-14 | August 15, 2026 | Recorded the evidence-backed free self-hosted Nango MVP boundary as long-tail Auth plus Proxy, explicitly excluded Functions, Webhooks, MCP, RBAC, full observability, and Enterprise features without claiming their routes absent, and left the authenticated Proxy GET and R-08 decision to M0-15. |
| M0-15 | August 15, 2026 | Two consecutive final-code exact-pinned Nango Proxy runs returned one deterministic provider event through the authenticated private Proxy route, retained only scoped references plus allowlisted event ID/action, proved raw provider-token exclusion and exact zero-resource cleanup, passed pinned gates/license/secret scans, and received a zero-finding whole-range review; R-08 is PASS. |
| M0-16 | August 15, 2026 | Two consecutive final-code exact-pinned Promptfoo runs executed one synthetic direct prompt-injection case against a local fake agent, retained only the objective, vulnerable verdict, and SHA-256 evidence reference, proved exact zero-resource cleanup and shared-resource non-mutation, passed pinned gates/license/secret scans, and received a zero-finding whole-range review; R-09 is PASS. |
| M0-17 | August 15, 2026 | The exact-pinned official OPA Go SDK prepared one embedded policy query in-process, returned deterministic Allow and Block decisions across 100 warm-ups and 1,000 measured evaluations per decision, kept both decision-specific p95 values below 10 ms, and passed strict malformed-result, cancellation, panic, license, full-gate, secret-scan, and whole-range review checks; R-10 is PASS. |

`PRE-01`, `PRE-02`, and `PROV-01` do not count as source-plan microtasks.

## Blocked

| Task | Blocked since | Exact dependency | Resume condition |
| --- | --- | --- | --- |
| M0-09 | August 13, 2026 | The reviewed real-AWS harness has none of the nine task-specific inputs and no isolated authenticated two-account fixture. Existing generic AWS values target loopback LocalStack. | Provide the documented isolated commercial-AWS source and target-admin credentials, expected distinct accounts/source principal, region, and exact isolation attestation. |
| M0-18 | August 15, 2026 | The reviewed harness is locally green, but the capability audit found 0/11 required inputs: no authenticated real EKS kubeconfig, disposable Fargate profile, product proxy endpoint, or canary credential. LocalStack k3s cannot prove AWS-managed Fargate scheduling. | Provide all eleven documented inputs for an isolated disposable real EKS Fargate profile, run the exact live proof, prove cleanup, repeat gates/scans/review, and only then decide R-11. |

The user approved a temporary delivery waiver for a fixture-only Cartography
normalization proof. M0-10 is Complete without claiming AWS or GitHub
authorization parity. M0-09 and PROV-01 remain Blocked, and R-03 remains
incomplete. M0-18 is also Blocked on its exact real-provider fixture. A
zero-finding implementation review does not override the failed
provider capability gate.

## Review findings

| Source | Finding | Ruling |
| --- | --- | --- |
| Prerequisite final review | Runnable UI workflow pinned immutable but older v4 GitHub Action SHAs; GitHub later warned that their Node 20 runtimes were deprecated. | Resolved August 13, 2026: updated to the immutable official `actions/checkout` v7.0.1 and `actions/setup-node` v7.0.0 SHAs, both using the Node 24 action runtime. |
| M0-02 task review | Password migration/authentication responses did not validate every required identity-bearing Organization field. | Resolved in `da13230`: require a newly created Member and matching expanded Organizations at both boundaries, with fail-closed cleanup tests. |
| M0-02 task review | Mixed credential, cleanup-failure precedence, and stalled-response deadline paths lacked direct regression tests. | Resolved in `da13230`: added black-box zero-I/O, dual-failure, and bounded stalled-body cleanup coverage; review rerun approved with no remaining findings. |
| M0-04 task review | A validated Neon-looking URL could still use pgx query, environment, or file fallbacks to dial a different effective destination. | Resolved in `e8a8f5f`: explicit URL identity, minimal query allowlist, PG environment refusal, effective-config/TLS validation, and per-connection revalidation now fail closed; hostile regressions and live `verify-full` proof pass. |
| M0-04 task review | Worker panics bypassed fixed errors/cleanup, and the documented live command changed directories before loading the root `.env`. | Resolved in `e8a8f5f`: each worker converts panics to one fixed result and cleanup is proven; the exact runnable root sequence is contract-tested. |
| M0-05 task review | Successful and partial create responses could authorize cleanup without re-fetching the provider-stored run marker; DELETE 204 responses were not reconciled. | Resolved in `ba0d2b3`: exact provider annotation value/type/ID now gates database access and deletion, branch-only emergency cleanup retains that proof, and both 200/204 delete outcomes require exact active-list absence. |
| M0-05 re-review | Valid but stale branch or endpoint identifiers in malformed create responses could override stronger provider-listed ownership and strand the proof branch. | Resolved in `37d638f`: incomplete responses provide no identifier authority, provider branch/annotation proof is established independently, and endpoint/hint mismatches block database access while preserving exact cleanup. |
| M0-06 task review | The committed README contract was red, and strict redrive-policy parsing accepted duplicate known JSON keys. | Resolved in `4b8ae34`: the documented boundary and focused/full gates pass with corrected evidence, and recursive duplicate-key validation rejects duplicate policy and nested-envelope members. |
| M0-06 re-review | Go's case-insensitive struct-field matching allowed case-variant JSON aliases to bypass exact-key policy and envelope validation. | Resolved in `ba02323`: recursive exact JSON-tag schema validation rejects 42 alias forms across every policy, envelope, and nested-event member while preserving duplicate, unknown, trailing, malformed, null-container, and type checks. |
| M0-07 task review | Non-idempotent KMS key creation inherited SDK retries, prefix-wide audits could miss extra proof resources, and several definite post-create results were not retained early enough for cleanup. | Resolved in `8617ca7`: key creation is single-attempt, preflight/final audit reject prefix extras and duplicate proof keys, and staged key/alias/object targets plus exact ambiguous-write reconciliation preserve fail-closed cleanup. |
| M0-07 task review | Readiness did not enforce hard body/time limits, pre-orchestrator construction could escape the fixed-output boundary, and the endpoint validator accepted a slash path. | Resolved in `8617ca7`: readiness has byte and absolute-time caps, all construction/orchestration failures emit one fixed line, and only an exactly empty endpoint path is accepted; final re-review found no remaining issues. |
| M0-08 task review | Index ownership did not validate the proof discriminator, and definitive HTTP failures could reconcile overwrite-capable document writes or adopt pre-existing exact-looking resources. | Resolved in `cb54031`: exact proof metadata now gates inspection/reconciliation/cleanup, non-2xx mutations are definitive, document writes are create-only, and only ambiguous applied-success outcomes may reconcile exact provider state. |
| M0-08 re-review | Unexpected successful 2xx mutation statuses were classified as definitive, so an applied index or document could bypass reconciliation and strand owned state. | Resolved in `959f033`: unexpected 2xx outcomes are ambiguous while non-2xx remains definitive; applied-exact, unapplied, and mismatched index/document regressions pass and final re-review found no remaining issues. |
| PROV-01 final review | The implementation reached zero remaining Critical, Important, and Minor findings, but exact-pinned LocalStack 4.7.0 returned no SourceIdentity and accepted the deliberately wrong SourceIdentity despite the trust condition. | PROV-01 is Blocked, not Complete. M0-10 is Complete only under the fixture-only Cartography delivery waiver; M0-09 stays Blocked and R-03 remains incomplete. Resume PROV-01 only with provider evidence for both required SourceIdentity behaviors. |
| M0-10 final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after the lifecycle, ownership, parsing, portability, and waiver-contract fixes. | Complete August 14, 2026 under the fixture-only Cartography delivery waiver after two consecutive live passes, exact zero-resource cleanup audits, pinned local gates, and redacted secret scans; no AWS/GitHub authorization-parity claim. |
| M0-11 final review | The final scoped implementation re-review found zero remaining Critical, Important, or Minor findings after definitive mutation classification, global absence audit, full runtime ownership, late-mutation settlement, and adapter-license evidence fixes. | Complete August 14, 2026 after the exact fixture-only live proof, linked normalized evidence capture, exact zero-resource cleanup, shared-target non-mutation, pinned local gates, license/secret audits, and zero-finding review; R-06 is PASS without a real-AWS parity claim. |
| M0-12 final review | The final scoped implementation re-review found zero remaining Critical, Important, or Minor findings after cleanup authorization, deadline, image-digest, concrete lifecycle, workload-identity, mutation-result, ownership, and evidence-boundary fixes. | Complete August 14, 2026 after two consecutive final-code live passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; R-07 is PASS under the approved observation-only boundary. |
| M0-13 final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after bounded child supervision, mutation settlement, retained pre-verification cleanup authority, concrete runtime coverage, and fixed-output taxonomy alignment. | Complete August 14, 2026 after two consecutive final-code exact Collector passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; R-12 remains Not run until M0-22 proves bounded remote-export failure behavior. |
| M0-14a final review | The final scoped implementation review found zero remaining Critical, Important, or Minor findings after bounded mutation settlement, initialization candidate retention, raw HTTP-byte validation, schema/start/remove reconciliation, coherent cleanup snapshots, and immutable cross-correlated private-network ownership. | Complete August 14, 2026 after two consecutive final-code exact Nango/PostgreSQL passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding independent review; R-08 was deferred to M0-15. |
| M0-14b final review | The final scoped pre-landing review found zero remaining Critical, Important, or Minor findings after live API-shape, exact Docker attachment, complete TLS-workspace identity, ambiguous lifecycle, coherent cleanup, and synthetic-secret scan fixes. | Complete August 15, 2026 after two consecutive final-code exact OAuth passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 was deferred to M0-15. |
| M0-14c final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact live provider-schema/header corrections and strict bounded synthetic-key validation. | Complete August 15, 2026 after two consecutive final-code exact API-key passes, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 was deferred to M0-15. |
| M0-14 final review | The evidence and status review found zero remaining Critical, Important, or Minor findings after binding the source task, PRD, accepted proof chain, exact exclusions, aggregate counts, and hostile status/risk mutations. | Complete August 15, 2026 as an evidence-only Auth-plus-Proxy boundary record with pinned local gates, audit, license and secret scans; R-08 was deferred to M0-15. |
| M0-15 final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact live Proxy response validation and duplicate wire-header rejection. | Complete August 15, 2026 after two consecutive final-code private Proxy passes, product-only secrecy capture, exact zero-resource cleanup audits, pinned local gates, license/secret scans, and zero-finding review; R-08 is PASS. |
| M0-16 final review | The whole-range review found zero remaining Critical, Important, or Minor findings after exact workspace, network, container, mutation-settlement, readiness, global-absence, normalization, and retained-resource ownership fixes. | Complete August 15, 2026 after two consecutive final-code exact Promptfoo passes, product-only objective/verdict/evidence capture, exact zero-resource cleanup audits, shared-resource non-mutation, pinned local gates, license/secret scans, and zero-finding review; R-09 is PASS. |

## Execution notes

- The pre-existing UI is a browser-local prototype. It currently persists demo
  actions in local storage and does not call the product API.
- The repository passed 20 tests, type-check, and production build under Node
  22.23.1 at preflight. Lint reported 37 errors and is part of `PRE-01`.
- Node 26 exposes an experimental global `localStorage` that conflicts with the
  current Vitest DOM setup. The project uses Node 22 types and is pinned to
  verified Node 22.23.1 as part of completed `PRE-01`.
- On hosts with Homebrew libvips, dependency installation must set
  `SHARP_IGNORE_GLOBAL_LIBVIPS=1` so the locked Sharp binary is used.
- `PRE-01` completed with pinned Node 22.23.1/npm 10.9.8, a root verification
  command, and a clean lint baseline. No source-plan task status changed.
- `PRE-02` completed with a GitHub Actions gate for pushes and pull requests.
  It pins Node 22.23.1/npm 10.9.8, uses the documented locked install, and
  runs `npm run verify`; a parsed-workflow test protects that contract.
- The first remote gate passed but warned that the original v4 action pins used
  deprecated Node 20 runtimes. The gate now pins the current official v7 action
  releases by immutable SHA; both declare the Node 24 action runtime.
- `M0-01` completed after independent review confirmed all 14 proof gates and
  the supported EKS Fargate scheduling signal.
- `M0-02` resumed after Test-prefixed Stytch credentials became available in a
  separate ignored environment file. The values are not copied into this
  repository or emitted by proof output.
- `M0-02` completed after its stricter disposable flow passed live against
  Stytch Test, a pinned Gitleaks v8.30.1 full-history scan found no leaks, all
  61 repository tests and quality gates passed, and independent re-review
  approved the two security fix areas with no remaining findings.
- `M0-03` completed with the exact-pinned official Stytch Node SDK after its
  fresh-local and forced-remote paths passed the disposable live proof, all 77
  repository tests and quality gates passed, production dependency audit and
  pinned full-history secret scan were clean, and independent review found no
  Critical, Important, or Minor issues.
- `M0-04` completed after its hardened effective pgx configuration, panic
  cleanup, and runnable documentation passed independent re-review with no
  remaining findings. The live proof completed ten concurrent pooled reads,
  reported zero acquired connections, and closed under hostname-verifying TLS.
- `M0-05` completed after a current-code live run applied and reverted the
  embedded migration, restored the exact namespace fingerprint, deleted the
  disposable branch, and found zero active proof branches. The final
  independent re-review found no remaining issues after two cleanup-ownership
  fix rounds; Neon soft deletion means the evidence does not claim immediate
  physical erasure.
- `M0-06` completed after the exact-pinned AWS SDK created and freshly proved
  a tagged Standard queue/DLQ, round-tripped strict redrive policies and one
  two-event Organization-scoped message, proved the source empty, and found
  zero proof queues after cleanup. LocalStack evidence does not claim IAM
  enforcement or real-AWS parity. Final independent re-review found no issues.
- `M0-07` completed after direct KMS encryption/decryption, one default-plus-
  explicit SSE-KMS Organization-scoped object, and one KMS-backed current
  secret all round-tripped in an exact-digest disposable LocalStack target.
  Prefix-wide audit proved zero active proof resources and exactly the tracked
  pending-deletion key; the container was absent and shared development
  infrastructure was unchanged. Local evidence does not claim real-AWS
  encryption, IAM, durability, or release parity. Final re-review found no
  remaining issues.
- `M0-08` completed after an exact-image disposable OpenSearch target indexed
  one strict metadata-only Organization A session event. The scoped EventStore
  returned exactly one matching session/environment hit for A and zero for B,
  then prefix-wide audit found zero active proof indices and the disposable
  container was absent. This local proof does not claim AWS OpenSearch Service,
  IAM, durability, or release parity. Final independent re-review found no
  remaining issues.
- `M0-09` has a fully reviewed real-AWS harness but is Blocked because no
  isolated two-account fixture or task-specific credentials are available.
  LocalStack cannot satisfy its release-parity gate.
- The user approved PROV-01 as a temporary, non-source-plan compatibility proof.
  It uses a separate disposable LocalStack IAM/STS target and cannot modify or
  complete M0-09/R-03. PROV-01 is Blocked on the exact LocalStack
  SourceIdentity/trust-condition capability dependency. M0-10 is Complete
  only under the fixture-only Cartography delivery waiver and makes no AWS or
  GitHub authorization-parity claim.
- M0-10 is Complete after its root commands exposed only the hermetic
  two-Organization Cartography fixture proof. It accepts no dotenv,
  credential, or proxy input, makes no AWS or GitHub calls, and cleans up only
  proof-owned disposable resources. This does not prove AWS/GitHub authorization
  parity: M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.
- M0-11 is Complete as a fixture-only Prowler evidence proof after one exact
  live run, cleanup audit, repository gates, license/secret scans, and a
  zero-finding independent re-review passed. R-06 is PASS with that retained
  evidence. M0-09 and PROV-01 remain Blocked, and R-03 remains incomplete.
- M0-12 is Complete after two consecutive final-code exact-pinned disposable
  Tetragon/Kubernetes runs produced process, file, and outbound TCP signals with
  one shared Kubernetes workload identity, explicit capability/drop state, exact
  cleanup, pinned gates and scans, and a zero-finding independent review. R-07
  is PASS under the approved observation-only boundary.
- M0-13 is Complete after two consecutive final-code exact-pinned Collector
  runs retained one trace/span with all six semantic identity attributes,
  disabled remote export, proved exact cleanup, passed pinned gates/scans, and
  received zero-finding independent review. R-12 remains Not run until M0-22
  proves bounded remote export and nonblocking exporter-failure behavior.
- M0-14a is Complete after two consecutive final-code runs of the exact free
  self-hosted Nango server with PostgreSQL as its only long-running dependency
  proved database-backed readiness from a one-shot client on a private product
  network, exact cleanup, zero-resource audits, pinned gates/scans, and a zero-
  finding independent review. R-08 was deferred to M0-15 and is now PASS.
- M0-14b is Complete after two consecutive final-code exact-pinned private
  fixture-provider OAuth runs through a product-owned wrapper retained only a
  durable Nango connection reference, proved exact zero-resource cleanup, and
  passed pinned gates and scans. It introduces no real provider credential or
  host publication and did not independently advance R-08; M0-15 later did.
- M0-14c is Complete after two consecutive final-code exact-pinned private fixture-provider
  API-key runs retained only the durable Organization-scoped connection reference,
  proved the raw key absent from product state, cleaned every exact-owned resource,
  and passed pinned gates and scans.
- M0-14 is Complete as an evidence-only boundary record: free self-hosted
  Nango is accepted for long-tail Auth plus Proxy, while Functions, Webhooks,
  MCP, RBAC, full observability, and Enterprise features remain out of scope.
  M0-15 is Complete after two consecutive authenticated private Proxy GETs,
  exact product-state secrecy and cleanup evidence, pinned gates/scans, and a
  zero-finding whole-range review. R-08 is PASS.
- M0-16 is Complete after two consecutive final-code exact-pinned Promptfoo
  runs executed one synthetic direct prompt-injection case against a local fake
  agent, retained only the objective, vulnerable verdict, and SHA-256 evidence
  reference, proved exact zero-resource cleanup and shared-resource
  non-mutation, and passed pinned gates, scans, and zero-finding review. R-09
  is PASS.
- M0-17 is Complete after two consecutive direct final-code OPA Go SDK proofs
  returned deterministic Allow/Block decisions with decision-specific p95 well
  below 10 ms, plus exact dependency/license audits, full gates, scans, and
  zero-finding whole-range review. R-10 is PASS. M0-18 is Blocked.
- M0-18 is Blocked with a reviewed real-provider-only Fargate proof boundary. The
  current capability audit has no real AWS credentials, authenticated EKS
  kubeconfig, disposable Fargate profile, product proxy endpoint, or test
  canary credential, so no cluster request has been made. LocalStack's embedded
  k3s/k3d EKS compatibility cannot advance M0-18 or R-11.
- M0-19 is In progress with a real-provider-only Security Groups for Pods and
  branch-ENI evidence boundary. M0-18 remains Blocked; R-11 remains Not run and
  M0-20 remains Pending.
