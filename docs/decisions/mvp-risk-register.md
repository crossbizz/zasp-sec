# MVP external and OSS proof risk register

## Purpose and decision rule

This register records the M0 proof gates for dependencies and platform
assumptions that can invalidate an MVP architecture decision. A **PASS** or
**FAIL** is recorded only after its named proof has run and its retained
evidence is linked from this file. Until then, the status is **Not run**;
neither an implementation plan nor vendor documentation is proof evidence.

For every FAIL, the listed owner must record a replacement, scope reduction, or
explicit MVP stop decision before dependent work starts. M0-23 is the final
gate that records the resulting architecture decisions; it must not mark an
unresolved proof as passed.

| ID | Uncertainty and proof boundary | Objective PASS criterion | Objective FAIL criterion | Owner and decision consequence | Initial status |
| --- | --- | --- | --- | --- | --- |
| R-01 | **Stytch B2B sessions.** Fresh B2B session JWT validation must use the documented local-validation path when eligible; old or expired tokens must follow normal remote refresh/auth behavior. | A non-production test login creates a session without repository secrets; an eligible fresh JWT validates locally; an expired/old JWT follows the documented remote path and is not accepted locally. | The test session cannot be created, a fresh eligible JWT cannot validate locally, or an expired/old JWT is locally accepted or silently extended. | Identity owner: block Stytch-dependent identity work and choose a compliant identity-path decision before M1/M2. | Not run — M0-02/M0-03 |
| R-02 | **Neon Postgres.** Product connections use a pooled application URL; migrations use a direct connection on a disposable branch. | Ten concurrent reads through the pooled URL complete with no connection leak, and one up/down migration through the direct URL returns the disposable branch schema to baseline. | Any concurrent read fails/leaks, the pool cannot be used, or the down migration does not restore baseline. | Data owner: do not build product persistence on the proposed Neon connection split; resolve provider/configuration or replacement before M1. | Not run — M0-04/M0-05 |
| R-03 | **LocalStack and real AWS are distinct authorities.** LocalStack covers supported local AWS behavior; real AWS is the release-parity authority for IAM. | LocalStack creates SQS/DLQ, sends/receives a batched event with asserted redrive attributes, and round-trips an encrypted S3 object and secret through the AWS SDK abstraction. Separately, a disposable real-AWS cross-account read-only role permits one allowed call and rejects one denied call. | Any stated LocalStack round trip/assertion fails, or either real-AWS authorization result differs from the policy. A LocalStack-only result cannot pass the real-AWS gate. | Platform owner: stop treating the failing operation as locally supported or as release parity; correct the abstraction/test environment or make an explicit architecture decision before M1A/M3. | Not run — M0-06/M0-07/M0-09 |
| R-04 | **OpenSearch and SQS event flow.** SQS is durable batch transport; OpenSearch is an Organization-scoped query projection, not the source of truth. | A disposable OpenSearch target indexes one session event, and a query filtered by that session and environment returns exactly the expected event; the LocalStack SQS proof also demonstrates the batched message/DLQ contract. | The expected event cannot be indexed or retrieved by the scoped filter, cross-scope data is returned, or the SQS batch/DLQ contract fails. | Event-plane owner: do not proceed with the proposed archive/index/correlation flow; revise projection or queue design before M3. | Not run — M0-06/M0-08 |
| R-05 | **Cartography normalization.** Vendor graph output must be reconciled into product-owned labels and Organization scope. | Two minimal AWS/GitHub fixtures for different Organizations emit required source IDs and relationships in separate Organization scopes, with no collision and no customer-visible Cartography labels. | A required ID/relationship is absent, the fixtures collide or cross scopes, or Cartography labels appear in the product-normalized output. | Discovery owner: block Cartography adapter adoption until the namespace/normalization design or alternative inventory path is decided. | Not run — M0-10 |
| R-06 | **Prowler evidence normalization.** A relevant cloud-posture finding must map to product evidence. | A minimal AWS fixture produces one relevant Prowler finding that maps to a canonical resource ID and normalized evidence. | No relevant finding is produced, or it cannot map to both a canonical resource ID and normalized evidence. | Discovery owner: block Prowler-derived MVP findings; revise the adapter or choose another evidence source. | Not run — M0-11 |
| R-07 | **Tetragon runtime signal quality.** Tetragon is runtime observation, not semantic truth, and must show usable workload identity and sensor health. | One supported Linux/Kubernetes test workload yields process, file, and outbound-network events sharing workload identity; the sensor reports capability and drop state. | Any required event class or shared workload identity is absent, or capability/drop state is unavailable. | Runtime-sensor owner: do not claim required runtime coverage; narrow supported environments or select an alternate signal before M3. | Not run — M0-12 |
| R-08 | **Nango free self-hosted Auth + Proxy boundary.** Only Auth and Proxy are in MVP; Functions, Webhooks, MCP server, RBAC, and Enterprise-only runtime features are excluded. | The free self-hosted build health endpoint is reachable from the product test network; OAuth and API-key fixture connections return durable references through the product wrapper; the API-key proof stores no raw provider key in product state; an authenticated proxied GET succeeds with no raw provider token persisted; the recorded boundary explicitly excludes Functions, Webhooks, and MCP. | The service cannot boot/reach health, either connection cannot yield the required reference, raw provider credentials/tokens persist in product state, proxy GET fails, or the design requires an excluded feature. | Connector owner: keep Nango off the core connector/runtime path; resolve the wrapper/boundary or choose a replacement for long-tail connectors before M3. | Not run — M0-14a through M0-15 |
| R-09 | **Promptfoo red-team normalization.** Promptfoo is the sole required MVP red-team engine. | One prompt-injection case against a local fake agent target produces a result normalized to an objective, verdict, and evidence reference. | The case cannot run or its result cannot produce all three normalized fields. | Safe-testing owner: block Promptfoo-backed MVP red-team results and decide a compatible orchestration path before M5. | Not run — M0-16 |
| R-10 | **Embedded OPA.** Runtime allow/block evaluation uses the OPA Go SDK in-process and remains deterministic on the fast path. | In-process OPA evaluation returns the expected Allow and Block decisions deterministically and meets the proof's recorded local latency sanity threshold. | Either decision is wrong or nondeterministic, or measured latency exceeds the recorded threshold. | Runtime-policy owner: do not adopt embedded OPA for the synchronous gateway path until policy evaluation or the architecture decision is corrected. | Not run — M0-17 |
| R-11 | **EKS Fargate Attack Lab isolation and egress.** The lab uses a disposable Fargate profile, test credentials, observed canary criteria, cleanup, Security Groups for Pods, and the product egress proxy; native Kubernetes NetworkPolicy is not relied on. | A canary Pod runs on an existing disposable EKS Fargate test profile, the canary criterion is observed, and run resources are deleted. With the SecurityGroupPolicy allowing only required cluster/DNS and proxy paths, direct undeclared egress fails while allowed proxy egress succeeds. | The Pod is not Fargate-scheduled, the canary criterion is not observed, cleanup is incomplete, direct undeclared egress succeeds, or allowed proxy egress fails. | Attack-Lab/platform owner: block Fargate as the MVP strong-isolation provider; remediate isolation/egress or choose a safer verification environment before M5. | Not run — M0-18/M0-19 |

## Evidence recording

When a proof runs, replace only its corresponding initial status with `PASS —
M0-xx — <evidence path or run identifier>` or `FAIL — M0-xx — <evidence path
or run identifier>`, and append the decision consequence actually taken. Do
not use a pending vendor account, an unrun command, or a local emulation result
as evidence for a real-AWS requirement.

## Scope guardrails

- This register establishes proof criteria only; it does not implement a
  dependency, connector, runtime component, or production environment.
- LocalStack proof coverage is intentionally limited to supported AWS SDK
  behavior. Real AWS is separately required for IAM/release parity.
- Nango remains a private internal Auth + Proxy service with a separate
  database/schema and encryption key; it is not required for core connectors
  or runtime enforcement.
- Runtime policy decisions remain local to the gateway; an external service or
  asynchronous worker cannot become an allow/block dependency.
