# Claude Enterprise inference hooks

An organization administrator can point a Claude Enterprise inference hook at a dedicated Zasp API deployment. The receiver handles one configured provider tenant and one Zasp Environment. It starts disabled. Local fixtures exercise the signed protocol. An enabled Enterprise organization is required to measure actual traffic, observe Claude's response to a verdict and approve a rollout. [Anthropic endpoint contract](https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint) · [Anthropic configuration](https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration)

## Provision the receiver

1. Create a dedicated Zasp API token scoped to the intended Environment with `decide_actions` as its sole permission. Record its credential ID and token. A tenant-wide webhook needs an unbound credential. Use a separate credential for each integration and deployment.
2. Allocate a stable Zasp product ID for the integration. Generate an independent random 32-byte reference key and encode it with standard Base64. Keep the same reference key, integration ID and credential across replicas and restarts so signed retries resolve to the original decision.
3. Configure the HTTPS URL `https://YOUR_PUBLIC_HOST/api/v1/runtime/provider-hooks/claude-enterprise/INTEGRATION_ID` in the organization's Enterprise inference-hook control. Use the organization's configured signing secret and exact tenant identifier. Route the hook through the normal trusted HTTPS proxy. Allow uncompressed requests up to the provider's 64 MiB limit on this exact path and disable request-body capture on the proxy, WAF and telemetry exporters. The raw provider frame can contain transcripts and tool arguments.
4. Mount a read-only, owner-controlled secret file and set `ZASP_CLAUDE_ENTERPRISE_HOOK_FILE` to its absolute path on the API deployment. Use file mode `0400` or `0440`. Grant read access only to the service account and authorized operators. Restart the API replicas to load the mapping.

The following template uses placeholders. Supply the tenant and signing secret from the provider's administration boundary and the Zasp scope IDs from the authenticated Environment.

```json
{
  "integration_id": "INTEGRATION_PRODUCT_ID",
  "tenant_id": "PROVIDER_TENANT_ID",
  "organization_id": "ORGANIZATION_PRODUCT_ID",
  "workspace_id": "WORKSPACE_PRODUCT_ID",
  "environment_id": "ENVIRONMENT_PRODUCT_ID",
  "credential_id": "SCOPED_TOKEN_PRODUCT_ID",
  "webhook_signing_secret": "whsec_BASE64_SIGNING_SECRET",
  "reference_key_base64": "BASE64_RANDOM_32_BYTES",
  "workload_token": "DEDICATED_ENVIRONMENT_TOKEN"
}
```

Ordinary frames must name the configured provider tenant. A signed configuration-test prompt may omit the tenant. It receives the same prompt policy as ordinary traffic. `source.application` is advisory. The receiver verifies the Standard Webhooks v1 HMAC-SHA256 over the exact body, delivery ID and timestamp and allows five minutes of clock skew. Synchronize the API host clock. A malformed configuration prevents API startup. Removing the environment setting and restarting restores the disabled receiver, which returns HTTP 404.

## Choose and test a policy

| Provider frame | Zasp policy trigger | Usable equality fields |
| --- | --- | --- |
| Prompt | `runtime` | `action=claude.prompt`, `resource=claude.prompt`, `environment_id` |
| Tool frame | `tool` | `action=claude.tool_frame`, `environment_id`, or a resource class such as `claude.tool_frame.platform`, `.application`, `.third_party`, `.client`, `.mixed` or `.unknown` |
| Provider configuration test | `runtime` | Same prompt classification and rules as an ordinary request. |

The authenticated provider can submit one frame with several tool requests. Zasp returns one allow or deny verdict for the complete frame. On a mixed frame, both the mixed classification and each reported constituent origin participate in equality matching. A policy blocking third-party tools also blocks a mixed frame containing one. Anthropic documents exceptions for tools its own applications omit from inference hooks. Provider fields naming an actor, tool or session do not establish a Zasp principal or managed agent. A potentially applicable rule that requires an unavailable identity yields HTTP 422. The credential's service principal is available for token audit only. Unknown future frame types receive an allow response after authentication as prescribed by the provider protocol and produce no Zasp coverage receipt.

Start with an Environment policy in monitor rollout and enable the provider's shadow setting. Have an authorized employee submit an ordinary harmless prompt and a harmless tool request. Confirm the inferred frame class, the Zasp decision and the provider's own observation. An enforced Zasp block maps to a provider `deny` with the Zasp decision ID as `reference_id`. Monitor rules can record `would_block` and return `allow`. Exercise the organization's fail-open or fail-closed setting and the provider timeout deliberately in staging. Record the actual client result and a harmless independent target readback before asserting prevention.

Zasp budgets 400 ms per callback, including signature checks and fresh authorization. Two active frames per replica can be processed concurrently. Excess concurrency or an unavailable dependency produces a non-success response. A timeout or HTTP error is handled by the provider's configured failure policy. The actual result depends on the provider's timeout, shadow mode and network path. Measure p50, p95, p99 and error/timeout rates at the tenant's expected frame sizes and concurrency before enforcement.

## Receipts, retries and rotation

PostgreSQL stores the scoped decision, opaque keyed delivery and frame references, policy revision and bounded classification. It can retain a keyed provider session reference as source metadata. Zasp sends neither the transcript, user email, tool arguments nor the raw session identifier into the decision ledger. Observing a verdict cannot establish whether Claude ran a tool. The outcome API refuses execution reports on provider-hook decisions.

A signed retry with the same ID and bytes returns the stored verdict across replica restarts. Reusing that ID with different signed bytes produces HTTP 409. Rotate the provider signing secret together across replicas during a controlled rollout. The previous secret is no longer accepted by updated replicas. Keep the reference key and dedicated credential stable across signing-secret rotation. Replacing either changes the replay boundary. Drain pending deliveries and record the cutover before replacing them or moving the integration to another Environment.

## Local callback measurements

On November 22, 2026, ten runs exercised the guarded R7 schema on a shared Linux 6.18.57 x86-64 build host with a four-CPU cgroup quota and 16 GiB memory limit. The signed callback, native Zasp token, policy evaluator and PostgreSQL 18 service login ran locally. The authorization test fixture supplied the OpenFGA decision and projection. Go ran with `GOMAXPROCS=2`.

Each run created a fresh test scope. It sent a wrong-Environment delivery, an enforced prompt, the identical prompt again, a conflicting signed body with the original delivery ID, and a tool frame. Nine runs completed all five deliveries. In the tenth, the prompt reached the **400 ms deadline** and returned HTTP 503. The suite ended that run at the failed prompt. These measurements use the original single-attempt client.

| Signed deliveries | Count | Median | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| All attempted deliveries, including wrong scope, retries and conflicts | 47 | 107.4 ms | 192.1 ms | 408.5 ms |
| First prompt or tool frame requiring a new decision | 19 | 137.8 ms | 408.5 ms | 408.5 ms |

Go runtime tracing measured from callback-handler launch until its caller resumed after the response or deadline. The maximum includes scheduler wake-up after the 400 ms timer. Percentiles use the nearest rank. The sample describes local processing of small synthetic frames. Provider round-trip timing, network and TLS, partner authorization, representative frame sizes, sustained concurrency and shadow-mode behavior still require measurement in the Enterprise pilot.

A separate run used a fresh PostgreSQL installation of the sealed release artifact `93f816f311bae3bf0105c45979125d2c4d6ea93290e3ed54c37dadd16b046ebb`. The first enforced prompt completed in 309.5 ms, its replay in 130.8 ms and the allowed tool frame in 229.7 ms. After the administrator revoked the integration token, the product API rejected both the old delivery and a new signed delivery with HTTP 401. The provider endpoint returned HTTP 503 for both and the ledger still held exactly the two original decisions. This run completed without a client retry.
