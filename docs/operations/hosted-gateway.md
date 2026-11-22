# Hosted gateway

Zasp hosts a gateway between your agents and what they talk to: their remote MCP servers and their model providers. It enforces the Environment's policy on each request in flight and records every decision.

## The agentless model

Nothing is installed in your environment. No sidecar, no proxy, no agent, no SDK.

What changes at your side is one address in the agent's configuration, and one credential:

| | Before | With the hosted gateway |
| --- | --- | --- |
| MCP server URL in the agent's MCP configuration | `https://mcp.example.org/mcp` | `https://<your Zasp address>/api/v1/gateway/mcp/<gateway server id>` |
| Model SDK base URL | the provider's | `https://<your Zasp address>/api/v1/gateway/llm/v1` (chat completions, responses) or `https://<your Zasp address>/api/v1/gateway/llm` (messages) |
| Credential the agent presents | the server's or provider's own | a Zasp API token in `Authorization`, and the server's or provider's own credential in `X-Zasp-Upstream-Authorization` |

Your MCP server's credential and your provider's key travel in a header of each request. Zasp forwards them for that request and does not store or log them. The Zasp token is never sent upstream.

Two alternatives exist for those who want them. Neither is required, and neither is part of the agentless path:

- **A gateway you already run** (LiteLLM, Kong, your own proxy) can ask Zasp for a decision per interaction and enforce it itself: [guardrail decision API](guardrail-decision-api.md). Still nothing of Zasp's is installed; the enforcement point is yours.
- **The in-cluster sensor** observes agent runtimes inside your cluster. It is installed software and is optional.

## What the gateway does

**MCP gateway** (`POST /api/v1/gateway/mcp/{id}`). It speaks the MCP Streamable HTTP transport to the agent and to the registered upstream server.

- A server that is **blocked** in the MCP registry is refused. A server the registry has no decision for is allowed or refused according to the gateway policy.
- `tools/list` answers are filtered: tools on the server's deny list, tools outside a non-empty allow list, tools of a risk class the policy denies, and tools whose description matches a guardrail rule in block mode (an instruction planted in a description) are removed. The tool's risk class comes from the words of its name (`run_shell` is execute, `create_issue` is write).
- `tools/call` is refused for a tool the policy does not allow. Its arguments and its result go through the guardrail detectors: a match of a blocking rule stops the call or replaces the result, a match of a redacting rule is replaced by `[REDACTED:<rule>]`. A blocked call or result is answered as a failed tool call (`isError: true`), so the model sees a tool error and can continue. Tool results are the indirect prompt injection path, and this is where it is closed.
- Results of `resources/read` and `prompts/get`, the server's `instructions`, and messages the server sends during a request (progress, logging) are inspected the same way.
- Each API token is rate limited. The limit is one limit for the token however many API replicas serve it.

**Model proxy** (`POST /api/v1/gateway/llm/v1/chat/completions`, `/responses`, `/messages`).

- The request's messages are inspected, tool results among them. A prompt that matches a blocking rule is refused with `400` and code `guardrail_blocked`, and the provider is not called. Sensitive data is redacted before the provider sees it. A system prompt is inspected for sensitive data only: it is the operator's text, and may legitimately speak about instructions.
- The answer's text and tool-call arguments are inspected, streamed answers included.
- Requests go only to the providers of the gateway's catalog.

The detectors are the deterministic ones of the guardrail policy (regular expressions, phrase lists, checksums; no model call). They are heuristics: see [what they match](guardrail-decision-api.md#rules). An `allow` means nothing known matched, not that the text is safe.

## Turning it on

The gateway is served by the API and is **off by default**. While it is off its traffic routes answer `404`; the policy, the registered servers and the activity can still be prepared and read.

In the chart:

```yaml
hostedGateway:
  enabled: true
  timeoutSeconds: 300          # one exchange, a stream included
  egressCIDRs: ["0.0.0.0/0"]   # where the API pods may go on port 443 for the gateway
  decisionRetentionDays: 90    # how long decision records are kept
```

With Terraform: `hosted_gateway = { enabled = true, egress_cidrs = ["0.0.0.0/0"] }`.

This sets `ZASP_HOSTED_GATEWAY_ENABLED=true` and `ZASP_HOSTED_GATEWAY_TIMEOUT` on the API, adds a NetworkPolicy that lets the API pods reach the listed addresses on TCP 443 (with the private, shared, link-local and loopback ranges carved out of `0.0.0.0/0`), and adds an ingress for the two traffic prefixes with a 4 MB body limit, the gateway's timeout and no response buffering. Every other route of the API keeps its limits.

Why the egress is so wide: a customer's remote MCP server can be anywhere, and NetworkPolicy matches addresses, not names. A deployment that fronts only known upstreams lists their ranges instead. Independent of the network policy, the gateway's own client refuses, at every connection and after name resolution, any address that is not public (private, loopback, link-local including the cloud metadata address, carrier NAT, and the IPv6 ranges that embed IPv4), speaks only HTTPS on port 443, uses no proxy and follows no redirect.

The gateway runs inside the API process, so its traffic shares the API's replicas. Size them for the traffic you route: a stream holds a connection and a goroutine for its length. A separate deployment for the gateway was not built.

## Setting up

### 1. Create a token

Administration, API Access, token use **Hosted gateway only**. Or over the API: `POST /api/v1/admin/api-tokens` with `"permissions": ["use_gateway"]`.

`use_gateway` is a permission of API tokens only. No role holds it. A token created with it alone can send traffic through the gateway and can read nothing: not the inventory, not findings, not the policy, not the gateway's own activity. The person who creates the token must be able to view the Environment; if they lose that access, the token stops working. Use one token per agent or per runtime, so that the rate limit and a revocation are scoped.

A gateway token is long-lived by nature. A token that holds `use_gateway` and nothing else, or `use_gateway` with `decide_guardrails`, reads nothing, so it may live up to 365 days, like a token of `decide_guardrails` alone; the API Access page offers "1 year" for it. With any other permission beside it the token may live 90 days. The Environment's own limit (API Access, **Longest token lifetime**) lowers both. Choose the expiry your rotation practice needs, and rotate the token from the same page; a rotation keeps the expiry.

### 2. Register an MCP server (for MCP)

Tools & MCP, **MCP servers behind the hosted gateway**, Register a server: a name and the server's `https` address. The address has no credentials, no query string and no port other than 443. The page then shows the gateway address for that server. Over the API:

```sh
curl -sS -X PUT "$API/api/v1/gateway/mcp-servers/$SERVER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: gateway-server-0001' -H 'If-Match: "0"' \
  -d '{"name":"Tickets","upstream_url":"https://mcp.example.org/mcp","enabled":true,"allowed_tools":[],"denied_tools":["delete_ticket"]}'
```

`$SERVER_ID` is a product identifier you choose (`pid_` followed by a UUID). Reading needs `view`; registering and removing need `manage_workflows`.

The registry decides a server by its host: approve or block `host:mcp.example.org` under MCP servers, exactly as for a discovered server.

### 3. Point the agent at the gateway

MCP, in the agent's MCP configuration:

```json
{
  "mcpServers": {
    "tickets": {
      "type": "http",
      "url": "https://<your Zasp address>/api/v1/gateway/mcp/<gateway server id>",
      "headers": {
        "Authorization": "Bearer <Zasp token>",
        "X-Zasp-Upstream-Authorization": "Bearer <the MCP server's own token>",
        "X-Zasp-Agent-Id": "<the agent's id in the Zasp inventory>"
      }
    }
  }
}
```

Models, chat completions and responses format. The SDK's key is the Zasp token; the provider's key is a default header:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://<your Zasp address>/api/v1/gateway/llm/v1",
    api_key="<Zasp token>",
    default_headers={"X-Zasp-Upstream-Authorization": "Bearer <provider key>", "X-Zasp-Agent-Id": "<agent id>"},
)
```

Models, messages format. The Zasp token is the SDK's bearer token (`auth_token`) and the provider's key is a default header. The SDK takes either `auth_token` or `api_key`, not both, so the provider's key cannot stay in `api_key`:

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="https://<your Zasp address>/api/v1/gateway/llm",
    auth_token="<Zasp token>",
    default_headers={"X-Zasp-Upstream-Authorization": "Bearer <provider key>", "X-Zasp-Agent-Id": "<agent id>"},
)
```

The two SDK configurations were run as written, with openai 3.51.0 and anthropic 2.8.0, against a local stand-in for the provider: complete and streamed answers, the Responses stream, a refused prompt (the SDK raises its `BadRequestError` with code `guardrail_blocked`) and a stream the gateway cuts (the SDK raises). The MCP gateway was run between the client and the server of the official MCP Python SDK 2.3.0, with the same two headers. The JSON form of an agent's MCP configuration above depends on the agent product and was not tried with one. See [What was verified](#what-was-verified).

Headers the gateway reads:

| Header | Meaning |
| --- | --- |
| `Authorization: Bearer <Zasp token>` | Authenticates the agent to the gateway. Never forwarded. |
| `X-Zasp-Upstream-Authorization` | The upstream's own credential. For an MCP server its value is sent as the upstream's `Authorization`. For a provider it is the API key (with or without `Bearer `), sent in the provider's own key header. A plain HTTP client of the messages route may send the key in `x-api-key` instead. |
| `X-Zasp-Upstream-Provider` | The provider of the catalog: `openai` (default for chat completions and responses), `anthropic` (default and only one for messages), `azure_openai`. |
| `X-Zasp-Upstream-Host` | For `azure_openai` only: `<resource>.openai.azure.com`. Any other host is refused. |
| `X-Zasp-Agent-Id` | Recorded with each decision. When it is the agent's identifier in the inventory, the agent's gateway traffic counts as its activity. |

The provider catalog is compiled into the gateway: `openai` (`api.openai.com`), `anthropic` (`api.anthropic.com`) and `azure_openai`. The Azure address form was written from memory and has not been called. Another provider is added as one catalog entry in `services/platform/hostedgateway/llm.go`.

### 4. Set the policy

Protect, Guardrails. The guardrail rules decide what is blocked and redacted in text. The **Hosted gateway policy** card decides:

- what happens to an MCP server the registry has no decision for: allow (default) or refuse;
- the tool risk classes the gateway hides and refuses (none by default);
- the requests one token may send a minute (600 by default; 0 is no limit).

To start in observation mode, set every guardrail rule to `monitor`, leave the gateway policy at its defaults, and read the activity.

## Bind a dedicated credential to a governed session

An administrator can reserve a Zasp API token for one active inventory agent and one governed session. Use a dedicated token whose permissions are `use_gateway`, `decide_actions`, or both. While freshly authenticated in the Zasp browser session, send `PUT /api/v1/runtime/workload-bindings/{tokenId}` with the selected inventory agent in `{"agent_id":"<product ID>"}`. Use the application's normal browser scope and CSRF headers. The response includes the issuing administrator, agent, credential ID and the assigned session ID. Repeating the same assignment returns the same binding. Use a new dedicated credential for another session. Revoking the API token stops new authenticated requests.

For subsequent hosted model/MCP requests, the gateway takes agent identity from this binding even if a caller supplies a different `X-Zasp-Agent-Id`. The existing Sessions projection records the decision under the governed session after the scheduler runs. This identifies traffic using the dedicated credential. A deployment using it across multiple provider conversations will see those conversations combined in its governed session. Unbound credentials keep their existing agent-header and daily activity view.

The Python companion can also use a dedicated credential to evaluate rules based on the governed `agent_id` and `session_id`. Its optional source session and call references remain adapter-supplied evidence. [Python tool guard](../../sdks/python-guardrails/README.md)

### Extend an approved isolation to a workload

Use this for a Python workload whose governed session is also the exact session in a supervised runtime gateway `isolate_session` approval. A fresh browser user holding `revoke_sessions` calls `PUT /api/v1/runtime/workload-bindings/{tokenId}/containments/{runId}` with the exact `step_id`. The source approval must match the signed plan, session and device. Its application must already be verified and unexpired. The added target inherits the source deadline. The credential owner cannot use their machine token to approve containment.

The initial status is `pending_readback`. An ensuing SDK admission returns `supervised_session_isolation` and prevents dispatch. When the SDK confirms `not_dispatched`, the scoped GET of the same path returns `adapter_confirmed` and the decision ID. Independent observation of a downstream side effect remains a separate staging check. Existing work already in flight continues under its original admission.

Send DELETE to the same path with fresh authorization to release this workload target. Expiry or verified cleanup of the source also ends the control. GET distinguishes released/expired and reports a post-release decision receipt once the workload makes another observed attempt. Another active control can still block that attempt. Existing runtime gateway approvals retain their original targets until an authorized operator opts in each matching workload.

## Where upstream credentials are

The gateway stores none. This was a decision: the product keeps secrets as references to a secret store that belongs to a connector (an OAuth connection at Nango, a secret in AWS Secrets Manager), each written by an authorization flow of its own. An MCP server's bearer token or a provider key has no such flow, and adding one would have put a new class of customer secret into the platform for no gain in control: the agent already holds the credential today. So the agent keeps it and sends it per request in `X-Zasp-Upstream-Authorization`.

The MCP authorization specification forbids a server from passing the token it received on to an upstream. The gateway does not: the token it receives for itself (the Zasp token) stops at the gateway, and the upstream receives only the credential that was issued for the upstream.

Consequences: an MCP server that needs an interactive OAuth sign-in by the gateway itself is not supported (the agent must hold a token it can present); and whoever can configure the agent can read the upstream credential, as before.

## What is recorded

One record per inspected direction of an exchange: the decision (`allow`, `redact`, `block`), a reason, the matched rule identifiers with their modes and counts, the size and SHA-256 digest of the request or response body as the gateway received it, and identifiers: gateway server, tool name, provider, model, agent, and the principal the token belongs to. A record has no member that could hold a prompt, an argument, a tool result or an answer; the database function that writes it refuses any other member.

- For MCP: every `tools/call` (request and response), every `tools/list`, every refusal, and any other answer in which something was redacted or blocked. Session traffic in which nothing was found (`initialize`, `ping`, notifications) is not recorded.
- For models: every request and every answer.
- Rate-limited requests are not recorded (a flood would otherwise become a flood of writes).

A decision is recorded before a non-streamed answer is returned; if it cannot be recorded the gateway answers `503` and returns nothing. A streamed answer is recorded when the stream ends; if that record fails the stream has already been delivered, and the failure is counted.

Records are read under Guardrails, **Gateway activity**, or `GET /api/v1/gateway/activity` (filters: `surface`, `decision`, `server_id`, `agent_id`).

**Retention.** Decision records are kept 90 days. The discovery scheduler deletes older ones in its pass over the gateway's records, once a minute, at most a few thousand rows a pass (it runs again at once while there is more). The number of days is `hostedGateway.decisionRetentionDays` in the chart (`hosted_gateway.decision_retention_days` with Terraform), which sets `ZASP_GATEWAY_DECISION_RETENTION_DAYS` on the scheduler: a whole number from 1 to 3650. It is one number for the deployment, not a setting of an Environment. The scheduler must be running for anything to be deleted.

The tools a server lists through the gateway (name and risk class; never a description or schema) are kept with the gateway server. Where the inventory holds a discovered MCP server of the same host, those tools join its tool list and its posture findings. An agent named in `X-Zasp-Agent-Id` by its inventory identifier shows the time of its newest gateway decision as its last activity.

**Sessions.** When `X-Zasp-Agent-Id` is the identifier of an active agent of the Environment's inventory (the `pid_...` shown in the agent's detail), the agent's gateway traffic appears under Sessions. The same scheduler pass writes each decision as one event of a runtime session:

- the session is the agent's gateway traffic of one UTC day (one session per agent per day, across servers and providers);
- an allowed or redacted `tools/call` request is a tool call (`tool` / `invoke`); every other decision is a policy event, `block` where the gateway blocked and `allow` otherwise, with what was done and why in its label (for example "Gateway blocked MCP tools/call run_shell (request): tool_risk_denied");
- the event's source is `gateway`, its evidence reference is the decision record, its time is the decision's;
- its confidence is `strong`, not `exact`: the agent is the one the token's holder named in a header, which the gateway cannot verify. A token holder can therefore attribute traffic to another agent of the same Environment. Use one token per agent if that matters to you, and read the principal on the decision record.

What this leaves out: a request without the header, or with a name that is not an inventory identifier, is recorded as a decision and appears in no session. Events appear within about a minute, not at once, and only while the scheduler runs. Gateway events are not put into the session search index, so they are found by opening the session or filtering by agent, not by searching event text. A new session changes what a member may read, like any new session: the authorization model is brought up to date for the Organization before it is listed. Session events are not deleted by the retention above.

## Streaming

A streamed answer cannot be searched piece by piece: an address, a card number or an injected instruction can lie across two pieces. The gateway holds back the newest 256 bytes of each streamed text (each choice, each content block, each tool call's arguments), searches everything it holds, and releases only what lies before that window. It never releases part of a match:

- a match that ends inside the window is held from its start, because the next piece may extend it;
- a run of token characters (letters, digits and `._~+/=-`) is never cut, up to 8 KB, so a JSON Web Token or a bearer token is seen whole, with the `Bearer ` before it;
- a private key block is held from its `BEGIN` line until its `END` line.

Every match of at most 256 bytes is therefore found exactly as it would be in the complete text; a test streams sample texts in pieces of one byte and larger and compares the result with the complete text's. What was held is released, as one more delta of the same shape, before the provider's own end-of-text event.

A blocking match ends the stream with the provider's error event (code `guardrail_blocked`); nothing from the match on was sent, though text released before the window had reached it stays sent. When what must be held would exceed 32 KB (a private key block that never ends), the stream is refused rather than released unsearched.

Costs and limits of this approach: the first 256 bytes of an answer arrive only once more text or the end has arrived, so the time to the first visible text grows by the time the model takes to produce about 256 more bytes. Hidden text encoded in a blob longer than the window (a long base64 or HTML comment) can be missed in a stream, where the complete text would have caught it. Thinking blocks of the messages format are passed unchanged, because a thinking block is signed and changing it would make it unusable in the next request.

## Protocol coverage

MCP, Streamable HTTP as specified in the 2025-11-25 revision, read from the specification's source:

- one JSON-RPC message per POST; a batch is refused with `400`;
- the answer is a JSON object or a stream of server-sent events, relayed with its event identifiers;
- `MCP-Session-Id` and `MCP-Protocol-Version` are passed in both directions; the end of a session (`DELETE`) is forwarded; an upstream `404` (ended session) and `400` reach the agent as such;
- the request headers of the 2026-07-28 revision (`Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) are forwarded. If redaction changes the arguments of a call that carries `Mcp-Param-*` headers, the call is blocked instead, because the upstream refuses a request whose headers and body disagree.

Not covered: the `GET` stream (answered `405`, which the transport allows), so messages a server starts outside a request, such as `tools/list_changed`, are not delivered; stream resumption with `Last-Event-ID` across connections; a long-lived stream of the 2026-07-28 revision (`subscriptions/listen`) beyond the gateway's timeout, after which the client must ask again; stdio servers (they are local processes, not remote ones); and the deprecated HTTP+SSE transport of 2024-11-05.

Models: the three request and answer formats, complete and streamed. Inspected in answers: text and tool-call arguments. Not inspected: images and audio, refusal and reasoning text, and the results of tools a provider runs on its own side.

## Latency and limits

Measured on one machine (4 cores of a 2.1 GHz Xeon that other work was using at the time, so the figures are upper estimates), with `go test ./hostedgateway -bench .`:

| Measurement | Result |
| --- | --- |
| A chat completion (2 KB prompt, 1 KB answer) sent directly to a local stand-in provider over HTTPS | about 0.08 ms |
| The same through the gateway's engine (one more local HTTP hop, both inspections, a store in memory) | 0.9 to 1.3 ms, so about 1 ms is the engine |
| Inspecting an 8 KB streamed answer that arrives in 16-byte pieces | about 39 ms in all, 75 µs for each piece |

**What these numbers leave out.** The deployed gateway also authenticates the token (one database statement), checks authorization (the authorization service and one statement), reads the policy (one statement) and writes the records (one statement), per request. None of that was measured, and neither was a real network path to a provider or an MCP server. Expect the database and authorization round trips, not the inspection, to dominate; measure in your deployment before promising a number.

Limits:

| Limit | Value |
| --- | --- |
| Request body | 4 MB |
| Upstream answer that is not a stream, and one event of a stream | 8 MB |
| One exchange, a stream included | `hostedGateway.timeoutSeconds` (300 by default, at most 1800) |
| Requests per token | the gateway policy (600 a minute by default; 0 is no limit), one limit across all API replicas |
| Requests per client address | the API's general limit (100 a second) |
| MCP servers per Environment | 200 |
| Tools kept per server | 512 |

A text of any length is inspected: one longer than 32 KB goes through the same window as a stream.

**The rate limit.** The token's rate is a token bucket in PostgreSQL, taken by the same statement that reads the policy at the start of a request, so every replica counts against one limit and a restart forgets nothing. The bucket holds one minute of the rate and refills continuously: a token may send a minute's worth at once and then the steady rate. A refused request (`429`, `Retry-After: 1`) costs nothing and is not forwarded. The cost is one row update per request, under a lock held for that statement; requests of the same token therefore queue behind each other for that update, requests of different tokens do not. The API's general limit per client address is still counted by each replica.

The gateway reads the policy on every request, so a policy change, a registry decision or a token revocation applies to the next request. It does not apply to a stream already in flight.

## What was verified

- The engine: unit tests and end-to-end tests over real HTTP against a local MCP server and a local model provider (`services/platform/hostedgateway`).
- A real MCP client and a real MCP server through the gateway: the client and the server of the official MCP Python SDK 2.3.0, with the initialize handshake (answers as JSON and as a stream) and in the 2026-07-28 revision (`TestRealMCPClientAndServerThroughTheGateway`). This run found that a result of the 2026-07-28 revision must say `resultType`, which the gateway's refusals now do.
- The providers' own SDKs through the model proxy: openai 3.51.0 and anthropic 2.8.0, against a local stand-in for the provider (`TestRealModelSDKsThroughTheProxy`; it needs a Python with both packages, named in `ZASP_GATEWAY_SDK_PYTHON`, and is skipped without one). This run found that the Anthropic SDK does not take a bearer token and an API key together.
- The database section: on PostgreSQL 18 with the baseline installed, and the whole path (a token created with `use_gateway`, requests authorized and executed as the API's database login, decisions read back) on an installed baseline (`services/platform/apiserver/hosted_gateway*_postgres_test.go`). The same test then runs the MCP Python SDK's client, in both modes, against that path with the raw token: the token is authenticated against PostgreSQL, each request is authorized and its statements fenced, and the upstream is the SDK's own server. It runs the openai and anthropic SDKs the same way, against the stand-in provider, and checks the decisions they left in the database.
- The shared rate: on the installed baseline, two gateway instances with their own in-process limiters serve one token at three requests a minute; the fourth request is refused on either. The bucket's arithmetic (refill, cap, no cost for a refusal) is tested in the database section's test.
- Retention and sessions: the scheduler's pass is run on the scheduler's database login; the decisions of an inventory agent are then read back as one session through the product's own session statements, with a member's proof. The scheduler's Go code is run against the same database (`TestGatewayMaintenanceInstalledScheduleSource`, which needs `ZASP_GATEWAY_SCHEDULER_DSN`). The Sessions page itself was not opened in a browser against this data; its decoder accepts the new source.
- The chart and Terraform: read as text. They were not rendered or applied.

Not verified: a real model provider, a remote MCP server on the internet, an agent product's own MCP client (the SDK's client is what many are built on, not all), other languages' SDKs, and the gateway behind the ingress of a running cluster. The MCP client and the providers' SDKs were each run both against the gateway's engine served directly and through the API's authentication, authorization and database path on an installed baseline. In every test the authorization model's decision is a stand-in (the authorization service is not running in the tests), and the API's outer middleware (the edge checks, the request limiter) is not in the path.

## Review MCP tool contracts after a supplier change

Use the existing approved server and its normal authorized client session to collect a complete `tools/list` exchange. The hosted gateway filters results under the caller's policy. Its inventory keeps observed tool names and risk, while the local schema baseline records fingerprints from the selected view. An operator may also import equivalent request and response pairs they independently reviewed. The CLI uses no network connection or credentials.

Save each matching request and response as a JSON object in a private local file. As an example, a complete one-page exchange can look like this.

```json
{"request":{"jsonrpc":"2.0","id":1,"method":"tools/list"},"response":{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ticket.read","description":"Read an assigned ticket","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}}}]}}}
```

For a paginated result, save the first request without a cursor and append each request/response pair until the final response has no `nextCursor`. An SSE client should export the decoded JSON-RPC message bodies. Keep HTTP headers, access tokens and session cookies out of the capture. Pick a stable view label for the same caller permissions and gateway policy, and use the Environment and gateway server IDs from the selected Environment and the registered server returned by `GET /api/v1/gateway/mcp-servers`.

```sh
zaspctl mcp snapshot --environment "$ENV_ID" --server "$SERVER_ID" --view employee-monitor \
  --out reviewed-tools.json --json < first-capture.jsonl
```

Retain the returned `snapshot_sha256` through a channel you trust. The new baseline contains the selected scope, tool names and separate hashes of input schema, optional output schema and remaining tool metadata. Descriptions, schema contents, cursor values and RPC IDs stay in the original local capture. Use an access-controlled directory for the capture and baseline. The CLI creates new baseline files with mode 0600 on POSIX. Windows file access follows the directory ACL.

```sh
zaspctl mcp rescan --environment "$ENV_ID" --server "$SERVER_ID" --view employee-monitor \
  --baseline reviewed-tools.json --baseline-sha256 "$REVIEWED_SHA256" \
  --fail-on-change --json < later-capture.jsonl
```

| Result | Operator action |
| --- | --- |
| `unchanged` | All visible tool names and fingerprints match the reviewed baseline. |
| `review_needed` | Inspect the indicated `input_schema`, `output_schema` or `metadata` in the original captures. For additions or removals, check the gateway's allow/deny rules, principal and upstream before attributing the change to the supplier. |
| Incomplete or incompatible capture, exit 3 | Supply the matching terminal pages or select the correct baseline, Environment, server and view. A failed read produces no clean comparison. |
| Invalid arguments or file access, exit 2 | Correct the command or choose a new writable baseline destination. |

With `--fail-on-change`, a complete comparison requiring review exits 10. A completed comparison otherwise exits 0. To accept a reviewed change, create a new snapshot and retain its new digest. A rescan leaves the prior baseline in place.

The importer admits at most 1 MiB, 32 pages and 256 tools. It checks JSON-RPC IDs, page continuity, duplicate object keys and duplicate tool names. It sorts object keys and tool names and keeps array order and numeric spelling, so equivalent schema rewrites may still require review. External schema references are fingerprinted as declared. The operator supplies the view binding, which is local evidence of the captured contract. Gateway approval, supplier provenance, actual invocation and effective downstream permissions require their own evidence.
