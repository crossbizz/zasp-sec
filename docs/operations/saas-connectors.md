# SaaS connectors

One discovery provider, `saas`, serves every SaaS platform that is read through
Nango. A platform is a definition in Go: data and one mapping function per list
endpoint. Adding a platform changes one file and one test. It needs no SQL, no
OpenAPI change and no web code.

The connector is agentless. Nango holds the provider token. Zasp stores a
reference to a Nango connection and sends read requests through the Nango
proxy, inside an allow-list the platform definition declares.

## How it fits together

| Part | Where | What it does |
| --- | --- | --- |
| Platform definition | `services/platform/connectors/saasdiscovery/platforms/<platform>.go` | Everything specific to one platform |
| Registry | `platforms.All()` in `platforms/registry.go` | The list of platforms. The collector, the authorization probe and the connector catalog read it |
| Collector | `services/platform/connectors/saasdiscovery` | Runs a definition: tenant lookup, list endpoints, paging, failure classes, canonical output |
| Test kit | `saasdiscovery/saastest` | Collects a platform against a stand-in Nango server to a typed snapshot |

Inventory kinds: `saas_tenant` (asset), `saas_agent` (agent, the platform's API
names it an agent), `saas_ai_application` (agent, inferred from signals the
API states), `saas_mcp_server` (tool). Every entity carries `platform` and
`tenant`. The subject of an integration is `saas_tenant` with the id
`<platform>/<tenant id>`.

## What a definition contains

`saasdiscovery.Platform`:

- `Token`: lowercase platform token (`databricks`). It is the first half of the
  subject id, the `platform` field and the discovery platform.
- `DisplayName`, `Description`, `AccessGuidance`, `TenantLabel`, `TenantHint`:
  the text of the catalog entry and the setup form.
- `Nango`: the Nango integration key (the Provider-Config-Key), the provider
  host, the auth mode and the proxy rules. Rules are `GET` only. A request
  that no rule allows is never sent.
- `RequiredScopes`: the provider scopes the Nango connection needs.
- `TenantPattern`: the grammar of the platform's tenant id.
- `Tenant`: the one request that says which tenant a connection reaches, and
  a function that reads the tenant id and name from the response. It runs at
  authorization and as the first page of every collection. A connection that
  reaches another tenant than the integration names is refused.
- `Lists`: the list endpoints. Each has a path, fixed query parameters, the
  place of the items in the response, a paging style and a mapping function.
- `Failure` (optional): reads a provider error out of a 200 response.

Paging styles: `PagingNone`, `PagingCursor` (a token in the response, sent
back in a query parameter), `PagingOffset` (offset and limit) and `PagingLink`
(the `Link` header's `rel="next"`, followed only on the endpoint's own path).

The mapping function turns one provider item into a `saasdiscovery.Entity`:
kind, native id, display name, object type, status, optional model and agent
type, the posture facts the API states, and discovery signals from the
`agentsignals` catalog. It returns `false` for an item that is not an AI
agent, AI application or MCP server. It must not copy secrets, prompts or
payloads. A posture fact the API does not state stays `false`.

## Add a platform

1. In Nango, create the integration for the provider. Note its key.
2. Add `platforms/<platform>.go` with a function that returns the
   `saasdiscovery.Platform`. If the API shape is from memory, say so in a
   comment headed `UNVERIFIED` and list what to check against a real tenant.
3. Add the function to `platforms.All()`.
4. Add `platforms/<platform>_test.go` (see below).
5. Run `go test ./connectors/saasdiscovery/...` in `services/platform`.

The catalog entry, the setup form, the authorization probe and the collector
pick the platform up from the registry.

## How it is tested

A platform test declares the provider's responses per path and collects the
platform with `saastest`:

```go
standIn := saastest.NewNango(t, registry, map[string]saastest.Route{
    "/api/2.0/serving-endpoints": saastest.Static(`{"endpoints":[…]}`),
})
snapshot := saastest.Collect(t, standIn, registry, platform, tenantID)
```

`Collect` runs the real collector, the real allow-listed Nango adapter and the
real Nango proxy client against a stand-in Nango HTTP server. It fails unless
the collection ends in a typed snapshot, every entity is bound to the platform
and the tenant and is canonical JSON, and no stored artifact holds the
connection reference or a token. The test then asserts on the entities.
`saastest.Run` returns the raw outcome, for failure cases.

A test against a fake proves the definition is consistent. It does not prove
the provider answers that way. A platform stays marked `UNVERIFIED` until it
has been collected from a real tenant.

## Enable it in a deployment

The provider is off by default. Set `discovery.saasCollectorVersion:
collector_v1` in the chart values (environment variable
`ZASP_DISCOVERY_SAAS_COLLECTOR_VERSION` for the API and the discovery worker).
The worker then also receives the Nango address, environment and service key
and may reach Nango; it gets no route to the SaaS providers. Add each
platform's addresses to `nango.providerEgressCIDRs`.

To connect a tenant: create the connection in Nango for the platform's
integration key, then create the integration in Zasp from the catalog entry
with the tenant id and `ref:nango/connection/<connection id>`, and authorize
it. Zasp does not start the provider sign-in itself yet; the connection is
created in Nango.

## Limits

- Requests are `GET` only and a response is at most 1 MiB. The proxy refuses
  a response whose text contains `access_token`, `refresh_token`,
  `client_secret`, `private_key` or `password`; the collection is then
  retried and nothing of that response is stored.
- One page of a collection is one provider request.
- The provider host of a definition is fixed. A platform whose host differs
  per tenant (Databricks) keeps the tenant's host in the Nango connection.
