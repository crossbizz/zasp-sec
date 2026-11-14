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
- `HostTemplate`, with `Nango.HostPattern` and `Nango.HostSuffixes`: only for
  a platform whose API host differs per tenant. See "Per-tenant hosts".
- `SignIn`: only for a platform a person can sign in to from the product.
  See "Connect a tenant".
- `RequiredScopes`: the provider scopes the Nango connection needs.
- `TenantPattern`: the grammar of the platform's tenant id.
- `Tenant`: the one request that says which tenant a connection reaches, and
  a function that reads the tenant id and name from the response (`Map`). It
  runs at authorization and as the first page of every collection. A
  connection that reaches another tenant than the integration names is
  refused. Where the API does not state the tenant id as one value, `Confirm`
  is given the tenant id and says whether the response confirms it (OpenAI:
  the id is one of the organizations listed; Databricks: the workspace's own
  host answered). The path may name the tenant: `/api/v4/groups/{tenant}`.
- `Lists`: the list endpoints. Each has a path, fixed query parameters, the
  place of the items in the response, a paging style and a mapping function.
  The path may contain `{tenant}`.
- `Failure` (optional): reads a provider error out of a 200 response.

Paging styles: `PagingNone`, `PagingCursor` (a token in the response, sent
back in a query parameter; `MorePath` names a `has_more` flag for an API that
states a token on its last page too), `PagingOffset` (offset and limit),
`PagingPage` (page number and page size) and `PagingLink` (the `Link`
header's `rel="next"`, followed only on the endpoint's own path).

List shapes beyond a plain list:

- `Single`: the response is one object, the one item of the endpoint (the
  group whose settings say an AI feature is on).
- `Distinct`: the endpoint is a log that names the same object many times,
  on one page and across pages (an activity report). Each object is reported
  once. The collector remembers what it reported in the collection cursor,
  at most 96 objects for one endpoint; a tenant with more ends the collection
  as a terminal failure, not as an incomplete inventory.
- `Parent` and `MapChild`: a nested list, read once for every object of a
  parent list, with `{parent}` in its path (the service accounts of every
  project). The parent list is walked one object at a time, so a tenant with
  N parents costs up to 2N provider requests.
- `Absent`: the statuses that mean the tenant does not have the feature
  (404; 400 only for an API that answers so for an object type that is not
  installed). The endpoint then contributes nothing.

The mapping function turns one provider item into a `saasdiscovery.Entity`:
kind, native id, display name, object type, status, optional model and agent
type, the posture facts the API states, and discovery signals from the
`agentsignals` catalog. It returns `false` for an item that is not an AI
agent, AI application or MCP server. It must not copy secrets, prompts or
payloads. A posture fact the API does not state stays `false`.

## Per-tenant hosts

Most platforms have one API host. Some have one per tenant:
`acme.service-now.com`, `acme.atlassian.net`, a Databricks workspace address.
Such a definition has no `Nango.ProviderHost`. It declares:

- `HostTemplate`: the host with `{tenant}` in place of the tenant id
  (`{tenant}.service-now.com`), or `{tenant}` alone where the tenant id is
  the host (Databricks);
- `Nango.HostPattern`: the pattern the whole host must match;
- `Nango.HostSuffixes`: the provider's own domains (`.service-now.com`). A
  host must end with one of them, so a loose pattern cannot admit another
  domain.

Every request of the platform is then sent to the tenant's host and to no
other. The Nango adapter refuses a host that does not match, an address, a
cluster or local name, and a host that resolves to anything but public
addresses (private, loopback, link-local, shared address space, reserved and
IPv4-embedding IPv6 ranges are refused). It tells Nango to send the request
to exactly that host (the `Base-Url-Override` proxy header), so the host a
connection was created with cannot redirect it. A tenant id whose host the
platform does not allow is refused when the integration is saved.

The public-address check is made by the product before it calls Nango; Nango
makes the connection. Keep Nango's own egress limited to the providers
(`nango.providerEgressCIDRs`); a per-tenant platform needs the provider's
address ranges there.

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

## Connect a tenant

A platform whose definition declares `SignIn` is connected from the
Integrations page (catalog entry with `auth_mode` `nango_sign_in`):

1. Configure the platform with its tenant id. The integration is saved with
   the configuration `{platform, tenant_id}`.
2. Choose "Sign in to <platform>". The API asks Nango for the provider's
   authorization address and sends the browser there. It refuses any address
   that is not the page the definition declares (`AuthorizationHost`, or the
   tenant's own host, and `AuthorizationPath`).
3. The provider returns the browser to the product
   (`/api/v1/integrations/oauth/callback`). The API hands the code to Nango,
   which exchanges it and keeps the token. The API then asks the platform
   which tenant the new connection reaches. A connection that does not reach
   the tenant the integration names is deleted from Nango and the sign-in
   fails.
4. The browser is sent back to the Integrations page with the id of the
   connection. The page stores `ref:nango/connection/<id>` in the integration
   with an ordinary update, in the tab that started the sign-in only.
5. Authorize the integration. This is the reference authorization every saas
   integration has: it needs fresh authentication and checks the tenant
   again.

A sign-in is recorded in `zasp_saas_sign_in_attempts` by the SHA-256 of the
provider's state value and of the browser session cookie. It is taken once,
by the person and the session that started it, within ten minutes. The
product never receives a provider token.

A platform without `SignIn` (an API key or an API token held by Nango:
OpenAI, Anthropic, Atlassian; and Databricks, whose connection parameter name
is not known to its definition) is connected as before: create the connection
in Nango for the platform's integration key, then create the integration with
the tenant id and `ref:nango/connection/<connection id>`, and authorize it.
Every platform accepts that form through the API.

Sign-in needs completion.sql section `ws6_saas_sign_in` in the database. An
API whose database does not have it starts without sign-in and still offers
the reference form.

Not done by a sign-in: deleting the integration does not delete the Nango
connection the sign-in created. Delete it in Nango.

## Limits

- Requests are `GET` only and a response is at most 1 MiB. The proxy refuses
  a response whose text contains `access_token`, `refresh_token`,
  `client_secret`, `private_key` or `password`; the collection is then
  retried and nothing of that response is stored.
- One page of a collection is one provider request; the first page of each
  parent of a nested list is two.
- A 429 without a usable `Retry-After` header is a rate limit with a wait of
  one minute. (Other providers' collectors still treat it as malformed.)
- A Databricks tenant id is the workspace address, not the numeric workspace
  id: the address is what decides the host.

## Platforms

Every provider API shape is written from memory and marked `UNVERIFIED` in
its definition file, with the list of what to check against a real tenant.

| Platform | Tenant id | Host | Connected by | What is listed |
| --- | --- | --- | --- | --- |
| `anthropic` | organization UUID | `api.anthropic.com` | reference (admin key) | workspaces, API keys (id, name, status; never a key value or its hint) |
| `atlassian` | site name | `<site>.atlassian.net` | reference (API token) | installed AI apps and Rovo apps; Rovo agents are not listed |
| `databricks` | workspace address | the workspace address | reference | serving endpoints and served agents |
| `gitlab` | group id | `gitlab.com` | sign-in | GitLab Duo for the group, projects tagged or named as AI |
| `google_workspace` | customer id | `admin.googleapis.com` | sign-in | third-party AI apps granted OAuth access (token activity report), Gemini usage |
| `openai` | organization id | `api.openai.com` | reference (admin key) | projects, service accounts; assistants are not listed |
| `servicenow` | instance name | `<instance>.service-now.com` | sign-in | Now Assist AI agents, installed AI applications |
| `slack` | workspace id | `slack.com` | sign-in | approved AI apps |

Three things about Nango itself are also written from memory and have not
been run against a Nango server: the `Base-Url-Override` proxy header that
pins a per-tenant host, the `params[<name>]` form in which a sign-in passes
connection parameters (ServiceNow's `subdomain`), and the integration key of
each platform (`Nango.Key` in its definition, which must be the key of the
integration created in Nango). The provider's callback address of every
Nango integration is the product's own:
`<public origin>/api/v1/integrations/oauth/callback`.
