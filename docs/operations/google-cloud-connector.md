# Google Cloud connector

Discovery provider `gcp` lists the AI agents of Google Cloud projects. It is
agentless: nothing is installed in a project. The discovery worker reads
Google's REST APIs with a short-lived access token of a read-only service
account the customer owns.

The connector is optional and off by default. A deployment serves it only
where `ZASP_DISCOVERY_GCP_COLLECTOR_VERSION` is set for the API and the
discovery worker.

## Status

Built and tested against a fake of the Google APIs and on PostgreSQL. **It
has not been run against a real Google Cloud organization.** The request
paths, query parameters and response members come from Google's published
API descriptions (the discovery documents of each API). A few facts could
not be confirmed from those and are marked `UNVERIFIED` in the code; they are
listed at the end of this page. Treat the first run on a real organization
as the verification.

## What is read

For the organization, folder or project an integration names, every active
project below it is read. Per project:

| What | Google API | Inventory kind |
| --- | --- | --- |
| Vertex AI Agent Engine reasoning engines | `aiplatform.googleapis.com` | `gcp_agent_engine` (agent) |
| Conversational Agents (Dialogflow CX) agents | `dialogflow.googleapis.com` | `gcp_conversational_agent` (agent) |
| Gemini Enterprise (formerly Agentspace) agents | `discoveryengine.googleapis.com` (v1alpha) | `gcp_gemini_enterprise_agent` (agent) |
| Vertex AI endpoints and their deployed models | `aiplatform.googleapis.com` | `gcp_model_endpoint`, `gcp_deployed_model` (assets) |
| Cloud Run services and Cloud Functions that call a model | `run.googleapis.com`, `cloudfunctions.googleapis.com` | `gcp_inferred_agent` (agent, inferred) |
| Every service account of a project, with the roles bound on the project and on the folders and organization above it | `iam.googleapis.com`, `cloudresourcemanager.googleapis.com` | `gcp_service_account` (identity) |
| Cloud Run services that are MCP servers | `run.googleapis.com` | `gcp_mcp_server` (tool) |
| Tools a Conversational Agents agent declares | `dialogflow.googleapis.com` | `gcp_agent_tool` (tool) |
| Model Armor floor setting and templates | `modelarmor.googleapis.com` | attribute `model_armor` of an agent |
| Vertex AI data access audit log, last seven days | `logging.googleapis.com` | `last_invoked_at`, signal `invoke:vertex_ai_*` |

The scope itself is `gcp_scope`, each project `gcp_project`, and each Google
API one `gcp_service` record that says whether it was read.

A Cloud Run service or a function is listed as an agent only on evidence:
one strong signal, or weak signals of two different kinds.

| Signal | Strength | Where it comes from |
| --- | --- | --- |
| `env:<provider>` | strong for a model provider's key name | The **name** of an environment variable. Values are never read |
| `image:<framework>` | per catalog | The container image reference |
| `surface:cloud_run_agent` | strong | Cloud Run's own `functionalType` says the service is an agent |
| `iam:vertex_ai_user` and similar | weak | A role of the service account in the project's IAM policy |
| `invoke:vertex_ai_model`, `invoke:vertex_ai_agent` | strong | The audit log shows the service account calling a model or a reasoning engine |

A service account that the audit log shows invoking a model, and that runs
nothing listed, is itself listed as an inferred agent.

A workload that runs as a service account of another project is related to
that identity when the other project lies in the scope and lists the
account; that project's page emits the identity.

### MCP servers and tools

A Cloud Run service is recorded as an MCP server, not as an agent, when
Cloud Run's own `functionalType` says so, or when its image or command is an
MCP server (the rule Kubernetes workloads are recognised by). It appears in
the MCP inventory (`GET /mcp-servers`) under the registry identity
`host:<host of its URL>`, where it can be approved or blocked.
Authentication is `declared` while Cloud Run's IAM invoker check is on and
`none` when it is switched off. No relationship says which agent uses a
Cloud Run MCP server: Google's APIs do not state it, so the MCP posture
findings, which are raised on the agents that use a server, are not raised
for these.

The tools of a Conversational Agents (Dialogflow CX) agent are listed with
their names and a risk class read off the name. Vertex AI Agent Engine and
Gemini Enterprise expose no list of an agent's tools: a reasoning engine's
`classMethods` are its own entry points, not its tools.

What is never recorded: tokens, keys, values of environment variables,
request or response payloads of audit log entries, and the addresses of
people (only service accounts are kept from an IAM policy or a log entry).

## Findings

| Rule | Raised when | Frameworks |
| --- | --- | --- |
| `agent_service_account_admin_role` | The service account an agent runs as holds an administrator-level role on its project: Owner, Editor, Security Admin, Service Account Admin, Project IAM Admin, Folder Admin or Organization Admin. A Cloud Run service or function without a service account of its own runs as the Compute Engine default service account, whose roles are checked | Same as `agent_role_administrator_access` |
| `agent_model_armor_missing` | A reasoning engine runs in a project whose Model Armor floor setting does not cover Vertex AI and that has no Model Armor template in the engine's location. Raised only when Model Armor could be read, or its API is switched off | Same as `agent_guardrail_missing` |

Roles count wherever they are bound: on the project, or on a folder or the
organization above it (their IAM policies are read up to the organization).
An ancestor the service account may not read is the coverage line
"Inherited IAM roles"; roles bound there are then not known. With a scope
below the organization, grant `roles/iam.securityReviewer` on the
organization as well to close it.

## Coverage

A project that refuses an API, or has it switched off, never fails a sync.
It is counted, and the integration's detail lists each Google API with a gap
under "Agent discovery coverage":

- *permission missing*: at least one project refused the service account.
  The line names the role to grant.
- *switched off*: the API is disabled in every project that was read, so
  there was nothing to list.

A rejected token, throttling or a server error does fail the page, and the
sync is retried like any other.

One collection reads at most 2,000 projects. Larger organizations should be
connected per folder.

## Setting it up

### 1. In the customer's Google Cloud

Create one service account for discovery, for example
`zasp-reader@<project>.iam.gserviceaccount.com`, and grant it these read-only
roles on the organization, folder or project to be read:

| Role | Needed for |
| --- | --- |
| `roles/browser` | Listing projects and folders, reading project IAM policies |
| `roles/aiplatform.viewer` | Reasoning engines, endpoints |
| `roles/dialogflow.viewer` | Conversational Agents |
| `roles/discoveryengine.viewer` | Gemini Enterprise agents |
| `roles/run.viewer` | Cloud Run services |
| `roles/cloudfunctions.viewer` | Cloud Functions |
| `roles/iam.securityReviewer` | Service accounts and IAM policies |
| `roles/modelarmor.viewer` | Model Armor floor setting and templates |
| `roles/logging.privateLogViewer` | Data access audit logs |

A role that is left out costs only that line of coverage. The role names are
Google's predefined roles as we know them; confirm each in the IAM console
before granting.

Model invocations appear in the audit log only where **data access audit
logs** are enabled for the Vertex AI API (`aiplatform.googleapis.com`,
log type Data Read) in the project. Without them the connector still lists
every agent; it only cannot say when a service account last called a model.

Then choose how Zasp reaches the service account.

**Workload identity federation (recommended; nothing is stored).**

1. Create a workload identity pool and, in it, an AWS provider for the AWS
   account Zasp runs in.
2. Allow the two AWS roles of the deployment to impersonate the service
   account: grant `roles/iam.workloadIdentityUser` on the service account to
   the principals of the pool that map to the API's connector role and to
   the discovery worker's role. Both roles are Terraform outputs of the
   deployment. The API uses its role once, to prove the authorization; the
   worker uses its role for every sync.
3. Note the provider's resource name:
   `//iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.

Zasp signs an AWS `GetCallerIdentity` request with its own role, Google's
Security Token Service verifies the signature with AWS, and the IAM
Credentials API then issues a one-hour token of the service account. No key
exists.

**A service account key (only where federation is not possible).**

Create a JSON key for the service account and hand it to the operator. The
operator stores the file in Secrets Manager at
`<connector secret root>/gcp/service-account-key/<id>` (Terraform:
`discovery_optional_providers.gcp_service_account_key_id`). The key is never
written to the product database, the browser or a log. Rotate it in Google
Cloud and replace the stored value.

### 2. In the deployment

Terraform (`deploy/staging/variables.tf`, `discovery_optional_providers`):

```hcl
discovery_optional_providers = {
  gcp_collector    = "collector_v1"
  gcp_egress_cidrs = ["<address ranges Google publishes for its APIs>"]
  # only for a customer that cannot federate:
  # gcp_service_account_key_id = "customer-0001"
}
```

This sets `discovery.gcpCollectorVersion` and
`network.connectorEgressCIDRs.gcp` of the chart, which give the API and the
discovery worker `ZASP_DISCOVERY_GCP_COLLECTOR_VERSION` and a network route
to the Google APIs (`*.googleapis.com`, which includes `sts`,
`iamcredentials` and `oauth2`). Without the collector version neither
variable is rendered, no route is admitted, the collector is not registered
and Google Cloud is not in the integration catalog.

No new AWS permission is needed: signing a `GetCallerIdentity` request needs
none.

### 3. In the product

Integrations, Google Cloud, Configure:

| Field | Value |
| --- | --- |
| Organization, folder or project | `organizations/<number>`, `folders/<number>` or `projects/<project id>` |
| Service account | Federation: `ref:gcp/workload-identity/<project id>/<service account name>`. Key: `ref:gcp/service-account-key/<id>` |
| Workload identity provider | Federation only: the provider's resource name from step 1 |

Authorize. The API obtains a token and reads the named organization, folder
or project; the integration becomes active only if both succeed. Then run a
sync and review "Agent discovery coverage".

## Where the code is

| Part | Where |
| --- | --- |
| Collector | `services/platform/connectors/gcpdiscovery` (`collector.go`, `project.go`) |
| Token exchange | `services/platform/connectors/gcpdiscovery/token.go` |
| Test kit | `services/platform/connectors/gcpdiscovery/gcptest` |
| Worker credential | `services/platform/agentsec-worker/discovery_gcp_credentials.go` |
| Authorization probe | `services/platform/agentsec-api/reference_gcp_connector.go` |
| Schema | `completion.sql` section X3d (`ws8_gcp_provider`, `ws8_gcp_rule_catalog`, `ws8_gcp_coverage_gaps`) |

## Not verified

These are from memory, not from a document we could read when this was
built, and are marked `UNVERIFIED` in the code:

- The service account key exchange (the JWT bearer grant at
  `https://oauth2.googleapis.com/token`) and the members of a key file.
- The host of a regional Dialogflow CX location
  (`<location>-dialogflow.googleapis.com`).
- The ids `default_collection` and `default_assistant` of a Gemini
  Enterprise app, and the `eu` host of the Discovery Engine API.
- That a project's Model Armor floor setting is read at location `global`
  on `modelarmor.googleapis.com`.
- The name of the data access audit log and the method names Vertex AI
  writes into it.
- The address of the Compute Engine default service account.
- The names of the predefined roles in the tables above and in the
  administrator role list.
