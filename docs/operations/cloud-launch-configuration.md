# Cloud launch configuration

The supported product API requires 43 base settings and 10 enabled runtime-service settings. These are configuration requirements, not a readiness result. The API composes PostgreSQL, Stytch, Temporal, OpenFGA, connector and policy-history dependencies; supplying their names or syntactically valid values does not establish their authority or availability.

The configuration partition below follows [the API loader and validator](../../services/platform/agentsec-api/runtime.go), [the mandatory-field tests](../../services/platform/agentsec-api/runtime_test.go), [the actual dependency builder](../../services/platform/agentsec-api/production_runtime.go) and [the runtime-service loader](../../services/platform/runtimeservices/config.go). The dependency builder requires runtime services enabled even though the lower-level loader accepts a disabled configuration. Full launch preserves these guards in every environment.

## Required base settings: 43 names

All names in this table are required. Configure credentials through the deployment's secret mechanism; do not place their contents in documentation, command arguments, logs or readiness reports.

| Group | Names | Contract |
| --- | --- | --- |
| Deployment | `ZASP_ENVIRONMENT`, `ZASP_DEPLOYMENT_MODE` | Supported environment and deployment mode. |
| Listeners and edge | `ZASP_PRODUCT_LISTEN_ADDRESS`, `ZASP_INTERNAL_LISTEN_ADDRESS`, `ZASP_PUBLIC_ORIGIN`, `ZASP_COOKIE_SECURE`, `ZASP_TRUSTED_PROXY_CIDRS` | Distinct valid listeners, HTTPS public origin, explicit cookie policy and trusted proxy networks. Production requires secure cookies. |
| Request limits | `ZASP_REQUEST_RATE_PER_SECOND`, `ZASP_REQUEST_BURST`, `ZASP_PROVIDER_TIMEOUT`, `ZASP_REQUEST_TIMEOUT`, `ZASP_SHUTDOWN_TIMEOUT`, `ZASP_READINESS_INTERVAL`, `ZASP_READINESS_MAX_INTERVAL` | Explicit bounded numeric/duration settings; these have no implicit loader defaults. |
| Discovery | `ZASP_DISCOVERY_PARSER_VERSION`, `ZASP_DISCOVERY_TOOL_VERSION` | Valid execution-version selectors. |
| PostgreSQL | `ZASP_POSTGRES_DSN`, `ZASP_SECURITY_AGENT_POSTGRES_DSN` | Same database authority with distinct runtime principals; current schema, authorization and identity registration must be ready. |
| Stytch | `ZASP_STYTCH_BASE_URL`, `ZASP_STYTCH_AUTHORIZE_URL`, `ZASP_STYTCH_PROJECT_ID`, `ZASP_STYTCH_SECRET`, `ZASP_STYTCH_WEBHOOK_SECRET`, `ZASP_STYTCH_PUBLIC_TOKEN`, `ZASP_STYTCH_ORGANIZATION_ID` | Real provider configuration, webhook signing authority and organization. Authentication/session acceptance must be observed separately. |
| Product signing | `ZASP_WORKFLOW_SIGNING_KEY`, `ZASP_TOKEN_REVEAL_KEY` | Valid private signing/reveal material with the required encoding and size. |
| Connector authority | `ZASP_CONNECTOR_AWS_REGION`, `ZASP_CONNECTOR_ROLE_ARN`, `ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE`, `ZASP_CONNECTOR_KMS_KEY_ARN`, `ZASP_CONNECTOR_SECRET_PREFIX` | Bound AWS region, role, mounted IRSA identity, KMS key and OAuth secret namespace. Standard AWS access-key variables do not supply this contract. |
| Policy history | `ZASP_POLICY_HISTORY_ENDPOINT`, `ZASP_POLICY_HISTORY_INDEX` | Supported policy-history authority and fixed supported index; actual readiness is required. |
| Customer and ticket authority | `ZASP_AWS_CUSTOMER_ROLE_PREFIXES`, `ZASP_AWS_CUSTOMER_ROLE_ARNS`, `ZASP_FINDING_TICKET_EGRESS_CIDRS` | Canonical registered customer role sets and bounded public ticket destinations. |
| GitHub | `ZASP_GITHUB_CLIENT_ID`, `ZASP_GITHUB_CLIENT_SECRET_REFERENCE`, `ZASP_GITHUB_APP_ID`, `ZASP_GITHUB_PRIVATE_KEY_REFERENCE` | Valid configured provider identifiers and secret references. |
| Okta | `ZASP_OKTA_CLIENT_ID`, `ZASP_OKTA_CLIENT_SECRET_REFERENCE` | Valid configured provider identifier and secret reference. |

The connector, customer-role and GitHub/Okta requirements are unconditional in the current full composition. Test mode has a specific loopback policy-history signer exception in [policy_production.go](../../services/platform/agentsec-api/policy_production.go); it does not supply connector AWS authority or waive those configuration fields. Do not invent references to satisfy validation.

## Required runtime-service settings: 10 names

| Group | Names | Contract |
| --- | --- | --- |
| Enablement | `ZASP_RUNTIME_SERVICES_ENABLED`, `ZASP_RUNTIME_SERVICES_TIMEOUT` | Enabled connections and a bounded timeout are required by the actual API builder. |
| Temporal | `ZASP_TEMPORAL_ADDRESS`, `ZASP_TEMPORAL_NAMESPACE`, `ZASP_TEMPORAL_TASK_QUEUE`, `ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE` | Reachable private service, existing namespace and distinct queues. |
| OpenFGA | `ZASP_OPENFGA_URL`, `ZASP_OPENFGA_STORE_ID`, `ZASP_OPENFGA_MODEL_ID`, `ZASP_OPENFGA_TOKEN_FILE` | Private service origin, explicit store/model ULIDs and mounted credential. Require actual product model readback and permission checks. |

Use [the Temporal/OpenFGA operations guide](temporal-openfga.md) for pinned versions, schema migration, local connection scope and TLS. A version/help result or a connection fixture is not product runtime acceptance.

## Conditional and optional settings

| Names | Rule |
| --- | --- |
| `ZASP_ORGANIZATION_ID` | Required product organization ID in single-tenant mode; empty in SaaS mode. This is separate from the Stytch organization ID. |
| `ZASP_TEMPORAL_TLS_CA_FILE`, `ZASP_TEMPORAL_TLS_CERT_FILE`, `ZASP_TEMPORAL_TLS_KEY_FILE` | All required outside the nonproduction loopback exception, or when any of these three is supplied. |
| `ZASP_OPENFGA_TLS_CA_FILE` | Optional explicit private CA. |
| `ZASP_RUNTIME_SESSION_INDEX` | Empty selects the supported first-generation session index; explicit selections remain closed. |
| `ZASP_KUBERNETES_EGRESS_CIDRS` | Empty is accepted; supplied CIDRs must be canonical. |
| `ZASP_SECURITY_AGENT_ORDERED_HTTP_ENABLED` | Empty defaults to disabled. |
| `ZASP_SECURITY_AGENT_EVIDENCE_EXPORT_WORKFLOW`, `ZASP_SECURITY_AGENT_ATTACK_LAB_WORKFLOW` | Empty disables each optional workflow; supplied selectors are closed. |
| `ZASP_NANGO_BASE_URL`, `ZASP_NANGO_SERVICE_SECRET_REFERENCE`, `ZASP_NANGO_ENVIRONMENT` | Omit the triplet or configure all three consistently. |

The [audit-export bundle](../../services/platform/agentsec-api/audit_export_config.go) is optional, but when present requires all four of `ZASP_AUDIT_EXPORT_POLICIES_JSON`, `ZASP_AUDIT_EXPORT_READER_ROLE_ARN`, `ZASP_AUDIT_EXPORT_WEB_IDENTITY_TOKEN_FILE` and `ZASP_AUDIT_EXPORT_CURSOR_SIGNING_KEY`.

The [compliance-export bundle](../../services/platform/agentsec-api/compliance_config.go) is optional, but when present requires all five of `ZASP_COMPLIANCE_EXPORT_BUCKET`, `ZASP_COMPLIANCE_EXPORT_BUCKET_OWNER`, `ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN`, `ZASP_COMPLIANCE_EXPORT_READER_ROLE_ARN` and `ZASP_COMPLIANCE_EXPORT_WEB_IDENTITY_TOKEN_FILE`. The legacy `ZASP_COMPLIANCE_EXPORT_ROLE_ARN` is rejected. Both bundles retain their reader-role, mounted identity and key/resource validation.

## Available mappings and entrypoints

[The API launcher](../../scripts/api-start.mjs) maps only `STYTCH_PROJECT_ID`, `STYTCH_SECRET` and `STYTCH_PUBLIC_TOKEN` to their corresponding `ZASP_` names. Conflicting or explicitly empty aliases are refused. It does not map `DATABASE_URL`, `TEMPORAL_ADDRESS`, generic signing secrets, AWS credentials or other provider keys.

After the full configuration and dependency authorities are admitted, launch from the repository root:

```sh
npm run api:start
```

This runs the current product API under the owned launcher. Verify its actual internal readiness and product session behavior before connecting the web origin. `npm run dev` starts the web development server; its HTML response alone does not prove an API proxy, authenticated session or live data. `npm run local:start` assembles the local AWS emulator/product-stub Kubernetes profile and is not the full API launcher.

For a bounded configuration/launcher check, use the current required toolchain and an admitted build window:

```sh
node --test scripts/api-start.test.mjs
go test -C services/platform -mod=readonly ./agentsec-api -run '^(TestLoadRuntimeConfigIsStrict|TestRuntimeNangoConfigurationIsOptionalAllOrNothingAndPrivate|TestP7GuardedRuntimeReadinessStartupGate|TestServeRuntimeReadinessTracksRequiredProviderChecks)$' -count=1 -v
```

These fixture tests do not establish provider or deployment readiness. The documented local connection smoke is bound to its disposable Compose credentials, ports and namespace, creates a one-type model, and does not activate the product model. Existing local product-model tests inspect the named Compose container for credentials; a native-process bootstrap needs its own supported credential binding.

## Provider bootstrap and deployment gate

An authenticated Stytch TEST organization search on 2026-10-06 returned HTTP/API success and zero organizations. This establishes read-only TEST authentication at that observation only. It does not establish a product organization, member, OAuth callback, session, SSO or tenant authorization.

[The disposable Stytch password-session proof](../../proofs/stytch-b2b-test-session.mjs) performs provider mutations and deletes its owned organization in cleanup. Run it only within explicitly authorized disposable scope. Its CLI cannot furnish a retained organization for product API launch. There is no standalone product bootstrap CLI supplied by this guide.

Complete the real organization/session bootstrap, database principal/schema/identity registration, native model/namespace authority, public TLS/proxy configuration and external connector/policy resources before reporting full launch. Record actual outcomes and normal cleanup separately from configuration presence. Hosted promotion additionally requires the immutable release and infrastructure gates in [production-deployment.md](production-deployment.md); this guide supplies no deployment acceptance or guard waiver.

## Report prerequisite name gaps

Run `npm run api:prerequisites` for a names-only inventory of the existing 53 required settings and the launcher's three supported Stytch aliases. It reads environment key names, never values, and reports absent names. Alias presence does not check emptiness, conflicts or credential validity. A complete name inventory does not establish configuration syntax, permissions, runtime access or production readiness. Use `npm run api:check-config` for the full production loader's syntax check; actual provider/deployment admission and readiness remain separate. No generic database, Temporal, AWS or signing credentials are mapped automatically.
