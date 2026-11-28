# Independent Nango release

`deploy/vps/nango` runs Nango, a private TLS proxy and a database migration job in a dedicated namespace. Use this release for a separately managed Nango installation. The hosted Zasp chart can also run a bundled Nango service. Both expose the Nango API privately. Zasp uses the `prod` environment in the chosen instance. The local Zasp profile does not provision Nango.

The standard `kubernetes` profile has its own bundled option. A single chart installs Nango and points Zasp at the same service. [Set up Nango in the standard Kubernetes chart](../getting-started/administrator.md#set-up-nango-in-this-cluster)

## Provision and install

1. Provision a dedicated persistent PostgreSQL database for Nango. Use a distinct owner and database, and grant this login the schema creation and migration rights it needs in that database. Scope its network route to this database on port 5432. Use a TLS server certificate for the database hostname, authenticate the login, and keep offsite PostgreSQL backups and the Nango encryption key outside the VPS. The chart consumes an existing database. Size and maintain its PVC or external service separately.
2. Choose namespace `connectors` for this example and enable an enforcing CNI network policy. Issue a private TLS certificate with a DNS SAN of `nango.connectors.svc.cluster.local`. Make the issuing CA available in the Zasp API and discovery container trust stores. Configure all deployments to use the same cluster DNS suffix required by Zasp's Nango client. Keep the TLS private key only in the service namespace. Require verified upstream TLS to both the database and the SaaS providers.
3. Prepare Nango's required encryption key and environment service key as protected files with the format required by the pinned image. The latter is a bearer credential with environment-wide privileges. Store it only in the trusted server processes that require it. Prepare a private database URL file with an explicit `:5432` and exactly `?sslmode=verify-full`. Each Secret key below contains the value bytes without a trailing newline. Supply the database CA separately.
4. Create a reviewed `nango-values.yaml` with the actual database and provider CIDRs, public Zasp origin, client namespaces and an immutable verified nginx-unprivileged image. No credentials belong in this values file.

```yaml
publicOrigin: https://zasp.example.com
tlsProxyImage: registry.example.com/nginx-unprivileged@sha256:<verified-digest>
databaseEgressCIDRs: [192.0.2.10/32]       # Replace with the dedicated database address
providerEgressCIDRs: [198.51.100.7/32]      # Replace with required provider addresses
clients:
  - namespace: zasp
    workloads: [agentsec-api, agentsec-discovery-worker]
```

```sh
kubectl create namespace connectors
kubectl label namespace connectors zasp.io/installation="$ZASP_VPS_INSTALLATION_ID"
kubectl -n connectors create secret tls nango-server-tls --cert=server-chain.pem --key=server.key
kubectl -n connectors create configmap nango-database-ca --from-file=ca.crt=database-ca.pem
kubectl -n connectors create secret generic nango-storage \
  --from-file=database-url=/secure/database-url --from-file=encryption-key=/secure/encryption-key \
  --from-file=service-key=/secure/nango-service-key
helm upgrade --install nango deploy/vps/nango -n connectors -f nango-values.yaml --wait --timeout 10m
kubectl -n connectors rollout status deployment/nango
```

The service reads Kubernetes Secret files with mode 0440 at startup and supplies the values to the Nango process. Restart it after rotating an environment credential. The migration pod receives only the database URL and encryption key. The same image digest and migration command as the bundled Zasp service run against the dedicated database. The migration hook has DNS and database egress. The Nango pod adds HTTPS egress only to the configured provider CIDRs. Ensure those CIDRs are current. k3s CoreDNS pods must match `k8s-app=kube-dns`. Additional NetworkPolicies can grant access, so restrict policy edits in this namespace. A provider that cannot supply stable addresses needs a separately controlled egress proxy before onboarding.

For a CLI-managed VPS, configure the cluster context, cluster UID, installation ID, chart values, CA and key file in the private operator config. Use the following CLI commands in place of the Helm command above. The first command previews the operation, the second installs, and the third checks readiness and authenticates with the environment service key. [VPS component configuration](vps-independent-services.md)

```sh
./zasp --config /secure/operator.env --profile vps --dry-run install nango
./zasp --config /secure/operator.env --profile vps install nango
./zasp --config /secure/operator.env --profile vps status nango
```

## Access Nango and configure a provider

The standard Kubernetes profile provides a private browser dashboard with the signup, login and public OAuth callback setup described in the administrator guide. The older independent and hosted production charts set Nango's server URL to the Zasp OAuth gateway. Their forwarded root serves dashboard HTML, but its login and settings requests target that gateway. Use their private Nango service API to manage providers. [Standard Kubernetes dashboard](../getting-started/administrator.md#set-up-nango-in-this-cluster)

1. From an operator workstation, open the tunnel that corresponds to the installed release. Replace the example context and namespace with the installed values.

   | Installed service | Command | Nango API origin |
   | --- | --- | --- |
   | Independent release with TLS | `kubectl --context "$ZASP_VPS_KUBE_CONTEXT" -n connectors port-forward --address=127.0.0.1 service/nango 18443:8443` | `https://nango.connectors.svc.cluster.local:18443` |
   | Hosted product's bundled release | `kubectl --context "$ZASP_VPS_KUBE_CONTEXT" -n agentsec port-forward --address=127.0.0.1 service/nango 13003:3003` | `http://127.0.0.1:13003` |

   For the independent release, verify readiness with `curl --fail --cacert /secure/nango-server-ca.pem --resolve nango.connectors.svc.cluster.local:18443:127.0.0.1 https://nango.connectors.svc.cluster.local:18443/ready`. A ready server returns `{"result":"ok"}`. Apply the same CA and hostname mapping to subsequent requests.
2. A fresh server needs a Nango account before the environment service key can authenticate. Using the private service origin, send `POST /api/v1/account/signup` with a protected JSON body containing `name`, `email` and `password`. The pinned server creates the default environments. Its email provider delivers a verification code, or writes it to private server logs when SMTP is absent. Complete verification by sending the token to the private service's `POST /api/v1/account/verify/code` endpoint. [Account signup](https://github.com/NangoHQ/nango/blob/7faf2c303bbb0322333f526e9ca31c0fe95ef58e/packages/server/lib/controllers/v1/account/signup.ts)
3. Use the `prod` service key in an `Authorization: Bearer` header to call `GET /integrations` and `POST /integrations` on the forwarded service. A creation request includes the upstream `provider`, the Zasp adapter's `unique_key` and the provider's required credentials. For Slack use `slack` for both identifiers and supply `credentials` with `type: OAUTH2`, the provider application client ID, client secret and scopes. Keep bearer headers and provider credentials in protected files. Register `<public Zasp origin>/api/v1/integrations/oauth/callback` with the provider. [Pinned creation API](https://github.com/NangoHQ/nango/blob/7faf2c303bbb0322333f526e9ca31c0fe95ef58e/packages/server/lib/controllers/integrations/postIntegration.ts) · [Supported platforms and scopes](saas-connectors.md)
4. Enable the SaaS collector as described below. In Zasp **Integrations**, select the configured provider, enter its tenant ID, authorize it and run the first sync. For an API-key adapter, supply the `ref:nango/connection/<connection-id>` reference for the existing customer connection.

The VPS status command first checks server readiness, then calls `GET /integrations` with the protected service key. An authenticated empty environment reports `healthy (no provider integrations configured)`. If the provider is missing from Zasp, check the environment, provider, adapter's unique key and collector setting. [Pinned Nango list endpoint](https://github.com/NangoHQ/nango/blob/7faf2c303bbb0322333f526e9ca31c0fe95ef58e/packages/server/lib/routes.public.ts#L183)

## Connect Zasp and migrate an existing installation

In the Zasp namespace project only the Nango service key into the supported API and discovery workloads. The independently managed Nango database credentials and encryption key stay in the Nango namespace.

```sh
kubectl -n zasp create secret generic nango-client --from-file=service-key=/secure/nango-service-key
```

Set `nango.externalNamespace: connectors` and `nango.storageSecretName: nango-client` on the existing production Zasp chart. This omits the bundled Nango workloads and produces an egress rule for the dedicated namespace and TCP 8443. The API and configured SaaS discovery worker use `https://nango.connectors.svc.cluster.local:8443`. Empty `externalNamespace` retains the existing bundled service. Keep per-provider customer credentials inside the original Nango environment. `ZASP_NANGO_SERVICE_SECRET_REFERENCE` identifies the mounted environment key. It does not grant Nango access to the platform's other secrets.

For discovery through the registered SaaS adapters, include the following in the **product release** values and apply them through that release's normal upgrade command. The setting enables the SaaS collector in both the API and the discovery worker. The independent Nango release keeps its own values file.

```yaml
nango:
  externalNamespace: connectors
  storageSecretName: nango-client
discovery:
  saasCollectorVersion: collector_v1
```

Before upgrading an existing Zasp release, quiesce sign-in and discovery writes, capture a consistent backup of Nango's schemas, encryption key and environment credentials, and restore into the independent database. Preserve Nango integration configuration keys, connection IDs and the exact data-encryption key. Use the same Nango version across the cutover. Rehearse an authorized read, wrong-tenant rejection and a sign-in callback against the independent endpoint, then switch the Zasp release. Keep the original database, volume, key and last successful release values until rollback retention expires. If new credentials or connections have been created after cutover, reconcile those writes before routing back to the original database. Helm rollback alone cannot reverse database migrations.

Other trusted applications can use the independent service with an explicit NetworkPolicy client selector and their own credential boundary. This chart sets the server's public callback origin for Zasp. For mutually untrusted applications or incompatible callbacks, use independently scoped environments with a validated application gateway or a separate instance. Handing out the same environment-wide service key would give those applications access to each other's connections.

## Verify

Run `python3 -m unittest discover -s deploy/vps/nango/tests` with Node, Helm, and PyYAML. These tests check URL policy, generated workloads and network policies. For a cluster acceptance run, verify authenticated TLS from the API and discovery worker, a rejected TLS chain, a denied direct connection to Nango port 3003 from another pod, and success/failure of a real authorized/unauthorized connector call. Record a backup/restore of the Nango database and the end-to-end OAuth callback separately. This package covers Nango's deployment. The remaining application services have their own infrastructure requirements.
