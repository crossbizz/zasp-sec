# Independent Nango release

`deploy/vps/nango` runs Nango, a private TLS proxy and a database migration job in a dedicated namespace. Use this release for a separately managed Nango installation. The hosted Zasp chart can also run a bundled Nango service. The independent release exposes a private operator dashboard and a separate application API. Zasp uses the `prod` environment in the chosen instance. The local Zasp profile does not provision Nango.

The standard `kubernetes` profile has its own bundled option. A single chart installs Nango and points Zasp at the same service. [Set up Nango in the standard Kubernetes chart](../getting-started/administrator.md#set-up-nango-in-this-cluster)

## Check the current K3s installation from your Mac

Connect to the tailnet and set `VPS` to your existing SSH destination. The examples use K3s's local kubeconfig on the VPS, so the Mac needs SSH and a browser. In this installation the production application release is `agentsec` in namespace `zasp`, and the independent Nango release is `nango` in namespace `connectors`. The Kubernetes evaluation release named `zasp` has its own installation lifecycle.

```sh
VPS='operator@your-vps-tailnet-name'
ssh -t "$VPS" 'sudo k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml config current-context && sudo k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml --context default get namespace kube-system -o custom-columns=CLUSTER_UID:.metadata.uid && sudo k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml --context default -n connectors get deployment/nango service/nango --ignore-not-found'
```

Confirm the context is `default` and compare the namespace UID privately with the installation's recorded `ZASP_VPS_CLUSTER_UID`. For a different named context, use its verified name throughout. If `deployment/nango` is ready and `service/nango` exists, proceed to **Access Nango and configure a provider** below. If both resources are absent and the current installation has only the evaluation release, follow the fresh-install steps in `connectors`. You can install and try Nango with a new empty database while evaluation stays up. No prior Nango database or restore rehearsal is needed for this fresh install. Switching the production application is a separate operation. [Evaluation cutover](vps-evaluation-cutover.md) If only one is present or the deployment is unhealthy, inspect the Helm release, the `nango-migrate` Job and pod status on the VPS before changing its storage or credentials.

## Provision and install

Run installation commands on the VPS with the verified context selected for both Helm and kubectl. For K3s, an authorized operator may use the local kubeconfig at `/etc/rancher/k3s/k3s.yaml`. Keep private values and credential files under operator-only permissions. Replace the example `/secure/` paths below with the actual private paths on the VPS.

1. Provision a dedicated persistent PostgreSQL database for Nango. Use a distinct owner and database, and grant this login the schema creation and migration rights it needs in that database. Scope its network route to this database on port 5432. Use a TLS server certificate for the database hostname, authenticate the login, and keep offsite PostgreSQL backups and the Nango encryption key outside the VPS. The chart consumes an existing database. Size and maintain its PVC or external service separately. On a fresh PostgreSQL server, an administrator can run the following in `psql` to create the dedicated owner and database. The password prompt avoids putting credentials in command history.

   ```sql
   CREATE ROLE nango LOGIN;
   \password nango
   CREATE DATABASE nango OWNER nango;
   ```

   Allow TLS-authenticated password connections from the Nango pods. Install the database's issuing CA as `nango-database-ca`. Its `database-url` must have the form `postgresql://nango:<URL-encoded-password>@<private-db-host>:5432/nango?sslmode=verify-full` and the database certificate must cover that hostname. Both Nango schemas, `nango` and `nango_records`, live in this dedicated database. An existing Zasp or Temporal database is a separate product store.
2. Choose namespace `connectors` for this example and enable an enforcing CNI network policy. Issue a private TLS certificate with a DNS SAN of `nango.connectors.svc.cluster.local`. Make the issuing CA available in the Zasp API and discovery container trust stores. Configure all deployments to use the same cluster DNS suffix required by Zasp's Nango client. Keep the TLS private key only in the service namespace. Require verified upstream TLS to both the database and the SaaS providers.
3. Preserve the existing Nango encryption key and valid environment service key on upgrade. On a new installation, generate three independent protected files without a trailing newline. Use `openssl rand -base64 32` for the encryption key. Nango requires a UUIDv4 for the environment service key. Generate it with `(umask 077; python3 -c 'import uuid; print(uuid.uuid4(), end="")' > /secure/nango-service-key)`. Generate the dashboard admin key separately with `openssl rand -hex 32`. For example, run `(umask 077; openssl rand -hex 32 | tr -d '\n' > /secure/nango-admin-key)` for a new admin key in a protected directory. The service key is a bearer credential with environment-wide privileges. The separate admin key signs dashboard sessions and password-reset tokens. Store it only in the trusted server processes that require it. Prepare a private database URL file with an explicit `:5432` and exactly `?sslmode=verify-full`. Each Secret key below contains the value bytes without a trailing newline. Supply the database CA separately.
4. Create a reviewed `nango-values.yaml` with the actual database and provider CIDRs, public Zasp origin and client namespace. The following nginx-unprivileged digest is exercised by the independent chart's hosted runtime test. Replace the sample private database address with its real routable destination as seen by the K3s CNI. Replace the provider placeholder with the approved public CIDRs required by each enabled provider. The chart requires nonempty ranges and rejects a default route. Keep credentials in the Kubernetes Secrets.

```yaml
publicOrigin: https://zasp.example.com      # Use the actual public Zasp origin
dashboard:
  allowSignup: true                       # New accounts only during initial setup
tlsProxyImage: nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
databaseEgressCIDRs: [10.50.0.15/32]      # Example private DB address; replace for this cluster
providerEgressCIDRs: ["<approved-public-provider-CIDR>"]
clients:
  - namespace: zasp
    workloads: [agentsec-api, agentsec-discovery-worker]
```

For the CLI-managed layout, prepare the release namespaces with the reviewed operator config. This command verifies ownership of existing namespaces and creates the missing ones. Then create the following inputs for the fresh Nango release.

```sh
./zasp --config /secure/operator.env --profile vps install namespaces
kubectl -n connectors create secret tls nango-server-tls --cert=server-chain.pem --key=server.key
kubectl -n connectors create configmap nango-database-ca --from-file=ca.crt=database-ca.pem
kubectl -n connectors create secret generic nango-storage \
  --from-file=database-url=/secure/database-url --from-file=encryption-key=/secure/encryption-key \
  --from-file=service-key=/secure/nango-service-key --from-file=admin-key=/secure/nango-admin-key
helm upgrade --install nango deploy/vps/nango -n connectors -f nango-values.yaml --wait --timeout 10m
kubectl -n connectors rollout status deployment/nango
```

To deliver verification, invitations and password reset links to the operator inbox, set `dashboard.emailSecret` to a private Secret containing `smtp-url` (a verified `smtps://` URL on port 465) and `smtp-from`. Set `dashboard.smtpEgressCIDRs` to the mail relay addresses. Only the Nango server receives these values and SMTP egress.

The service reads Kubernetes Secret files with mode 0440 at startup and supplies the values to the Nango process. Restart it after rotating an environment credential. The migration pod receives only the database URL and encryption key. The same image digest and migration command as the bundled Zasp service run against the dedicated database. The migration hook has DNS and database egress. The Nango pod adds HTTPS egress only to the configured provider CIDRs. Ensure those CIDRs are current. k3s CoreDNS pods must match `k8s-app=kube-dns`. Additional NetworkPolicies can grant access, so restrict policy edits in this namespace. A provider that cannot supply stable addresses needs a separately controlled egress proxy before onboarding.

For a CLI-managed VPS, configure the cluster context, cluster UID, installation ID, chart values, CA and key file in the private operator config. Use the following CLI commands in place of the Helm command above. The first command previews the operation and the second installs. The service readiness endpoint can respond as soon as migration and startup complete. Run the authenticated status check after creating the first Nango account, which creates its `prod` environment. [VPS component configuration](vps-independent-services.md)

```sh
./zasp --config /secure/operator.env --profile vps --dry-run install nango
./zasp --config /secure/operator.env --profile vps install nango
```

## Access Nango and configure a provider

For the VPS layout, the Nango release lives in `connectors` and the production Zasp release is named `agentsec` in namespace `zasp`. The Nango login URL is **`https://nango.connectors.svc.cluster.local:18443/`**. Zasp and other explicitly allowed pods call the same server through `https://nango.connectors.svc.cluster.local:8443`. Its dashboard listener accepts loopback connections inside the pod by default. The chart creates a private ClusterIP and installs no external Ingress.

1. On the Mac, map the certificate hostname to loopback by adding `127.0.0.1 nango.connectors.svc.cluster.local` to `/etc/hosts`. Obtain the public Nango **server CA certificate** from the operator, verify its fingerprint through a trusted channel, and trust it in macOS Keychain Access for the browser. The curl example assumes you saved that public certificate as `$HOME/.config/zasp/nango-server-ca.pem` on the Mac. This is the CA that issued `nango-server-tls`; the database CA can be different.
2. With `VPS` set as above, run this single command from the Mac and leave the terminal open. SSH carries local port 18443 over Tailscale and starts the K3s port-forward on the VPS. The VPS-side dashboard port stays bound to loopback.

   ```sh
   ssh -t -o ExitOnForwardFailure=yes -L 127.0.0.1:18443:127.0.0.1:18443 "$VPS" \
     'sudo k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml --context default -n connectors port-forward --address=127.0.0.1 deployment/nango 18443:9443'
   ```

   Open **`https://nango.connectors.svc.cluster.local:18443/`** on the Mac. A successful `curl` check below returns `{"result":"ok"}`. Press Ctrl-C in the SSH terminal to close the tunnel. If running directly on a workstation with the installation's authenticated kubeconfig, `./zasp --config /secure/operator.env --profile vps nango dashboard` verifies the pinned cluster UID, namespace owner and Helm deployment and forwards the same dashboard port.

   ```sh
   curl --fail --cacert "$HOME/.config/zasp/nango-server-ca.pem" \
     --resolve nango.connectors.svc.cluster.local:18443:127.0.0.1 \
     https://nango.connectors.svc.cluster.local:18443/ready
   ```

3. Sign in with the existing Nango account. For a fresh database, start with `dashboard.allowSignup: true`, create the first operator account, and open its one-time verification link while the tunnel is active. Without an email service configured, the pinned server records that private message in the Nango container log. Read it privately on the VPS with `kubectl -n connectors logs deployment/nango -c nango --since=10m`. Protect access to pod logs. After verifying the first account, set `dashboard.allowSignup: false` in the same values file and apply the reviewed Helm upgrade. Existing accounts can sign in after signup is closed. Dashboard requests, verification links and authenticated sessions use the private HTTPS origin.
4. Select **prod**, then **Integrations**. Add a provider with the exact unique key registered by its Zasp adapter, such as `slack` or `openai-admin`. For OAuth, enter the provider application's credentials in Nango and register `<public Zasp origin>/api/v1/integrations/oauth/callback` with the provider. This independent chart derives that callback from `publicOrigin`. If the Nango environment has a previously overridden **Auth callback**, set it to that exact URL. Verify the value shown by Nango before registering the provider. [Supported platforms and scopes](saas-connectors.md)
5. In the Zasp product at its public origin, open **Sources → Integrations** (`/connectors`). The catalog shows entries whose unique key and provider template match an enabled Zasp adapter in this Nango environment. Select the configured provider, enter its tenant ID, authorize it and run a sync. For an API-key adapter, supply its existing `ref:nango/connection/<connection-id>` reference. `./zasp --config /secure/operator.env --profile vps status nango` checks readiness and authenticates `GET /integrations` with the product environment key. An empty configured environment reports `healthy (no provider integrations configured)`.

The current source registry supports Anthropic, Atlassian/Jira, Atlassian organization, Databricks, GitLab, Google Workspace, OpenAI organization and project, ServiceNow, and Slack AI apps. Most use matching integration and template keys. For example, the Databricks integration key is `databricks` and its Nango template is `databricks-workspace`. An empty catalog after signup is expected until you configure the first matching provider. [Exact keys, authentication and scopes](saas-connectors.md#configure-an-existing-provider)

To make the dashboard available through an existing private network gateway, configure `dashboard.hostname` with its private DNS name and include that name in the TLS certificate. Add only the trusted gateway's namespace and pod workload name to `dashboard.clients`. The chart then exposes the dashboard on port 18443 of the same ClusterIP and restricts pod ingress on port 9443 to these gateways. Configure private DNS, authenticated operator access and TLS forwarding on the gateway. Its browser origin must match `https://<dashboard.hostname>:18443`. Without an assigned private DNS name, the tunnel above uses the existing service certificate.

The standard Kubernetes evaluation chart has its own dashboard setup. The older hosted chart's bundled Nango instance supports private environment-key provider management through `GET /integrations` and `POST /integrations`; its browser API is configured differently. [Evaluation dashboard](../getting-started/administrator.md#set-up-nango-in-this-cluster) · [Pinned Nango integration API](https://github.com/NangoHQ/nango/blob/7faf2c303bbb0322333f526e9ca31c0fe95ef58e/packages/server/lib/controllers/integrations/postIntegration.ts)

## Connect Zasp and migrate an existing installation

Give the production Zasp API and discovery workloads the Nango environment service key and the server CA in namespace `zasp`. The independently managed Nango database credentials and encryption key stay in the Nango namespace.

```sh
kubectl -n zasp create secret generic nango-client --from-file=service-key=/secure/nango-service-key --from-file=ca.crt=/secure/nango-server-ca.pem
```

Set `nango.externalNamespace: connectors` and `nango.storageSecretName: nango-client` on the existing production Zasp chart. This omits the bundled Nango workloads and produces an egress rule for the dedicated namespace and TCP 8443. The API and configured SaaS discovery worker use `https://nango.connectors.svc.cluster.local:8443`. Empty `externalNamespace` retains the existing bundled service. Keep per-provider customer credentials inside the original Nango environment. `ZASP_NANGO_SERVICE_SECRET_REFERENCE` identifies the mounted environment key. It does not grant Nango access to the platform's other secrets.

For discovery through the registered SaaS adapters, include the following in the **product release** values and apply them through that release's normal upgrade command. The setting enables the SaaS collector in both the API and the discovery worker. The independent Nango release keeps its own values file. When upgrading an older independent Nango release, add the new `admin-key` to its existing `nango-storage` Secret while preserving all existing keys. If an earlier deployment used a hex string for the environment service key, replace it with one UUIDv4 in the independent server and the application client Secrets and restart both consumers. Keep the encryption key. Start with signup disabled when accounts already exist.

```yaml
nango:
  externalNamespace: connectors
  storageSecretName: nango-client
  clientCAKey: ca.crt
discovery:
  saasCollectorVersion: collector_v1
```

When transferring already-populated Nango data from another installation, quiesce sign-in and discovery writes, capture a consistent backup of its schemas, encryption key and environment credentials, and restore into the independent database. Preserve Nango integration configuration keys, connection IDs and the exact data-encryption key. Use the same Nango version across the cutover. Rehearse an authorized read, wrong-tenant rejection and a sign-in callback against the independent endpoint, then switch the Zasp release. Keep the original database, volume, key and last successful release values until rollback retention expires. If new credentials or connections have been created after cutover, reconcile those writes before routing back to the original database. Helm rollback alone cannot reverse database migrations.

Other trusted applications can use the independent service with an explicit NetworkPolicy client selector and their own credential boundary. This chart sets the server's public callback origin for Zasp. For mutually untrusted applications or incompatible callbacks, use independently scoped environments with a validated application gateway or a separate instance. Handing out the same environment-wide service key would give those applications access to each other's connections.

## Verify

Run `python3 -m unittest discover -s deploy/vps/nango/tests` with Node, Helm, and PyYAML. These tests check URL policy, generated workloads and network policies. Run `python3 deploy/vps/nango/tests/dashboard_smoke.py` on a workstation with Docker, kind, Helm, kubectl and OpenSSL. It creates a disposable cluster, then exercises the actual TLS PostgreSQL connection, pinned server and TLS proxy, dashboard verification and login, session cookies, authenticated provider inventory, public OAuth redirect and persistence after a Helm upgrade. It deletes its isolated cluster afterward. For a cluster acceptance run, verify authenticated TLS from the API and discovery worker, a rejected TLS chain, a denied direct connection to Nango port 3003 from another pod, and success/failure of a real authorized/unauthorized connector call. Record a backup/restore of the Nango database and the end-to-end OAuth callback separately. This package covers Nango's deployment. The remaining application services have their own infrastructure requirements.
