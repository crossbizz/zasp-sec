# Independent Nango release

`deploy/vps/nango` runs Nango, a private TLS proxy and a separate pre-install/pre-upgrade migration job. Install it in a dedicated namespace with its own database and release lifecycle. Zasp reaches this service only over the internal TLS endpoint. The application and the TLS proxy share a pod network. The only non-TLS hop is the loopback connection from the proxy to Nango. There is no public service or ingress in this chart.

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
kubectl -n connectors create secret tls nango-server-tls --cert=server-chain.pem --key=server.key
kubectl -n connectors create configmap nango-database-ca --from-file=ca.crt=database-ca.pem
kubectl -n connectors create secret generic nango-storage \
  --from-file=database-url=/secure/database-url --from-file=encryption-key=/secure/encryption-key \
  --from-file=service-key=/secure/nango-service-key
helm upgrade --install nango deploy/vps/nango -n connectors -f nango-values.yaml --wait --timeout 10m
kubectl -n connectors rollout status deployment/nango
```

The service reads Kubernetes Secret files with mode 0440 at startup and supplies the values to the Nango process. Restart it after rotating an environment credential. The migration pod receives only the database URL and encryption key. The same image digest and migration command as the bundled Zasp service run against the dedicated database. The migration hook has DNS and database egress. The Nango pod adds HTTPS egress only to the configured provider CIDRs. Ensure those CIDRs are current. k3s CoreDNS pods must match `k8s-app=kube-dns`. Additional NetworkPolicies can grant access, so restrict policy edits in this namespace. A provider that cannot supply stable addresses needs a separately controlled egress proxy before onboarding.

## Connect Zasp and migrate an existing installation

In the Zasp namespace project only the Nango service key into the supported API and discovery workloads. The independently managed Nango database credentials and encryption key stay in the Nango namespace.

```sh
kubectl -n zasp create secret generic nango-client --from-file=service-key=/secure/nango-service-key
```

Set `nango.externalNamespace: connectors` and `nango.storageSecretName: nango-client` on the existing production Zasp chart. This omits the bundled Nango workloads and produces an egress rule for the dedicated namespace and TCP 8443. The API and configured SaaS discovery worker use `https://nango.connectors.svc.cluster.local:8443`. Empty `externalNamespace` retains the existing bundled service. Keep per-provider customer credentials inside the original Nango environment. `ZASP_NANGO_SERVICE_SECRET_REFERENCE` identifies the mounted environment key. It does not grant Nango access to the platform's other secrets.

Before upgrading an existing Zasp release, quiesce sign-in and discovery writes, capture a consistent backup of Nango's schemas, encryption key and environment credentials, and restore into the independent database. Preserve Nango integration configuration keys, connection IDs and the exact data-encryption key. Use the same Nango version across the cutover. Rehearse an authorized read, wrong-tenant rejection and a sign-in callback against the independent endpoint, then switch the Zasp release. Keep the original database, volume, key and last successful release values until rollback retention expires. If new credentials or connections have been created after cutover, reconcile those writes before routing back to the original database. Helm rollback alone cannot reverse database migrations.

Other trusted applications can use the independent service with an explicit NetworkPolicy client selector and their own credential boundary. This chart sets the server's public callback origin for Zasp. For mutually untrusted applications or incompatible callbacks, use independently scoped environments with a validated application gateway or a separate instance. Handing out the same environment-wide service key would give those applications access to each other's connections.

## Verify

Run `python3 -m unittest discover -s deploy/vps/nango/tests` with Node, Helm, and PyYAML. These tests check URL policy, generated workloads and network policies. For a cluster acceptance run, verify authenticated TLS from the API and discovery worker, a rejected TLS chain, a denied direct connection to Nango port 3003 from another pod, and success/failure of a real authorized/unauthorized connector call. Record a backup/restore of the Nango database and the end-to-end OAuth callback separately. This package covers Nango's deployment. The remaining application services have their own infrastructure requirements.
