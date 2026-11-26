# OpenBao clients in the production Helm chart

The production chart projects separate credentials for connector secrets in the API and discovery worker, and recovery signatures in the backup and restore workers. Enable either capability independently. The control plane still requires its configured database, AWS workload identities, CSI startup secret delivery and remaining AWS dependencies. The OpenBao service has its own release and lifecycle.

## Prepare the trust relationship

1. Install the independent OpenBao chart in a separate namespace, for example `bao-system`. Issue its server certificate with the SAN `openbao.bao-system.svc`. Set its `clientNamespace` to the actual Zasp release namespace (for example `agentsec`) and keep its `clientPodLabels` set to `zasp.io/openbao-client: "true"`. Enable a CNI that enforces NetworkPolicy and the existing cluster DNS egress. Protect control of both namespace and pod labels.
2. In the Zasp namespace, provision a ConfigMap named `zasp-openbao-ca` containing the CA certificate in `ca.crt`. Provision only the workload Secrets needed from the table below. Each Secret has one key named `token`. Use protected files or a secret controller for provisioning. Keep credentials out of Helm values, terminal history and release artifacts. Enable Kubernetes Secret encryption at rest and restrict RBAC and pod creation permissions.
3. Configure the KV mount with CAS and one retained version. Initialize the Transit signing key as ECDSA P-256 under its lowercase UUIDv4 name on the fixed `transit` mount. Issue tokens with workload-specific policies. Complete the documented connector migration and inventory historical signing authorities before switching writers.

| Kubernetes Secret | Policy scope |
| --- | --- |
| `zasp-openbao-api` | Read connector credentials, create and consume OAuth records in the configured root |
| `zasp-openbao-discovery` | Read the discovery credential paths and required KV mount configuration |
| `zasp-openbao-backup` | Read key metadata and sign with the selected Transit key |
| `zasp-openbao-restore` | Read key metadata and verify the selected Transit key |

## Configure and verify

Overlay these public settings on a complete production values file. Use the UUID of the actual key. Discovery and API share the same credential root, with the API’s `connectors.secretPrefix` ending in `/oauth`.

```yaml
openbaoClients:
  namespace: bao-system
  connectorSecretsProvider: openbao
  kvMount: zasp-kv
  recoverySigningProvider: openbao
  transitKey: 1876a280-89c6-4aa4-aac0-ac263a11056a
recovery:
  canaryEnabled: true
```

Run `helm lint deploy/staging/product -n agentsec -f production.yaml -f openbao-clients.yaml` and `helm template zasp deploy/staging/product -n agentsec -f production.yaml -f openbao-clients.yaml`. The production `renderRelease` helper accepts the same `openbaoClients` object in its options. Roll out the reviewed values and verify readiness. Exercise one OAuth secret lifecycle, one discovery read, one new backup and one restore with each configured historical verifier. Under Transit, the backup receives only the Transit signing selector. The restore receives the previous `recovery.signingKMSKeyArn` if configured. Keep the AWS key for existing manifests. Remove obsolete AWS signing and connector write grants from these role policies once the migration and rollback requirements permit it.

Each selected Pod copies its projected token and CA into a small memory-backed volume during initialization. The application runs as UID 65532 and receives only the read-only private subdirectory, with mode 0700 and files at 0400. Only the init container sees the Kubernetes Secret projection. The chart adds egress to the selected OpenBao pods in the configured namespace on TCP 8200. Keep the existing read-only workload identity and health checks in place.

## Renewal, rotation and rollback

A token renewed in place by its issuer keeps the same bytes. For a replacement token or CA bundle, update the corresponding Kubernetes object and roll the affected Deployments. The in-pod copy takes effect at pod startup. Check readiness and perform an authorized operation before revoking the replaced token. For CA rollover, distribute a bundle containing old and new trust anchors before the server certificate changes, then remove the retired anchor after all clients have rolled.

To return new signing to KMS, set `openbaoClients.recoverySigningProvider: aws-kms` and restore the original `recovery.signingKMSKeyArn`. Keep the Transit key and namespace for historical Transit verification. This projects OpenBao credentials only to the restore worker for signing history. To return connector credentials to AWS, first reconcile all active and removed references under the original KMS key, then change `connectorSecretsProvider` to `aws-secrets-manager` and clear `kvMount`. Clear the OpenBao namespace when no clients remain.

[Connector migration and policy details](openbao-connector-secrets.md) · [Recovery signing and rotation](recovery-signing-providers.md) · [Kubernetes Secret delivery](https://kubernetes.io/docs/concepts/configuration/secret/)
