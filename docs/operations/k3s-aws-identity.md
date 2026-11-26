# k3s workload identity for AWS-backed workers

The existing discovery and recovery binaries call regional STS with a rotating Kubernetes service-account token. The k3s preflight tests the same role, session name, audience and token path before an operator starts a worker. It can check each identity separately. It does not start jobs or access customer accounts.

| Worker | Kubernetes service account in `agentsec` | AWS role | Application inputs |
| --- | --- | --- | --- |
| Discovery | `zasp-discovery-worker` | `<cluster>-discovery-worker` | `ZASP_DISCOVERY_ROLE_ARN`, `ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE` |
| Recovery backup | `zasp-recovery-backup` | `<cluster>-recovery-backup` | `ZASP_RECOVERY_ROLE_ARN`, `ZASP_RECOVERY_WEB_IDENTITY_TOKEN_FILE` |
| Recovery restore | `zasp-recovery-restore` | `<cluster>-recovery-restore` | `ZASP_RECOVERY_ROLE_ARN`, `ZASP_RECOVERY_WEB_IDENTITY_TOKEN_FILE` |

## Establish the issuer

On a dedicated pilot cluster, configure the k3s API server to issue projected service-account tokens with an operator-owned HTTPS issuer. Set `service-account-issuer` and, for externally published keys, `service-account-jwks-uri` through the k3s server's `kube-apiserver-arg` option. Use the matching configuration on every server. Preserve the Kubernetes API's own audiences and never add `sts.amazonaws.com` to those accepted audiences. Validate the effective issuer on the cluster before trusting it in IAM. Existing clusters need an issuer-rotation plan for tokens already issued to their workloads. [K3s server configuration](https://docs.k3s.io/cli/server) · [Kubernetes service-account issuer discovery](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery)

Publish only the issuer's public discovery document and its public JWKS over verified HTTPS, reachable by AWS. You can retrieve the authoritative documents over the private API with `kubectl get --raw /.well-known/openid-configuration` and `kubectl get --raw /openid/v1/jwks`. Confirm the public document's `issuer` exactly matches the configured issuer and its `jwks_uri` points to the correct public keys. Protect publishing authority. Publish new keys before use and retain old public keys while outstanding tokens can still be valid. Keep signing keys and the cluster administration endpoint private. In the infrastructure AWS account register an IAM OIDC provider for that issuer and the audience `sts.amazonaws.com`. [AWS OIDC provider configuration](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

## Check one workload

The renderer requires only Python 3.9 or newer. Run it from the repository root with identifiers from the installation. For the preflight, obtain and verify an official AWS CLI v2 image digest for your CPU architecture from the Amazon ECR public registry.

```bash
identity=deploy/vps/aws-identity/render.py
issuer=https://identity.example.org/k3s-pilot
account=123456789012
cluster=zasp-pilot
workload=discovery-worker
region=us-east-1
# Set AWS_CLI_IMAGE to the verified public.ecr.aws/aws-cli/aws-cli@sha256:... reference.

python3 "$identity" trust --workload "$workload" --cluster "$cluster" \
  --account "$account" --issuer "$issuer" > "$workload.trust-statement.json"

python3 "$identity" preflight --workload "$workload" --cluster "$cluster" \
  --account "$account" --issuer "$issuer" --region "$region" \
  --image "$AWS_CLI_IMAGE" > "$workload.preflight.json"
```

Review the trust statement and add it only to the associated infrastructure role. It binds the exact IAM issuer, audience and service-account subject. Keep any EKS trust still in use. The trust statement grants no data-plane permissions. Keep separate resource policies for discovery, backup and restore. In the cluster, restrict who can deploy Pods or request tokens for these privileged service accounts. A principal who can run arbitrary Pods as one of these service accounts can use its workload role. [AWS STS web identity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)

The manifest contains a service account and a short-lived Job in the existing `agentsec` namespace. Inspect an existing account of the same name before applying the manifest. The Job disables the default Kubernetes API token, requests one STS-only token and mounts it read-only. It exchanges that file for a 15-minute session with a deny-all session policy and checks the returned identity fields. It uses a verified regional STS HTTPS endpoint and filters credentials out of stdout. For an authorized cluster check:

```bash
kubectl apply --dry-run=server -f "$workload.preflight.json"
kubectl apply -f "$workload.preflight.json"
kubectl -n agentsec wait --for=condition=complete --timeout=150s "job/zasp-$workload-identity-check"
kubectl -n agentsec logs "job/zasp-$workload-identity-check"
```

Success prints `AWS verified the workload identity.` Check the Job status and logs for a failed probe. Check public discovery/JWKS reachability, role trust, token audience, and regional STS egress. For another attempt, rerun after the finished Job is removed. Repeat separately with `workload=recovery-backup` and `workload=recovery-restore`.

## Using the tested boundary

In the corresponding worker Pod use the same service account and projected volume. Set the worker's role ARN from the table, `ZASP_AWS_REGION` to the chosen region, and its web identity token file to `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`. The path is fixed in the worker and works with a normal k3s projected volume. Mount the directory as in the probe so kubelet rotation remains visible. Do not use a `subPath` mount, copy the token into an environment variable, add static AWS keys, or set local AWS endpoint overrides. The worker independently exercises its existing AWS resource, identity and tenant authorization checks. Customer discovery continues to use the customer integration’s separately authorized role and external ID.

**Verification scope.** Local tests run the actual shell probe against a deterministic STS command fixture, including wrong issuer, subject, audience and role, and inspect the emitted trust and Pod specifications. The check has to pass against the installation's IAM and k3s to establish a live identity. It does not verify queue delivery, recovery signing, data permissions or backups. The complete pilot still requires credential delivery, database and index services, TLS, storage, queue configuration, and all required worker health checks.

To withdraw trust, remove only the new k3s statement for the affected role after workloads have moved and account for previously issued STS session lifetimes. Keep the old infrastructure and recovery keys while required for retained data.
