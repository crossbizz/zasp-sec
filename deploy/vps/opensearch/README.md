# Independent production OpenSearch

Install the `opensearch` Helm release in the `opensearch` namespace. It runs one OpenSearch 3.8 node with its Security plugin, a retained ReadWriteOnce PVC, private HTTPS on port 9200, and mandatory client certificates. This is a single-node deployment. Schedule a maintenance window for search updates and organize independent backups. The application release uses the service at `https://opensearch.opensearch.svc.cluster.local:9200`.

## Connect from a Mac to K3s

Choose the target that contains the data you want to inspect.

| Target | Kubernetes endpoint | REST API |
| --- | --- | --- |
| Evaluation release `zasp` | Pod `zasp-0` in namespace `zasp` | HTTP inside the all-in-one pod. Its search container runs with the Security plugin disabled. |
| Independent release `opensearch` | Service `opensearch` in namespace `opensearch` | HTTPS with mandatory mutual TLS. The hosted production application uses this service. |

Both endpoints serve the OpenSearch JSON REST API. Neither chart installs the OpenSearch Dashboards web application. The Nango dashboard has its own private access path. [Nango operator access](../../../docs/operations/independent-nango.md)

Set `VPS_SSH` on the Mac to the SSH host alias or login for your server, for example `export VPS_SSH=operator@vps.example.net`. On the VPS, the examples use K3s and the remote operator's `$HOME/.kube/config`. Provision that account for its target namespace. Port forwarding to a Service requires permission to read the Service, find its pods, and open the `pods/portforward` subresource. For a VPS administrator using the default K3s installation, use `k3s kubectl` as root, or `sudo -n k3s kubectl` where the remote account already has that permission, in place of `k3s kubectl --kubeconfig "$HOME/.kube/config"`. Keep the Kubernetes administrator kubeconfig on the server under its existing access controls. Each command below runs SSH and the Kubernetes forward together. Leave its terminal open and press Ctrl-C to close it.

### Evaluation search

Run on the Mac.

```sh
ssh -T -o ExitOnForwardFailure=yes -L 127.0.0.1:19201:127.0.0.1:19201 "$VPS_SSH" \
  'k3s kubectl --kubeconfig "$HOME/.kube/config" -n zasp port-forward --address=127.0.0.1 pod/zasp-0 19201:9200'
```

In a second Mac terminal, query the evaluation cluster.

```sh
curl --fail --silent --show-error --noproxy '*' 'http://127.0.0.1:19201/_cluster/health?pretty'
```

### Independent production search

Run on the Mac after the independent release is installed.

```sh
ssh -T -o ExitOnForwardFailure=yes -L 127.0.0.1:19200:127.0.0.1:19200 "$VPS_SSH" \
  'k3s kubectl --kubeconfig "$HOME/.kube/config" -n opensearch port-forward --address=127.0.0.1 service/opensearch 19200:9200'
```

Have the search CA operator issue a short-lived client certificate for your own identity. The authentication endpoint returns its username and mapped roles. For cluster health, the operator must map that identity to a role granting `cluster:monitor/health` on the server. The built-in application identities have index-specific roles. Keep their private keys with their workloads and the security administration key with the installation hook.

In a second Mac terminal, use your CA certificate and operator identity files. Set `SEARCH_TLS` to their directory. The explicit DNS resolution sends traffic through the tunnel and verifies the service hostname against its TLS certificate.

```sh
SEARCH_TLS="$HOME/.config/zasp/search"
search_api() {
  curl --fail --silent --show-error --noproxy '*' \
    --resolve opensearch.opensearch.svc.cluster.local:19200:127.0.0.1 \
    --cacert "$SEARCH_TLS/ca.crt" --cert "$SEARCH_TLS/operator.crt" --key "$SEARCH_TLS/operator.key" \
    "https://opensearch.opensearch.svc.cluster.local:19200/$1"
}
search_api '_plugins/_security/authinfo?pretty'
search_api '_cluster/health?pretty'
```

An HTTP 403 on the health endpoint means the server authenticated the request and the identity lacks the health permission. On a workstation that already has a scoped Kubernetes context, the equivalent direct tunnel is `kubectl --context "$ctx" -n opensearch port-forward --address=127.0.0.1 service/opensearch 19200:9200`.

## Prerequisites

Use the intended Kubernetes context, a working persistent StorageClass and at least 2 GiB of schedulable memory for the default node request. Configure resources, JVM heap and volume size in private Helm values. Apply the peer namespaces separately from the product release. Verify their installation ownership before changing existing namespaces. The VPS CLI checks the `zasp.io/installation` label against the installation ID in the protected operator configuration. Use an enforcing CNI for namespace and workload restrictions.

Issue certificates from a dedicated search CA. Each named Secret has `ca.crt`, `tls.crt` and an unencrypted PKCS#8 `tls.key`. Protect the key files and Kubernetes Secret access. Each client certificate has a single CN, clientAuth EKU and its own private key. Issue the server certificate with both clientAuth and serverAuth EKUs, CN `opensearch-node`, and DNS SANs for `opensearch.opensearch.svc.cluster.local` and `opensearch-0.opensearch-headless.opensearch.svc.cluster.local`.

| Namespace | Kubernetes Secret | Certificate CN | Access |
| --- | --- | --- | --- |
| opensearch | opensearch-node-tls | opensearch-node | Server and node transport |
| opensearch | opensearch-security-admin-tls | opensearch-security-admin | Security configuration installation hook |
| zasp | opensearch-api-client | zasp-search-api | Read runtime event and session records |
| zasp | opensearch-inventory-client | zasp-search-inventory | Update inventory projections |
| zasp | opensearch-runtime-client | zasp-search-runtime | Write runtime event and session projections |
| zasp | opensearch-schema-client | zasp-search-schema | Create the four product indices and their schema markers |

Create each Secret in its listed namespace from the corresponding issued certificate and key. Select the verified context explicitly. For example, these commands create only the node Secret and then install the independent release. Create the other five Secrets in the same manner before starting their consumers.

```sh
kubectl --context "$ctx" -n opensearch create secret generic opensearch-node-tls \
  --from-file=ca.crt=/secure/search/ca.crt \
  --from-file=tls.crt=/secure/search/node.crt \
  --from-file=tls.key=/secure/search/node.key
helm --kube-context "$ctx" upgrade --install opensearch deploy/vps/opensearch \
  --namespace opensearch -f /secure/search-values.yaml --atomic --wait --timeout 10m
```

The release hook runs the image's `securityadmin.sh` over verified HTTPS using the dedicated admin certificate. It installs the chart's certificate authentication domain, index-scoped roles and CN mappings. A failed hook fails the Helm operation. The product receives only the client identities listed for its namespace. Include `deploy/vps/production/values.yaml` after the private hosted-product values on the application release to set the Nango and OpenSearch endpoints.

## Verify persistence

Check the production claim from the operator's Kubernetes context.

```sh
kubectl --context "$ctx" -n opensearch get pvc data-opensearch-0
```

The StatefulSet retains its claim on scale-down and deletion. Retention protects against Helm uninstall. Also keep a verified offsite snapshot with its search configuration and keys. Before switching an existing writer, quiesce it, restore or rebuild the indices using the product's schema initializer, validate read and write permissions and compare the projected data. Rotate certificates through the Secret owner, restart the relevant workloads, and verify identities after rotation. Product-only upgrades do not run this chart's hooks.

The independent integration test boots the pinned server, runs its security hook, round-trips a runtime record, checks cross-role write refusals and requires a TLS client certificate. It upgrades the release, verifies the replacement pod uses the same claim, and checks the persisted document and its write protection again. It uses a disposable kind cluster and an ephemeral CA. Run `bash deploy/vps/opensearch/tests/acceptance.sh` on a host with Docker, kind, Helm, kubectl, curl and OpenSSL.
