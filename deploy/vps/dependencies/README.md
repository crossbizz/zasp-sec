# Persistent OpenFGA and Temporal on a single VPS

The `dependencies` unit installs three separate PostgreSQL 18 databases, Temporal 1.32.0 and OpenFGA 1.21.0 in the selected k3s cluster. Each database has a dedicated credential and a 10 GiB PVC. OpenFGA uses a preshared key and HTTPS. Temporal uses mutual TLS and creates the namespace `zasp-staging` with three days of history retention. Each runtime service starts one replica per role. OpenFGA store/model publication and the Zasp application have separate lifecycles. [VPS deployment](../../../docs/operations/vps-first-deployment.md)

## Prepare the cluster

Use an operator host with kubectl, Helm 3.16 or later in the 3.x series, Python 3.10+, PyYAML, OpenSSL and curl. The cluster must enforce NetworkPolicy, protect Kubernetes Secrets at rest and have sufficient persistent disk and memory. Install the verified CloudNativePG controller and CRDs before this unit. The included policy permits its controller in `cnpg-system` labeled `app.kubernetes.io/name=cloudnative-pg`. The database contract was checked against the 1.30.2 CRD. Review a CNPG-compatible PostgreSQL 18 image, pin it by digest in the VPS config as `ZASP_VPS_POSTGRES_IMAGE`, and choose `ZASP_VPS_STORAGE_CLASS` (default `local-path`). Reserve disk for PostgreSQL WAL and migrations beyond the live data, and place recovery backups off the VPS. [CloudNativePG operator installation](https://cloudnative-pg.io/docs/1.30/installation_upgrade/)

Initialize the VPS config with `./zasp --profile vps config init`. Record the context, independently verified kube-system UID and installation ID. For these examples export `ZASP_VPS_KUBE_CONTEXT`, `ZASP_VPS_CLUSTER_UID` and `ZASP_VPS_INSTALLATION_ID` in your shell with the same values as that config. Run the following first-install commands in Bash from the repository root. They use create-only requests and require a selected cluster matching your recorded identity. Use dedicated namespaces. Grant permission to create pods, change labels, read Secrets and install network policies only to the authorized operator and service controllers.

```bash
set -euo pipefail
: "${ZASP_VPS_KUBE_CONTEXT:?}" "${ZASP_VPS_CLUSTER_UID:?}" "${ZASP_VPS_INSTALLATION_ID:?}"
test "$(kubectl --context "$ZASP_VPS_KUBE_CONTEXT" get namespace kube-system -o jsonpath='{.metadata.uid}')" = "$ZASP_VPS_CLUSTER_UID"
for ns in zasp-data zasp-runtime; do
  kubectl --context "$ZASP_VPS_KUBE_CONTEXT" create namespace "$ns" --dry-run=client -o json |
    kubectl label --local -f - "zasp.io/installation=$ZASP_VPS_INSTALLATION_ID" -o json |
    kubectl --context "$ZASP_VPS_KUBE_CONTEXT" create -f -
done
```

On retry inspect both existing namespaces' ownership before resuming. A namespace, managed resource or Helm release owned by another installation must be resolved independently. Ingress grants are additive. The installer rejects unexpected ingress policies in these two dedicated namespaces.

## Issue and deliver credentials

In a private, operator-owned directory on encrypted storage, place your internal CA's **public** trust bundles as `database-ca.crt` and `runtime-ca.crt`. Supply one operator-issued PEM leaf certificate and its matching unencrypted private key per row. The filename stem receives the suffixes `.crt` and `.key`. Protect the directory with mode 0700 and the keys with mode 0600. Use a trust bundle that allows OpenSSL to validate the leaf certificates. Keep CA signing keys in the issuing system.

| Filename stem | Required DNS SAN | Verified TLS purpose |
| --- | --- | --- |
| `openfga-db` | `openfga-db-rw.zasp-data.svc.cluster.local` | Server |
| `temporal-db` | `temporal-db-rw.zasp-data.svc.cluster.local` | Server |
| `temporal-visibility-db` | `temporal-visibility-db-rw.zasp-data.svc.cluster.local` | Server |
| `openfga` | `openfga.zasp-runtime.svc.cluster.local` | Server |
| `temporal-frontend` | `temporal-frontend.zasp-runtime.svc.cluster.local` | Server and client |
| `temporal-internode` | `temporal-internode.zasp-runtime.svc.cluster.local` | Server and client |

Set `TLS_DIR` to that directory and `INPUT_DIR` to a separate private operator-owned directory. The preparation utility validates certificate/key pairs, names, purposes and trust. It generates an independent random password for each database and an OpenFGA authentication token. It creates a single private Secret manifest exclusively, so an interrupted deployment can reuse the original credentials.

```bash
umask 077
python3 deploy/vps/dependencies/prepare_inputs.py --tls-dir "$TLS_DIR" --output "$INPUT_DIR/dependencies.json"
test "$(kubectl --context "$ZASP_VPS_KUBE_CONTEXT" get namespace kube-system -o jsonpath='{.metadata.uid}')" = "$ZASP_VPS_CLUSTER_UID"
kubectl --context "$ZASP_VPS_KUBE_CONTEXT" create -f "$INPUT_DIR/dependencies.json"
```

The manifest contains recoverable credentials. Protect the file and recovery copies on storage separate from the VPS. If the creation request partially succeeds, use the same manifest to create the remaining original inputs. Existing Secrets are never replaced by `kubectl create`. The runtime Secret names are `runtime-database-ca`, `openfga-datastore`, `openfga-auth`, `temporal-persistence`, `temporal-visibility`, `openfga-tls`, `temporal-frontend-tls` and `temporal-internode-tls`. Each database uses its own `<cluster>-tls` and `<cluster>-owner` in `zasp-data`, with the public root in `openfga-db-public-ca`.

## Validate and install

```bash
./zasp --profile vps --dry-run install dependencies
./zasp --profile vps doctor dependencies
./zasp --profile vps install dependencies
./zasp --profile vps status dependencies
```

Dry-run prints the plan offline. Doctor checks the target and namespace owner, CRDs, storage class, Secret fields, database identities, TLS parameters, conflicting objects and release identities. It verifies the chart archive digests and renders both releases without changing the cluster. For an offline mirror set `ZASP_VPS_RUNTIME_CHART_DIR` to the directory containing the original `temporal-1.7.0.tgz` and `openfga-0.3.15.tgz` archives. The same SHA-256 checks apply. [Version and artifact pins](../../../docs/operations/temporal-openfga.md)

Install creates ingress policies before pods, waits for all three databases, runs the pinned Temporal schema Job and then waits for both Helm releases. It retains the completed Job to support retries. An owned release with the expected version and values is reused. If a schema Job fails, inspect its status and the two database schema versions before recovering. Retain an off-host backup before any repair or upgrade. Status checks database readiness, bound volumes, private Services, Helm release ownership and values, and current deployment rollouts. OpenFGA is available inside the cluster at `https://openfga.zasp-runtime.svc.cluster.local:8080`. The Temporal frontend listens at `temporal-frontend.zasp-runtime.svc.cluster.local:7233`. Application access requires a separately issued client certificate, the OpenFGA credential, and the published store and model.

A lost single host can also lose local-path volumes. Schedule encrypted off-host backups for all three databases, retain their credentials separately, and rehearse restoration into an isolated installation before using the unit for durable records. [VPS backups](../../../docs/operations/offsite-backups.md)
