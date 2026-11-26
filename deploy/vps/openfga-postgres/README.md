# Private OpenFGA database on k3s

This component provisions a persistent, single-instance PostgreSQL database on the VPS for Zasp's existing OpenFGA deployment. OpenFGA's runtime and schema migrator use the same dedicated database owner. Zasp's API continues to use the authenticated OpenFGA HTTPS endpoint with its pinned store and model IDs.

## Prerequisites

Use a k3s cluster with persistent default storage, enforced NetworkPolicy and a CloudNativePG operator. The manifest was checked against the CloudNativePG 1.30.2 CRD. The operator is expected in namespace `cnpg-system` with label `app.kubernetes.io/name=cloudnative-pg`. Choose a reviewed CNPG-compatible PostgreSQL 18 image and set `PG_IMAGE` to its digest-pinned reference. Size the initial 10 GiB volume, requests and limits for the workload before installing. One node and one disk remain a single point of failure. [Operator installation and signed release verification](https://cloudnative-pg.io/docs/1.30/installation_upgrade/)

Prepare the following existing inputs on the operator machine.

- `db-server.crt` and `db-server.key` are a PostgreSQL server certificate and its private key. The certificate must cover `openfga-db-rw.zasp-data.svc.cluster.local`. Use the internal database CA already trusted by the OpenFGA deployment. Deliver the CA's public certificate as `database-ca.crt` and keep its signing key offline.
- The `zasp-data` and `zasp-runtime` namespaces exist. The existing runtime deployment uses a Secret named `runtime-database-ca` in `zasp-runtime` with the same public trust bundle in `ca.crt`. It may also contain the roots used by Temporal. Coordinate any change to that shared bundle.
- Protect both namespaces with RBAC. Restrict who can create pods or change their labels. Restrict Kubernetes Secret access and enable datastore encryption for the cluster. The network policy permits TCP 5432 only from the labeled OpenFGA release and migration pods in `zasp-runtime`. It also permits the operator to reach the instance manager on 8000. Review any additional policies that select these pods because ingress grants are additive.

## Initialize a new database

Run in this component's directory on an operator host with encrypted local storage. The preparation command creates a new private output directory, a random app password, a PostgreSQL URI with `sslmode=verify-full`, and the name and digest binding for the database image. A repeat using the same directory exits before modifying its contents.

```sh
umask 077
openssl verify -CAfile database-ca.crt -verify_hostname openfga-db-rw.zasp-data.svc.cluster.local db-server.crt
python3 prepare.py --image "$PG_IMAGE" --output /secure/openfga-bootstrap
kubectl apply -f /secure/openfga-bootstrap/catalog.json
kubectl -n zasp-data create secret tls openfga-db-tls --cert=db-server.crt --key=db-server.key
kubectl -n zasp-data create secret generic openfga-db-public-ca --from-file=ca.crt=database-ca.crt
kubectl -n zasp-data create secret generic openfga-db-owner --type=kubernetes.io/basic-auth \
  --from-file=username=/secure/openfga-bootstrap/username --from-file=password=/secure/openfga-bootstrap/password
kubectl -n zasp-runtime create secret generic openfga-datastore --from-file=uri=/secure/openfga-bootstrap/uri
kubectl apply --dry-run=server -f cluster.yaml
kubectl apply -f cluster.yaml
kubectl -n zasp-data wait --for=condition=Ready cluster/openfga-db --timeout=10m
```

The `create secret` commands serve first installation. They refuse to replace an existing secret. Resume an interrupted installation using the same prepared credentials and inspect existing Secret identities before continuing. Keep recovery copies of the database credential, TLS material and private data separate from this VPS. The `openfga-db-rw` Service provides the private PostgreSQL endpoint. The authorization service is separately installed using the upstream chart pins, probes, database migrations, service certificate and token described in the runtime guide. [Runtime deployment](../../../docs/operations/temporal-openfga.md)

## Verify a VPS installation

From an operator terminal forward the Service with `kubectl -n zasp-data port-forward svc/openfga-db-rw 15432:5432`. From a second terminal, use the app password at the prompt and the trusted public CA. Hostname verification continues to use the certificate's Kubernetes DNS name.

```sh
psql -X -W 'hostaddr=127.0.0.1 host=openfga-db-rw.zasp-data.svc.cluster.local port=15432 user=openfga dbname=openfga sslmode=verify-full sslrootcert=database-ca.crt' \
  -c 'SELECT current_user, current_database(), ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()'
```

Require the `openfga` role and database and an active TLS connection. Repeat with a wrong host or untrusted CA and verify the connection fails. Check the OpenFGA migration job status, deployment readiness, and an authenticated read of the pinned store and model via Zasp. The repository tests validate the manifest, image pin, credential file permissions and the consumer chart contract. Installation, TLS handshake, persistent-volume recovery and a running OpenFGA service require the operator drill.

## Backup, restore and cutover

Before release or schema migration, take an encrypted off-host database backup and retain the private CA trust bundle, server certificates, OpenFGA service credentials, original store ID and model ID independently. For a logical backup, use PostgreSQL 18 `pg_dump --format=custom` with the same verified connection and a protected file on encrypted storage. Upload with `./zasp backup upload`. A storage snapshot on the same VPS cannot recover a lost host. [Offsite backup and recovery](../../../docs/operations/offsite-backups.md)

Rehearse restoration into a separately named cluster with its own storage, DNS SAN, secrets and tightly scoped NetworkPolicy. Download the backup, run `pg_restore --single-transaction --exit-on-error --no-owner` as the authorized owner against an empty isolated database and verify representative stores, models and tuple decisions. For an existing OpenFGA installation, quiesce writers and verify the old and new model IDs and decisions before switching the datastore URI. Keep the old database until rollback and retention requirements are met. For password rotation, coordinate the application role password, the runtime Secret and an OpenFGA restart, then recheck authorized reads. Updating only one credential will interrupt service.
