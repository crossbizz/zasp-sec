# OpenBao on a single k3s node

`deploy/vps/openbao` installs one independent OpenBao server with integrated Raft storage. Use a dedicated namespace, TLS trust chain and persistent disk. A failed VPS takes the server offline until an operator restores it. There is no failover between providers or hosts. Disk, offsite copies, monitoring, patching, key custody and restore time are part of the operating cost. Size the disk from measured Raft growth and rehearse recovery before setting a pilot's recovery objectives.

## Install and unseal

1. Configure k3s with an enforcing NetworkPolicy controller, encrypted Kubernetes Secrets, encrypted storage, restricted administration and swap disabled or encrypted. OpenBao relies on the host to keep sensitive memory out of unencrypted swap. Choose a persistent storage class that supports the container's UID/GID 1000 and retains the data needed for recovery. A local-path volume on a destroyed VPS needs an offsite restore.
2. Create namespace `openbao-system`. Issue a TLS server certificate whose SANs include `openbao.openbao-system.svc` and IP `127.0.0.1`. Include certificate intermediates in `tls.crt`. Secure its private key and retain the CA and reissuance capability outside OpenBao. Set `OPENBAO_IMAGE` to the verified upstream 2.7.3 image and its immutable registry digest. Use the architecture of the VPS. Review subsequent security releases before upgrading.
3. Install from a secured operator workstation. The release manages one service per namespace. An empty image or tag-only image fails chart validation. A sealed pod fails readiness while its listener remains alive.

```sh
kubectl create namespace openbao-system
kubectl -n openbao-system create secret generic openbao-server-tls \
  --from-file=tls.crt=server-chain.pem --from-file=tls.key=server.key --from-file=ca.crt=ca.pem
helm upgrade --install openbao deploy/vps/openbao -n openbao-system \
  --set-string image="$OPENBAO_IMAGE" --set-string storageClass="$OPENBAO_STORAGE_CLASS"
kubectl -n openbao-system port-forward pod/openbao-0 18200:8200
```

In another terminal set `BAO_ADDR=https://127.0.0.1:18200` and `BAO_CACERT` to the trusted CA file. Use a host on which command output, PGP private keys and the CLI token cache are protected. Leave verification enabled. A port forward to the pod also works before the headless service has a ready endpoint. For initial setup, identify each custodian's PGP public key and a separate root token recipient:

```sh
bao operator init -key-shares=5 -key-threshold=3 \
  -pgp-keys=custodian1.pub,custodian2.pub,custodian3.pub,custodian4.pub,custodian5.pub \
  -root-token-pgp-key=bootstrap.pub
bao operator unseal
```

Each of three custodians enters a different decrypted share at the hidden prompt. Repeat after restart. Store shares and their decryption keys with independent custodians outside the VPS. Create scoped operator authentication and the policies below, check a second operator's access, enable an audit device and protected external log shipping, then revoke the bootstrap root token. Chart traffic is private to selected pods in one named namespace. Restrict RBAC over those labels, Secret reads, volume snapshots, port forwards and pod exec. Use the Kubernetes API tunnel for administration.

This profile uses Shamir. An auto-unseal deployment needs an independent supported seal service with its own credentials, permissions, availability and recovery plan. Auto-unseal recovery keys authorize administrative recovery procedures. They cannot decrypt the barrier after the external seal key is lost. Changing to auto-unseal needs a separate planned seal migration, tested snapshots and corresponding egress policy.

## Mounts and workload permissions

Create dedicated mounts once, with a scoped provisioning identity. Generate a unique UUIDv4 for this deployment's recovery key. Retain the identifier with the restore inventory. Repeat these operations only after checking existing mounts, the key type, retention policy and key identity.

```sh
bao secrets enable -path=zasp-kv -version=2 kv
bao write zasp-kv/config max_versions=1 cas_required=true
bao secrets enable -path=transit transit
bao write "transit/keys/$RECOVERY_KEY_UUID" type=ecdsa-p256 exportable=false allow_plaintext_backup=false
bao policy write zasp-snapshot-reader deploy/vps/openbao/files/snapshot-reader.hcl
bao policy write zasp-restore-operator deploy/vps/openbao/files/restore-operator.hcl
```

Keep `deletion_allowed=false` for the Transit key. A separate administrator may rotate it. Preserve versions needed for all retained manifests. Disallow workload writes to key configuration, ACLs, token creation and sys/mounts. KV's single-version setting belongs on a dedicated mount because rotation and CAS tombstones discard the prior online version. Older backups retain the state captured when they were made.

| Identity | Minimum policy paths and capabilities |
| --- | --- |
| API connector | `read` on `zasp-kv/config`, `create, read, update` on `zasp-kv/data/<exact workload/OAuth prefix>/*`. Grant `read` separately on required static credential paths. |
| Discovery worker | `read` on `zasp-kv/config` and only its authorized data paths. |
| Recovery signer | `read` on `transit/keys/<uuid>`, `update` on `transit/sign/<uuid>/sha2-256`. |
| Recovery verifier | `read` on the selected key and `update` on `transit/verify/<uuid>/sha2-256`. Retain verification access to historical signers required by that worker. |
| Snapshot service | The included read-only snapshot policy. Treat this identity and its copies as highly sensitive. |
| Disaster recovery operator | The included restore policy, granted only during an approved restore and restricted to the isolated replacement. |

Set the selected workload's `ZASP_OPENBAO_ADDR=https://openbao.openbao-system.svc:8200` and `ZASP_OPENBAO_CA_FILE` to the mounted trusted CA. Scope its `ZASP_OPENBAO_TOKEN_FILE` to that workload. Use a private regular file owned by its process UID with mode 0400 or 0600. Bind the issuance policy to the workload, set a TTL, and independently renew or replace the token before expiry. A token file requires a trusted delivery and renewal process. Mount it on private memory-backed storage and replace it atomically. Test rotation and sealed responses before the first pilot. Test a negative request from an adjacent tenant or workload with its own restricted token. An API process serving multiple tenants still depends on application tenant authorization; an installation-wide ACL wildcard cannot isolate those tenants from that process.

## Offsite snapshot and key rotation

Capture from the active server. With a protected CLI token cache and the snapshot-reader identity, run the following in a fresh private directory on the backup host. Use a unique name for each snapshot. The backup provider must be configured before using the Zasp archive commands.

```sh
umask 077
SNAP_DIR=$(mktemp -d)
bao operator raft snapshot save "$SNAP_DIR/raft.snap"
./zasp backup upload "$SNAP_DIR/raft.snap" "$SNAP_DIR/raft.receipt"
```

Retain the receipt offsite, ideally in a separate write-protected inventory. Record the source cluster, seal type, OpenBao version/digest, backup time, TLS trust and Transit key versions. A backup is usable once a separate read-only identity has downloaded and authenticated it. Keep several verified generations. Delete transient local material under your backup handling policy. The bucket recovery credentials, archive identity/private key, TLS material, infrastructure access and original seal material must remain accessible while the entire VPS is offline.

Schedule snapshots to meet a measured recovery-point objective. The loss window extends from the last **verified offsite** snapshot to failure. Immediately after Transit key creation or rotation, capture and verify a new offsite snapshot before signing the first manifest with the new version. An operator can pause recovery-signing workers, rotate with `bao write -f "transit/keys/$RECOVERY_KEY_UUID/rotate"`, snapshot, rehearse historical and new-version verification on the replacement, then resume. Apply the same sequencing to changes to seal configuration, credential provisioning and other unrecoverable key material. A restored service can resurrect leases or credentials that were revoked after that snapshot; reconcile them against authoritative revocation records before permitting traffic.

## Restore onto a replacement

1. Fence the lost/old node. Leave its disk and earlier snapshots intact. Build an isolated single-node release with an empty volume, the original image digest, the same Raft node ID, verified certificates and no application ingress. Allow enough free space on its encrypted volume for both the uncompressed staging copy and restored Raft database. Keep the new instance isolated until all checks pass. Point the CLI at the replacement by an explicit pod port forward. Keep contexts for the replacement and production separate.
2. Retrieve the archived receipt from the offsite inventory. Using independent read-only storage credentials and the archive private key, download to a new protected file. Authenticate the receipt against the incident inventory before forcing a restore. The archive helper verifies integrity before returning the snapshot.
3. Initialize and unseal the empty replacement with a temporary set of shares. Assign an operator the scoped restore policy on **that replacement**. For a compatible snapshot from the same seal configuration use ordinary restore. A newly initialized Shamir instance has different shares, so it specifically needs the forced form on the isolated replacement.
4. After the replacement installs the snapshot it seals if its previous root key cannot decrypt it. Unseal with the **source cluster's** original shares. The temporary credentials and policies of the replacement have been superseded. Authenticate through a source identity retained for disaster recovery.
5. Check `bao status`, `bao operator raft list-peers`, the expected cluster ID, a preselected KV canary and verification of at least one retained signature from each needed key version. Confirm a wrong-tenant read and a verifier signing attempt are both denied. Restore current external credentials, reconcile revoke/delete events after the backup cutoff, test workload readiness, then change service routing. If acceptance fails, leave traffic fenced and rehearse an earlier verified snapshot on a new volume.

```sh
./zasp backup download "$RECEIPT" "$RESTORE_DIR/raft.snap"
bao operator raft snapshot restore -force "$RESTORE_DIR/raft.snap"
bao operator unseal
```

The included disposable drill brings up two independent TLS Raft servers, snapshots the first with a read-only policy, destroys it, restores onto the second and checks KV state, two Transit versions and rejected permissions. Run it with Docker, OpenSSL and Python 3. Run the Helm tests with Helm 3 and PyYAML.

```sh
python3 -m unittest discover -s deploy/vps/openbao/tests
python3 deploy/vps/openbao/tests/restore_drill.py
```

For archive configuration and receipt handling see [offsite backups](offsite-backups.md). Upstream references cover [Raft snapshots](https://openbao.org/docs/commands/operator/raft/), [seal and recovery keys](https://openbao.org/docs/concepts/seal/), [initialization](https://openbao.org/docs/commands/operator/init/) and the [production checklist](https://openbao.org/docs/concepts/production-hardening/).
