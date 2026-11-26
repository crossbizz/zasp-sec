# VPS backups and isolated recovery

The VPS CLI collects explicitly configured state, produces a hashed manifest, encrypts the complete bundle and verifies the offsite ciphertext by reading it back. An operator can restore the verified contents to a new directory on a recovery machine. A successful component backup describes exactly what it captured. Services marked absent or independently protected appear as such in the manifest.

## Prepare the source and recovery inventory

Use the existing S3/R2 backup credentials, recipient certificate and independently held recovery key described in [Encrypted offsite backups](offsite-backups.md). The R2 writer needs GetObject for read-back. Give DeleteObject only to a separate operator credential used for explicit pruning. Store the original trusted receipts outside the VPS and independently from the bucket writer. Disabling object lifecycle expiry for this prefix prevents an outage from aging out the last good generation. Review cloud retention and deletion permissions separately.

Copy the [source inventory](../../deploy/vps/backup/sources.example.json) to a private file. In `zasp.env` set:

```dotenv
ZASP_VPS_BACKUP_SPEC_FILE=/etc/zasp/vps-backup.json
ZASP_VPS_BACKUP_RECEIPT_DIR=/mnt/recovery-inventory/zasp
ZASP_VPS_BACKUP_KEEP=7
ZASP_VPS_BACKUP_VERIFIED_RECEIPT=/mnt/independent/last-drilled-vps.receipt.json
```

Set the same `ZASP_VPS_INSTALLATION_ID` on the source and recovery configuration. The source spec, receipt, object key and encrypted manifest bind to that ID. Use a separate receipt directory per installation and destination, owned by the backup operator with mode 0700. Protect source specifications, PostgreSQL passwords, the OpenBao snapshot token and archive input files with mode 0600 or 0400. Keep signed certificates in trusted locations without group/other write access. Specify how to recover every source.

| State | Capture or recovery path |
| --- | --- |
| Product, Nango, OpenFGA, Temporal and visibility databases | Each `postgres` source runs PostgreSQL `pg_dump` in custom format with hostname-verified TLS, a private password file and a finite lock wait. `pg_restore --list` must accept the result. Use version-compatible PostgreSQL client tools and a role that can read all required objects and rows. Preserve role definitions, row-security arrangements, extensions and grants for fresh clusters separately. |
| OpenBao | A `openbao` source fetches a Raft snapshot over verified HTTPS with a snapshot-only token. It checks the HTTP response and the nonempty sealed-checksum member, as the OpenBao CLI does. Renew the reader token before expiry. Keep the original seal shares or auto-unseal dependency separate. |
| Nango encryption key | Preserve the exact original key inside the encrypted bundle as a `file` source or identify its independently recoverable escrow reference. An initialized database requires the matching key. |
| Configuration and artifacts | `release-config` is a reviewed manifest file containing the image digests, deployment values or their immutable artifact references, schema versions, secret references, TLS issuers and external DNS or registry dependencies. Mark derived or external state explicitly. Do not point this at arbitrary directories, decryption identities, AWS/R2 recovery credentials or unseal material. |
| OpenSearch and Neo4j | Supply existing consistent backup files, or an `external` reference to the provider-native snapshot and its restore instructions. A raw active data directory is not a consistent backup. |
| S3 evidence and SQS/outbox | Record the independent versioned-object inventory/retention and the DB outbox and queue-reconciliation procedure. A queue identifier alone does not preserve outstanding messages. Use an explicit `absent` reason for a service that has never been deployed. |

The bundle includes dumps, the Raft snapshot and private files named in the spec, plus references. Its `custody` section contains only references for the offsite read credential, client decryption key/passphrase and OpenBao unseal holdings. Keep the underlying materials outside both the archive and the OpenBao it protects. Database dumps each have their own native consistency point. For an application-consistent multi-service checkpoint, pause incoming writes and workers, drain or record in-flight/outbox work, quiesce Nango writes and key rotation, and take the snapshots inside that maintenance window. Restore-tested off-host backup age determines the achievable recovery point.

## Schedule and retention

Run one backup and copy its receipt into trusted offsite custody.

```sh
./zasp --profile vps backup pilot-initial.receipt.json
./zasp --profile vps backup scheduled
```

Install the supplied systemd user units under the dedicated backup operator's account. They run the checkout at `/opt/zasp` with `/etc/zasp/vps.env`. Adjust the unit's working directory and command to the actual checkout/config before installation if they differ. The operator needs read access to source credentials, root-protected scratch or encrypted temporary storage, writable receipt inventory and an independently accessible network mount. Configure the mount and check its availability before enabling unattended runs. A directory path alone does not prove an independent storage location.

```sh
mkdir -p ~/.config/systemd/user
install -m 644 deploy/vps/backup/zasp-backup.service deploy/vps/backup/zasp-backup.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zasp-backup.timer
systemctl --user start zasp-backup.service
systemctl --user status zasp-backup.service
systemctl --user list-timers zasp-backup.timer
```

Enable login lingering for this dedicated user if the timer must run without a session. The timer runs daily at 03:00 UTC with up to 15 minutes of jitter and catches a missed run after reboot. Override `OnCalendar` in a timer drop-in to change cadence. An unsuccessful upload, read-back or source capture exits nonzero without a receipt. Monitor failed units and the age of new receipts in a separate system. Serialize scheduled backups and retention by keeping the inventory on storage with working POSIX file locking and atomic hard links.

Timer runs never delete prior backups. To enforce a generation cap, a separate retention operator runs `./zasp --profile vps backup prune --yes` with its scoped delete credential. This keeps at least `ZASP_VPS_BACKUP_KEEP` distinct recent scheduled generations (minimum two), plus the independently restore-tested receipt. First restore and validate one actual generation, retain its receipt in trusted storage, and point `ZASP_VPS_BACKUP_VERIFIED_RECEIPT` to it. Pruning verifies the retained ciphertext against every retained digest before removing older scheduled objects. Unrecognized, ad-hoc and legacy receipts are outside this process. Per-object prune receipts remain in `pruned/`. In a versioned S3 bucket deletion may add a delete marker; storage usage then depends on noncurrent-version policy. Cloud-side lifecycle policies or privileged administrators can still delete objects independently.

## Recover on a fresh host

1. Provision an isolated network and fresh data volumes. Block downstream SaaS delivery, workers and application traffic. Obtain the trusted receipt, offsite read credential and matching private key/passphrase from their independent locations. Re-create the original provider, bucket and account or region settings.
2. Configure an absolute, unused `ZASP_VPS_RESTORE_DIRECTORY` on encrypted storage; its parent must exist. Run `./zasp --config /path/to/recovery.env --profile vps restore /trusted/generation.receipt.json --yes`. It reads back the ciphertext, checks the receipt, authenticates decryption and verifies the archive's exact member set, sizes and SHA-256 digests. Only then are private output files published into the new destination. No service restart, in-place database replacement or cutover is performed.
3. Review `manifest.json`. Match the installation, release, capture window, component evidence, external artifacts and expected independent-key references to the recovery inventory. Restore every externally referenced snapshot. Provision compatible database engines, original database roles, schemas and extensions first.
4. Using verified TLS and protected PostgreSQL credentials, restore each dump to its own new empty database with `pg_restore --single-transaction --exit-on-error --no-password --dbname=<fresh-database-name> <component-file>`. Supply host and trust roots through `PGHOST`, `PGPORT`, `PGSSLMODE=verify-full`, `PGSSLROOTCERT`, `PGUSER` and private `PGPASSFILE`. Validate schema, row counts, sampled checksums and service-specific data. A matching dump hash alone cannot certify SQL replay or cross-service consistency.
5. Restore `openbao-raft` into a separate disposable OpenBao installation using Zasp's [OpenBao recovery procedure](openbao-vps.md) and the original seal material. Enable Nango only against its restored DB and identical encryption key, verify authorized connections and test a benign read. Verify FGA model IDs and representative decisions, Temporal namespaces/history, graph/index snapshots, original S3 evidence versions and outbox idempotency from isolated workers.
6. Record the successful drill and its receipt separately. Coordinate an explicit maintenance window, block writers, verify the intended target, then promote the validated replacement. Keep the prior installation and its keys until rollback and retention requirements permit retirement. On a failed drill or interrupted setup, leave production running and use a new empty recovery directory for the next attempt.

The automated tests exercise real OpenSSL and file protections, a disposable TLS snapshot endpoint, fixture database clients, object operations and fresh-directory validation. Set `ZASP_TEST_VPS_POSTGRES=1` with PostgreSQL server/client binaries on PATH to run a real disposable TLS database dump and replay into a fresh database. Cloud buckets and a complete installed customer environment require separate contract tests and an actual restore drill.
