# Encrypted archives and offsite backups

`./zasp backup` still uses the selected deployment profile to take its archive. The backup provider determines where the result goes. Configure this on the operator host running the CLI. API and worker credentials are independent.

| Backup provider | Result of `./zasp backup [file]` | Recovery input |
| --- | --- | --- |
| Unset or `local`, no backup keys configured | Existing private profile archive | Original archive, existing profile restore command |
| `local` with a recipient certificate | Private encrypted CMS envelope | Encrypted file from trusted custody plus its corresponding private key |
| `s3` or `r2` | Private JSON receipt after the CLI encrypts, uploads and reads back the entire object | Trusted receipt, read access to the original bucket, corresponding private key |

Use Python 3.8+ and OpenSSL 3 with CMS AES-GCM and RSA-OAEP support. Remote storage also requires an AWS CLI v2 that accepts `s3api put-object --if-none-match`. Use a Linux or macOS directory with hard-link support for the output. Allow space on encrypted temporary storage for the source, ciphertext and complete read-back. A forced shutdown can leave temporary files containing sensitive data. Secure the operator host and its scratch volume.

## Create recovery material

On a separate recovery machine create an encrypted RSA key and its public certificate. OpenSSL prompts for the key passphrase. Retain the private key, its passphrase and the bucket recovery credential in independently recoverable custody. Keep the public certificate fingerprint in the recovery inventory.

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 \
  -keyout recovery-private.pem -out recovery-public.pem -subj '/CN=Zasp backup recovery'
openssl x509 -in recovery-public.pem -noout -fingerprint -sha256
```

Install only the verified public certificate on the backup writer. Use a recipient certificate owned by root or the operator, without group or other write permission. On a recovery machine, use a private key and optionally a passphrase file readable only by the owner. Encrypt and store both independently of OpenBao and of the backup server. Rotate by switching the writer to a new public certificate, making and restoring a test backup, and recording the cutover with certificate fingerprints and receipts. Keep old keys until their last backup has expired.

## Operator configuration

Put paths and destination identifiers in the configured `zasp.env`. Put credentials in their own mode-0600 file. This example selects the standard Cloudflare R2 endpoint. Create a private general-purpose bucket and a dedicated bucket-scoped R2 access key pair. Use separate write/read and recovery read-only credentials as supported by the account.

```dotenv
ZASP_BACKUP_PROVIDER=r2
ZASP_BACKUP_BUCKET=organization-pilot-backups
ZASP_BACKUP_R2_ACCOUNT_ID=0123456789abcdef0123456789abcdef
ZASP_BACKUP_CREDENTIALS_FILE=/etc/zasp/backup-writer.credentials
ZASP_BACKUP_RECIPIENT_FILE=/etc/zasp/recovery-public.pem
```

For a general-purpose S3 bucket, replace the provider and R2 account setting with the following. Use the bucket's real region and its owner's 12-digit account ID. Grant the writer `s3:PutObject` and `s3:GetObject` beneath `zasp-backups/v1/`. A recovery role only needs `s3:GetObject` there. Add the necessary permissions if the bucket also enforces a customer-managed KMS key. Keep a recovery path to that key.

```dotenv
ZASP_BACKUP_PROVIDER=s3
ZASP_BACKUP_REGION=us-east-1
ZASP_BACKUP_EXPECTED_BUCKET_OWNER=123456789012
```

The separate credentials file accepts a single `[default]` section containing `aws_access_key_id`, `aws_secret_access_key` and, for temporary credentials, `aws_session_token`. Replace the file atomically before credentials expire. Supply sufficiently long-lived credentials to finish a write and read-back. The CLI uses system TLS trust and its own endpoint configuration. AWS credentials or endpoints used by an evaluation stack or customer discovery stay outside the transfer process.

For recovery, supply the original provider settings plus the following on the recovery machine.

```dotenv
ZASP_BACKUP_CREDENTIALS_FILE=/run/zasp/backup-reader.credentials
ZASP_BACKUP_IDENTITY_FILE=/run/zasp/recovery-private.pem
ZASP_BACKUP_PASSPHRASE_FILE=/run/zasp/recovery-passphrase
```

## Take a backup and rehearse a restore

```sh
./zasp backup pilot-before-upgrade.receipt.json
./zasp backup download pilot-before-upgrade.receipt.json isolated-profile.tar.gz
```

Copy the exact receipt into a trusted off-host recovery inventory with the time, profile, run, release and recipient certificate fingerprint. Limit who can modify that inventory. The receipt authorizes the expected ciphertext hash. Someone with the public certificate can encrypt another file, so choosing a receipt supplied by an untrusted bucket writer would allow substitution.

On an isolated local deployment with its original profile configuration, `./zasp restore pilot-before-upgrade.receipt.json --yes` verifies and decrypts, then runs the profile's existing restore. The local restore verifies the schema after database replay, which allows expected bootstrap-role errors. Review the restore log, compare scoped row counts and application checksums, and run the profile health checks before returning it to service. For evaluation Kubernetes, use the download command and isolate the target before exercising the existing restore procedure. Its PostgreSQL replay currently suppresses errors. The encrypted backup command refuses automated restore for this profile until replay can report database failures. For AWS production, download the encrypted logical backup for inspection and follow the separate database snapshot restore procedure. Existing profile limits on what the source archive captures still apply. [Backup and rollback](backup-restore-rollback.md)

Existing backups or independent service snapshots can use the same wrapper.

```sh
./zasp backup upload openbao.snap bao-before-rotation.receipt.json
./zasp backup download bao-before-rotation.receipt.json restored-openbao.snap
```

Use the service's own restore command on the verified file. For local encrypted storage, use `ZASP_BACKUP_PROVIDER=local` with a recipient certificate for encryption or private key for decryption. The upload output and download input in this mode are the CMS envelope itself. Keep local encrypted inputs in trusted custody.

## Retention, loss window and migration

Every backup uses fresh encryption. The object key contains its ciphertext SHA-256. The client requests a create-only write, reads the object back, and checks its complete length and SHA-256 even if the upload response was lost. A failed read-back returns an error and issues no receipt. Retrying the backup creates a fresh object. An interrupted upload or failure to save a receipt can leave an unreferenced object. Reconcile inventory and retention before removing anything. The single-write implementation accepts ciphertext up to 5,000,000,000 bytes. Larger backups need the existing provider-native snapshot path or a separate backup system.

Configure retention on the bucket and verify it in the provider console. The CLI never deletes backups. A writer with delete rights or a bucket administrator may still delete an object. The independently retained receipt detects substitution, not deletion. Retain multiple generations and administrative access independent of the backed-up environment. A backup becomes recoverable when its receipt and decryption material are safely held and a drill verifies the source service can restore it. The backup loss window extends to the last such recoverable snapshot. Take a new one after important changes such as key rotation.

To change providers, start new writes with the new destination, keep old receipts, keys and provider settings, and rehearse both restore paths. Explicitly select the old settings to read a historical backup. To move an old archive, download it to protected storage, upload to the new provider, and verify a separate restore before changing your inventory. For an original plaintext local backup, invoke the original profile restore with `ZASP_BACKUP_PROVIDER=local`, `ZASP_BACKUP_RECIPIENT_FILE=` and `ZASP_BACKUP_IDENTITY_FILE=`. Existing production snapshot procedures continue to govern rollback.

Full read-back incurs an extra GET and transfers the entire object to the operator host. Include storage class retrieval, egress and operation charges in provider comparisons. The test suite runs real OpenSSL and exercises both provider command contracts against a filesystem-backed AWS CLI fixture. It does not contact a cloud bucket. Qualify each actual bucket with the upload and independent download drill above. For an opt-in live R2 contract test, set `ZASP_TEST_R2_BACKUP=1`, `ZASP_TEST_R2_BACKUP_BUCKET` (a dedicated `zasp-contract-*` bucket), `ZASP_TEST_R2_BACKUP_ACCOUNT_ID` and `ZASP_TEST_R2_BACKUP_CREDENTIALS_FILE`. Run `python3 -m unittest discover -s deploy/zasp -p offsite_backup_test.py -v`. For S3, set `ZASP_TEST_S3_BACKUP=1`, `ZASP_TEST_S3_BACKUP_BUCKET`, `ZASP_TEST_S3_BACKUP_REGION`, `ZASP_TEST_S3_BACKUP_EXPECTED_BUCKET_OWNER` and `ZASP_TEST_S3_BACKUP_CREDENTIALS_FILE`. Both opt-ins require the dedicated bucket prefix and isolated bucket-scoped credentials. Each test stores a small random fixture encrypted to a disposable test key. Configure a short lifecycle rule in that dedicated bucket to expire test objects.

[Cloudflare conditional writes](https://developers.cloudflare.com/r2/api/s3/conditional-operations/) · [AWS PutObject](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html) · [OpenSSL CMS](https://docs.openssl.org/3.5/man1/openssl-cms/)
