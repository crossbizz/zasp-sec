# Recovery signing providers

Recovery backup workers sign the canonical manifest. Restore workers verify the
pinned manifest object, its digest, its recorded signing authority and the
child artifacts. S3 evidence encryption, SQS and Neon restore are independent
dependencies. The existing recovery worker still requires these services.

| Recovery worker | Signing settings |
| --- | --- |
| Existing AWS backup or restore | Keep the existing `ZASP_RECOVERY_SIGNING_KMS_KEY_ARN`. The provider defaults to `aws-kms`. |
| Backup with OpenBao | Select `ZASP_RECOVERY_SIGNING_PROVIDER=openbao` and configure the OpenBao settings below. Remove the signing KMS ARN from this worker. |
| Restore using OpenBao and historical KMS | Set the OpenBao provider and key. Retain the original signing KMS ARN and permission to describe and verify it. |
| Restore during rollback to AWS writes | Set the AWS signing provider and ARN. Keep the OpenBao key, TLS settings and verify-only token for outstanding OpenBao manifests. |

## Provision and rotate a key

1. On the independent OpenBao deployment, enable Transit at `transit`. Generate
   a UUIDv4 for a new key and record it in the deployment inventory. Zasp uses
   the actual Transit key name in its UUID-typed database locator.
2. With an operator identity, create that key with
   `bao write "transit/keys/$key" type=ecdsa-p256 exportable=false allow_plaintext_backup=false`.
   Leave `deletion_allowed=false`. Keep the minimum decryption version at 1
   so older signatures remain verifiable. Save an encrypted offsite Raft
   snapshot after creating or rotating keys.
3. Set `ZASP_OPENBAO_ADDR` to the verified HTTPS origin, `ZASP_OPENBAO_TOKEN_FILE`
   to the private workload token file, and `ZASP_OPENBAO_CA_FILE` for a private
   CA. Set `ZASP_OPENBAO_TRANSIT_KEY` to the UUID. Configure a separate token
   for each worker. Grant both tokens read on `transit/keys/<uuid>`. The backup
   token needs update on `transit/sign/<uuid>/sha2-256`. The restore token
   needs update on `transit/verify/<uuid>/sha2-256`. Operators manage keys
   and rotate, renew and replace workload tokens separately.
4. Roll out restore readers first. Verify a retained AWS manifest through the
   installed recovery flow. Switch the backup worker and produce a fresh
   backup. Rehearse a restore of that manifest in a disposable environment.
   To rotate a Transit key, write `bao write -f "transit/keys/$key/rotate"`,
   take another offsite snapshot and verify manifests from both versions.
   Keep key versions available for the full manifest and backup retention window.

The artifact records `signing_key_ref=openbao:transit/v<version>/<uuid>` and
the ASN.1 ECDSA signature. Historical AWS envelopes keep `signing_key_arn`.
The database stores the native key UUID and the digest of the complete envelope.
Workers route each restore to its recorded provider. A restore worker checks
readiness for every configured verification authority. An unavailable historical
provider can therefore pause restores even for newer backups. Retain the new restore binary when rolling writes back to
AWS. Earlier binaries do not understand OpenBao envelopes. Recover the original
Transit keyring from an independently accessible snapshot if the Bao instance is
lost. Creating a new key with the old name does not recover its signatures.

The version and hash algorithm follow the [OpenBao Transit API](https://openbao.org/docs/api/secret/transit/).

Both providers sign ECDSA P-256 over SHA-256 of the canonical payload. AWS
receives the raw message through 4,096 bytes and its SHA-256 digest above
that limit, preserving the signature algorithm. See the
[AWS KMS Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).
