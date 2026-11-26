# Connector secrets in OpenBao

The API uses this provider for OAuth PKCE grants, GitHub and Okta credentials, reference-backed integrations, and ticket webhook credentials. The discovery worker reads from the same credential namespace with its own read-only token. Existing authorization and reference validation still happen before lookup. Customer AWS role assumption, evidence encryption, Nango's separate service-key projection, and secret stores used by other worker modes retain their own configuration.

| Setting | API | Discovery worker |
| --- | --- | --- |
| `ZASP_CONNECTOR_SECRETS_PROVIDER` | `aws-secrets-manager` (default) or `openbao` | Same selection as API |
| `ZASP_OPENBAO_ADDR` | Verified HTTPS origin such as `https://bao.internal:8200` | Same origin |
| `ZASP_OPENBAO_CA_FILE` | Optional absolute path to PEM CA roots, otherwise system trust | Same CA |
| `ZASP_OPENBAO_TOKEN_FILE` | Absolute path to a private API workload token file | Separate private read-only workload token |
| `ZASP_OPENBAO_KV_MOUNT` | Name of a dedicated KV v2 mount, for example `zasp-kv` | Same mount |
| Credential root | `ZASP_CONNECTOR_SECRET_PREFIX=zasp/pilot/oauth` | `ZASP_DISCOVERY_SECRET_PREFIX=zasp/pilot` |
| `ZASP_CONNECTOR_KMS_KEY_ARN` | Required with AWS. Unset with OpenBao | Not used by the discovery worker |

Configure the connector selector only on the API and discovery worker. Set a separate credential root and tokens for every workload or deployment that requires isolation. Application tenant checks continue to use the database's scoped credential references. A deployment-wide service token can access its authorized workload prefix. Deploy tenants with separate roots and workload identities when provider-enforced tenant isolation is required.

## Initialize and operate the mount

1. Enable a dedicated KV v2 mount using an operator identity. Configure the mount with `bao write zasp-kv/config max_versions=1 cas_required=true`. Use a fresh mount and retain the default per-key version settings. Deny application identities permission to modify the mount or key metadata. Both workloads read the mount config at startup and reject version limits other than one.
2. Issue short-lived tokens with separate policies. Allow both tokens to read `zasp-kv/config`. Grant API read access to the specific credential paths it resolves and create/read/update on dynamic OAuth and connector credential paths. Grant discovery read access only to the credential paths it consumes. Restrict the tokens' paths to their workload root and omit root, sudo, list, metadata, destroy, undelete and config-write privileges.
3. Supply the token with an OpenBao Agent auto-auth file sink or a workload-specific renewal process. Place its sink in a protected directory accessible only to the workload. Use mode `0400` or `0600`. The clients reread the token for each request and reject group/world access. Monitor renewals and handle revoked tokens. Restart the workloads after rotating the CA bundle. Sealed, unreachable, unauthenticated and untrusted TLS responses fail closed.
4. Use the exact existing credential name beneath the mount. The JSON record contains a `value` field with standard base64 of the original bytes. OAuth writes use KV v2 check-and-set with version zero. Consumption replaces the record with a single-use tombstone at the observed version. With `max_versions=1` the preceding secret value is purged on successful update. Keep tombstones for used OAuth grant IDs. PKCE expiration is checked by the existing application logic. Protect retained snapshots separately, as they can contain older values.

## Startup credentials from protected files

An OpenBao Agent template or another workload credential projector can render a startup value into a private file. For the API, `ZASP_POSTGRES_DSN`, `ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN`, `ZASP_SECURITY_AGENT_POSTGRES_DSN`, `ZASP_STYTCH_SECRET`, `ZASP_STYTCH_WEBHOOK_SECRET`, `ZASP_WORKFLOW_SIGNING_KEY` and `ZASP_TOKEN_REVEAL_KEY` accept a sibling setting with the suffix `_FILE`. The discovery worker accepts `ZASP_POSTGRES_DSN_FILE` and `ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN_FILE`. For example, set `ZASP_STYTCH_SECRET_FILE=/run/zasp/api/stytch-secret` and omit `ZASP_STYTCH_SECRET`.

Use an absolute path to an owner-only regular file in an administrator-controlled directory. The file and its parent directories must be owned by root or the effective runtime UID. Shared writable parents are rejected, except for sticky ancestors above a protected private directory. A single trailing LF is accepted. The original runtime validator still checks the value's syntax. Supplying both the direct value and a file fails startup. The API’s `--check-config` reads and validates explicitly configured startup projections. It never prints their values or contacts OpenBao. Rotate the projected file and restart the affected process to load updated startup credentials. Runtime OpenBao authentication token rotation takes effect on the next request.

## Cutover and rollback

1. Inventory active integration references and their AWS secret names using an authorized operator identity. Record their workload, tenant binding, logical reference and source version identifiers in a restricted manifest. Keep secret values out of the manifest and command-line arguments.
2. Quiesce new OAuth activity, allow outstanding grants to complete or expire, and stop all writers and discovery consumers for the migrating workload. Take independently recoverable backups.
3. For each durable reference, retrieve the explicit AWS version into protected process memory. Preserve `SecretBinary` bytes or encode `SecretString` as UTF-8. Create the corresponding KV v2 object at `<mount>/data/<same-name>` with `options.cas=0` and `data.value` equal to the base64 of those bytes. Read each object back and compare the decoded bytes in memory. On an existing destination value, verify equality before accepting that row. Stop on disagreement, missing references, or provider errors. Record reference names, version identifiers and verification status. Preserve the source objects and keys.
4. Switch the API and discovery together. Validate readiness and perform a credential read and one new OAuth flow in the intended tenant. Stored logical reference strings are provider-neutral. Staff must migrate every active reference before switching this existing dataset. There is no cross-provider retry. Keep workloads using separate namespaces on their applicable provider.
5. To roll back, quiesce both processes again, drain outstanding grants, and reconcile new, changed **and deleted** references back into the original AWS namespace using its original KMS key and read-back verification. Restoring the previous flags alone would expose stale data. After verification, restore original settings and check readiness. Retain both backups per policy.

[OpenBao KV v2 semantics](https://openbao.org/docs/secrets/kv/kv-v2/) · [OpenBao HTTP authentication](https://openbao.org/api-docs/)
