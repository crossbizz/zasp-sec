# Private static add-on scans

The private worker handles manual ZIP uploads. Enrolled devices can also scan installed skills locally and send findings during inventory check-in. [Automatic device scans](../getting-started/local-skill-scan.md#when-a-skill-is-added-or-changed)

The private worker scans an explicitly selected ZIP for one Environment. The API authorizes one archive digest and size. The worker receives the bytes over TLS and returns aggregate static finding counts. Administrators can also enable registry delivery so AppSec can review an exact version. The submitting browser previews which destination will receive the findings. A regular local scan and findings-only submission remain available without this worker.

## Provision the private worker

1. Select a development, test or staging Environment with extended collection enabled in Data Controls. The existing production-class policy requires metadata-only collection. Select an HTTPS worker origin reachable from authorized employees. The product API and worker both require `ZASP_PRIVATE_ADDON_WORKER_SCOPE` in the form `ORGANIZATION_ID/WORKSPACE_ID/ENVIRONMENT_ID` and `ZASP_PRIVATE_ADDON_WORKER_ORIGIN` as the exact HTTPS origin without a path. Leave these unset to disable issuance. With the product Helm chart, set `privateAddonWorker.scope` and `privateAddonWorker.origin` together. The chart configures the API and adds just that exact HTTPS destination to the browser connection policy. Set `privateAddonWorker.resultCredentialID` for registry delivery. Other deployments must allow the same exact worker origin in the product UI’s `connect-src` directive.
2. Build the worker from the repository root with `go build -C cmd/zaspctl -o ./private-addon-worker ./cmd/private-addon-worker`. In its packaging, run as a dedicated unprivileged user, with a dedicated identity and no access to employee files. The browser-only worker needs no API credential. Provide TLS cert/key paths in `ZASP_PRIVATE_ADDON_TLS_CERT` and `ZASP_PRIVATE_ADDON_TLS_KEY`, and set `ZASP_PRIVATE_ADDON_UI_ORIGIN` to the exact HTTPS product UI origin. The process serves TLS on port 8443. Browser uploads require a trusted TLS certificate and network connectivity from the browser to that origin.
3. Provision `ZASP_PRIVATE_ADDON_MARKER_DIR` as an operator-owned persistent directory writable by the worker alone. Run one worker or share a storage volume that provides atomic exclusive creation, directory sync and durable writes. Each upload creates an empty replay marker named with an opaque grant ID. The worker checks the directory at startup and once a minute, removing markers older than one hour. Restarts reuse the same volume. On Windows provide a local NTFS service directory with inheritable allow entries restricted to the worker account, SYSTEM and local Administrators. The worker checks the pinned directory owner and DACL and publishes markers by write-through rename. Clearing the marker volume while five-minute grants remain active would break replay protection.
4. Pin the independently authenticated API's per-Environment Ed25519 verification key as `ZASP_PRIVATE_ADDON_VERIFY_KEY` (base64url, without padding). A freshly authenticated data-controls administrator can obtain the public value from the scoped grant response over the trusted product API. This response is available before the worker starts. A worker never accepts a public key from an upload. A change to the deployment token-reveal key rotates this derived public key. Reconfigure the worker, and issue fresh grants after rotation.
5. In a staging Environment, verify the exact recipient in the UI. Confirm that a synthetic skill produces the expected manifest and finding counts, and that replay and an altered ZIP are rejected. Confirm that application, ingress, tracing and proxy logging do not capture authorization headers or request/response bodies. Disable HTTP request-body buffering to disk, core dumps and unencrypted swap where the deployment requires memory-only processing.

The product API records the grant, approved actor, scope, archive SHA-256, size, idempotency key and expiry in PostgreSQL. It holds the signing key. The worker holds only the public key. Its request limit is 8 MiB compressed and the scanner caps individual members at 2 MiB, expanded bytes at 12 MiB and traversed entries at 1,024. The ZIP must contain a root-level `SKILL.md`. The process uses at most two concurrent scan slots. It runs no add-on code and writes no uploaded source to its filesystem. Rescanning source requires a new upload. The worker can retain findings through the optional registry setup below. An operator must separately verify the worker's ingress, storage, process and TLS configuration on its deployed host before advertising live coverage.

## Record private findings for review

1. Create a dedicated product token in the same Environment with the single `submit_addon_scans` permission. Give the product API its identifier in `ZASP_PRIVATE_ADDON_RESULT_CREDENTIAL`. Give the worker the token through an owner-readable, read-only secret mount at `ZASP_PRIVATE_ADDON_RESULT_TOKEN_FILE` (mode 0400 or 0600 on Unix, private service DACL on Windows) and the trusted product API HTTPS origin through `ZASP_PRIVATE_ADDON_RESULT_API_ORIGIN`. Restrict its egress to this origin. Keep token values out of service arguments, files in the source checkout and logs. Rotate both ends together and finish outstanding submissions before retiring a token. Leaving all three settings unset selects browser-only results.
2. Confirm a registered scan with a harmless ZIP. The worker writes only the grant ID, Environment, archive size/digest, expiry and aggregate finding/skip counts and manifest metadata to a restricted retry file. It sends those fields through `POST /api/v1/addon-scans`. The service checks the exact issuing grant and assigned credential before creating a receipt. Reviewers see `private_worker` and the reported provenance. Every review and its revision remains scoped to that Environment, origin and version.
3. Check restart and outage behavior in staging. **Queued** means the worker durably stored the aggregate result for retry. It retries with the same idempotency key for up to one hour after grant expiry. A confirmed response removes the pending report. Expired pending files are removed by the next sweep. **Recorded** includes the scan reference and, for a complete manifest, a review link. A queued result has no confirmed registry link yet. Check Tools & MCP after recovery or prepare a fresh upload after expiry. Protect this metadata volume with deployment-managed encryption and access controls.

## Submit and interpret a scan

Open **Tools & MCP → Skill scanner**. Choose a ZIP up to 8 MiB with `SKILL.md` at its root. Select **Review upload** to hash the file locally and request authorization for that digest and size. Private uploads require a freshly authenticated data-controls administrator, extended collection and a worker assigned to the selected Environment. Under **Scan this device**, you can also run the scanner locally.

Review the worker hostname, archive retention and where the findings will go. Select **Scan on** followed by the worker hostname to send the ZIP directly to the worker with a single-use grant. The browser omits Zasp cookies. The result shows scan completeness and static finding counts. A partial scan has no approvable version. AppSec reviews completed versions separately.

The API operation is `POST /api/v1/addon-scan-uploads`. The request selects `mode=private_upload`, `retention=memory_only`, `archive_digest=sha256:…` and `archive_bytes`. It requires the authorized browser session, current scope, CSRF and an idempotency key. An authorized retry returns the same unexpired grant. Switching to metadata-only collection prevents new grants. A worker validates issued grants locally until their five-minute expiry. To stop uploads immediately, disable worker ingress or stop the worker. Revoking its reporting token stops future registry submissions. The worker accepts `PUT /v1/uploads/{id}` with the signed grant, `Content-Type: application/zip` and the exact content length. The worker consumes a grant when it begins processing. On a failed or interrupted transmission, prepare a new grant. Raw content does not enter Zasp logs or report fields through the worker code.

To reproduce just the static result offline, pipe the privately selected ZIP into the local scanner with its independently expected length and SHA-256.

```sh
zaspctl addons scan-archive --local --size "$ARCHIVE_BYTES" --sha256 "$ARCHIVE_DIGEST" < skill.zip
```

The JSON report contains coverage and rule-count identifiers only. It omits member names, script arguments and archive contents. The canonical bundle digest covers the sorted member paths and uncompressed bytes. The archive digest binds the exact transfer, including ZIP container metadata.

## Retain an encrypted archive for 24 hours

In **Tools & MCP → Skill scanner**, select the archive, choose encrypted retention and review the Environment, destination and deletion deadline before confirming the transfer. Each new file starts in memory-only mode. The retained grant binds the Environment, actor, exact ZIP SHA-256, byte length and expiration. The returned retention receipt identifies the grant and deadline after the storage process reads back the encrypted object. If a retained transfer is interrupted, give the operator its grant ID so they can check its state.

Enable this mode independently on the API, scanner and storage process. The existing extended-collection and fresh data-control permissions apply. The API requires `ZASP_PRIVATE_ADDON_RETAINED_SCOPE` to equal its configured private worker scope. With the staging chart set `privateAddonWorker.retained: true` alongside its existing scope and origin. The scanner requires `ZASP_PRIVATE_ADDON_RETENTION_UPLOAD_SOCKET` pointing at the storage process's `uploads.sock`. A memory-only grant bypasses that socket. A retained grant uses a distinct signed version so an older scanner rejects it.

### Install the storage process

Build the Linux storage process from the repository root.

```sh
go build -C services/platform -o /tmp/agentsec-private-retention ./agentsec-private-retention
```

The storage process checks the original signed grant again. Give it the same `ZASP_PRIVATE_ADDON_WORKER_SCOPE`, `ZASP_PRIVATE_ADDON_WORKER_ORIGIN` and public `ZASP_PRIVATE_ADDON_VERIFY_KEY` as the scanner. The scanner runs static analysis in memory. The storage process accepts exact archive bytes over a local Unix socket and stores them in the configured backend.

| Storage process variable | Value |
| --- | --- |
| `ZASP_PRIVATE_ADDON_RETENTION_JOURNAL_DIR` | Absolute path to a durable, owner-only directory with mode 0700. The receipt records the grant, digest, byte length, object version, deadline and cleanup state. |
| `ZASP_PRIVATE_ADDON_RETENTION_SOCKET_DIR` | Absolute path to a local socket directory. Give the scanner's group traversal access and avoid group or other write permission. `uploads.sock` is group-accessible. `admin.sock` is owner-only. |
| `ZASP_PRIVATE_ADDON_RETENTION_BACKEND` | `s3` for versioned, SSE-KMS protected S3 storage. `local_encrypted` is available in local/test deployments. |

Run one storage process per journal. Restore its journal and backing store together. Startup checks the Environment and backend fingerprint before trusting earlier receipts.

```sh
/tmp/agentsec-private-retention serve
```

For a local staging rehearsal, set `ZASP_ENVIRONMENT=local`, use `local_encrypted`, and supply `ZASP_PRIVATE_ADDON_RETENTION_LOCAL_DIR` as a second durable owner-only directory and `ZASP_PRIVATE_ADDON_RETENTION_LOCAL_KEY_FILE` as an owner-only file containing 32 random bytes in unpadded Base64URL. Keep this key with the storage operator. The local store uses AES-256-GCM with the scoped object key as associated data. A key or volume change requires restoring the matching journal and storage identity.

For S3, configure the following variables under the `ZASP_PRIVATE_ADDON_` prefix.

| Suffix | Value |
| --- | --- |
| `RETENTION_S3_BUCKET`, `RETENTION_S3_OWNER` | Versioned bucket and its 12-digit AWS owner account. |
| `RETENTION_AWS_REGION`, `RETENTION_KMS_KEY_ARN` | Bucket Region and a customer-managed KMS key ARN in that account and Region. |
| `RETENTION_AWS_ROLE_ARN`, `RETENTION_IDENTITY_TOKEN_FILE` | Narrow workload role and absolute path to its projected web-identity token. |

Scope the role's object permissions to `organizations/<org>/workspaces/<workspace>/environments/<environment>/private-addons/*`. Each key includes the grant ID, archive SHA-256 and size. Permit conditional `PutObject`, object and version reads, and `DeleteObjectVersion` on that prefix. Permit `GetBucketVersioning` and prefix-constrained `ListBucketVersions` on the bucket, and `kms:GenerateDataKey` and `kms:Decrypt` on the configured key. Require SSE-KMS with that exact key and TLS in the bucket policy. Configure the prefix's current and noncurrent version lifecycle as a backstop for loss of the journal or a prolonged worker outage. Include any replication or backup destination in the organization's retention policy.

### Confirm storage and deletion

As the storage-process owner, use the same `ZASP_PRIVATE_ADDON_RETENTION_SOCKET_DIR` and pass the Environment scope and grant ID explicitly.

```sh
/tmp/agentsec-private-retention status --scope "$SCOPE" --grant "$GRANT_ID"
/tmp/agentsec-private-retention verify --scope "$SCOPE" --grant "$GRANT_ID"
/tmp/agentsec-private-retention delete --scope "$SCOPE" --grant "$GRANT_ID"
```

`status` shows the durable journal. `verify` reads and checks the immutable stored bytes against the original binding while the retention grant is active. Both return metadata. `delete` requests immediate cleanup of the pinned version and returns its receipt. The service also sweeps once per minute and on startup. `cleanup_pending` covers failed, held or unconfirmed cleanup. An outage can delay deletion beyond the deadline. Restore access and keep the service running to retry. `deleted` includes the trigger, request time and confirmed deletion time. An S3 delete marker, an access denial or an ambiguous response leaves cleanup pending.

Run `python3 scripts/smoke-private-addon-retention.py --help` for the local TLS rehearsal with both binaries. Before enabling a live AWS staging scope, exercise a harmless grant through the intended workload identity, verify the actual bucket owner and pinned KMS/version readback, and confirm deletion of the exact version plus an empty exact-key version listing. Temporarily denying delete permission on a staging test object should leave a pending receipt that clears after access is restored. Local ciphertext tests and AWS SDK contract tests exercise the application path; AWS authorization, KMS, bucket lifecycle, retention holds and provider behavior require that deployment-specific rehearsal.

### Compare declarations in a synthetic skill workspace

The attack-lab runner has two released synthetic archives, `declared` and `undeclared-local-socket`. Both exercise a fixed marker file, a child process from the released runner and a Unix socket inside an owner-only temporary directory. The second archive omits the local socket from its declaration. The output identifies the archive and grant, declared and observed capabilities, differences and completion time. A missed witness or timeout leaves the result inconclusive. This experiment establishes behavior for the named synthetic workspace. A customer-supplied skill continues through the private static scanner.

1. Configure a dedicated Ed25519 issuer for the retention administrator. Set `ZASP_PRIVATE_ADDON_FIXTURE_SIGNING_SEED_FILE` on the retention service to an owner-only file containing the unpadded base64url 32-byte seed. Set `ZASP_SKILL_FIXTURE_PUBLIC_KEY` to its corresponding raw base64url public key on the fixture task and `ZASP_SKILL_FIXTURE_SCOPE` to the exact Organization/Workspace/Environment. Keep the private key out of the scanner, runner and job handoff.
2. On the operator host generate a reference ZIP with `agentsec-attack-lab-runner --write-synthetic-skill declared > fixture.zip`. Submit it through the existing fresh-auth private scan with 24-hour encrypted retention. For the comparison repeat with `undeclared-local-socket`.
3. On the retention administration socket, run `agentsec-private-retention prepare-fixture --scope "$SCOPE" --grant "$GRANT_ID" > handoff.json`. The service verifies the unexpired, immutable stored object, checks its exact digest and size against the two released ZIPs, and signs a bounded handoff. No archive, command, path or credential leaves the retention service through this operation. A deleted grant, foreign scope or any other archive is ineligible.
4. Stage the released attack-lab-runner image in an isolated Linux task with a read-only root, writable memory-backed temporary directory, no cloud/task account credentials, a 60-second wall clock limit and no network ingress or egress. Its fixed child gets an empty credential environment. The test uses an inotify access record, the child’s successful exec/wait and a local socket with kernel-verified peer PID and UID. The ordinary AWS attack-lab proxy and workload credential are unnecessary for local Unix sockets.
5. Pass the fresh handoff to `agentsec-attack-lab-runner --run-synthetic-skill` on stdin or provision the mounted-file variant illustrated in the staging Job. Provide the task’s trust ConfigMap and a per-run handoff Secret in a dedicated namespace. Pin the released image digest, assign a unique Secret per concurrent run, apply the deny-all network policy before starting the Job, and delete the handoff after completion. Expiry can occur during scheduling. Issue a new handoff after verifying the retained grant again. [Staging Job](../../deploy/staging/skill-fixture-job.yaml)

For a local end-to-end acceptance run, use `CGO_ENABLED=0 python3 scripts/smoke-private-addon-retention.py --isolated-container`. It creates disposable keys and storage, runs the real TLS private scanner and retention service, verifies both differences in an unprivileged network-disabled container, and checks rejection for a different Environment and deleted grant. Omitting `--isolated-container` runs the same compiled Linux witnesses directly in a temporary workspace. A live hosted deployment requires its operator-approved image, signing key and enforced task isolation.
