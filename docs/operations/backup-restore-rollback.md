# Backup, restore and rollback

## Backup

Before every schema or application release, take a provider-native encrypted PostgreSQL snapshot and record its immutable identifier, schema version, creation time, region and restore-retention deadline. Verify backup completion; an initiated backup is not evidence. Export Helm values with secret references redacted and retain the reviewed image digests and rendered manifest fingerprint.

Run a restore drill at least quarterly into a newly created isolated database. Apply network isolation first, restore the snapshot, run schema/readiness checks, compare scoped row counts and sampled checksums, exercise a read-only authenticated workflow, and destroy only the drill resources by their ownership label.

## Application rollback

Stop promotion when error, latency, auth, dependency or canary budgets fail. Preserve correlation and trace IDs. If schema v16 remains compatible, use Helm rollback to the previously attested image digests and verify every API, gateway, ingest, and worker readiness check plus the read-only synthetic before reopening traffic.

Do not run `agentsec-migrate down` as a routine rollback. The command removes migrations through the baseline and is destructive. When a release cannot run safely on the current schema, block writes, restore the pre-release snapshot into a new isolated database, validate it, switch the secret reference atomically, and keep the failed database for investigation. Prefer a forward-compatible repair migration whenever possible.

## Queue and provider recovery

Provider calls use bounded timeout, concurrency and retry rules; non-idempotent mutations are never retried automatically. Keep the API ready only while PostgreSQL and required identity provider checks pass. For queue recovery, stop consumers, measure visible/in-flight/DLQ counts, redrive only after the poison message cause is fixed, preserve idempotency keys, and confirm each durable effect once. Never delete a queue or DLQ to clear an alert.

For stale projections, keep PostgreSQL authoritative, disable the affected read surface, and retain immutable evidence. Verify the OpenSearch mapping/marker or Neo4j constraints with the separate init authority; never grant DDL to a runtime worker. Rebuild from version-pinned discovery snapshots or runtime-raw object versions, compare scope/source/generation-keyed counts and content digests, then re-enable. Do not replay provider mutations or surface stale OpenSearch/Neo4j data as authoritative truth.
