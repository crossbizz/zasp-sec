# M1-12 S3 Artifact Interface Design

## Decision

Add a dependency-free `services/platform/artifactstore` package that owns the
product artifact contract and delegates storage to a narrow typed driver. Keep
the AWS SDK, bucket/KMS configuration, LocalStack endpoint, and disposable
provider lifecycle in the existing `proofs/localstack-storage` module.

This preserves the product/provider boundary established by M1-11: product
code owns scope, identity, content integrity, deadlines, and fixed errors;
proof and deployment adapters own provider credentials, transport, encryption,
and response parsing. Reusing the M0-07 `main` package as a product dependency
or exposing S3 bucket/key/ETag types through the product API is rejected.

## Product interface

The package exports an `ArtifactStore` interface with `Put`, `Get`, and
`Delete`. A concrete `Store` is constructed from a narrow `Driver` and a
`Config` containing a positive operation timeout no greater than 30 seconds and
a positive maximum artifact size no greater than 64 MiB.

Every request carries an already validated `domain.Scope` and
`domain.EvidenceRef`. `PutRequest` also carries an allowlisted media type and a
nonempty bounded byte payload. The store derives one canonical opaque key:

`organizations/<org>/workspaces/<workspace>/environments/<environment>/artifacts/<artifact>`

The product computes SHA-256 itself and passes only typed identity, media,
content, size, and checksum fields to the driver. Returned provider state must
exactly match the derived key, scope, artifact reference, content, media type,
size, and checksum. `Get` re-computes the checksum before returning a defensive
copy. `Delete` is scoped to the same canonical locator. No caller supplies a
bucket, raw object key, provider ID, ETag, encryption key, tag, or metadata map.

Supported skeleton media types are `application/json`,
`application/octet-stream`, `application/gzip`, and `text/plain`. Later
repository tasks may add higher-level artifact kinds, retention, and streaming;
M1-12 does not add public upload/download APIs or retention policy.

## Failure and concurrency behavior

Each operation validates its input before driver I/O, applies one total
configured deadline, contains driver panics, and returns only a fixed product
error: configuration, put, get, delete, or artifact validation. Product code
does not retry. The interface is safe for concurrent independent operations;
provider adapters remain responsible for their own connection safety.

Payload and driver-returned byte slices are copied at the boundary so callers
and drivers cannot mutate retained product state. Invalid UTF-8 identifiers,
zero/mismatched scope, invalid evidence references, unsupported media types,
empty/oversized content, malformed driver state, timeout, cancellation, error,
or panic all fail closed without exposing content, keys, provider messages, or
panic values.

## S3 adapter and LocalStack proof

The existing exact-pinned AWS SDK S3 client gains a narrow
`s3ArtifactDriver`. It maps the typed product object into one SSE-KMS object in
an exactly owned disposable bucket. The six product identity/integrity fields
are stored as exact S3 metadata; proof ownership uses exact marker/role tags.
The adapter always re-fetches body, metadata, tags, encryption identity, size,
and checksum after Put. A provider error or malformed success is accepted only
if that exact state is independently present, making an identical Put
idempotent while rejecting mismatched collisions.

The live artifact mode creates one proof-owned KMS key, alias, and encrypted
bucket, then performs the product `Put`, `Get`, and `Delete`. Cleanup retains an
expected object candidate before mutation, re-proves exact state before any
delete, removes the object before the bucket, schedules only the owned KMS key,
and completes the existing prefix-wide audit. The fixed success line is:

`LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.`

The disposable runner keeps loopback-only publication, an exact image digest,
owned labels, bounded readiness/build/proof phases, fixed output, and exact
container/temp cleanup. It reads no dotenv, cloud profile, real credential,
proxy, or ambient Docker authentication. LocalStack evidence does not claim
real-AWS authorization, durability, availability, or release parity.

## Tests and completion

Hermetic product tests cover configuration, scope/reference/media/content/key
validation, exact forwarding, defensive copies, checksum verification, fixed
errors, timeouts, cancellation, panics, malformed state, and concurrent use.
Adapter tests cover exact S3 mapping, encryption/metadata/tag validation,
idempotent reconciliation, collision rejection, deletion authorization, and
cleanup precedence. The retained M0-07 storage proof remains green.

Root commands are `npm run artifact:store:test` and
`npm run artifact:store:run`. M1-12 may move to Complete only after six focused
passes, all Go and pinned repository gates, the exact disposable live proof,
secret scans, zero-finding review, push, and exact-SHA Runnable UI success.
M1-13 remains Pending throughout.
