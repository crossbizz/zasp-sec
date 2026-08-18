# M1-40 S3 Organization Artifact Prefix Design

## Decision

Harden the existing dependency-free `services/platform/artifactstore` product
boundary. Add one unexported scope-mandatory driver-locator builder and route
`Put`, `Get`, and `Delete` through it before constructing a deadline or calling
the driver. Do not add a second artifact interface, S3 adapter, bucket, or live
provider lifecycle.

M1-12 remains the ArtifactStore and provider-compatibility authority. M1-34
remains the separate provider-neutral evidence/export/policy bucket-layout
authority. M1-40 makes the existing SaaS artifact key's Organization component
explicit and directly proves cross-Organization denial through one product
store instance. It does not change either predecessor's public API or claim a
new AWS authorization property.

## Product boundary

The store retains the existing public `ArtifactStore` interface and typed
`Locator`, `PutRequest`, `Artifact`, `DriverLocator`, and `DriverObject` values.
The new internal builder is:

```go
func buildDriverLocator(domain.Scope, domain.EvidenceRef) (DriverLocator, error)
```

It accepts only one fully valid canonical scope and evidence reference. It
returns exactly one value whose key is:

```text
organizations/<organization-product-id>/workspaces/<workspace-product-id>/environments/<environment-product-id>/artifacts/<evidence-product-id>
```

The builder copies the exact validated scope and reference into the typed
driver locator. Missing, malformed, duplicated, or forged scope identity and
invalid evidence references return only `ErrArtifact` with a zero locator.
Callers cannot supply an Organization prefix, raw key, suffix, filename,
provider ID, bucket, URL encoding, metadata map, or path segment.

`Put`, `Get`, and `Delete` validate their complete product request and invoke
the builder before deadline construction or driver I/O. Builder failure causes
zero driver calls. The existing exact returned-state checks continue binding
key, Organization, Workspace, Environment, reference, media type, bytes, size,
and SHA-256. There is no store-global or session-global tenant value.

## Cross-Organization proof

The primary hostile fixture uses one store and one in-memory typed driver. It
constructs two valid scopes that differ only in Organization while sharing the
same Workspace, Environment, and evidence reference. The fixture is written
through Organization B. A read through Organization A must issue exactly the
Organization-A locator, must not return the Organization-B object, and must
return only the fixed `ErrGet` product error.

The test also proves the two canonical keys have identical suffixes below the
Organization segment but distinct immutable Organization prefixes. Concurrent
alternating operations across both Organizations must derive each locator from
that call's scope without caller-slice mutation, retained tenant state, or
cross-call aliasing.

This is a product authorization boundary, not evidence that AWS IAM, bucket
policy, or real-S3 behavior enforces tenant isolation. The M1-12 disposable
LocalStack adapter tests remain regression authority for provider mapping and
cleanup; no live Docker, LocalStack, S3, KMS, AWS, credential, or shared-target
mutation is required for M1-40.

## Failure, privacy, and compatibility

All existing fixed errors, total operation deadlines, panic containment,
defensive byte copies, supported media types, maximum sizes, checksums, driver
interface, adapter behavior, root commands, and canonical key bytes remain
unchanged. No error or log may expose object bodies, keys, scope identifiers,
provider messages, credentials, bucket names, or encryption identifiers.

M1-34's `bucketlayout` class prefixes are not substituted into ArtifactStore:
that package owns typed evidence/export/policy layout, while the M1-12 store
owns its existing artifact namespace. Joining the packages would broaden the
task, change established provider keys, and contradict the M1-40 dependency
boundary on M1-04 and M1-12.

## Verification and completion

Tests directly pin the builder's exact bytes and typed fields, zero/invalid
rejection, same-session Organization-A/Organization-B denial, concurrent
separation, and unchanged Put/Get/Delete behavior. Six race-enabled focused
passes, full platform and M1-12 regression gates, pinned repository
verification, production audit, whitespace and redacted secret scans, and a
zero-finding review are required.

M1-40 may move to Complete only after its status transition is tests-first,
the branch is pushed, and exact-SHA Runnable UI succeeds. M1-39 remains
Complete and M1-41 remains Pending.
