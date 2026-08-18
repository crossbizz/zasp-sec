# M1-34 S3 Bucket Layout Design

## Decision

Add one dependency-free `services/platform/bucketlayout` package that owns the
provider-neutral version-1 object-key and SSE-KMS configuration contract for
the product S3 bucket. The package accepts deployment-owned bucket, Region,
account, and customer-managed KMS key identity; validates their exact
relationship; and builds only typed evidence, export, and policy keys beneath
one immutable Organization/Workspace prefix.

M1-34 does not provision a bucket or KMS key. M1A-03 owns staging S3/KMS
infrastructure, M8-02 owns production versioning, lifecycle, retention,
encryption, access, and hardening, and M1-40 owns the product-store
cross-Organization authorization proof. The existing M1-12 `ArtifactStore`
interface and disposable S3/KMS proof remain unchanged.

The alternatives are rejected. The package will not accept raw object keys,
filesystem-like relative paths, arbitrary prefix segments, provider clients,
AWS aliases, or mutable maps. It will not create one bucket per Organization or
Workspace because the PRD selects Organization-scoped prefixes for SaaS and
dedicated storage for dedicated deployments.

## Public contract

```go
var ErrLayout = errors.New("bucket layout rejected")

type Class string

const (
    ClassEvidence Class = "evidence"
    ClassExport   Class = "exports"
    ClassPolicy   Class = "policies"
)

type Configuration struct {
    BucketName string
    Region     string
    AccountID  string
    KMSKeyARN  string
}

type Encryption struct {
    Algorithm        string
    KMSKeyARN        string
    BucketKeyEnabled bool
}

type Layout struct { /* private validated state */ }

func New(Configuration) (Layout, error)
func (Layout) Validate() error
func (Layout) Configuration() Configuration
func (Layout) Encryption() Encryption
func (Layout) WorkspacePrefix(domain.Scope) (string, error)
func (Layout) Prefix(domain.Scope, Class) (string, error)
func (Layout) Key(domain.Scope, Class, domain.ProductID) (string, error)
```

`Layout` is a validated immutable value. A zero or forged value rejects with
only `ErrLayout`; its accessors return zero values. Every returned structure is
a value copy. There are no provider calls, environment reads, global mutable
state, or construction-time side effects.

## Exact key grammar

Every key begins with this exact workspace root:

```text
organizations/<organization-product-id>/workspaces/<workspace-product-id>/
```

The full class prefix is:

```text
organizations/<organization-product-id>/workspaces/<workspace-product-id>/environments/<environment-product-id>/<class>/
```

The object key appends one opaque canonical product ID:

```text
organizations/<organization-product-id>/workspaces/<workspace-product-id>/environments/<environment-product-id>/<class>/<object-product-id>
```

`<class>` is exactly one of `evidence`, `exports`, or `policies`. Product IDs
come only from the existing canonical `domain.ProductID` value. Callers cannot
supply slashes, dots, URL encodings, Unicode separators, empty segments,
absolute paths, `.`/`..`, provider-native IDs, filenames, extensions, or
arbitrary suffixes. Organization, Workspace, Environment, and object IDs must
all be valid; the scope's three IDs must remain distinct, and the object ID
must be distinct from each scope ID.

The builder constructs bytes directly; it never joins, cleans, normalizes,
decodes, or round-trips a filesystem path. Every result must be valid UTF-8,
contain only the fixed ASCII grammar, be at most 1,024 bytes, start with the
exact requested Workspace prefix, and contain no empty or period-only segment.
This is stronger than accepting S3's broad key alphabet. AWS documents that
period-only path segments can be interpreted inconsistently by applications
and tools, so the product contract does not admit them:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html

## Bucket and KMS configuration

`Configuration` is supplied explicitly by deployment code. The bucket name is
exactly `zasp-product-data-<deployment-token>`, where the deployment token is
32 lowercase hexadecimal characters generated outside this package. That
50-byte form is a conservative general-purpose-bucket name, carries no
customer identity, and avoids accepting periods, underscores, uppercase,
whitespace, IP-shaped names, URLs, ARNs, aliases, arbitrary prose, or reserved
prefix/suffix forms. Infrastructure still owns collision-resistant token
generation and globally unique name allocation; the package never assumes
availability or uses a name as an authorization fact.

`AccountID` is exactly 12 decimal digits. `Region` is one bounded lowercase
AWS Region token without whitespace, slashes, colons, dots, or empty hyphen
segments. `KMSKeyARN` must be a fully qualified customer-managed key ARN:

```text
arn:<aws-partition>:kms:<same-region>:<same-account>:key/<lowercase-uuid>
```

The accepted partitions are `aws`, `aws-cn`, and `aws-us-gov`. Alias ARNs,
bare aliases, bare key IDs, AWS-managed `aws/s3`, mismatched account/Region,
uppercase UUIDs, extra path/query/fragment data, and unsupported partitions
reject. Infrastructure must prove that the referenced key is enabled,
symmetric, and policy-authorized; those properties are not derivable from an
ARN and are not claimed by this value.

The encryption contract is fixed, not caller-selectable:

- algorithm `aws:kms`;
- the exact validated customer-managed KMS key ARN; and
- S3 Bucket Key enabled.

AWS recommends fully qualified KMS key ARNs for cross-account-safe identity,
requires the KMS key to be in the same Region as the bucket, supports only
symmetric KMS keys for S3, and permits S3 Bucket Keys with SSE-KMS. S3 does not
validate a general-purpose bucket's configured KMS key ID, so later
infrastructure must re-prove it:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html

## Rejection and privacy boundary

All invalid configuration, scope, class, reference, zero/forged state, and
impossible output conditions return exactly `ErrLayout`. Error text never
contains a rejected bucket, Region, account, ARN, scope, reference, or key.
The package produces no logs or metrics.

Object keys contain opaque product IDs because the selected SaaS layout needs
stable scoping. They never contain customer names, emails, prompts, raw
evidence, policy text, provider account aliases, resource ARNs, credentials,
or secrets. Bucket names likewise cannot contain product scope or customer
identity through this contract.

## Verification and completion

Hermetic race tests pin the exact three prefixes and keys, all valid
configuration accessors, the fixed encryption result, and fresh deterministic
concurrent calls. Hostile tests cover every configuration field, zero/forged
layout state, invalid scopes/references/classes, all escape spellings, ID
collisions, control/Unicode/encoding attempts, overlength output, and mutation
of returned values. The suite independently splits every result and proves its
exact segment count and requested Workspace prefix.

The root exposes only:

```bash
npm run s3:bucket-layout:test
```

There is no live command because M1-34 owns no provider resource. M1-34 may
move to Complete only after genuine RED/GREEN, six focused race passes, full
platform and repository gates, dependency/audit/diff checks, pinned secret
scans, zero-finding whole-range review, push, and exact-SHA Runnable UI success.
M1-35 remains Pending.
