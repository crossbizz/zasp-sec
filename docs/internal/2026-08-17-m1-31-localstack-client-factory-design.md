# M1-31 LocalStack Client Factory Design

## Goal and boundary

M1-31 adds one product-side Go factory for the five AWS clients named by the
source task: SQS, S3, KMS, Secrets Manager, and OpenSearch Service. The factory
uses ordinary AWS endpoints in production and accepts the M1-30d endpoint
override only in explicit local or CI mode. It never reads the process
environment, shared AWS configuration, profiles, IMDS, web identity, proxies,
or dotenv directly.

This task proves client construction and routing only. It does not provision
queues, buckets, keys, secrets, or OpenSearch domains; add adapter behavior;
change the M1-30 manifests; claim LocalStack parity; or advance M1-32. The
existing artifact, queue, event, and secret product boundaries remain
unchanged. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **One strict factory with an explicit runtime mode and injected lookup
   (selected).** The caller selects production, local, or CI. Local and CI read
   only `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` through an injected lookup,
   replace credentials with fixed synthetic values, disable retries, and point
   all five clients at the validated endpoint. Production accepts no lookup or
   endpoint override and uses only explicitly supplied credentials and HTTP
   client authority.
2. **Call `config.LoadDefaultConfig` and rely on AWS SDK environment support.**
   This would silently read profiles, shared configuration, credential helpers,
   IMDS, proxy variables, and unrelated endpoint variables. It cannot enforce
   the local/CI-only boundary.
3. **Create one factory per AWS service.** This repeats the same endpoint,
   credential, retry, and runtime-mode rules five times and makes drift likely.

The selected factory keeps the authority decision in one place and uses the
exact M1-30d variable names without adding a second local endpoint contract.

## Package and API

Add `services/platform/awsclient` with this public shape:

```go
type Mode string

const (
    ModeProduction Mode = "production"
    ModeLocal      Mode = "local"
    ModeCI         Mode = "ci"
)

type Options struct {
    Mode        Mode
    Region      config.AWSRegion
    Lookup      func(string) (string, bool)
    Credentials aws.CredentialsProvider
    HTTPClient  aws.HTTPClient
}

type Clients struct { /* private concrete clients and owned transport */ }

func New(Options) (*Clients, error)
func (*Clients) SQS() *sqs.Client
func (*Clients) S3() *s3.Client
func (*Clients) KMS() *kms.Client
func (*Clients) SecretsManager() *secretsmanager.Client
func (*Clients) OpenSearch() *opensearch.Client
func (*Clients) Close()
```

The exported values contain no provider response, credential material, or
mutable endpoint string. `Close` only closes idle connections owned by a local
or CI factory and is safe to repeat. Production transport ownership remains
with the caller.

## Configuration and trust rules

Production requires a valid region, a non-nil explicit credential provider,
and a non-nil explicit HTTP client. `Lookup` must be nil. The factory supplies
no base endpoint, custom resolver, config source, middleware callback, logger,
or retry authority. It creates all five clients from one clean `aws.Config` and
uses `aws.NopRetryer` so operation-specific adapters retain retry decisions.

Local and CI require the exact region `us-east-1`, a non-nil lookup, and nil
caller credentials and HTTP client. The lookup is invoked exactly once for
each of `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` and for no other key. Both
values must be present, nonempty, byte-identical, canonical URLs with no
userinfo, path, query, fragment, percent escape, or trailing slash.

Local mode accepts only:

```text
http://localstack.zasp-local.svc.cluster.local:4566
```

CI mode accepts only an explicit IPv4 loopback URL of the form
`http://127.0.0.1:<1-65535>`. Hostnames, wildcard addresses, IPv6 aliases,
public/private non-loopback addresses, default ports, and HTTPS are rejected.
The narrow CI form supports a disposable test listener without creating a
general endpoint escape hatch.

Local and CI replace any possible AWS authority with fixed credentials whose
access key and secret are both `test` and whose source is
`zasp-localstack-client-factory`. The owned HTTP client disables proxies and
redirects, disables keep-alives and HTTP/2, applies finite dial, TLS,
response-header, and total deadlines, and caps response headers. The S3 client
also enables path-style addressing. Every service receives the same validated
base endpoint; S3 receives the independently required but equal S3 endpoint.

## Dependency boundary

Use the official AWS SDK for Go v2 modules released together on August 14,
2026:

- `github.com/aws/aws-sdk-go-v2` `v1.43.6`;
- `github.com/aws/aws-sdk-go-v2/service/sqs` `v1.46.6`;
- `github.com/aws/aws-sdk-go-v2/service/s3` `v1.107.2`;
- `github.com/aws/aws-sdk-go-v2/service/kms` `v1.55.6`;
- `github.com/aws/aws-sdk-go-v2/service/secretsmanager` `v1.44.6`; and
- `github.com/aws/aws-sdk-go-v2/service/opensearch` `v1.75.6`.

All six modules are Apache-2.0 product runtime dependencies owned by
`platform-data`. Add them to `services/platform/go.mod`, `go.sum`, and the
strict repository dependency inventory. No proof module is imported by the
product package.

## Verification

Tests begin with compiler RED for the absent package. They then prove:

- the exact source row, selected design, status arithmetic, dependency set,
  and M1-32 deferral;
- production rejects any lookup or endpoint authority and preserves only the
  explicit region, credentials, and HTTP client;
- local and CI request only the two fixed keys, use fixed synthetic
  credentials, disable retries, and reject partial, unequal, malformed,
  noncanonical, public, or wrong-mode endpoints;
- real AWS SDK read operations from SQS, S3, KMS, Secrets Manager, and
  OpenSearch Service all reach one bounded loopback capture server in CI mode,
  carry the `us-east-1` signing scope and synthetic access key, and never
  contact a default AWS endpoint;
- S3 uses path-style routing, each operation is attempted once, redirects are
  rejected, close is idempotent, and fixed errors expose no endpoint or
  credential value; and
- the full platform race suite, tidy-diff, module verification, vet,
  dependency validation, repository verification, production audit,
  whitespace checks, and pinned redacted Gitleaks scans pass.

The HTTP capture server returns only minimal protocol-correct empty responses.
It is not provider compatibility evidence and does not replace the completed
M1-30d disposable LocalStack proof.

## Status boundary

Starting M1-31 changes overall status from `657/0/68/3` to `656/1/68/3`
and M1 from `68/24/0/44/0` to `68/23/1/44/0`. Completion changes those values
to `656/0/69/3` and `68/23/0/45/0`. M1-32 remains Pending throughout. The
three exact blockers remain M0-09, M0-18, and M0-19.
