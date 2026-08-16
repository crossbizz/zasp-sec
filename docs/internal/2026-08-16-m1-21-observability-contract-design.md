# M1-21 Observability Contract Design

## Decision

Add a dependency-free `services/platform/observability` package that defines
the product-owned resource and correlation boundary before any OpenTelemetry
SDK or exporter adapter is introduced. The package produces one closed,
ordered set of string resource attributes and one typed correlation value.
It does not accept an arbitrary attribute map.

The alternatives were an OpenTelemetry SDK wrapper and a generic map
validator. The SDK wrapper would couple a small domain contract to an adapter
and dependency graph before service wiring exists. A generic map would make
unsafe extension the normal call path. The closed value is smaller, keeps the
current platform module dependency-free, and makes every new resource key an
explicit source and test change.

M0-13 and M0-22 remain proof evidence rather than production dependencies.
Their established `service.name`, `service.version`, and `organization.id`
names are retained. M1-21 adds the complete production scope, fixed namespace,
and bounded deployment catalog without changing either disposable proof.

## Common OTLP resource attributes

The package exports:

```go
type Service string

const (
    ServiceAPI    Service = "agentsec-api"
    ServiceWorker Service = "agentsec-worker"
)

type Deployment string

const (
    DeploymentDevelopment Deployment = "development"
    DeploymentTest        Deployment = "test"
    DeploymentStaging     Deployment = "staging"
    DeploymentProduction  Deployment = "production"
)

type StringAttribute struct {
    Key   string
    Value string
}

type ResourceAttributes struct {
    values [7]StringAttribute
}

func NewResourceAttributes(
    domain.Scope,
    Service,
    string,
    Deployment,
) (ResourceAttributes, error)

func (ResourceAttributes) OTLP() []StringAttribute
func ValidateResourceAttributes([]StringAttribute) error
```

`NewResourceAttributes` accepts a valid Organization/Workspace/Environment
scope, one catalogued service, a bounded release version, and one catalogued
deployment. The version is 1 to 63 bytes and contains only ASCII letters,
digits, period, plus, underscore, or hyphen; it starts and ends with an ASCII
letter or digit and has no adjacent separators. There is no hostname, pod,
container, customer label, request path, provider, or free-form deployment
value.

The exact ordered resource output is:

1. `service.namespace = agentsec`
2. `service.name = <catalogued service>`
3. `service.version = <validated version>`
4. `deployment.environment.name = <catalogued deployment>`
5. `organization.id = <canonical product Organization ID>`
6. `workspace.id = <canonical product Workspace ID>`
7. `environment.id = <canonical product Environment ID>`

`OTLP` returns a fresh slice. Mutating it cannot change the retained value.
`ValidateResourceAttributes` accepts only those seven keys, in that order,
with exact values and valid scope identity. Missing, duplicate, reordered,
unknown, aliased, empty, malformed, or extra attributes fail closed. In
particular, raw prompt/response text, tool arguments, evidence, secret values,
stack traces, URLs, provider payloads, arbitrary customer content, and product
correlation IDs cannot enter the resource set.

The fixed key cardinality, service catalog, deployment catalog, bounded
version grammar, and typed product scope are the initial cardinality boundary.
Adding a service, deployment, or attribute requires an explicit source and
test change.

## Correlation helper

Correlation is a request/span value, never a resource attribute:

```go
type Correlation struct {
    correlationID domain.CorrelationID
    traceID       string
    spanID        string
}

func NewCorrelation(
    domain.CorrelationID,
    string, // trace ID
    string, // span ID
) (Correlation, error)

func (Correlation) Validate() error
func (Correlation) CorrelationID() domain.CorrelationID
func (Correlation) TraceID() string
func (Correlation) SpanID() string
func WithCorrelation(context.Context, Correlation) (context.Context, error)
func CorrelationFromContext(context.Context) (Correlation, bool)
```

Trace IDs are exactly 32 lowercase hexadecimal characters, span IDs exactly
16, and neither may be all zero. The product correlation ID must be a valid
typed `domain.CorrelationID`. Zero, uppercase, shortened, oversized,
non-hexadecimal, all-zero, or forged values fail closed.

`WithCorrelation` rejects nil context and invalid correlation. An empty
context accepts one value. Reattaching the exact same value is idempotent;
attempting to replace it with a different value fails rather than silently
cross-correlating operations. `CorrelationFromContext` returns false for nil,
missing, or invalid state and never manufactures identifiers. The helper
retains no global state and is safe for concurrent context trees.

## Failure and authority boundary

The package exposes fixed resource and correlation sentinel errors. Rejected
attribute keys or values are never included in error text. There is no log,
metric, trace, exporter, Collector, network, credential, environment-variable,
filesystem, database, Docker, provider, or shared-resource I/O.

This contract does not decide sampling, retention, remote OTLP enablement,
backend selection, exporter retry, metric units, span names, or whether a
customer has approved external observability. It gives no raw telemetry or
product content permission. Grafana Cloud, New Relic, and disabled-export
adapters remain later work.

## Verification and status boundary

Hermetic Go tests prove the exact seven-attribute representation, stable order,
copy isolation, service/deployment/version bounds, malformed scope rejection,
and rejection of unknown/high-cardinality/raw-customer-content keys. They also
prove exact trace/span/product correlation identity, context propagation,
replacement rejection, nil/forged state handling, and concurrent safety.

Repository contracts bind the source task, PRD rules, prior OTLP proof names,
root command, README boundary, exact tracker arithmetic, and unchanged blocked
tasks. M1-22 remains Pending. M1-21 may move to Complete only after witnessed
compiler RED/GREEN, six race passes, full platform/repository gates, dependency
and secret audits, zero-finding whole-range review, push, and exact-SHA
Runnable UI success.
