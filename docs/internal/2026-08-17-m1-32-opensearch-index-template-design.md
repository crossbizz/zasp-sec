# M1-32 OpenSearch Index Template Design

## Decision

Add one dependency-free `services/platform/eventindex` package that owns the
exact version-1 OpenSearch index-template contract for scoped session/runtime
events. The package reuses the 12-field M1-14 `eventstore.DriverDocument`
projection instead of introducing another event model. It constructs no AWS or
OpenSearch client, performs no network operation, and does not apply the
template to a provider.

The selected design is a closed, immutable Go value with deterministic JSON
output and an exact document-field admission check. This gives later provider
adapters one reviewed payload while allowing M1-32 to prove mapping-explosion
rejection hermetically. A loose map, dynamic template, checked-in unvalidated
JSON file, and a second OpenSearch lifecycle are rejected.

## Public contract

```go
var (
    ErrTemplate = errors.New("event index template rejected")
    ErrDocument = errors.New("event index document rejected")
)

type Field struct {
    Name        string
    Type        string
    IgnoreAbove int
    Format      string
}

type Template struct { /* private exact state */ }

func SessionRuntimeTemplate() Template
func (Template) Validate() error
func (Template) Pattern() string
func (Template) Priority() int
func (Template) Version() int
func (Template) Fields() []Field
func (Template) JSON() ([]byte, error)
func (Template) ValidateDocumentFields([]string) error
```

`SessionRuntimeTemplate` is the only constructor. A zero value, copied value
with invalid private state, or forged direct state fails `Validate`, `JSON`,
and document admission. Accessors return zero values for an invalid template.
`Fields` returns a fresh copy on every call.

## Exact template

The immutable index pattern is `zasp-session-runtime-events-v1-*`, priority is
`100`, and version is `1`. The canonical JSON contains exactly
`index_patterns`, `priority`, `version`, and `template`. The nested template
contains only:

- setting `index.mapping.total_fields.limit` equal to `12`;
- mappings metadata `zasp_contract=session_runtime_events` and
  `zasp_contract_version=1`;
- `dynamic` equal to `strict`; and
- exactly the 12 properties below.

| Field | Mapping | Bound |
| --- | --- | ---: |
| `organization_id` | `keyword` | 40 |
| `workspace_id` | `keyword` | 40 |
| `environment_id` | `keyword` | 40 |
| `event_id` | `keyword` | 40 |
| `session_id` | `keyword` | 40 |
| `agent_id` | `keyword` | 40 |
| `source` | `keyword` | 32 |
| `source_event_id` | `keyword` | 256 |
| `event_class` | `keyword` | 32 |
| `action` | `keyword` | 64 |
| `decision` | `keyword` | 16 |
| `event_time` | `date` with `strict_date_time` format | not applicable |

Every keyword property contains exactly `type` and `ignore_above`. The date
property contains exactly `type` and `format`. No analyzer, text multi-field,
dynamic template, object, nested field, alias, runtime field, null substitute,
coercion rule, script, or provider metadata is accepted.

The limits align with the current product contracts: canonical product IDs are
40 bytes, the M1-14 source event ID is at most 256 bytes, and every other
keyword is a closed short product vocabulary. `ignore_above` is an index bound,
not input validation or permission to retain oversized content. Existing
product constructors remain responsible for value validation before provider
I/O.

OpenSearch documents keyword fields as non-analyzed exact-match values and
`ignore_above` as the indexed-string length bound. Its mapping-explosion
guidance identifies `index.mapping.total_fields.limit` as the field-count
limit. The design therefore uses all three controls together rather than
treating one as sufficient:

- https://docs.opensearch.org/latest/mappings/supported-field-types/keyword/
- https://docs.opensearch.org/latest/field-types/mapping-parameters/ignore-above/
- https://docs.opensearch.org/latest/mappings/mapping-explosion/

## Mapping-explosion rejection

`ValidateDocumentFields` receives field names only, not customer values or a
generic document map. It first rejects any count other than 12, then requires
each name to be valid UTF-8, nonempty, unique, and one of the exact properties.
Order is irrelevant because JSON object order is irrelevant. Missing,
duplicate, unknown, dotted, nested-looking, control-bearing, or oversized names
fail with only `ErrDocument`.

The required verification fixture begins with the 12 valid names and appends
1,024 unique attacker-controlled names. It must fail before any provider or
driver call. Separate hostile cases cover one unknown field at a valid count,
duplicate known fields, missing fields, and key-order permutations. The
canonical set passes.

This admission check is defense in depth for future serialization boundaries.
The provider mapping itself remains `dynamic: strict`, so bypassing the helper
does not authorize OpenSearch to add fields.

## Scope and authority boundary

Organization, Workspace, and Environment are mandatory mapped keyword fields.
Their presence does not by itself enforce tenant authorization. M1-39 remains
responsible for binding Organization scope into every index and query builder
and for proving Organization-A queries cannot return Organization-B documents.

M1-32 does not create a domain, index, index template, alias, document, queue,
bucket, key, secret, credential, endpoint, HTTP client, Docker resource, or
Kubernetes resource. It reads no environment, profile, dotenv, IMDS, proxy,
filesystem, clock, randomness, provider response, or customer content. M1-31
remains the reviewed AWS client factory; the control-plane OpenSearch Service
client is not a data-plane template client and is not misused here.

## Determinism and failure behavior

The package uses fixed structs and arrays internally. `JSON` validates the
template first, constructs a fresh serialization value, and returns fresh
bytes. The exact bytes are deterministic, compact UTF-8 JSON ending in one
newline. Mutating returned fields or JSON cannot change later calls.

All public rejection paths use only `ErrTemplate` or `ErrDocument`; rejected
field names and values never enter error text. The package has no retry,
deadline, panic boundary, cleanup, logging, telemetry, or concurrency state
because it performs no I/O and retains no mutable shared state. Independent
calls are race-safe.

## Verification and completion

Hermetic Go tests bind the exact pattern, priority, version, settings, mapping
metadata, field names, field types, bounds, canonical JSON bytes, fresh-copy
behavior, invalid zero state, and field-order independence. Hostile tests reject
every individual field mutation, missing/duplicate/unknown fields, nested and
dotted additions, non-UTF-8/control names, oversized names, and the 1,024-field
mapping-explosion fixture.

The root command is `npm run event:index-template:test`. Repository contracts
bind the M1-32 source row, M1-31 prerequisite, M1-33 Pending state, this design,
the exact README boundary, tracker arithmetic, and unchanged blockers. M1-32
may move to Complete only after tests-first RED/GREEN, six race passes, full
platform and repository gates, dependency and vulnerability checks, pinned
secret scans, zero-finding whole-range review, push, and exact-SHA Runnable UI
success.
