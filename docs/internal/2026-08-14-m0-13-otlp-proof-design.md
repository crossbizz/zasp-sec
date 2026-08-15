# M0-13 OTLP ingest proof design

## Status and scope

M0-13 proves one narrow ingest boundary: an exact synthetic agent/task/tool
trace passes through a real local OpenTelemetry Collector and reaches a
product-owned ingest adapter with its trace identity and bounded semantic
attributes intact. This is not the later M0-22 remote-export or exporter-
failure proof. For this proof, remote OTLP export is disabled.

The runtime is the official multi-platform Collector Contrib image:

`otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`

The release was published August 4, 2026. Docker must resolve the immutable
index to the exact supported host platform and retain the resulting image ID
for every ownership check.

## Data flow

```text
fixed synthetic OTLP/HTTP trace
        |
        v
loopback-only random port
        |
        v
real Collector OTLP/HTTP receiver
        |
        v
bounded file exporter artifact
        |
        v
product-owned ingest adapter
        |
        v
exact normalized trace evidence
```

The Collector configuration enables only the OTLP/HTTP receiver, a memory
limiter, a batch processor with fixed bounds, and the local file exporter.
There is no remote exporter, telemetry backend credential, cloud endpoint,
proxy, or ambient configuration input.

## Semantic contract

The single trace uses exact lowercase hexadecimal trace and span IDs and one
allowlisted span. The ingest adapter requires exactly these bounded identity
attributes:

- `organization.id`
- `agent.id`
- `session.id`
- `task.id`
- `tool.id`
- `sandbox.id`

The Organization and all semantic IDs use fixed synthetic grammars. The
adapter rejects missing, duplicate, unknown, aliased, wrong-typed, oversized,
or differently scoped values. It also rejects extra resource, scope, span,
event, link, status, and instrumentation-library content.

The proof forbids raw prompt text, arbitrary tool arguments, secrets, provider tokens, customer
payloads, stack traces, and unbounded/high-cardinality labels are forbidden at
the source, Collector artifact, and normalized output boundaries.

## Trust and parser boundaries

The proof writes a fixed Collector configuration into an exact-owned temporary
directory and mounts it read-only. The file exporter writes to a separate exact
owned output directory. The product adapter opens the resulting artifact with
no-follow semantics, requires one regular file with stable device/inode/size,
caps reads at 64 KiB plus one byte, rejects duplicate JSON keys recursively,
and validates the complete OTLP JSON shape before normalization.

Collector acceptance alone is not success. Success requires the output
artifact to contain exactly the sent trace, span, service scope, and semantic
attributes, followed by exact cleanup and prefix-wide absence.

## Disposable runtime ownership

Each run creates one name `zasp-m0-13-<16 lowercase hex>` with proof and run
labels. Docker receives only an allowlisted `PATH` and an exact-owned empty
`DOCKER_CONFIG`. The container:

- uses the exact pinned image/index and retained platform image ID;
- publishes only container port 4318 to a random host port on `127.0.0.1`;
- uses a read-only root filesystem, no-new-privileges, all capabilities dropped,
  no host/network namespace sharing, bounded PID/memory/CPU resources, and an
  exact tmpfs;
- mounts only the exact read-only configuration and exact writable output
  directory; and
- receives no `.env`, cloud credential, auth, profile, proxy, or remote-export
  value.

Creation results are definitive on ordinary nonzero exits. Only thrown,
signaled, or malformed successful mutation results enter exact ownership
reconciliation. Candidate state is retained before interpretation. Every
cleanup mutation re-proves exact full-ID ownership immediately before removal,
uses an independent bounded cleanup context, and requires exact absence.

## Deadlines and output

The main lifecycle has a hard 90-second bound and cleanup has an independent
30-second bound. Child output has one combined 64 KiB diagnostic cap, but the
public CLI always emits one fixed line without provider data. Readiness and
artifact polling use bounded attempts, per-call deadlines, and absolute phase
deadlines. A timed-out phase loses authority before cleanup begins.

Success is exactly:

`OTLP ingest proof passed: traces=1 spans=1 identity=true cleanup=true.`

Failures use only fixed configuration, provider, normalization, ownership,
cleanup, deadline, or panic categories.

## Verification boundary

Completion requires hermetic parser/lifecycle tests, six stability passes, two
consecutive live runs against the exact image, an exact product-adapter result,
a prefix-wide zero-resource audit, production dependency/license and secret
scans, full repository verification, and independent review with no remaining
Critical, Important, or Minor findings. R-12 remains Not run because M0-22 must
still prove bounded remote export and nonblocking exporter failure.
