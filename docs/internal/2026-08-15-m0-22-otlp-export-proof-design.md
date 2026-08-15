# M0-22 OTLP export and failure proof design

Date: August 15, 2026

## Decision

Prove bounded optional telemetry export with two exact-pinned disposable
OpenTelemetry Collector Contrib containers on one proof-owned
private internal network. The source Collector starts on Docker's built-in
bridge solely to publish one random loopback-only OTLP/HTTP host port, then is
attached to the private exporter network. The sink exists only on that private
network and writes one bounded artifact. No hosted backend, credential, `.env`, proxy,
profile, ambient Collector configuration, or arbitrary destination is used.

Both containers use:

`otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`

## Bounded export and application boundary

The source pipeline contains one OTLP/HTTP receiver, memory limiter, fixed
batch processor, and OTLP/HTTP exporter. Its bounded sending queue has one
consumer and four entries; retry elapsed time is capped at two seconds. The
sink pipeline contains one private OTLP/HTTP receiver and the bounded file
exporter already validated by M0-13.

The first operation must reach the sink artifact with the exact trace/span and
six Organization/agent/session/task/tool/sandbox identities. The proof then
stops only the exact sink Collector, re-proves it stopped, and performs one
nonblocking application operation. Application state changes before its
best-effort telemetry attempt, the OTLP submission has a 500 ms absolute bound,
and success requires the application operation to complete within 750 ms while
the exporter is unavailable. The second telemetry item need not be delivered.

## Ownership and lifecycle

Every run uses a fresh marker, two exact names, complete proof/run/role labels,
one exact private network, three canonical configuration/output roots, and one
canonical owned empty Docker-configuration root. Image identity, container configuration,
security options, mounts, network attachment/peers, loopback publication, state,
and full IDs are retained and re-proved before every mutation.

Ordinary nonzero create/start/stop/remove results are definitive. Only thrown,
signaled, or malformed successful results enter bounded exact reconciliation.
Main work has a hard 90-second deadline. Mutation settlement and reverse cleanup
run under an independent 30-second deadline, cleanup wins precedence, and final
audit requires global zero proof-prefix containers, networks, and temporary
roots.

## Fixed output and R-12

Success is exactly:

`OTLP export proof passed: delivered=true bounded=true exporter_failed=true application_unblocked=true cleanup=true.`

Failures expose one fixed category and no trace, identity, endpoint, port,
artifact, Docker, injected error, or provider output. R-12 may become PASS only
after this proof and M0-13's retained ingest evidence both pass final review.
