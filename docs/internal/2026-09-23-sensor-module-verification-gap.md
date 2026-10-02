# Sensor module verification gap

Read-only diagnosis during the P4B fix1 source freeze. No dependency files changed.

The overbroad P4B race command failed the runtime-ingest HTTPS recovery test when
`exerciseInstalledChunkSensorRecovery` compiled the actual sensor test binary.
The helper in `services/platform/apiserver/sensor_chunk_installation_postgres_test.go`
runs `go test -race -c -o <temporary binary> .` in `services/sensor-agent` with
a 30-second build context. The observed error requests module updates, not a
provider credential or PostgreSQL fix.

On local Go1.25.6, running `go list -mod=readonly ./...` from the sensor module
reproduces exit1: updates to go.mod are needed. `go mod tidy -diff` also exits1
and prints the required changes without applying them. It proposes Go1.25.4
instead of1.25.0, grpc1.83.1 instead of1.76.0, protobuf1.36.11 instead of1.36.10,
x/sys0.45.0 instead of0.44.0, and associated indirect dependency/sum changes.

The sensor module replaces its platform dependency with `../platform`. That
platform module already declares Go1.25.4 and those higher grpc/protobuf/x/sys
requirements. The sensor's checked-in module graph has not been reconciled with
the local dependency graph. This explains the reproducible module-update refusal;
it does not establish that the sensor compiles or its HTTPS recovery passes after
reconciliation. `git diff --exit-code` confirmed sensor go.mod/go.sum unchanged
after the diagnostic.

The same read-only command also exits1 with the module-update refusal in
`services/event-ingest`, `services/gateway-control` and
`services/runtime-gateway`. Each has a local platform replacement and still
declares Go1.25.0. These are confirmed additional affected build boundaries;
their exact tidy diffs have not been inspected yet. Do not assume updating the
sensor module alone clears the repository build. The probes did not run tests
or mutate module files.

Required follow-up: capture a scoped baseline, reconcile the dependent module
metadata under review, verify the actual race-enabled sensor build and affected
sensor/runtime-ingest contracts, then rerun the installed HTTPS recovery test.
Check other locally linked modules for the same consistency issue before release.
Do not bypass readonly module checks in the test helper to hide stale metadata.

The later four-minute package timeout during SecurityAgentActionNaturalRecovery
is separate. This diagnosis does not identify its cause or clear full-suite/P8
verification. No production-availability classifications change.
