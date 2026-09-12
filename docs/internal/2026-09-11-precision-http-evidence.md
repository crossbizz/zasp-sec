# Enrolled V2 HTTP intake

The explicit precise handler requires precision readiness and acceptance lookup
capabilities. Historical construction still refuses V2 transport. New transport
requires the expected enrollment binding, checked against authenticated scope and
sensor identity before parsing or persistence. Caller scope headers and duplicate
constraints are refused. Readiness is checked before authentication.

V2 uses the closed precise input decoder, produces archive2, retains nanosecond
source/process times and applies the authenticated collection mode. Reservation
and acceptance requests carry schema2 and the digest of those exact archive bytes.
Existing artifact-before-finalization ordering and accepted-replay behavior remain.
V1 body decoding stays on its original branch.

Superpowers RED reproduced400 rejection of valid enrolled V2. Full and metadata
tests now pass with exact source `.123999999` and process `.123456789` times.
Negative transport/enrollment/source/readiness tests prove zero persistence.
Declared accepted replay performs no reserve, artifact write or finalization.
Unqualified V2 records remain valid without invented lineage. A test initially
mistook a lineage-free body for an invalid V1 body; its bytes legitimately fit
the V2 transport. The negative test now covers an actual legacy lineage profile,
and a separate positive test preserves unqualified-record behavior.

Full runtimeevent race suite passed in5.364s and UI build passed. Independent review
found no blocking issue. Follow-up coverage checks exact acceptance lookup bindings,
readiness before authentication and constructor capability requirements. Its
readiness-only fake initially inherited acceptance support; restricting the embedded
interface fixed the fixture. Full runtimeevent race suite then passed in5.529s.
The event-ingest production factory still selects the historical handler;
production composition must be verified before activation. No push or original
task credit.

Registered PostgreSQL intake now passed in6.165s with PostgreSQL18 explicitly on
PATH. `TestRuntimePrecisionHTTPRegisteredIntake` composes the actual client,
precise HTTP handler, registered `invocation_ingest` login and migration51.
It checks exact archived source/process timestamps and persisted schema2 with
archive2/index2/correlation4/projection3/complete3. After losing the accepted
response and rotating the token, replay succeeds without a second artifact write
or changes to batch-authority, stage-work, discovery-job and discovery-outbox
snapshots. Wrong enrollment and release-checksum drift reject that accepted replay
without changing those four table snapshots or writing another artifact.

The first run reached acceptance but its assertion used `schema_version`; the
actual column is `payload_schema_version`. Correcting that test query required no
product change. Independent follow-up review found no blocking issue and repeated
targeted HTTP races successfully in1.481s. The snapshot does not claim every
database table is unchanged. Transport and artifact storage are local fixtures;
this is not TLS, S3, production composition or deployed sensor proof.
