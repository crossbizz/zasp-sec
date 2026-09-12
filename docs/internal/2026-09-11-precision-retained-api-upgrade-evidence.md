# Retained API and V1 intake across51

TestRuntimePrecisionUpgradeKeepsExistingAPIAndV1Intake constructs the schema50
target2 API/repository and historical V1 ingest handler/client before installing
51, and keeps those same instances for all post-migration requests.

Actual registered PostgreSQL checks cover readiness, target2 search reporting
catching_up with pending work, byte-identical historical event pages/details,
authenticated pre51 acceptance and post51 replay, fresh V1 acceptance after51,
and checksum-drift refusal before more artifact writes. Two accepted batches
retain ten stage rows. Test artifact storage supports two immutable keys.

Implementer PG18 race passed7.939s. Root read-only review found no blocking issue;
independent actualPG rerun passed7.570s. These results precede the newly assigned
fresh-semantic routing correction. Root reran the same actualPG race test on
semantic pin f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd;
it passed7.501s with no skips.

The test runs current compiled code with retained historical constructors, not
an old deployed binary. Identity, search candidate provider and artifact storage
are declared fixtures. Historical session evidence uses an existing SQL fixture;
fresh HTTP acceptance does not seed successful pipeline stages. It does not
prove live pod readiness, provider-currentness, or zero-downtime migration.

No deployment, push or original task credit.
