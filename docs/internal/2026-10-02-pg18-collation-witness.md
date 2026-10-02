# PG18 registration collation witness correction

The second frozen Linux original-registration attempt reached PostgreSQL and failed SQLSTATE42703 while evaluating the outer collation control witness. The safe failed statement digest was `e61fd5bc920a9960e4586d0eb2a66d624cf02579899cd84a5ac37d800f9d92fc`. No reference output was published; normal owned PostgreSQL stop and join passed.

Read-only source generation reproduced that exact digest. Independently reviewed PostgreSQL18.3 bootstrap schema SHA256 `ba43fc265c5e477644ac7c28b1771e42d020ee76520cb80bf9a82074a9e90756` declares pg_collation.collicurules, while the witness selected nonexistent collrules. The defect is in the control-witness generator's catalog mapping. It does not demonstrate a defective original fingerprint query branch.

TDD first reproduced the missing field in all three emitted witnesses against an independent PG18 catalog-column roster. The correction changes only the field projection to collicurules. The output key remains rules with the same nullable string schema. Original scalar/source fingerprints, bags, ordering, bounds, dispatch-source pins and refusal policies remain unchanged. Existing original-registration scalar authority SHA256 stays `28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016`.

Independent source/security review approved the two-file delta without findings. Focused count1 race checks passed after RED. The coordinator independently reran the grouped unit controls before commit. Source correction does not establish PostgreSQL reference capture, native379, installed worker acceptance or production readiness. A fresh immutable build and separate controlled capture retry remain required; preserved v1/v2 evidence stays intact. No728 ledger row changes.
