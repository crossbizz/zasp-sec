# Search authority explicitly selects release51

The new private constructor uses compiled precision readiness and
`zasp_runtime_precise_search_claim`. It keeps target `zasp-runtime-sessions-v2`.
The claim must supply projection implementation1/2/3; absent and unknown versions
are refused. Old authorities reject the new field, including null. Leases retain
this version and cannot cross historical/precision heartbeat or finish authority.
Successful V3 decoding must have an exact projection-v3 claim before archive or
index I/O. Historical receipt drain remains supported.

Superpowers tests first reproduced old claim selection, then a foreign-capability
heartbeat reaching the database. Removing the executor version check reproduced
provider execution with a mismatched claim. Independent review found missing
claim version could still reach provider I/O; a new RED reproduced that too.
The guard now requires projection-v3 when precise decoding succeeds.

Worker races passed in19.015s before the final review fix. The amended full
worker race run passed in19.170s (session4342); re-review closed the finding with
no new issues. UI build passed
before that one-line guard change. No activation or publication.

Separately, the registered actual PostgreSQL repository completion test passed
in5.063s against the then-current6508ca6f precision fingerprint. It installed51,
completed through the real repository, replayed, preserved source-qualified
events and one target queue entry, refused rollback with retained evidence and
refused replay after readiness drift. The rollback expectation now follows the
existing50 ErrDatabase mapping for SQL evidence guards, with schema51 and retained
event count asserted after refusal. Migration tests are still being extended;
this is not full migration approval or live production proof.
