# Independent connector rejection review

Reviewer: `/root/connector_rejection_review`, GPT-6 Astra, read-only.
Scope: the ten-file frozen patch, SHA256
`7de38817e78aa2d0946344b2fcbdce60f86ca676e172d75e5e7a4eb065f74c9e`.
No tests rerun, files edited or child reviewers dispatched.

Plan/spec: PASS for scoped local implementation. Quality: PASS.
No actionable scoped findings. The reviewer checked the two HTTP branches,
safe command, actual READ COMMITTED transaction, membership/credential/grant
locks, pgxpool/tracing coverage and rollback-after-insert tests. The no-migration
design, PAT intersection, per-attempt events, fixed errors and unchanged success
paths match the task brief.

Two provisional concurrency concerns were withdrawn after tracing registered
writer dependencies. The suspected phantom mapping schedule cannot commit
through the current mapping writer after the credential lock because the writer
also revokes active credentials. The apparent mapping/credential inversion is
not a demonstrated current path: an inherited updater predicate prevents
existing-row updates from reaching that branch. That separate defect needs
focused diagnosis and regression evidence; it is not a finding in this patch.

Authority proof remains bounded to existing product writers. Arbitrary SQL
using legacy API CRUD privileges is not covered. Any repair of the inherited
mapping updater must recheck its concurrency with this new rejection path.

The review initially made publication conditional on pinned Node22 evidence.
Root subsequently verified the joined Node22.23.1/npm10.9.8 log: 224 test files,
2136 tests, typecheck, lint and build passed. All ten frozen source hashes
remain unchanged. External approved-scanner and deployment gates remain open;
this review is not live-production acceptance or permission to bypass them.
