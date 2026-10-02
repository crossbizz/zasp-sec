# Stored proof rendering subtask

Implement the rendering portion of Task1 in the existing public-proof plan.
Read `2026-09-17-existing-test-public-proof-design.md` as the binding contract.
The user authorized autonomous implementation and feature-batch verification.

Own only `app/features/securityagents/ActionDetails.tsx`, new
`ExistingTestEvidence.tsx`, new `ExistingTestEvidence.test.tsx`, and
`docs/internal/2026-09-17-existing-test-proof-ui-report.md`.

Use existing generated `SecurityAgentExistingTestDetail` and related types.
Render the optional stored proof from ActionDetails. Show pending vs settled,
safe outcome/reason labels, before/after run IDs, attempts, input digests,
immutable artifact reference digests/version IDs/checksums/sizes, and the
per-check before/after protected comparison. Label this recorded evidence,
not current provider health or a fresh test. Do not equate parent status with
test outcome. Unknown cancellation is unconfirmed execution, not success or
confirmed cancellation; partial cancellation must say prior work was not undone.
Handle missing before/after without inventing evidence; absence stays compatible.

No navigation in this subtask: scoped history links and route handling remain
an explicit next integration step owned by the controller. No raw storage URLs,
extra APIs, feature enablement, demo data in production, or broad UI redesign.

Use Superpowers TDD. Test through the real ActionDetails component with complete
typed fixtures, first observe failures for missing rendering, then implement.
Cover pending, remediation, missing baseline, uncertainty, partial cancellation,
and absent compatibility. Run only focused tests; controller runs grouped gates.
Do not import fixtures from a .test.ts file. No commits, staging, pushes, database
processes, broad test commands or subagents. Preserve inherited changes.
Report exact commands, RED/GREEN evidence, files and concerns in the report file.
