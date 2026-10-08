# Launch readiness and remaining work

Latest fetched main is `c1c45b24c5e0eec76b49e80c9f2f632087a6b33f`; required `e13ccb95451b03107681ccb59b3fc6fe175a228f` is its ancestor. This batch starts at published `06f1dd02492db40da28b788ef0ed2a201f9f315b`. The handoff and all original 728 requirements remain authoritative.

Launch is not accepted. The ledger records 523 historical production-available rows, 144 component-only and 61 blocked/external. Those categories are not fresh deployed coverage. No row is promoted by this batch. The [remaining task list](launch-remaining-tasks-2026-10-07.tsv) contains every one of the 205 rows outside production-available, with original ID, milestone and owner. Fresh deployed end-to-end verification remains required across all 728 requirements, including historically available behavior.

| Milestone | Rows outside production-available |
| --- | ---: |
| M0 | 20 |
| M1 | 11 |
| M1A | 10 |
| M2 | 5 |
| M3 | 2 |
| M7 | 32 |
| M7A | 18 |
| M8 | 107 |

Remaining owners and their recorded row counts:

| Owner | Rows |
| --- | ---: |
| T11-identity-admin | 8 |
| T04-discovery-worker | 14 |
| EXT-live-aws | 2 |
| T03-launch-connectors | 7 |
| T12-red-team | 1 |
| EXT-live-fargate | 2 |
| T14-data-workflows | 41 |
| T07-security-agent-authority | 2 |
| T10-product-ui | 7 |
| T15-deployment | 18 |
| EXT-cloud-deploy | 42 |
| EXT-human-observation | 13 |
| T08-supervised-agent | 6 |
| T09-agent-actions | 5 |
| T16-recovery-ops | 35 |
| EXT-image-attestation | 2 |

The launch critical path remains:

1. Connect approval and connector background consumers to genuine registered native authority. Connector claim alone is insufficient: all eight repository methods and workflow metadata reads require proper authority and captured enqueue provenance. Original tenant, lease, retry, approval and readiness checks must remain. Do not authorize legacy originless work retroactively.
2. Complete genuine current Temporal/OpenFGA composition, native registration, projection acknowledgement and measured cutover. Preserve original outbox consumers, PostgreSQL isolation, Stytch identity and all security behavior. Component controls do not issue native authority or establish production activation.
3. Verify scoped deployment targets, distinct database role DSNs, store/model and migration bindings, Stytch organization/member/session flows, and actual provider permissions. The managed cloud exposes 51 generic variables; readiness of those variables does not prove the required permission scope or target. Earlier Stytch TEST authentication accepted a read-only search with zero organizations; production identity and deployed flows remain unverified.
4. Complete official advisory intake and full Go/npm/image/SBOM release evidence. The bounded public metadata attempt remains incomplete at an oversized monthly tree; caller receipts and local Git fixtures are not upstream admission. Release guards stay closed.
5. Verify discovery/sync, connected UI security flows and recovery/operations milestones against the actual deployment, including backup/restore, provider failures, budgets, approvals, tenant denials, audit evidence and required human observation. Retire old implementations only after equivalent behavior is verified.

Current implementation batch repairs the hosted prerequisite contract after the mandatory signed-webhook CI step was added. The original four-file command reproduced 235 PASS / 2 FAIL at stale 36-step assertions. The correction requires the exact new step and 37-step total, then removes only three validated additions to retain the unchanged original 34-step fingerprint. All original cases plus nine hostile mutations pass: 246 PASS, zero skips. No workflow step, runtime intake implementation, permission or release guard changes.

Main remains unmerged while hosted checks fail or are pending. The previous full logs could not be fetched because the cloud denied the results-receiver destination; no proxy or policy bypass was attempted. Permitted annotations and the local reproduction establish this prerequisite defect, not the sole deployed readiness cause. Local lint initially could not resolve the deliberately minimal TMP dependency tree; using the existing original configuration resolved the setup issue. Both outcomes are retained.
