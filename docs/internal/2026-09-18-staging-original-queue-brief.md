# M1A-04 staging original queue repair

## Requirements and bounds

Original authority: `agent_security_platform_Technical_Implementation_Plan_v1.5.md`, M1A-04: add the three staging queues and DLQs using the product queue contract; verify Terraform plan redrive policies and outputs. Canonical definitions are in `services/platform/queuedefinition/definitions.go`. The original tests queue is separate from Red Team.

Bounded design: add the missing `tests` entry to staging's existing queue contract, matching canonical visibility 900, maximum receive count 5 and schema `agentsec.tests.v1`. Verify the existing shared resources construct its queue, DLQ, encryption, redrive and output entries with canonical settings. Preserve all other queues and narrowly scoped consumer IAM. Do not replace `red-team-tests`, redirect its consumers or grant additional wildcard authority. Investigate any mismatch in the shared resource settings before expanding the repair.

User-authorized autonomous implementation and grouped testing apply. No extra approval pause for this local repair. No cloud calls, credentials, provider downloads, Terraform init against remote services, apply, commit, staging or push. Cached offline tooling only. No live production claims. Existing unrelated edits belong to the user.

## One batch

1. Capture exact before bytes of touched files. Inspect existing cached Terraform tooling and relevant tests.
2. Add a focused regression and observe RED for the absent original tests queue. Prefer an actual offline Terraform mock plan if the required tool/providers are already cached. Otherwise use the existing local contract testing approach, explicitly recording that it does not satisfy real Terraform plan acceptance.
3. Apply the minimal queue correction. Verify all three original queues, DLQs, schema/settings/redrive/outputs and distinct Red Team identity/consumer/IAM preservation. Use negative controls where practical to establish the regression catches removal or mutation.
4. Run the connected affected suite once. Reuse unchanged UI evidence; no frontend edits and no push in this batch. Any inherited failure is retained and diagnosed separately, not silently treated as passing.
5. Self-review and retain before/after hashes, scoped diff, commands, RED/GREEN logs and limitations in `docs/internal/staging-original-queue-20260918/`. Full report is `report.md`; return its path and a short status. Root will arrange independent review and update the authoritative availability ledger. Do not edit that ledger yourself.

## Preflight ruling

The original task's actual account Terraform plan cannot be substituted by source matching or a mocked provider. Local repair and offline verification can proceed, with M1A-04 remaining component-only until its remaining acceptance/publication gates are proven. Cost if wrong: deployment contract rework, never implied cloud readiness.

Single task coherence: canonical definitions produce settings consumed by staging queue resources; redrive references the matching DLQ, and existing outputs enumerate both resource maps. No other task shares the editing scope. The potential mismatch is missing map membership, not authorization to replace unrelated infrastructure.

## Review fix ruling

Root and independent review traced `queue_definitions_proof.go:160-170,190-195`
and `queue_definitions_proof_test.go:554-565`: the canonical scalar attributes
apply to the original DLQs as well as their work queues. Pin receive wait20,
maximum message bytes262144 and delay0 explicitly for original DLQs; also pin
work delay0. Scope any newly explicit settings to `background`,
`runtime-events`, and `tests`; preserve the other queues' existing declarations
and implicit defaults. This resolves a source guarantee without claiming what
AWS would currently choose. Add focused regression/negative controls and run
only covering queue checks for this fix, reusing unchanged connected-suite
evidence and its separately retained56-rollout failure. Retain fix-before/after
identities and a fix-only patch for scoped re-review.

Ruling: canonical source and DLQ attributes are local implementation obligations,
not merely a missing external-plan observation. Cost if wrong: a conditional
Terraform setting change to the three originals requiring further local review;
no live infrastructure is changed by this batch.
