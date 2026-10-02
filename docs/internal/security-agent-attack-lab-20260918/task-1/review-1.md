# Independent review 1

Reviewer: /root/compliance_deployment_review. Spec: NEEDS FIXES. Quality:
NEEDS FIXES. Reviewed frozen patch SHA256
61cc67271f26fe641c256158796d8cc6db3aa914b09a196d2bb3c7385a65c1aa.

## Important P2: repository routing blocks retained receipt replay

security_agent_attack_lab_repository.go:66 calls zasp_sa_attack_lab_run_kind
before the requested operation. security_agent_attack_lab_links.sql:106
requires a live worker lease or an Attack Lab dispatch link. Successful
planner acceptance prepares the run and clears its lease into waiting_approval,
before any dispatch link exists. An identical real-repository acceptance retry
is rejected before existing_test_planner.sql:307 retained-receipt replay.
Legacy run_test/rerun_test on57 are affected too, as are retained failure
receipts. PrepareSecurityAgentRun uses the same routing gate.

Fix must preserve scoped immutable receipt recovery without weakening fresh
work authorization. Reproduce via actual registered repository on57: accept,
discard response, retry with original worker/lease and identical intent; expect
retained response with replayed=true. Cover Attack Lab, legacy run/rerun,
failure receipt recovery and altered-intent denial. SQL dispatch replay alone
does not cover this boundary.

## P3: fragment allocation

Task1's file list included reconcile/settlement fragments, but their real
implementation belongs to Task2. Controller ruling: move those two file-list
requirements to Task2, preserving all signatures and behavior. Empty or
success-returning placeholders would misrepresent readiness. Cost: Task1
cannot be cited as implementing settlement; Task2 must implement both files.
Plan corrected accordingly; no original microtask scope removed.

## Evidence and limits

Reviewer checked29 current blobs and29 before files, patch identity and
preservation of published1..56 SQL/pins. Separate cached-container evidence
and exact-name native race evidence are usable. Host-PG incident remains
historical process noncompliance and is excluded from accepted database proof.
No test reruns, edits, external calls or child reviewers occurred.
Task2/3 and live acceptance remain pending. No Task1 acceptance yet.
