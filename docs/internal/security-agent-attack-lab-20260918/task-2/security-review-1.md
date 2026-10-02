# Task2 bounded security review1

Independent reviewer: /root/attack_lab_settlement_review, GPT-6 Astra.
Read-only review of settlement/reconciliation authority, client, evidence and
decoder semantics. No tests, edits or external calls. Deployment, CLI, UI and
whole-feature acceptance are outside this pass. Verdict: NEEDS FIXES.

## Important findings

1. Settlement SQL lines44–50 checks authority before blocking organization and
   row locks, then returns an existing receipt without rechecking. Revocation
   during that wait can still disclose the receipt. Re-authorize before the
   replay return while retaining exact authorized replay after lease expiry.
   Root subsequently inspected settlement-edges-red-2.log: the observed-wait
   test fails with "revoked waiting replay returned settled receipt". That run
   was still executing its Create403 case when inspected, so no overall exit
   status or denial-case result is asserted here.
2. Settlement SQL lines17/26 require started_at IS NULL for no-sandbox cleanup
   and pre-execution denial. Existing controller Claim sets started_at before
   Create (published0026 SQL line448). A definitive Create403/retry-to-failed
   can remain pending because it lacks both a cleanup checkpoint and a null
   start time. Implementer independently identified this issue and is adding
   the connected case before changing classification. Unknown creation must
   retain cleanup obligations; simply treating every absent sandbox as safe
   would not resolve the requirement.

No other Critical/Important finding in the inspected scope. Artifact validation
checks pinned version, body hash, size, scope, execution/attempt/input, source
run and target; both valid verdicts map to needs_human. Strict typed decoding
rejects duplicate/aliased/missing keys and null nonnullable fields.

## Reviewed production identities

All six hashes were unchanged before/after reviewer inspection:

| File basename | SHA256 |
| --- | --- |
| security_agent_attack_lab_reconcile.sql | 8e7c83005bdd298105a7aebd40d9656cf96fcd29d2ed0e4a74d63294d6389452 |
| security_agent_attack_lab_settlement.sql | 3e45c2a9db94fd31db1b0a22018e9d8dc46ff3f9e13ccadab0b5c3a6605622f0 |
| security_agent_attack_lab_client.go | 94f616da148215e2babea89eb2377cc7073950a46fbcfddae5e2f60aaee06687 |
| security_agent_attack_lab_evidence.go | 5711a523f6a3f68e03cc261f82eda89ffab559e76028ba95343c776497316d0c |
| security_agent_attack_lab_reconciler.go | 43c00f7fb8ee6af02f146bd2f8174a12de8c1772b900e8769ce4134dd864044f |
| security_agent_attack_lab_json.go | 5adeedca97474454b4399bacd6057ce9982cf847c05a260e9dc77e97026e4036 |

SQL files are under services/platform/migrations/sql/fragments; Go files are
under services/platform/agentsec-worker. The settlement test changed during
review (hash prefix64a2b52a to f7be7f8a); its new edits were not reviewed.

Re-review the affected settlement branches, denial classification, compiled pins
and new tests/evidence. Reuse only unchanged reviewed scope. Passing13 controlled
runtime scenarios, later grantor correction and native race evidence are local
component acceptance, not live provider or production proof.
