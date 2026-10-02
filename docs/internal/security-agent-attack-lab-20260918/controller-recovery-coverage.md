# Controller recovery coverage, source inspection

Inspected2026-09-19 while Task1 is the sole active source implementation.
This note maps existing tests to Task2's missing connected proof. No tests were
run for this note; test source is not a passing result or live provider proof.

## Existing tests worth reusing

- `agentsec-worker/attack_lab_runtime_test.go`:
  `TestAttackLabProcessorReconcilesLostCreateResponseBeforeCancellationCleanup`
  checks the processor's create/reconcile/cleanup ordering with a recording
  authority and provider. It does not call real PostgreSQL or the egress proxy.
- `agentsec-worker/attack_lab_timeout_test.go`:
  `TestAttackLabTimeoutCheckpointsBoundedEvidenceBeforeCleanupAndResumes`
  uses production Kubernetes HTTP collection/deletion with controlled replies.
  Its database authority is a recording fixture. The second processor starts
  from a manually supplied cleanup claim and does not repeat execution.
- `agentsec-worker/attack_lab_kubernetes_provider_test.go`:
  `TestProductionAttackLabProviderEnsuresExpiredProvisioningIntentIdempotently`
  rejects expired Create, then expects Reconcile to ensure the deterministic
  Job. A recording cluster supplies its UID. This test does not prove external
  egress authorization or duplicate execution after a committed transition.
- `agentsec-migrate/main_test.go`:
  `TestAgentsecMigrateCLIReachesV34FromEmptyAndV12` includes registered-role
  provisioning, mark-running, proxy destination/credential checks, lease
  expiry and a running reclaim preserving the exact sandbox reference. Those
  assertions are database calls, not a restarted production processor using
  the production provider. Do not run this large historical chain solely to
  replace the focused Task2 acceptance case.

## Where the proof must join

`attack_lab_runtime.go` branches on claimed/provisioning/running/cleanup.
MarkAttackLabRunning errors stop the processor without inventing a new run.
A recovered running claim bypasses both Create and Reconcile and proceeds to
Run with the saved sandbox reference. The connected test must obtain that
claim from the actual registered database authority after a committed reply
is lost, not set the disposition in a recording fixture.

The published execution SQL resolves egress only for a running, uncancelled,
cleanup-pending run with a current lease and valid destination/credential
authority. Task2 must exercise the installed release chain's actual function
through the registered proxy role, not rely on reading this predicate.

Required fault points for one connected batch:

1. Lost Create reply while provisioning remains durable: issue a real proxy
   authorization request before mark-running and assert denial. Controlled
   external target request count stays zero. Recovery may ensure the same
   deterministic Job, but must not invent a new attempt or target.
2. Lost MarkRunning reply after its database transaction commits: expire or
   release the first controller lease deterministically, create a new processor
   instance, and obtain a running claim through the repository. Assert the
   retained UID, no new Job create and no second external invocation.
3. Missing/expired Job after running: retain the uncertainty and cleanup
   obligation; prove no fresh execution through the provider transport. A
   missing result is not a verified or not-reproduced verdict.
4. Cleanup reply lost: restart from durable cleanup state, use UID-fenced
   cleanup, and acknowledge only after confirmed destruction. The external
   execution count must remain unchanged.

Use existing controlled Kubernetes transport and owned cached PostgreSQL
fixtures with real repository/processor/proxy connections. A fault wrapper
may drop an already committed response, but must delegate the real operation
first and retain its exact source/UID/attempt. No production test hooks or
fake authority transitions. Record the installed release, registered roles,
source hashes and exact test command with the feature batch.

No controller correction is justified solely by these source gaps. Add the
connected tests first; change implementation only if they expose a defect.
