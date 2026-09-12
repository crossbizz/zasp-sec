# Read-only precision consumer observation

observePrecisionConsumers checks the exact schema51 consumer set, including the
separate target2 index worker. It retains the existing explicit kubeconfig,
context and namespace-UID checks, bounded kubectl reads, admitted-template/image
pins, generation/replica readiness, controller ownership and pod-status checks.
The historical schema49 observer remains a separate fixed entrypoint.

Precision observation also checks the intended runtime versions independently of
template digests. Intake must remain V1; queue consumers select V2; precise
stages and index targets must match the consumer-phase contract. An orphan pod
identified as a coordinator by label, service account or worker-mode environment
is rejected. Owned old/terminating pods still fail the existing rollout checks.

revalidatePrecisionConsumers repeats the observation, requires unchanged
identities and rejects an observation at least30 seconds old. This is read-only
evidence in the specified namespace, not permission to deploy, authenticated
release provenance, proof of processes outside Kubernetes, provider checkpoints
or protection against a later rollout race.

TDD reproduced three missing behaviors: the old observer rejected51; internally
consistent old-coordinator/early-intake templates were accepted; and an orphan
coordinator was ignored. After correction, all28 observer tests passed in0.948s,
including rendered51 templates with controlled provider metadata. No live
kubectl calls were made. Independent review found no blocking findings and
repeated all28 tests in1.013s. Added separate label-free orphan service-account
and worker-mode cases; final30-test run passed in0.927s.

Activation still needs integration of this observation/revalidation with the
deployment workflow, schema/database readiness and provider-catch-up evidence.
No deployment, push or original task credit.

The separate observePrecisionIntake/revalidatePrecisionIntake entrypoints now
require intakeV2 while retaining the same51/all11-consumer checks. The choice is
fixed by the entrypoint, not a caller option. The V1 consumer observer still
rejects intakeV2. TDD first caught a wrapper acceptingV1 and rejectingV2; the
correction passed33/33 tests in1.492s, including rendered precision-intake,
old-coordinator refusal, expiry and replaced-pod revalidation. Independent review
found no issues and repeated33/33 in1.416s. All kubectl responses were controlled
fixtures. This fills the read-only post-intake observation step; source activation
still needs the serialized deployment workflow and real provider/database evidence.

The earlier schema50/backfill transition now has its own fixed
observeSandboxBackfill/revalidateSandboxBackfill entrypoints. They require all11
workloads, schema50, API target1, both index targets with stage1, historical
archive/correlation/projection/completion versions and no precision ingest or
delivery overrides. Existing49/51 entrypoints retain their own fixed profiles.
The first rendered50 test failed against the old49 observer. The new tests use
actual backfill manifests with controlled cluster metadata and reject premature
query target, precise stages/intake and expired evidence. No live kubectl calls.
Final focused run passed34/34 in1.488s; independent review found no issues and
repeated34/34 in1.650s.
This supplies read-only backfill identity evidence, not a canonical receipt-set
provider checkpoint, serialized query switch or release authorization.
