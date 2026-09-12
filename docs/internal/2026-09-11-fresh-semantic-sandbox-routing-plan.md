# Fresh semantic sandbox routing correction

Original scope still requires sandbox-bound fresh runtime evidence. The provider
proof exposed a production gap: OTLP normalization already requires sandbox.id,
but fresh V1 semantic batches still select correlation2, which does not persist
that sandbox identity. Worker support for correlation3/project2/complete2 alone
does not close this requirement.

Correction accepted by bounded read-only design review:

1. Within unpublished51, choose the existing 1/1/3/2/2 tuple only for newly
   committed, persisted source_kind=otlp and payload_schema_version=runtime-event-v1.
   V1 Tetragon stays1/1/2/1/1; precise V2 Tetragon stays2/2/4/3/3. Do not change
   archive bytes, request digests, accepted historical tuples, or receipts.
2. Read source/schema under the existing batch lock. Fence cached predecessor
   commit bodies from inserting an incompatible fresh semantic tuple; recheck
   full51 readiness around mutations. Preserve authenticated recovery, final
   attempt and immutable accepted replay. Test exact Down behavior with retained
   schema50-compatible semantic evidence and separately retained V2 evidence.
3. Prove the new route through actual registered PG and the HTTP/recovery paths,
   then extend the real provider pipeline proof to require the observed sandbox
   on a fresh Strong event and no sandbox on the second, unattributed process.
   No direct row relabeling or seeded successful evidence for the fresh flow.
4. Keep V2 intake/source activation disabled until compatible consumer rollout
   and source/provider acceptance gates pass. Historical consumers must leave
   unsupported fresh work pending during a rollout; the new consumer phase must
   drain it. Verify that behavior, not just configuration versions.

Review decisions: installing51 activates the new semantic route even while
intake remainsV1. A temporary semantic backlog during consumer replacement is an
explicit rollout barrier, not proof of uninterrupted service. Pending semantic
3/2/2 work must block rollback to the current50 deployment configuration, since
its2/1/1 workers cannot drain it; completed schema50-compatible evidence may be
retained when safe. Source/schema and the immutable stage rows provide the
persisted decision, so no caller-controlled selector is added.

This revises the earlier design's blanket "fresh V1 tuple unchanged" rule for
new OTLP commits only. That rule was a compatibility design choice, not a reason
to omit the user's sandbox-binding product requirement. Existing accepted V1
evidence remains immutable. Review must reject this design if source/schema
alone is insufficient authority or if the retained evidence cannot be safely
interpreted by its recorded implementation versions.

SQL implementation and actualPG tests are assigned and in progress; no task credit.
