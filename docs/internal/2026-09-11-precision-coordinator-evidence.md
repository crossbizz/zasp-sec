# Explicit precision coordinator, local prerequisite

The new explicit coordinator requires a precision-readiness capability, checks
it before consuming the queue, and admits only runtime-event-v1/v2 payloads.
Historical construction remains V1-only. Shared transport version15, artifact
keys, payload schema value, queue authority digest and delivery lease/ack checks
are unchanged. This does not make old coordinators safe readers of mixed V2
queues; rollout must replace them before V2 production admission.

The V2 regression failed with the historical coordinator. The explicit path then
completed database/queue acknowledgement without changing the authority digest.
Tests cover wrong/empty schema refusal, preserved V1 behavior, missing readiness
capability and unavailable precision authority before queue consumption.
Targeted coordinator races passed in2.242s. Full runtimeevent and worker races
passed in5.239s and18.995s before a final public-readiness context fix.

Public repository ReadyPrecision now rejects invalid contexts before database
access. A nil-context test reproduced a panic in the initial exported wrapper;
the wrapper now uses the existing repository/context validator. Its full
runtimeevent rerun passed in5.296s. Independent core review found no blocking
issue and repeated targeted coordinator/schema races in2.132s. These use the
actual jobqueue codec with fixture delivery authority/provider, not a deployed queue.

Production selection follow-up: `ZASP_RUNTIME_DELIVERY_SCHEMA` now selects the
coordinator's repository and decoder together. Empty/v1 retain historical
behavior; v2 selects the precise repository and coordinator. Unknown values and
nonempty selection on other worker modes fail configuration validation. Outbox
selection is not yet enabled.

The unknown-schema test first failed because the loader silently ignored the
value. The composition test then failed because readiness did not check release
51. After implementation, targeted races passed in 2.277s; full worker and
runtimeevent races passed in 19.287s and 6.021s. The composition test also changes
database readiness after a successful cached check and confirms RunOnce refuses
work after a fresh precision check. Independent review is pending. These are
local declared-dependency tests, not deployed provider proof.

Review correction: the initial composition assertion could pass after an old
coordinator consumed V1 and the precise repository rejected its claim. The test
now counts actual queue-driver ConsumeBatch calls and requires zero after drift.
Changing only the coordinator factory to the old constructor reproduced the
failure (1.096s); restoring it passed coordinator/schema races (2.195s).
Independent rereview approved this correction with no new findings.

Versioned outbox publication, full provider pipeline and schema51 rollout are
still required. No activation, push or original task credit.
