# Sandbox search deployment sequence

This is the deployment portion of the original M3 implementation, not a new
milestone or reduced launch target. The user authorized autonomous decisions.
Status: design, not deployed or accepted.

## Decision

Use explicit deployment phases. Keep the historical worker, API target and
initializer available while the separate v2 queue catches up. A single worker
target switch would leave the v1 API without fresh checkpoints during backfill.
Reusing the v1 checkpoint table would destroy the history already covered by
acceptance. Both approaches are rejected.

| Phase | Schema command | API target | Session workers | Initializers |
| --- | --- | --- | --- | --- |
| Compatibility | `up-to-49` | v1 | v1 | v1 |
| Backfill | `up-to-50` | v1 | v1 and v2 | v1 and v2 |
| Query cutover | `up-to-50` | v2 | v1 and v2 | v1 and v2 |

These phases leave correlation-v2/projection-v1/complete-v1 producer routing
unchanged. Fresh sandbox producers are a subsequent forward activation, with
their own pinned migration and compatible consumers. That work and browser
acceptance remain required before original M3 completion.

## Rendered resources

Add a closed `runtime.sessionSearchPhase` value: `compatibility`, `backfill`, or
`query`. Compatibility accepts schema49; existing schema48 staging remains a
legacy path. Backfill/query require schema50. Reject unknown values and mixed
phase/schema combinations in both Helm rendering and release validation.

Keep `agentsec-runtime-index` explicitly on `zasp-runtime-sessions-v1`. For
backfill/query add `agentsec-runtime-session-index-v2`, using runtime-index mode,
the same registered database index authority and the existing index service
account/secret mount, but an independent pod worker identity and explicit
`ZASP_RUNTIME_SESSION_INDEX=zasp-runtime-sessions-v2`. Both binaries support the
same raw-index stage contract, so existing claims can distribute normally; only
session progress targets differ. Do not create a second database authority.

The extra deployment needs its own selector, service, health probes, bounded
resources, PDB/HPA and matching network policy/monitor coverage. Reusing a
service account does not make labels or network policies interchangeable.

Keep the existing v1 search initializer. Add a separate v2 initializer job using
the existing initializer service account, explicit v2 selection and the same
bounded provider initialization code. Retain graph/raw/inventory initialization
semantics. Do not duplicate service-account resources with the same name.
Require successful migration50 before initialization. Run the v1 initializer
before the v2 initializer with distinct hook weights, since both touch shared
raw/inventory schemas. Workers start only after both bounded jobs succeed.
Check v2 readiness and monitoring against its own Deployment and pod selectors;
healthy v1 pods cannot satisfy v2 availability.

Wire API selection explicitly in every phase. Update rendered-resource
validation and environment gates to expect the exact phase-specific deployment
and job sets; preserve closed sets and reject missing/extra/duplicate target
variables, valueFrom overrides and wrong index names.

## Transition evidence

Helm's schema job is a pre-upgrade hook. It runs before replacement deployments,
so a rendered backfill manifest cannot establish that compatible pods already
run. Before applying backfill, inspect the actual49 deployment generations and
ready pod image digests against the intended compatible API/worker images.
Reject stale observations, partially rolled deployments, wrong cluster/namespace
or a different schema release. A caller-supplied Boolean is not evidence.
Bind observations to Deployment UID/generation, observed generation, exact
pod-template/config digest, ready Pod UIDs and resolved image IDs. Revalidate
these identities immediately before applying50. An intervening rollout or config
change invalidates the observation even if the image tags stayed unchanged.

Before query cutover, establish compiled50 database readiness, fixed v2 mapping
and marker readiness, complete target-specific checkpoints for a captured
canonical receipt set, zero quarantined target rows and provider-visible ordered
occurrence IDs. The check must revalidate the same receipt set after observing
provider visibility; concurrent v1 arrivals must not turn an old successful
check into permission to hide pending work. New arrivals after cutover still use
normal catching-up semantics. API pod Ready alone does not prove search coverage.
Record a deterministic digest of every receipt identity/digest in the captured
set, the database and provider identities, the intended query-release manifest
digest and observation time. At switch authorization, recapture the complete
canonical set and compare it, not only the rows in the first capture. Any added
or changed receipt restarts coverage validation. Authorization is the cutoff:
receipts committed after it may be catching up normally. Evidence expires after
30 seconds and is single-use for that exact manifest; revalidation is required
after expiration, interruption or any target/config change.

Local evidence verifies the transition mechanism against controlled providers.
Live cluster observations and managed-provider/IAM results remain separate
deployment gates. Never promote a local fixture as a live deployment record.

## Permissions and recovery

Preserve v1 IAM paths. Add only exact v2 mapping/marker reads to API, index worker
and initializer. API gets v2 `_search` POST; worker gets `_bulk`, `_mget` and
`_refresh` POST; initializer gets index and marker PUT. No session wildcard,
delete, API write, or initializer bulk/search authority.

Before any v2 attempt or retained new evidence, `down-to-49` uses the guarded50
rollback. After that boundary, failures need forward recovery. A failed API
rollout must not reset either queue, edit canonical receipts or falsely mark
unindexed rows current. Retain the v1 worker during query cutover; retiring it is
a separate step after fresh producer activation and compatibility proof.

## Acceptance boundaries

Real Helm renders must prove each phase and reject mixed/unknown phase inputs.
Mutation controls must reject missing parallel workers, wrong authorities,
missing network coverage and premature API selection. Evaluate Terraform policy
objects, with provider fixture limitations stated separately from live IAM.
Run actual executable/environment composition, historical provider cutover,
fresh sandbox ingestion/recovery and authenticated browser acceptance before
publishing. The existing chart49/embedded50 failure stays visible until the
phase-aware chart and gate are implemented, not merely renumbered.
