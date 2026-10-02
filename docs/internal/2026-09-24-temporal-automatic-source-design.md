# Automatic trigger rules and durable sources

Controller design ruling within the approved September22 architecture and the
user's explicit autonomous, scope-preserving instruction. This is implementation
direction, not completion or production proof. The audit report of the same date
contains source references and remaining evidence gaps.

The original M7A-35..38d requirements and PRD11.3/SA-1 remain the acceptance
boundary. All responder families must be accounted for. Single-test success
cannot close this group or the full goal.

## Chosen contracts

Persist optional versioned trigger_rules in the existing immutable definition
body, including public strict schemas, actual API create/update/readback and UI.
Omission preserves exact historical behavior. Explicit rules support manual-only,
finding family/minimum severity, exact path state, runtime decision/action/risk
and distinct-event count/window, plus configured cooldown. Count is1..100;
window and cooldown are1..86400 seconds. Save returns a disabled draft and
requires reactivation. Rules participate in definition digests and audit intent.

Manual-only suppresses automatic admission; it does not change human admission
provenance or require a fabricated source. Preserve existing public IDs and
receipt semantics. Unknown/partial/unsupported rule shapes fail closed.

Runtime risk is an optional scoped policy annotation, versioned with the policy,
included in signed compiled material and carried from actual evaluation through
the authenticated, digested gateway event. Vocabulary: low, medium, high,
critical, matching existing product severity terms. Historical/unannotated risk
is unknown, not an invented default. A configured risk filter does not match
unknown. Never alias decision, request outcome, HTTP/MCP action or resource
finding severity to policy-evaluation risk. Keep request classification unchanged.

For multiple evaluated policies, determine risk from policies contributing to
the resolved decision, using the highest annotated level only when provenance
is complete for that contributor set. If any contributor has unknown risk, the
resolved risk is unknown. Preserve the existing decision precedence; do not
change allow/monitor/block outcomes to obtain a risk value. Document the exact
contributor rule against the real evaluator before coding its aggregation.

Capture immutable source-event identity within the canonical finding, path or
gateway-event mutation transaction. The capture does not contact Temporal or
acquire run/budget locks. Rollback removes capture. Consume after commit, when
path child evidence is complete, and recheck current scoped source/authority.
Preserve original timestamps and evidence; do not rewrite historical events.

Temporal owns durable dispatch/retries. A bounded committed-event outbox relay
and deterministic workflow identity may bridge SQL to Temporal. No replacement
custom lease/scheduler engine. Admission preserves current service authority,
definition/version, tenant isolation, shared capacity, budgets and controls.
Use the same configured matcher for event dispatch and periodic catch-up.

Keep permanent source-occurrence dedup separate from serialized cooldown:
replaying an old occurrence never creates a new run after cooldown expires;
a genuinely new occurrence can qualify afterward. Keep an unexpired cooldown
across definition edits for the same definition ID/source-pattern identity.
Changing settings must not reset suppression through a version-only key.
Retain catch-up for still-current pre-activation findings and paths, using
canonical source identity/time; activation itself is not a source mutation.

Potential, observed and verified paths remain distinct. Matching a configured
potential path does not grant an action's execution authority or fabricate
verification. Existing action eligibility and path-integrity checks remain.
Where an action/state combination is unsupported, reject it before activation
with an actionable reason and record the remaining original product dependency;
do not silently drop matched work or count that family complete.

## Delivery sequence and acceptance

Implement in three dependent groups: persisted rule/API/UI contract; policy-risk
evaluation/event contract; atomic sources plus Temporal matching/admission and
responder adapters. Each uses grouped TDD on actual product boundaries, with
focused checks for affected code. These stages do not reduce the final scope.
The same implementation owner can develop them sequentially; controller review
occurs at a coherent frozen deliverable, not every small edit.

Every enabled responder family needs explicit matching, admission owner and
delivery evidence. Retained families stay explicitly retained until equivalent
Temporal execution is verified. Do not manufacture automatic service authority
from human receipts, wrap old claim loops in Activities, or call partial family
coverage complete. Preserve all existing SQS/event-stream uses and unknown debt.

Periodic-only reconstruction was rejected because it does not prove original
atomic source emission. Per-Go-caller publication was rejected because it misses
shared SQL writers and creates a postcommit loss window. Canonical table capture
is selected, with exact catalog/role effects enumerated in an additive release.

The cost of an incorrect ruling is rework of versioned public/event contracts,
matching semantics or source capture. Mitigate with strict backwards-compatible
validation, actual writer/rollback/replay checks and current-authority negatives.
No historical SQL edits, shared database resets, external provisioning or release
gate bypass. Full FGA enforcement and deployed real integrations remain required.
