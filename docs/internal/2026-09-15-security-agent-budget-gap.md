# Security Agent durable budget gap

M7A-49 is reclassified from production-available to component-only. M7A-95
remains component-only. All 728 IDs and historical Complete/Blocked labels stay
intact. Current availability is 534 production-available, 133 component-only,
61 blocked/external and zero missing; M7A is 97/16/0/0.

## September 16 registered worker readiness checkpoint

### Negotiated budget details

Replaced the client-first refresh dependency below with an explicit optional
`X-Zasp-Budget-Details: v1` request header. Only one exact supported value
enables the reason after normal data validation. Legacy/unsupported/duplicate
requests receive the original seven fields. Updated clients emit the header
and tolerate old-server omission. No SQL authority or candidate pin changed.
Go RED4b2767 caught unwanted legacy fields; browser RED780a6a caught missing
request opt-in. Go race ca7bc0 passes2.732s, browser/API93/typecheck/build3d2188
passes (plugin timing warnings only), OpenAPI39/check bc69b6 passes. Real
PostgreSQL/worker fresh and missing-cost cases b2b401 pass25.223s, with legacy
and opted-in reads, no-store and independent foreign org/workspace/environment
denials. Review found no Critical/Important issue; its minor unsupported-header
schema mismatch was corrected to string, matching the fallback contract.
Final post-review generation/check,39 OpenAPI tests, typecheck, ledger and
diff check617e2d pass.
Mounted authentication/proxy and live rollout remain
unproven; this is controlled local evidence. No push or class promotion.

### Public budget-stop visibility

Real worker REDd4eec2 confirmed a budget_usage_unknown stop persisted with zero
provider calls/artifacts, while the registered API omitted the reason. Go
RED6b88b6 rejected all five valid new codes; browser REDa8843c rejected them and
the drawer displayed no guidance. Added optional run-detail budget_stop_reason
through the existing v24 authorized projection, constrained Go/OpenAPI/client
contracts and fixed drawer messages. Full tenant/run tuple controls the SQL
lookup; no raw provider text or lease/accounting data enters the response.
Legacy omission remains readable. Sticky stops may accompany retained contained
results, so the reason does not imply every existing effect has been cleaned up.

Measured unpublished candidate fingerprint9a4ca4 is
10ac4fb7b3212c5b89164911070c184e5aa3525cb29aacbb526bf5e183e20eb5.
Go read group9fde83 passes2.591s. Browser group1cd3f2 passes117 tests, typecheck
and all build stages; OpenAPI generation/check/39 tests and unfiltered migration
unit suite01a831 pass. Independent review found no Critical/Important source
issue. The composed test now checks real public-handler200/no-store and expected
reason or omission, plus404/no reason for foreign organization, workspace and
environment. Final verification is pending those extended checks and migration
rollback/consumer cases. This is injected request identity with real SQL, not
mounted browser authentication or a live deployment.

Original rollout gap: cached older strict clients rejected additional fields.
The negotiated-details checkpoint above replaces the client-first requirement.
Mounted-authentication/proxy and deployed mixed-version behavior remain open.
No production class promotion or push.
Final six-mode composed worker plus migration rollback/fences/consumer group
f2a2bd passes63.040s. Extended public-handler fresh/missing-cost run5ddb39
passes16.442s with separate foreign organization/workspace/environment404 checks
and no-store assertions. This closes the bounded read/visibility integration,
not the documented client rollout or mounted-authentication acceptance.

### Production planner request compatibility

Tracing the actual pinned `openai/gpt-5-mini` request found temperature:0 and
provider support left optional. Official [OpenAI compatibility guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.2)
states GPT-5-mini does not support temperature. [OpenRouter provider routing](https://openrouter.ai/docs/guides/routing/provider-selection)
documents that unsupported parameters can be ignored unless require_parameters
is true. RED510f36 observed the incompatible serialized field and missing routing
constraint. The production request now omits temperature and sets
provider.require_parameters:true while preserving data_collection:deny, the
model, output-token limit, schema and bounded single-request behavior.

The test uses RawMessage to distinguish absence from zero/null; the 404 no-
compatible-provider case checks one attempt, generic failure and no candidate.
Affected planner/budget race checks84a453 pass2.220s. Independent review found no
Critical/Important source issue; full worker/composed reruns remain pending.
Full worker race suite24f0b6 subsequently passes29.487s. Composed verification
subsequently passes all six modes indda2bf (40.198s), using the real migrated
worker with controlled transport and test-only pricing. Ledger32e48a remains
valid at728/534/133/61/0. These checks do not establish live provider operation.

Read-only public [endpoint metadata](https://openrouter.ai/api/v1/models/openai/gpt-5-mini/endpoints)
was fetched without credentials or completion calls (b99383). The OpenAI endpoint
listed max_tokens, response_format and structured_outputs, but no temperature;
Azure listed max_completion_tokens instead. Requiring support can exclude an
incompatible endpoint. This does not prove account routing, ZDR, live billing,
or an overall per-request cost bound. Endpoint prompt capacity is much larger
than the product run token ceiling; catalog rates alone cannot authorize a
bounded request. PlannerBudget still returns unknown maxima, so paid execution
remains stopped before dispatch. No guessed tokenizer overhead, dollars/credits
conversion, automatic spending, main push or task-class promotion was added.

### Observed definition activation/edit contention

`security_agent_cost_concurrency_postgres_test.go` exercises both first-winner
orders with registered API connections and real repository calls. A successful
first operation remains uncommitted while the second tries the same public
version3. The owner observes the second PID blocked by the first before commit;
the second must then conflict. Assertions require the winner's literal version4,
activation/enabled state and cost, exactly one new revision, and no losing
receipt/idempotency/audit. A repeated losing operation leaves a nine-table
authority snapshot byte-identical. Cancellation, rollback and joining precede
connection closure on all paths. No production function or readiness pin changed.

The two contention modes plus two admitted-run reconfiguration modes pass with
the race detector (959862,20.417s). Independent review found no Critical/Important
issue and accepted the bounded observed-lock condition. This is not all possible
interleavings, mounted browser authentication, provider billing or release proof.

A separate route audit found `securityagent.NewHTTPHandler` is memory-backed and
used by component tests. Production mounts `NewSecurityAgentPublicHTTPHandler`
and `newWorkflowHTTPHandler` at apiserver/production.go. The alternate handler
and RunLimits still omit the optional nano-credit field; keep the consistency
task open without treating it as a second live product route. The production
planner still supplies no verified total-token/cost policy, so paid planning
stops before dispatch. Pricing authority and full release remain unfinished.

### Active-definition reconfiguration and stale-client refusal

The registered SQL regression now increases or removes cost after supervised
activation and actual worker admission. The update returns public version5 and
disabled draft; a later validation reaches6. Stale direct CAS is refused, both
HTTP and direct SQL replay return the original version5 receipt, conflicting
intent is rejected, and deletion writes audit version7. The original run's full
budget snapshot stays byte-identical throughout, with zero provider reservations
or effects. Final expanded regression910d1c passes10.147s (two modes).

The unpublished53 wrapper uses the existing idempotency lock, workflow-row then
definition-row locks, public definition CAS and internal mirror version. It
leaves public intent unchanged and adjusts only the new mutation's audit version.
Candidate fingerprint24365b6e369af1611f8b4bfd757395ca0660a65c47d6336d934558eb9f5fd8a0
was measured in3e20ea. The earlier failed repair run44b4a0 was subsequently
diagnosed with raw database failure locations: daeab9 showed audit23505 because
the fixture reused its previous update's correlation ID. A distinct ID fixed
that fixture defect; the first corrected regressione2a119 passed9.406s. Test
diagnostics retain database error locations without logging request arguments.

The UI now handles a known400 cost_budget_required even when cached state has
a cost amount, shows fixed save/revalidate guidance, refuses repeated activation,
and clears this refusal after successful saving. REDad05b1 preceded the change.
Fresh targeted drawer/receipt checksccd8e8 pass89 tests, typecheck and full build.
Independent source review found no Critical/Important issue. Direct SQL replay
and delete-audit coverage were added in response to review; observed concurrent
activation/update and side-effect counts on rejected calls remain extra coverage
to complete. Full release and real pricing authority remain open. No production
promotion, external provider call, commit or push occurred in this slice.
The current candidate also passes grouped cost/activation, migration roundtrip/
fences and unrelated-consumer checks0230cb (73.868s). That command's migrations
package filter matched no tests; the database migration cases ran in apiserver.
The separately unfiltered migrations suite250e4a passes0.513s. Final ledger
validator487abf confirms728 rows (534/133/61/0); diff whitespace checks pass.

### Existing-definition editor and actionable refusal

Drawer editing now preserves an explicit amount or deliberately removes it on
blank input; every save sends enabled:false and the existing receipt callback
returns activation to draft. Labels explain nano OpenRouter credits and unchanged
existing-run limits. Missing saved cost blocks supervised/autonomous activation,
and an unsaved different cost blocks activation until saved. RED8ea507/0aa2f9
preceded these changes; positive activation fixtures now carry explicit budgets.
Tests cover draft/validated/supervised editing, removal and saved-versus-displayed
authority using API boundary fixtures, not real enabled-definition SQL updates.

The exact known PostgreSQL22023/message becomes ErrRepositoryCostBudgetRequired,
still errors.Is(ErrRepositoryOperation). Repository propagation preserves it;
public output is fixed400 cost_budget_required, nonretryable, with no provider
details. Other22023 errors remain generic. RED513ea1 preceded mapping; actual
11-case activation/write-read/public-error run d92a59 passes53.753s and affected
unit group81ed9d passes2.016s. No SQL fingerprint change in this slice.

Independent review found leading-zero input remained dirty after successful
integer normalization. Three-case regression241899 reproduced it; updated receipt
application now normalizes editor state from returned cost. Final UI/build checks
are pending. Live billing, full authentication, SQL enabled-definition editing,
stale-client error rendering and release verification are not claimed.
Final corrected group62d74d passes100 UI/decoder tests, typecheck and all five
UI build stages. No remaining failure in this bounded group; broader gates stay
open and the ledger's availability counts are unchanged.

### SQL cost persistence and activation guard

Actual workflow handler create/update now has migrated53, registered API login
and real repository evidence: request cost survives response, scoped definition
storage and activation-state readback (bf0e41). The fixture injects authenticated
request context; it does not prove the full mounted authentication stack.

RED7de03a reproduced missing-cost supervised activation with a working configured
control. The unpublished53 starts fragment now inserts a guard after existing
definition row lock/CAS and replay handling, before kill-switch/definition writes.
Only JSON numeric integers1..10^12 allow supervised/autonomous activation. Missing
or malformed authority raises22023. Legacy draft validation remains available.
The predecessor snapshot/restore already covers the replaced function; historical
migrations and function ACL/signature are unchanged. The measured fixed candidate
fingerprint is4ddc0bce4e1dee80258a994ce5347c52ab3dc69da59c00be3ec0c629657bc036
(b3969b), not runtime acceptance of a mutable live fingerprint.

Group84570e passes65.330s across11 cost cases plus real write/read, roundtrip/
retention fences and unrelated-consumer compatibility. Migrations53d515 passes.
Independent bounded review found no blocking issue. Added autonomous, exact replay
and full refusal-side-effect snapshots are pending their final verification.
Generic operation rejection still needs explicit user-facing cost-configuration
mapping/UI gating. No live price policy, deployment or availability promotion.
Final expanded run90fc35 passes55.265s: all11 cost cases now exercise both
execution activation targets, rejected calls return the expected operation error
and leave complete definition/revision/receipt/audit/control snapshots unchanged.
Successful validation/execution activation replays return the same response with
only replayed changed and no persistent changes. Invalid autonomous cases model
legacy enabled definitions using owner fixture setup, not real tenant writes.
No production source changed after the successful grouped migration checks.

### Browser cost input and typed receipts

OpenAPI definition/input schemas now carry optional integer cost1..10^12 with
explicit nano OpenRouter credit units. Generated clients were regenerated with
the repository script. Definition and mutation-receipt decoders share validation,
preserve legacy absence and reject present null/undefined/invalid amounts; receipt
intent must match returned cost. REDafb956 reproduced the missing-field rejection.
The create form leaves cost blank until the user supplies it, rejects malformed
text and sends the exact integer at the API boundary. UI regression setup was
corrected to open the builder; removed-field mutation2f6141 then failed as intended.

Grouped UI/decoder run772995 passes96 tests; OpenAPI39 tests and generated check
passb19216; typecheck/lint passe528fd; five-stage UI build passes9fd806. Tests use
an API boundary fixture, not a real SQL-backed browser session or live billing.
Existing-definition cost editing/display, missing-cost activation refusal,
SQL write integration, alternate HTTP/domain and pricing/release gates remain
open. This slice does not promote either original task or authorize paid calls.
Independent source review found no blocking issue in this slice. Suggested tests
now verify blank submit omits cost, minimum input enables save, exponent/space
input is rejected and lost-response retry keeps cost123456789 plus its original
idempotency key despite an attempted edit. Final grouped96 tests and typecheck
pass673e81; production source is unchanged since successful UI build9fd806.

### Explicit cost allowance at production API boundaries

The workflow request parser now preserves an explicitly supplied integer
`max_ai_cost_nano_credits` between1 and10^12 inclusive for creates and updates.
Twenty cases cover both operations, boundary values, absence, zero, negative,
overflow, fraction, string and null. Legacy draft absence stays absent.
Activation-state readback now accepts both the legacy exact field set and its
cost-bearing extension, with eight additional valid/invalid cost cases.
RED373ed4 and053d8a preceded the corresponding repairs. Group832b28 passes the
affected workflow/repository race suite in2.997s after rerunning with owned
PostgreSQL fixture permissions (initial45a89b was an initdb sandbox failure).

These changes do not yet complete SQL-backed creation/update, missing-cost
activation refusal, alternate domain HTTP serialization, OpenAPI/generated
contracts, browser decoders/forms or cost-policy pricing. Continue that combined
configuration batch before release; no new paid dispatch is enabled by these
parser changes. M7A49/95 and availability counts are unchanged.

Independent bounded review found no blocking issue. Review additions cover
boolean/object/array/exponent input and read-side overflow/unknown fields:
28 request cases plus10 cost-bearing read cases. Final grouped API race
runf1b7e6 passes3.114s. Existing request duplicate-key/trailing-JSON acceptance
is not repaired here. Replacement update omission leaves cost absent, so the
client transition must deliberately preserve or remove that field; omission is
not an instruction to restore an older allowance. No batch completion claimed.

### Settled accounting survives process loss before acceptance

The original M7A-49/M7A-95 requirements enforce cumulative budgets and prohibit
new action after a stop; the reliability section prohibits replay of unknown
destructive actions. They do not impose one paid planning call per run. After
confirmed settlement, a new attempt may replan only with a fresh reservation
against the remaining original allowance and deadline. Independent requirement
review confirmed this interpretation. Unknown/same-attempt redispatch remains
blocked; settlement itself is never a start permit.

The new child wrapper exits86 only after actual repository settlement returns a
known, nonstopped acknowledgement and an actual observed provider call. The
parent confirms120 prompt+40 completion=160 tokens and100 nano-credits persisted,
then reclaims in another process/worker after expiring the owned lease. With
2000-token/400-nano-credit run allowance, restart creates a distinct attempt2
reservation; cumulative usage is320/200, both rows are settled, the original row
is byte-identical, and exactly one plan/step/approval/receipt exists without an
effect. With1000/200 allowance, the next1000-token maximum cannot fit the
remaining840 tokens: no new provider call/reservation/artifact occurs and SQL
commits budget_tokens_exceeded. "Insufficient" does not mean zero remains.

All four crash/restart cases compare the full original budget snapshot excluding
only stop_reason, so original start/deadline/limits/definition/unit/concurrency
cannot reset. Initial settled-only run1cfa73 passed22.548s. Final grouped race
run5b4f27 passes70.761s across unknown-before-dispatch, unknown-after-response,
settled-with-allowance, settled-with-insufficient-allowance and six prior composed
worker modes. Independent source review found no Critical/Important issue;
the recommended immutable start/deadline and stopped-limit assertions are included.
Existing production code satisfied these new acceptance oracles.

This is owned worker-process loss with a surviving database and controlled
provider billing. It does not prove host/database power-loss durability or live
pricing, and it does not claim that the first lost candidate is recovered without
another accounted call. No automatic spending/key creation, class promotion,
commit or push occurred.

### Abrupt worker loss with unknown usage retained

Two parent-owned process fixtures now exercise the actual reservation/worker
boundary. The child exits86 without deferred cleanup either immediately before
provider dispatch or after the controlled provider response is captured but
before settlement. The exit marker reports the transport's actual observed
count (zero/one); after-response capture also checks160 tokens/100 nano-credits.
The parent joins the exited process, verifies a committed attempt1 reservation
with1000/200 caps and all usage/settlement fields NULL, then expires only that
owned run's lease and starts a new worker process with a different identity/token.

The restart must claim attempt2 and retain valid original token/cost/deadline
authority plus a supported fixture request bound. Missing authority cannot
explain its zero dispatch. It returns with zero provider calls/artifact IDs;
owner readback requires byte-identical reservation contents, exactly one
reservation, sticky budget_usage_unknown, cleared lease fields and no plans,
steps, approvals, receipts or effects. No reservation credit is refunded.

Initial two-case run462c63 passed21.885s. Independent review recommended actual
transport counters and explicit zero-effects readback; both are included in
final grouped race run2cbe01, passing57.480s across the two crash/restart cases
and all six existing composed worker modes. Independent review found no
Critical/Important issue. Existing production behavior satisfied these new
oracles, so this checkpoint changes tests/evidence, not production code.

Scope: abrupt worker-process exit against a surviving PostgreSQL server, with
owner-controlled lease expiry and controlled transport. This is not host power
loss, database restart/failover, daemon supervision, live billing or proof for
crash after settled accounting but before candidate acceptance at that checkpoint.
The later settled-recovery section above adds bounded accounted-retry evidence;
host/database power-loss gates remain open. No task-class promotion, commit or push.

### Committed completion and in-flight heartbeat reconciliation

Actual worker RED63548b (13.204s) showed a committed approval reported as worker
failure when an in-flight heartbeat observed the cleared lease. The instrument
waits for the real repository Accept result, then permits the real SQL heartbeat
and delays result delivery until heartbeat cancellation. It changes no SQL,
payload or error. Focused RED9383d8 reproduced both Accept and Execute cases.

The processor now reconciles validated success or durable stop with only a nil
heartbeat result or lease conflict. Unconfirmed operations, operation conflicts
and unrelated heartbeat outages still fail. Initial grouped run4f5692 passed all
six composed API scenarios but failed existing malformed alternate-authority
worker cases; that run is not a combined green checkpoint. Normal Accept/Execute
results are now validated at the worker boundary too. Separate RED845586 proved
the same missing guard for a foreign-run Fail result before its repair.

Final grouped race run3b2453/b733e5 passes worker3.120s/API39.205s:15 completion
matrix cases across Accept/Execute/Fail, existing stop/processor tests and all
six real migrated worker scenarios. Committed approval→heartbeat conflict now
returns success with exactly one controlled provider call, three artifact IDs,
one observed SQL lease conflict, exact settled accounting and approval readback.
All child operations and owned servers are joined. Independent review found no
Critical/Important issue in the repaired boundary. Per-field malformed normal
result expansions remain useful coverage; current foreign-run and malformed
state/artifact guards are exercised. No live billing, restart/crash, daemon or
release completion claim; no commit, push or task-class promotion.

### Heartbeat-advanced result versions

Actual worker RED68cdf5 (13.297s) reproduced failed processing after two real
registered heartbeats advanced the run version while the worker retained its
original claim. Unit REDf0d928 independently rejected the later version for
all seven result shapes: normal/stop Accept, normal Fail, normal/stop Prepare,
and normal/stop Execute; two worker flat-stop heartbeat cases also failed.
The repair accepts result versions greater than the original and at most
1,000,000, retaining all existing run/state/artifact/submission checks. SQL
still authenticates the current scoped lease; the result does not renew it.

Final focused group d3afcb passes API1.839s/worker2.922s, with42 version cases
(including exact upper bound), existing worker repository tests, processor
tests and flat-stop races. Five actual migrated worker modes a48cc1 pass34.100s.
The new positive mode asserts two persisted heartbeat increments, then uses
the original claim through reservation, controlled provider response, exact
accounting and approval. This is sequential prior-heartbeat evidence, not a
complete concurrent successful completion/heartbeat race test. Independent
source review found no Critical/Important issue. No migration identity change,
task-class promotion, commit, push or live billing request.

Pricing research, September16: OpenRouter's official
[provider-routing documentation](https://openrouter.ai/docs/guides/routing/provider-selection)
describes max_price as filtering provider per-token rates and, for applicable
providers, per-request pricing. This is not sufficient evidence of a total
charge ceiling. Before enabling paid planning, the supported policy must bind
the actual prompt/completion token upper bounds, model, billing unit and all
applicable charges to the outbound request. Do not turn a configured number or
provider-rate filter alone into a claimed total-cost permit.

### Worker reservation and settlement integration

RED9ac4e7 showed Plan/artifact creation without reservation or settlement.
The processor now calls durable reserve before Plan, binds a stable run/attempt
reservation ID, checks the permit, bounds provider work by its expiry, and settles
before artifact generation/Accept/Fail. Captured responses use a separate
five-second accounting context after parent cancellation. Unknown usage is never
zero; a durable stop returns the existing typed stop for heartbeat reconciliation.
Cancellation/expiry prevents subsequent outcome authorization.

Four actual migrated worker modes pass f6f0dc (27.335s). Missing cost now produces
zero provider calls and zero artifact IDs, with the parent's committed
needs_human/unknown/cleared-lease oracle reached. Expired and heartbeat-stop
controls also pass. A permitted controlled transport makes one call, durably
settles120 prompt+40 completion=160 total tokens and100 nano-credits against
1000/200 reserved caps, then creates approval artifacts. Its pricing wrapper is
test-only; heartbeat interval20 seconds makes this accounting evidence, not
successful planning concurrent with heartbeat.

Production PlannerBudget currently has no verified request-cost upper bound,
so production paid dispatch stays blocked. The controlled positive path does
not close supported pricing/configuration, live billing, restart/crash, full
lifecycle or release gates. This temporary fail-closed state is not completion
of the original usable paid-planning requirement. The later heartbeat-result
checkpoint above repairs flat-result version assumptions. Full worker race suite25fd39 passes25.346s;
expanded eight-case ordering/cancellation group59f575 passes2.111s. Its deadline
assertion proves a five-second timeout is installed, not a stalled driver's
termination time. Independent review found no Critical/Important issue in this
bounded integration. No task-class promotion, commit, push or live request.

### Strict Go adapters and heartbeat compatibility

The registered repository now exposes reserve/settle methods with mandatory
compiled-release verification, exact scope/attempt/request binding and strict
duplicate/null/extra response rejection. Unknown usage sends SQL NULL, while
known zero sends explicit integer zero. A settlement response acknowledges
accounting only. Database conflicts retain the repository conflict classification.

RED955ac1 showed missing APIs, then executable stub REDbd7f38 showed missing
behavior. Heartbeat-stop regression012eb9 demonstrated the old exact version+1
assumption. Tagged stops now require a later bounded version in the same scoped
attempt; permits accept the original or later bounded version. SQL still owns
the current lease/deadline. Go checks future expiry within300 seconds of its
clock without a positive skew allowance. This is a sanity check, not independent
deadline evidence. Original flat Accept/Prepare/Execute/Fail result paths still
have exact-version assumptions and remain a separate integration gap.

Independent review found lost conflict classification (RED8dd967), now repaired
using the existing provider-error convention. Real PostgreSQL testing exposed
an offset-format mismatch (REDb0323d): SQL returns timestamptz in its connection
timezone. Go now normalizes the same instant to UTC. Final grouped race run
4f8bcc passes15.165s, including three migrated PostgreSQL adapter scenarios:
heartbeat→permit→known zero, heartbeat→permit→unknown settlement, and
heartbeat→missing-cost durable stop. Owner readback checks exact zero accounting,
cleared lease fields, and durable unknown stop. Independent source review found
no remaining Critical/Important issue in this adapter slice.

No UI changes, commit, push, live billing proof, or task-class promotions in
that checkpoint. Processor integration was absent then; see the latest section.
Additional adapter negatives for absent verifiers and malformed request usage
remain useful coverage; current response negatives and release drift are covered.

### Exact settlement draft and reviewed replay repair

RED6ac05e (5.267s) reached a real registered-worker reservation and proved the
settlement function was absent. The new SQL operation locks org→run→budget→
reservation and authenticates the saved issuing worker/attempt/lease digest.
It accepts accounting after lease expiry/reclaim or an existing stop, without
renewing execution authority. Complete response-bound usage is written once;
invalid/missing usage retains the full reservation and stops further starts.
Known overage is retained; exact zero is distinct from unknown. Conflicting
output digest or usage raises23505 without mutation. Only the registered
planner worker role has EXECUTE authority.

Initial17-case settlement plus release/migration group311066 passed86.623s;
expanded malformed/ACL/concurrent eight-case group538c57 passed36.767s. These
passes did not cover an Important issue found by independent review: after
settling attempt1 and legitimately reserving attempt2, retrying attempt1's
settlement treated the pending second reservation as unknown and stopped it.
The new ordered actual-settle/reclaim/reserve/replay test reproduced this as
RED14a159 (5.186s). Exact replay now only reports existing stop state; it does
not recalculate accounting or mutate run/budget/usage. First settlement still
counts actual usage plus outstanding reserved maxima using numeric sums.
Independent review approved this repair. Final combined group396234 passes
224.061s:20 reservation cases,27 settlement cases, storage constraints, nine
cutover fences, empty migration roundtrip and registered-consumer drift checks.
This includes the previously failing ordered replay, actual two-reservation
exact-total accounting, concurrent same/conflicting settlement, issuer/ACL
denial and fixture-terminal preservation. All owned processes and concurrent
operations joined. Unfiltered migrations b932f5 passes1.831s.

The revised unpublished candidate fingerprint measured by5f5cdb is
12269f3a0d88456978a49ca0bf76e521638295f81c721ac34dab0509c9c3fec6.
The prior32e33c... candidate contained the replay defect and is not current.
Terminal-state setup and request caps are local owner fixtures. Real provider
cost-policy verification, strict Go methods, processor dispatch/settlement,
response loss/process death and live production acceptance remain open. The
composed missing-cost provider regression is still open because the actual
worker does not invoke the new operations. No availability promotion or push.

### Atomic planner reservation primitive, not dispatch integration

RED060d91 (5.266s) proved the registered53 worker had no reserve operation.
`zasp_security_agent_budget_reserve_planner` now uses org→run→budget locks,
recomputes current canonical context, and checks scope/attempt/input plus live
worker/lease. It validates declared request maxima/model/policy/unit, counts
prior usage with numeric sums, and persists the exact request/issuer before
returning a scoped permit with expiry=min(lease,deadline). Missing authority,
exhaustion, any prior unknown usage, or reused attempt/reservation identity
commits a sticky stop with lease clearing; it never reissues a dispatch permit.

The declared request caps are trusted-worker inputs, not independently verified
provider prices. No production Go caller or transport guard is wired. Prior
usage/attempt rows in arithmetic tests are owner fixtures, not real settlement
or restart proof. The existing composed missing-cost provider RED remains open.

Owned-fixture fingerprint2e5b58 was frozen as
c7ee671aa9deecd7b70f0fa794983658a167bebd521752354e7ab0829bd1a34b.
The initial16-case+release group390e36 failed only wrong_scope: its invented
organization did not exist and hit FK23503. The input was corrected to the
actual foreign tenant from the two-tenant fixture, retaining expected40001.
Other15 cases and release/consumer/fence tests passed in that run; it was not
an all-green command (81.194s). Four-case observed-wait group76fa33 passes
21.145s, including exact owner-readback, two connections behind a held org lock,
one permit/one stop, and definition-lock fresh/deadline-crossing controls.
This race is duplicate delivery of the same worker/lease, not distinct active
lease owners. Full migrations72d861 passes1.745s.
Final corrected20-case reservation group48ce1b passes90.949s, including scope
and API-denial cases, exact caps/overage, unknown history and observed waits.
Every owned server and in-flight worker operation joined.

Independent review found no Critical/Important source or test issue. Remaining
coverage includes same-ID cross-attempt reuse, changed-parameter replay, explicit
lease expiration, malformed model/policy, and strict Go permit decoding. Next
implement exact settlement under the same lock order using persisted issuer
identity after lease loss, then verified-bound configuration and actual worker
dispatch. No push, production availability promotion or live billing claim.

### Provider reservation storage, not spending enforcement

RED2de97d reproduced absent reservation storage on the actual33→53 migration
chain (4.938s). The unpublished53 artifact now contains scoped run/attempt and
reservation-ID uniqueness, request digest/model/policy/unit/maxima plus issuing
worker/lease-digest binding. Private forced-RLS rows retain NULL unknown usage;
known zero requires a complete response-bound usage record. Actual overage is
storable, not discarded by a maximum constraint. Numeric token addition avoids
bigint overflow. Future helper functions must enforce immutable identity and
exact settlement; owner-fixture rewrites are not settlement proof.

All catalog fingerprint inventories, cutover locks and retained-history down
checks include the table. Owned-fixture fingerprint f003c3 was frozen as
f6351a15474b68b79ea379f0115c592fc90819f6ea83f9dcf02938eecc745e48;
this is an unpublished artifact identity, not an accepted live rebaseline.
Grouped387b89 passes19.363s:26 invalid-storage cases, independent duplicate
identities, cross-connection unknown retention, forced-RLS member visibility,
actual rollback refusal with retained rows, security drift denial, nine cutover
fences, empty roundtrip and registered-consumer readiness. Migration selection
in that command matched no package tests; separate unfiltered migrations
d8febe passes1.435s. All owned PostgreSQL servers joined.

Independent review found no Critical/Important storage blocker. Its requested
coverage was added; direct INSERT denial was further isolated from source-table
SELECT permissions. Budget/admission parents also block rollback, so this is
not isolated behavioral proof of the provider-specific retention branch.
The final literal-VALUES direct-write test passes in the current storage run
d9903e (6.370s); ledger check d051a7 retains728 rows and534/133/61/0 counts.
This storage checkpoint alone proves no reserve/settle operations, request-cost
policy verifier, processor permit, restart/replay enforcement or production
readiness. The subsequent reservation primitive is recorded above. Keep M7A-49/95
component-only and the missing-cost worker regression below open.

### Historical RED: provider starts without cost authority

The new missing_cost_authority composed mode verifies a fresh claimed run on
registered53 with NULL immutable max_cost_nano_credits and no existing stop.
Without injecting deadline expiry, it invokes the actual processor and a
controlled provider transport. RED1ff0e1 fails at one provider call/three
artifact IDs where zero are required (14.151s, owned child/server joined).
No live provider or paid request occurred. The parent's expected durable
needs_human/budget_usage_unknown/cleared-lease/no-artifact oracle is not reached
after the child's fatal assertion, so those durable outcomes are not yet proof.

At that checkpoint this acceptance was intentionally failing; prior consolidatedb5fc59 is a
historical baseline, not a current all-green claim. No production repair has
been applied then for the missing reservation/settlement boundary. The plan
records the table/fingerprint/rollback, atomic permit, exact settlement and
processor integration sequence. Keep the original accounting and restart
requirements; do not replace them with a process-local counter or disable all
planning to make the negative pass.
Independent RED-stage review found no Critical/Important test defect and
confirmed the missing-authority isolation. This approves the counterexample,
not a repair or release. It also requires outstanding-plus-settled accounting,
non-reusable dispatch permits and settlement that cannot renew execution.

### Exact provider usage capture (Batch2, not enforcement)

The actual planner now returns optional reported usage independently of
candidate acceptance. RED1bbc8e showed22 accepted/rejected candidate cases
discarding valid usage. `security_agent_budget.go` now validates exact-key
accounting objects, rejects duplicate outer/usage fields, binds returned model,
checks nonnegative int64 token counts and consistent sums, and converts cost
to integer nano-credits using rational arithmetic with upward rounding.
Unsigned JSON cost numbers are bounded to128characters and exponent±1000 before
big-number parsing; int64 overflow is unknown. Known zero has a nonnil usage
record; missing/malformed/oversized/non200/model-mismatched usage stays nil.

Official [OpenRouter usage documentation](https://openrouter.ai/docs/cookbook/administration/usage-accounting)
identifies usage.cost as account credits and distinguishes upstream inference
cost. The parser does not substitute upstream cost or claim it bounds BYOK
charges. No new provider parameter, retry, request or spending authority added.

Expanded real-planner controlled-transport group3108f4 passes (2.285s), including
accepted/rejected candidates, sub-nano rounding, exponent notation, values beyond
float precision, int64 ceiling/overflow, null/missing/duplicate fields, model
binding, inconsistent/fractional tokens and numeric resource boundaries.
Independent source review found no Critical/Important issues; requested minor
coverage improvements and exact-success assertions were added and reviewed.
This is response capture only. The worker does not yet reserve or settle this
usage durably; unknown usage does not yet cause a worker budget stop. The
original tasks remain component-only. The consolidated50477 run started before
this parser change and is separate baseline evidence, not its verification.
Current-source SecurityAgent worker race suite741a4c also passes2.380s after a
sandbox build-cache access denial39dc12; the authorized retry ran the tests.

### Consolidated migration/worker baseline

Race runb5fc59 exits0 for selected `SecurityAgent` tests across apiserver
(432.502s), agentsec-worker (2.568s) and migrations (2.895s). It closes the
previous combined35ca12 fixture-readiness failures after the registered53
fixture conversions. This command is the plan's selected security-agent group,
not all tests in those modules. Parent-owned child tests cover their scenarios
through the API package; standalone child harness tests require parent-owned
DSNs and intentionally skip without them. No live provider/gateway/deployed
production proof, complete milestone or publication follows from this result.
The usage-parser edit occurred after this run's initial compilation; its
current-source worker verification is recorded separately above.

### Action lifecycle matrix on registered v53

The33-case action lifecycle fixture now runs actual migrations34..53 before
registering its action principal and constructing fresh restricted planner and
action repositories. Both Ready checks must pass; no post-construction fragment
injection remains. Legacy cases still select their old store leaf explicitly
while retaining real role checks and decoding. Version REDb1c7f9 failed20
selected suffix-matching cases at33 (48.015s); this was a broader selection
than the intended two cases, not20 distinct production defects.

Full matrixeb32fa passed33cases in179.899s, all owned servers joined: current
and legacy fresh/expired starts, busy effect/deployment/credential locks,
target/bundle waits crossing deadlines, pending/reclaimed stops, partial-device
source cleanup, exact replay and actual session-isolation payloads. Independent
source review found no findings or weakened assertions. All setup and durable
oracles remain; it proves these fresh post-migration lifecycles, not backfill
of populated production effects, credential rotation, daemon/gateway delivery
or the complete combined suite. The broader35ca12 run remains historical RED.

### Composed workers on registered v53

Both composed worker parents now use the real34..53 migration helper; child
processes require version53, construct fresh restricted repositories and verify
compiled readiness. They no longer inject SQL fragments after construction.
Version regressions26fa39 failed both expired cases at33 before conversion.
Six-mode race groupdbc63d passed in53.002s with every child/server joined.
Provider expired/heartbeat modes make zero controlled transport calls and no
artifacts; fresh makes one call and three IDs. The heartbeat case observes one
actual conflict after committed stop. Action expired/heartbeat modes preserve
generation2 and make no Read/Finish calls; heartbeat sees one successful call.
Fresh action stores source and enqueues2→3, then correctly fails Finish without
a deployment daemon. Parent durable state/effect/reservation oracles are
unchanged. Independent source review found no findings or weakened assertions.
This is migrated processor.process evidence, not daemon/RunOnce, live provider
billing, fresh-auth approval API or delivered gateway policy proof.

Expanded the real v52 predecessor upgrade/drift fixture to include registered
restricted planner/action logins. It checks warmed `Ready` and fresh repository
construction alongside API and ingest. RED4ad6ce (7.935s) accepted changed SQL
checksum+matching metadata and coherent replacement of both SQL roots in all
four worker checks. The API/ingest controls continued to reject those changes.

Both worker repository Ready methods now invoke the existing application pin
hook before historical readiness. Every constructor fallback calls Ready, so
failed compiled-pin verification cannot fall back to older accepted profiles.
Production worker pool adapters use the concrete PostgresJSONDatabase that
exposes the hook. The release grants only the read-only client-readiness entry
point to planner/action roles; no new table or mutation authority is granted.
The ACL change intentionally invalidated the former fingerprint (104117).
The frozen unpublished fingerprint is now
`2e687065ef94bf66c0459230d0b0eff9068ff9ed96944a3512384ed67b052be8`.

Grouped race23ce11 passed in14.965s: all six consumer checks across baseline,
upgrade, helper drift, metadata rebaseline, restoration, checksum replacement,
SQL-pin replacement and coherent two-root replacement; actual runner roundtrip,
eight busy-table fences and retained-authority/RLS refusal also pass. All owned
PostgreSQL processes joined. Independent source review found no
Critical/Important issues. Direct operations do not automatically recheck;
alternate wrappers can omit the optional hook. This does not prove old-binary
behavior, full populated lifecycle, provider accounting or production rollout.
The broad combined SecurityAgent run started before this edit and is baseline
evidence only, not verification of the new worker-hook delta. It finished
35ca12 with14 failed budget cases (apiserver329.059s): five cross-organization,
one snapshot/legacy-claim, two organization-admission, two deadline and four
prepare/dispatch cases reject fresh repository construction. Diagnostics show
release=false, principal=true and fingerprint mismatch. Their shared fixture
installed budget fragments over version33 without the registered release.
Worker and migration selected packages passed (2.651s and2.356s). This is a
failed combined run, not evidence of a passing full suite. The next scoped
repair migrates that shared fixture through actual versions34..53, preserving
all behavioral assertions and compiled readiness checks.

That scoped repair now passes all14 cases (b5beb0, 63.379s). Fresh registered
workers schedule/claim/prepare/dispatch under the actual v53 migration, testing
cross-organization nonblocking progress, immutable snapshots/legacy routes,
shared-organization versus independent-organization capacity and fresh/expired
claim, prepare and dispatch. Independent fixture review found no findings and
confirmed the actual CLI migration order, unchanged behavioral assertions and
retained fixture data. All owned servers joined. Explicit staged-fragment and
backfill fixtures remain separate; this is not a full populated production
upgrade, provider accounting or gateway-effect delivery proof. The earlier
combined run remains failed historical evidence; no full rerun is claimed.

Current-source full migration/runtime-event race suites372f0b pass (2.063s and
5.315s). Node22 `npm run build` passesb5aaeb and emits standalone UI output;
that proves a build, not browser behavior or a live API path. No push occurred.

## September 16 executable CLI checkpoint

Explicit `up-to-53` and `down-to-52` now invoke the budget runner. Forward53
performs principal registration and compiled-checksum/fingerprint readiness.
Default `up` stays49; historical commands cannot downgrade53 implicitly.

The expanded owned-PostgreSQL binary test failed first (c5bafa, 9.880s) at the
missing up-to-53 path. After implementation, group342486 passed in30.615s:
missing-principal preflight leaves52 untouched; actual upgrade reaches53;
compiled readiness holds; retry preserves identity; historical commands refuse;
empty rollback restores the exact52 versions/metadata/function/ACL/binding
snapshot; rollback retry is unchanged. The existing audit52 cases also pass.
This fixture uses a migrator owner, not a restricted migration login. Its
wrong-future-release probe inserts a wrong53 identity, not a real54 release.

Broader command group40a791 exposed three stale unsupported-command assertions
(52/53), now updated to54. That run also hit sandbox initdb denial. Authorized
owned-PG rerun72cd4f passed all six selected command tests in5.527s, including
the existing sandbox release test. Independent source review found no
Critical/Important issues in the CLI slice or the three fixture corrections.
Runner retention refusal is separate evidence, not exercised through this CLI
fixture. No full migration-package suite, UI build, push or live release is
claimed by these runs. Remaining gates include populated lifecycle, provider
accounting, all runtime consumers, genuinely old binaries and production.

## September 16 registered migration checkpoint

Version53 now has complete up/down metadata and transactional Runner methods.
The checksum covers the assembled up template plus a NUL separator and down
SQL, before expanding v53 pins. The compiled semantic fingerprint is
`fbc384fcbb0a8e4cd4bbab1417def721aca2314d31ab03947177b1fbc39654df`.
Private predecessor copies preserve function definitions and the planner
receipt constraint for exact empty rollback. Retained admission, budget,
reservation or budget-stopped receipt authority refuses rollback.

Local race group4a07be passed in12.415s: actual runner up/down, eight busy-table
fences (four tables in each direction), exact v52 readiness after rollback,
retained-admission refusal, and updated API/ingest drift checks. Full migration
race suite8b968e passed in1.673s. All owned PostgreSQL processes joined.
Initial runner RED71b715 preceded implementation. Suite failureb419d6 exposed
the old future-version fixture using53; it now uses54 and includes valid53.
Review found that a caller-owned rollback check could miss forced-RLS rows.
RED61374d reproduced zero visible admissions and passage beyond the retention
barrier (then a schema permission failure, with no committed deletion).
The first down statement now calls an authority-owned, PUBLIC-revoked
SECURITY DEFINER assertion. The passing restricted-login test proves that
barrier, not an entire nonprivileged Runner execution.

At that checkpoint CLI integration, full ACL/lifecycle coverage, provider accounting, unchanged
old binaries, UI and production acceptance remain open. Counts are unchanged.
The historical checkpoints below describe earlier artifacts, not the current
registered candidate. This batch is still unpublished.

Historical checkpoint: claim/backfill previously passed fourteen local cases, but
the subsequent release integration remains RED and not approved. The context
deadline regression (e774cd/f6e4da) now has a staged SQL repair described below;
earlier grouped passes do not prove its nested replay changes. The current
fixture installs both drafts atomically; fresh worker construction rejects their
changed functions under the unchanged v33 release fingerprint. Neither draft is
registered or activated as a v53 release. Full M7A-49/M7A-95 enforcement and
production availability remain unproved. Do not describe the current combined
budget suite as passing or push this batch.

## September 16 release integration regression: unrelated consumers

### Draft versioned release envelope

#### Updated application pins

The candidate now has application-compiled pins in
`migrations/security_agent_budget_candidate.go`. Its checksum covers all three
embedded admission/start/release templates plus the substituted v52 predecessor
checksum, before expanding embedded pin literals. It is still not registered
migration metadata and does not yet cover an implemented down artifact.
Candidate fingerprint:
`7ba7ea039092cb279e409bbc4425836a413dcb824b3c693e99174addf694cef9`.

`PostgresJSONDatabase.VerifySecurityAgentBudgetRelease` probes installed budget
readiness without caching absence, then supplies compiled pins to a restricted
SQL client-readiness entry point. Updated API Ready and precise-ingest
ReadyPrecision invoke that adapter hook before inherited readiness. This closes
the excluded-literal plus metadata regression for these updated applications
warmed before cutover; it does not establish unchanged old-binary safety.

Scoped race218b53 passed (7.057s). Expanded regression also replaces a budget
helper, both SQL pins, and matching metadata coherently: the fixture verifies
the replacement is internally ready, but both updated consumers still reject
it using external Go pins. Grouped race93781e passed (exit0, 16.133s, all owned
PostgreSQL joined), including the existing v51→v52 compatibility controls:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^(TestSecurityAgentBudgetUpgradePreservesUnrelatedConsumers|TestAuditExportsUpgradeKeepsWarmed51Consumers)$' -count=1 -v
```

Full `go test -race ./runtimeevent -count=1` passed85439e (5.280s). Independent
source review found no new Critical/Important issues in these Ready callers.
Optional-interface wrappers/alternate adapters, all operation and worker paths,
fresh construction, genuinely old binaries, registered atomic up/down,
rollback, CLI and deployment remain gates. The raw inherited SQL-only path is
not an independent trust root. Do not publish or generalize this bounded fix.

#### Preserved SQL-only failure

The SQL-only gate was RED and unapproved. After the bounded
d9acc6 pass below, independent review identified that the two normalized SQL
pin literals are outside the body fingerprint. New regression85a498 (exit1,
6.183s, owned PostgreSQL joined) changes the compiled checksum guard literal
and coherently changes both v53 checksum rows. Both warmed consumers wrongly
accept it while original v52 pins remain unchanged. This is not a worker
privilege escalation; it is a missing drift-rejection boundary in this draft.
Upgrade test SHA256 at that RED checkpoint:
`bdfc444f746b2491f9fca07a451506bacef9ea13afc3f256cbf42a42ed0d6d17`.
Do not describe normalization as protecting the excluded root literals. The
application-pin repair above retains and extends this acceptance test; further
runtime/migration integration and old-binary fail-closed checks remain required.

`security_agent_budget_release.sql` now stages v53 predecessor identity,
compatibility ceilings, catalog fingerprint coverage for budget authority,
and a v52 readiness wrapper that retains historical v52 pins. Its inherited
fingerprint clone excludes only the new release's own metadata to avoid a
self-reference; the original v52 fingerprint function and identity stay intact.
This is not a registered migration or permission to install fragments directly.

Initial candidate compatibility passed72116d, but independent review found an
Important trust-root defect: inherited consumers could accept helper drift if
the v53 fingerprint metadata was replaced with the new live value. Regression
d71395 reproduced both API and ingest accepting that rebaseline. The initial
pass is not drift-resistance evidence.

The repaired draft binds expected checksum/fingerprint to compiled literals in
v53 readiness. The catalog identity normalizes only those two 64-hex guard
literals, preserving the surrounding body and catalog attributes in the hash.
Creation-order error144eb5 was corrected with deferred regprocedure lookup.
Pinned draft candidate is
`a4c3af2ce7552e4c0f0b5605a49ceb086d9188e666a130c28443e4306a55ed5c`.
Race rund9acc6 passed (exit0, 7.101s, owned PostgreSQL joined): warmed API and
ingest readiness, helper drift rejection, metadata-rebased drift rejection,
restored-helper readiness, and coherent checksum metadata/version drift
rejection. Release fragment SHA256:
`74639d6702edc80d0a108d18b42cc827e9ab4c12f18e29e5389da396bfa2f859`.

The test supplies draft metadata and hashes only the release envelope template.
Full migration metadata must bind admission/starts/up/down too. Atomic cutover,
predecessor restoration, rollback refusal, runner/Version/CLI integration,
fresh worker/API constructors, actual operations and mixed binaries remain
unimplemented or unverified. Do not promote task status or publish this draft.

The new `TestSecurityAgentBudgetUpgradePreservesUnrelatedConsumers` installs
the actual predecessor migration graph through v52, checks Runner.Version=52,
and constructs registered-role API and precise-runtime-ingest repositories.
Both constructors and baseline readiness pass before atomic budget fragment
installation. Their subsequent readiness checks fail (RED1e2066).

Diagnostic rerun563cf8 and final controlled runf0b128 (exit1, 5.518s) show the
v52 live fingerprint changed while the pinned fingerprint remained unchanged.
The inherited structural-security check remains true before and after. Explicit
context guards exclude fixture timeout; the owned PostgreSQL process joined.
Test SHA256:
`6ec9b34a99267139ef48b6dfa9e6cb9578ca76a0c44cc4a19b7302b59f6dff9f`.
Command from services/platform:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestSecurityAgentBudgetUpgradePreservesUnrelatedConsumers$' -count=1 -v
```

Independent RED-stage review found no Critical/Important fixture issues.
This proves the bare fragments are not compatible with warmed unrelated
consumer readiness on the v52 graph. It does not authorize relaxing fingerprint
checks or rewriting v52 identity. Implement registered v53 identity and a
versioned predecessor compatibility path retaining exact drift rejection,
then verify fresh constructors, actual operations, rollback and mixed binaries.
No v53 release was added or activated in this checkpoint. The test remains RED;
do not publish the budget batch. All original task classifications are unchanged.

## September 16 actual session-isolation budget coverage

Follow-up isolation cleanup/replay now covers both current and legacy stores.
Real fresh isolation storage precedes the owner-fixture sticky stop. Exact
apply replay retains its valid lease; after lease loss, actual cleanup claims
must retain action/session/run/step binding. Empty cleanup storage and another
lease-loss/replay preserve target coordinates, sticky stop, and expected
generation/bundle counts. The first reclaim retains one effect/reservation;
these counts are not independently rechecked after final replay.

Initial two-case race pass1cc59a (7.331s) was followed by mutationf21281:
removing stored-source eligibility from target enumeration failed both cleanup
claims. The exact restored fragment SHA256 remains
`05c0c2f7b29983ffd3f7f749ca5911fe96e57a973cdabb571af54a6194112226`;
test SHA256 is
`7f83cf2a573fdc603aebb0999f43ffb6dfb5736704bf71f24d1f41bd278932ac`.
Restored grouped race run3dcd56 passed six cases in 17.662s, exit0, all owned
PostgreSQL processes joined. Independent source review found no Critical or
Important issues. Exact command from services/platform:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/(.*cleanup_replay|stored_reclaim|partial_devices)$' -count=1 -v
```

This closes the tested stored-isolation cleanup/replay schedule only. Actual
gateway removal, credential/device lifecycle and full rollout remain open.
The test file now contains 33 cases; this run selected six.

Four new cases schedule actual runtime-decision triggers, prepare/dispatch
through the registered planner repository, and require a claimed
`isolate_session` action bound to the literal fixture session. Signed policies
use session-specific HTTP/tool blocking conditions. Current and legacy store
paths each have a fresh and pre-store-expired control. Initial race run96cf36
passed all four (13.058s).

Mutation6b311f bypassed enforcement only for isolate_session and failed both
expired cases: current storage returned success and enqueued generation2→3;
legacy storage returned success and wrote one bundle. The mutation was removed;
the starts fragment restored to SHA256
`05c0c2f7b29983ffd3f7f749ca5911fe96e57a973cdabb571af54a6194112226`.
Test file SHA256:
`9cf6ecd3e7f65609afd2a350fd34abe42bfe44259fbf191dd32f3e265b4f7a9c`.

Independent read-only review found no Critical/Important issues. Seeded gateway
events and approval do not prove runtime ingestion or fresh-auth approval APIs.
This is SQL planner/repository evidence, not AI-planner, isolation cleanup/replay,
isolation lock waits or gateway delivery proof. Restored-source race run383bed
terminated exit0 (841481, 78.980s), passing all 20 selected cases with owned
PostgreSQL processes joined. This includes the four isolation cases and current/
legacy fresh/expired policy and lock-wait controls. Exact command, run from
services/platform:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/(isolation_|legacy_session_isolation_|expired$|fresh$)' -count=1 -v
```

The unanchored subtest alternatives also select target/bundle wait cases; the
reported count includes them. The file now has 31 cases, not all rerun here.
M7A-49/M7A-95 remain component-only.

## September 16 legacy cleanup and replay checkpoint

Consolidated action-budget race verification subsequently passed all 27 cases
in 95.907s (bebba1, exit0), with every owned PostgreSQL process joined:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply$' -count=1 -v
```

Run from services/platform. This freezes one affected-suite checkpoint across
current/legacy starts, lock waits, reclaim, partial-device cleanup and exact
replay. It does not replace the composed-worker, release or live acceptance
gates, and no source changed between the scoped and consolidated runs.

Scoped race verification terminated exit0 (ecc049, 9.671s):
`TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/(legacy_.*cleanup_replay|stored_reclaim)$`.
All three cases passed and their owned PostgreSQL processes joined. Both
retained `_v27` leaves accept the exact stored apply envelope under its valid
lease after a fixture-seeded sticky stop, then claim/store cleanup and replay
that cleanup after another lease loss. Two bundles, exactly one empty cleanup
bundle, prove no duplicate bundle in this local schedule. The current v28
stored-reclaim case is the control. Both legacy routes use the temporary-policy
payload; this does not prove the isolate_session payload or gateway delivery.

Earlier mutation087e2c removed the planned-target replay exemption and failed
both legacy exact-apply assertions. The restored SQL verified here has SHA256
`05c0c2f7b29983ffd3f7f749ca5911fe96e57a973cdabb571af54a6194112226`;
the test file has SHA256
`b0065ee9e0da40cb183e25708d4df28167388d1128405124d2c3cc92be9690db`.
Independent review confirmed that this restored-source pass closes its prior
verification condition for these three tests, without release approval.
The prior lost process handle is not counted as a pass. This scoped rerun is
component evidence only; the full batch, release integration and production
availability remain open.

## September 16 staged action-source repair

The v28 policy-source apply boundary now checks the registered action principal,
exact active effect lease and durable budget reservation. Nonblocking run,
budget and effect locks precede target locking; deployment prerequisite locks
precede the final database-clock check. A stop preserves effect/reservation
history without storing a source or advancing deployment generation. Cleanup
and already-stored replay paths are not newly authorized by this evidence.

The repository decodes only an exact, scope/claim/target-bound 14-field stop
receipt. RED a68f17 failed the valid receipt; race run61f718 passed after the
decoder change. SQL-only run d73b1c already stopped writes but failed typed
error propagation; d77968 passed expired/fresh after the decoder repair.

Expanded PostgreSQL run98ad19 passed expired, fresh, busy-effect and
busy-deployment cases. Consolidated race command below terminated exit0 in
123.577s (session26076, terminal956d13), including exact retained effect and
reservation counts in all four cases:

```sh
PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^(TestProductionSecurityAgentBudget(StopsClaimedPolicyApply|StepReservation|LegacyWorkerDeadlineDuringLock|ProviderSuppressionThroughWorker)|TestSecurityAgentAction(RecognizesOnlyBoundBudgetStop|Repository.*))$' -count=1 -v
```

Run from services/platform. This covers 4 apply, 8 reservation, 15 lock/deadline,
3 composed-provider and 33 decoder cases plus existing action repository tests.
Owned PostgreSQL processes joined. Controlled provider transport and fixture
approval are not live service, gateway-delivery or billing proof.

Source SHA256 at that checkpoint:

- starts fragment: `92efbce4f5a16ef5360e470c5a1b18906ade67519f502df612ddd8bbc5aea6bc`
- action repository: `8e738dbf319b563b7833a39f15fa87def1568c4a934bfeb229a32d1cc404a67b`
- apply test: `5f233177389ce8ba527c9f2d9be7c66e5acc8e322a55dbe25471fbf9b0bf4fd6`
- decoder test: `110b9012682a823ad6d0d53eb9891955abb5bc984f2e5baef442e25206701433`

Independent review accepted the bounded guard/decoder and expanded contention
assertions without Critical/Important findings. Counts do not prove byte-for-byte
history preservation; the reviewer did not rerun the suite. Still open: action-worker
stop consumption, target-lock delayed expiry, replay/cleanup after stop, legacy
and other action routes, downstream application, partial effects, full budget
accounting, v53 release/readiness and UI/release checks. No availability promotion
or publication follows from this checkpoint.

## Action-worker typed-stop consumer checkpoint

RED37e059 demonstrated that the real action processor read back a target after
the repository returned a confirmed budget stop, then returned execution failure.
Both direct and wrapped sentinel cases failed; same-text error and cleanup
negative controls passed. The staged worker now exits the apply loop immediately
on the typed stop, before readback, subsequent targets, ID allocation or finish.
After joining its heartbeat, it consumes that stop only if heartbeat returned nil.
Unrelated heartbeat failures are not hidden.

The four-case test uses a repository-boundary double, not PostgreSQL. It covers
real processor signing/control flow, but does not prove SQL/worker composition,
partial-target cleanup or the racing heartbeat path. Those remain required.
Grouped `GOTOOLCHAIN=local GOPROXY=off /opt/homebrew/bin/go test -race
./agentsec-worker -run '^TestSecurityAgentActionProcessor' -count=1` from
services/platform passed exit0 in 2.214s (f6853f). Independent review found no
Critical/Important issues in the current repository path. Minor follow-up:
process consumes the sentinel without a separate source/phase marker; a future
Finish implementation emitting it could be normalized too. Current concrete
Finish does not emit it. Add a negative test before extending sentinel use.
This is not publication approval.

SHA256: action runtime
`ff4036b0b9a291b2a1062bc69673467e0979545628f8e44a5162ffeac1747d13`;
new action budget test
`20cb5b1d66a83d6b0a986e8773c7e9bf99028b05a9df9c4bc28d4939241e57d5`.

### Stop-origin and heartbeat follow-up

REDbf1ad3 reproduced the reviewer's stop-origin concern: public budget errors
from Finish returned nil for both apply and cleanup after two stored/read-back
targets. A private marker is now created only at apply Store and consumed by
exact identity after heartbeat joins. Finish errors remain failures.

Eight boundary-double cases now include coordinated heartbeat conflict and
unavailable errors. Store waits for the heartbeat callback, independent of work
context cancellation; both require failure without readback, further targets,
ID allocation or Finish. The bounded wait fallback also fails those assertions.
This proves error preservation at the consumer boundary, not the actual SQL
heartbeat behavior after a committed stop.

`GOTOOLCHAIN=local GOPROXY=off /opt/homebrew/bin/go test -race ./agentsec-worker
-run '^TestSecurityAgentActionProcessor' -count=5` passed exit0 in 2.332s
(021cef). Independent follow-up review found no Critical/Important/Minor issues
and confirmed the previous source-marker concern is addressed. No release claim.

Current SHA256: action runtime
`eb1cbb2647db43e960cb7e404986fdf5be9ed050b364612b2639f2fa39063c5e`;
action budget test
`615b0ecdf1625d63b2403a1c1b6143b1df955f469ea934039f005c1d451daaff`.

## Composed action-worker PostgreSQL checkpoint

New parent/child tests connect the actual action processor to a registered
restricted action repository and owned loopback PostgreSQL. Planner and action
repositories are constructed before installing the staged fragments; fresh
planner readiness must reject the changed release. Real schedule, prepare,
dispatch and action claim create the effect/reservation. Approval and gateway
enrollment remain owner fixtures, not API or device proofs.

Expired mode changes only the durable run budget after action claim. Actual
processor.process returns nil and allocates zero IDs. The parent independently
reads needs_human/budget_deadline_exceeded, zero stored targets/bundles/completion
audit events, and exactly one effect and reservation. Fresh mode stores one
target, retains running/no-stop and allocates two IDs for finish preparation.
With no deployment daemon, its worker failure remains expected; no delivered
generation or successful action completion is claimed. Neither case proves
RunOnce, a deterministic heartbeat overlap or partial-target cleanup.

Initial run d8bdba passed both child paths but failed the parent oracle because
the test referenced a nonexistent outcomes table. Correcting it to the actual
effect_verified/effect_cleaned audit rows produced pass450a4c (18.480s).
Temporary removal of worker stop consumption then failed expired mode exactly
at worker execution (34312c, 11.459s), proving the composed test detects that
regression. Runtime restored byte-for-byte to SHA256
`eb1cbb2647db43e960cb7e404986fdf5be9ed050b364612b2639f2fa39063c5e`.

After restoration, both cases passed again (9b3263, 17.612s, exit0):
`PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsThroughActionWorker$' -count=1 -v`
from services/platform. All owned processes joined.

Independent review found no Critical/Important issues. Two limits remain:
the parent does not independently compare deployment generation (the separate
direct-store fixture does), and allocated IDs establish finish preparation,
not an instrumented Finish call count. Owned workers and PostgreSQL processes
are joined before teardown. This is local component evidence, not publication.

Test SHA256:
- child: `6b8e29c19e215e392e1598bf31a88485058b2f89d06385fd200e19367fed61e5`
- parent: `fce50f9f1dae3334ad28bd44ac6b5156325c8fd474b6034e513d9a5e873fff1b`

### Composed post-commit heartbeat and stronger oracle

Expanded run d263ab passed all three cases under the race detector in 26.100s
(exit0). In heartbeat mode the instrument waits for actual Store to commit,
then allows the actual SQL heartbeat, then delivers the unchanged Store stop
to process. The heartbeat succeeds because the effect lease is preserved.
This is post-commit/pre-result-delivery synchronization, not an arbitrary
overlap or a planner-style revoked-run-lease conflict.

Observed expired: zero IDs/readbacks/finishes, generation2→2. Observed heartbeat:
one successful heartbeat, zero IDs/readbacks/finishes, generation2→2. Fresh:
two IDs, one readback, 501 actual Finish calls and generation2→3; no deployment
daemon still means expected worker failure. Retry count is an observation, not
a required exact constant. All child workers and owned PostgreSQL processes
joined. Parent durable-state assertions passed in all three cases.

Independent source review found no Critical/Important/Minor issues and accepted
the owner-read generation delta and forwarded Finish observations as addressing
the prior two oracle limitations. Runtime was unchanged. This does not verify
partial-target cleanup, every action route, deployment delivery or v53 rollout.

Command: `PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsThroughActionWorker$' -count=1 -v`
from services/platform. Current SHA256:
- child: `23f87944a64ad9e30146c440a8c265e5d6762b0cf9b1c5ee53c3c781fada7ae2`
- parent: `853abdf5c4ef20c8d5c00eab044e9bb92de7e4efae3c2d251e63ca3597bd1964`

### Target-lock deadline crossing

The apply fixture now has six cases, adding target_wait_expired and
target_wait_fresh. The owner holds the actual target row; a separate observer
requires the exact holder PID in the action connection's blockers while the
persisted deadline is still future. Expired mode releases only after the
database clock passes that deadline. Fresh mode releases after observed blocking.
Both require the existing durable-state, source, generation and history checks.
Cancellation, holder rollback and operation join precede connection teardown.

Six-case baseline a938b2 passed in 22.229s. A first mutation accidentally changed
the identical clock expression in the planner helper, not the action helper;
its pass e6b22d is not sensitivity evidence. After restoring the planner clock,
the correctly targeted action-gate transaction_timestamp mutation failed
3d0484: nil store error, running/no reason, one stored target, generation2→3
after observed deadline crossing. The current-clock fragment was restored to
exact SHA256 `92efbce4f5a16ef5360e470c5a1b18906ade67519f502df612ddd8bbc5aea6bc`.

Independent source review found no Critical/Important/Minor issues in the
observed-wait oracle or cleanup. This proves this source/enqueue boundary's
post-wait time check, not cleanup, gateway application or release activation.
Apply test SHA256:
`de8a4000384c45d2341c557a69a761b6cde3b3c6a7706d142fc3c3a4f79979b6`.

Restored six-case race run001dc2 passed exit0 in21.880s; all operations and owned
PostgreSQL processes joined. Command from services/platform:
`PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply$' -count=1 -v`.

### Stopped action reclaim regression, currently RED

New stopped_reclaim case first executes the real source guard, verifies the
committed needs_human/budget_deadline_exceeded stop, zero stored sources and
unchanged generation, with one effect/reservation. It then expires only the
effect lease as a worker-loss fixture and calls the registered action repository
with a new lease. Any returned apply claim violates the durable stop; cleanup
claims are not rejected by this oracle.

Run2064a3 failed as intended in3.318s: the stopped run returned an apply claim
with one target. Owned PostgreSQL joined. Existing source enforcement still
blocks that later write; this is evidence of incorrect reclamation/retry work,
not evidence that a policy was delivered after stop. No SQL fix is claimed.

The v24 claim resets expired leased effects to pending unless an apply target is
verified, and selects pending effects without consulting the sticky budget stop.
Repair must cover registered and legacy claim routes, preserve exact replay,
and retain cleanup for policy sources already stored or partly applied. Merely
filtering pending claims does not establish that existing controls are cleaned.
The seven-case apply test file now contains this unresolved RED; prior six-case
passes do not mean the expanded group passes. Independent RED-stage review
accepted the counterexample, not a fix. It confirmed that v28 deployment can
consume stored as well as verified sources, while old cleanup recognizes only
verified targets. Repair must cover both. Add post-reclaim sticky-state/history
assertions before accepting a repaired empty-claim result. Current test SHA256:
`123d17f68f273fe7432d26ff40722b03327653f93db45cfe2dc4fb05299d593b`.

Command: `PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/stopped_reclaim$' -count=1 -v`
from services/platform.

### Staged expired-lease reclaim repair

Expanded RED754620 reproduced both stopped/no-source reclaim and stored-source
reclaim as apply. The latter first stores a real source, then seeds a sticky
stop as fixture state before lease expiry; it is not proof of the full partial
multi-device stop path. Post-reclaim assertions now also preserve run stop/reason
and one effect/reservation.

The staged fragment transforms both temporary-policy and session-policy claim
functions. Expired leased effects with a sticky budget stop enter cleanup.
Stored sources join verified sources in cleanup discovery only for stopped runs,
including the no-active-target check and per-device enumeration. A private,
authority-owned read-only stop lookup adds no run/budget row locks while claim
owns effects. Fresh stored-source retry behavior is unchanged by the predicate.
The two reclaim cases passed bd60e1 (6.858s).

The stored-source test now also signs and writes the returned cleanup source
through the registered repository, requires empty cleanup policies and one
additional deployment generation. This is cleanup source/enqueue acceptance,
not gateway delivery or completed compensation. Remaining lifecycle work
includes already-pending stopped effects, repeated lease loss, credential/device
changes, partial multi-device sets, direct legacy-path execution and deployment.
The full budget release remains incomplete and unpublished.

Current SHA256: starts fragment
`9a53dd723cea2f6ee29839d33ba09a4b971107d8c3c82833b4e4ac647dbcc169`;
apply test `b33e9807549ef5a61e9ec052b77051b28239c6251ea4655d60c9f5fa529d3d30`.

Combined race run83796a passed8 apply/reclaim cases plus3 composed worker cases
in47.586s, exit0; all owned PostgreSQL processes joined. Command from
services/platform: `PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudget(StopsClaimedPolicyApply|StopsThroughActionWorker)$' -count=1 -v`.
Independent review found no Critical/Important issues in this bounded repair.
The read-only helper observes a snapshot, not serialized stop-vs-claim authority;
the final apply guard remains necessary. No lifecycle or release completion.

### Pending effects and repeated cleanup replay

RED1c3030 reproduced apply claims from already-pending stopped effects, both
without a source and with a real stored source. Pending/unleased state is an
owner fixture; sticky state and source setup follow the earlier real stop/store
paths. The repeated cleanup replay control passed in that RED group.

The staged transform now includes pending effects with a sticky stop in the
same cleanup-routing sweep as expired leases. The original action predicate
still encloses both alternatives; unstopped pending work is not converted.
No new lock is added. Existing bulk effect UPDATE can wait on effect rows,
so this is not a proof of nonblocking claim behavior.

Both stored-source scenarios now expire the cleanup lease a second time,
require a cleanup claim with identical target coordinates, and replay the exact
signed stored cleanup envelope. The assertions require unchanged deployment
generation, needs_human and the same stop reason after replay. This covers
same-credential stored cleanup retry, not full process restart or credential
rotation. Independent review found no new Critical/Important issues.

Current SHA256: starts fragment
`b4d5bd89d494a06ca2fe21a9dd510a3997177bea3e0896458c6ae8462fef0d3a`;
apply test `dce0b258c42f7095cf791ab169cfc5e347d25697995be4996b3a5aa4dc6a5efb`.

Grouped race run eb0fce passed10 apply/reclaim cases plus3 composed-worker
cases in52.489s, exit0. All owned PostgreSQL processes joined. Command from
services/platform: `PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudget(StopsClaimedPolicyApply|StopsThroughActionWorker)$' -count=1 -v`.

### Two-device partial-source cleanup

The partial_devices case creates two active gateway credentials before actual
action claim and requires two targets. It stores the first source under a fresh
budget, expires only budget timestamps, then calls Store on the second target.
That call must commit the typed budget stop. Unlike the single-source reclaim
fixture, this mode does not seed needs_human or stop_reason directly.

Actual reclaim must return one cleanup target, belonging to the first device.
Signed empty cleanup storage and a second lease-loss replay must leave the
aggregate generation at initial+2. The second device remains an apply target
in planned state with NULL desired_generation and no cleanup target. Sticky
run/reason and effect/reservation counts are checked after initial reclaim;
sticky state/reason and generation are checked again after replay. Counts are
not independently rechecked at every stage.

Baseline208b02 passed7.358s. Temporarily removing stored-source eligibility
only from cleanup device enumeration failedf2137f at the actual claim's repository
validation (repository unavailable,3.369s). The fragment was restored exactly
to SHA256 `b4d5bd89d494a06ca2fe21a9dd510a3997177bea3e0896458c6ae8462fef0d3a`.
Independent review found no Critical/Important issues. This proves this two-device
partial stored/enqueued-source path, not delivered gateway compensation or all
multi-device/credential-change schedules. Test SHA256:
`91a9c6459da3e93169acb4df84787a1af0d8b3d2ac649a0ddd19ec029e41b930`.

After restoration, grouped partial_devices/stored_reclaim/pending_stored race
run592a63 passed9.446s exit0; all owned PostgreSQL processes joined. Command
from services/platform: `PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/(partial_devices|stored_reclaim|pending_stored)$' -count=1 -v`.

### Retained legacy bundle-store leaves

Actual registered-role calls to both `_v27` store leaves bypassed the staged
source guard. REDfddfeb showed expired temporary and session-store entry points
each returning nil, run still running, one stored target and one gateway bundle;
fresh controls passed. This is local database bundle persistence, not gateway
delivery. Tests select the old SQL leaf in the already-constructed real repository
while retaining its role, envelope validation and strict result decoder.

Both retained leaves now acquire the scoped action gate's nonblocking authority
before their original locks, then check budget after target prerequisites and
before planned-target bundle insertion. Cleanup and already-stored replay paths
retain their existing logic. Four initial cases passed158cb4 (12.008s); the
expanded19case apply matrix passed095e47 (66.883s), including observed
expired/fresh target waits through both legacy leaves.

Independent review identified an Important remaining FK prerequisite wait:
the credential check was a plain SELECT, so the bundle INSERT could wait for
credential key protection after the final deadline check. Two held-credential
regressions failed2f3f30 by hitting the3s call deadline. The legacy guard now
takes scoped `FOR KEY SHARE NOWAIT` on the exact credential before final budget
enforcement, mapping missing/busy authority to retry conflict. This closes that
blocking prerequisite through refusal, not a deadline-crossing commit test.

The unique-index conflict wait at bundle INSERT is still an open final-mutation
boundary. Session-store tests carry create_temporary_policy, not isolate_session
payloads; direct legacy cleanup and full deployment/release remain unverified.
Do not claim the whole legacy boundary complete.

Current SHA256: starts fragment
`a8cef7a953161db15e03532c19ee38ead6cea4ffa03c0d6af9c770573b21fe0c`;
apply test `24ee661d4c96819a45b76643ec2a16171649f65986b8cd7ab835a2dbca86324e`.

Final ten-case legacy race groupa42dbd passed37.808s exit0, all owned PostgreSQL
joined. Command from services/platform:
`PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/legacy_' -count=1 -v`.
Independent follow-up review accepted the FK protection with no new findings.
Key protection is not serialization of non-key revocation/expiry updates; the
unique-index wait remains unresolved and prevents whole-boundary approval.

### Legacy bundle uniqueness wait rollback

Four new cases hold an identical signed bundle in an uncommitted owner
transaction. The registered legacy action call must be observed waiting on
that exact holder before the database deadline passes. Releasing the holder
uses rollback, so any surviving bundle belongs to the action call, not the
fixture. Expired cases wait for database time; fresh controls release early.
RED87653a showed both expired legacy leaves storing one bundle and one target
after the deadline, with nil error and no stop. Both fresh controls passed.

The original legacy mutation block is now a PL/pgSQL subtransaction. Existing
org/run/budget/effect/target/credential protection and the precheck stay outside.
After tentative bundle/target writes, a current-clock guard checks planned apply
work again. A dedicated ZB001 exception rolls back only that mutation block,
including its provisional stop update; its handler reruns the gate outside the
rolled-back block, persists the stop and returns the bound receipt. A null
handler result fails with40001. Other exceptions retain their original behavior.
The original target record is not reassigned, so cleanup and already-stored
replay remain outside the new-start postcheck.

All four wait cases passed90c09c (22.257s, exit0); all owned PostgreSQL processes
joined. Independent actual-source review found no new Critical/Important issues.
This verifies the tested uniqueness wait plus rollback/persisted-stop behavior,
not live gateway delivery, all isolation payloads or release readiness. If an
effect lease also expires during a longer wait, conflict still rolls back writes;
that distinct longer-wait outcome is not proved by these cases.

Current SHA256: starts fragment
`05c0c2f7b29983ffd3f7f749ca5911fe96e57a973cdabb571af54a6194112226`;
apply test `ffb7c393469265fe4c7c52868802bdb4c5d78a6f995ddc061faa74b5304c1494`.

Consolidated14case legacy race run6f4aad passed58.471s exit0, with all owned
PostgreSQL processes joined. Command from services/platform:
`PATH=/opt/homebrew/bin:/opt/homebrew/opt/postgresql@18/bin:$PATH GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply/legacy_' -count=1 -v`.
This supersedes the earlier unique-index wait gap for the tested rollback
schedule; remaining isolation payload, legacy replay/cleanup and rollout
acceptance still prevent whole-product completion.

## Start-boundary work, currently RED

`TestProductionSecurityAgentBudgetStopsNewPreparationAndDispatch` adds four
real-repository cases: fresh/expired preparation and fresh/expired dispatch.
The dispatch fixture first creates a real plan, then the fixture owner sets
approved/authorized/queued state before the registered worker reclaims it.
Only the persisted budget clock is expired after claim; lease and approval
remain valid. This isolates dispatch authority, not fresh-auth API acceptance.

Before the guard draft, run 68e356 failed both negatives: expired preparation
created one plan/step/approval; expired dispatch created one pending effect.
Both fresh controls passed. No external policy application was performed.

`security_agent_budget_starts.sql` is a draft guarding eighteen explicit old
prepare/execute/dispatch entry points with private scoped lease/budget helpers.
Prepare/Execute repository decoding accepts only a needs_human result bound to
the claimed run and next version with empty artifact fields. This is not a
complete verified repair yet. Independent review found an Important gap: after the entry
guard, an old leaf can block on a definition/plan/step/approval row and then
write after the deadline. The repair must recheck at the mutation boundary,
with a deterministic lock-delayed regression. Existing planner acceptance
also locks run before organization and can invert the new lock order; at this
checkpoint it labeled stopped preparation as accepted. The repairs below fix
the tested mutation waits, stop propagation and the demonstrated planner lock
inversion. Context budget permits and provider accounting still require work
before activation.

Combined race run eee70a/f9c9d0 exited 1 in 46.839s: four legacy-backfill leaf
cases passed, fourteen other cases failed at fresh repository construction.
All eighteen owned PostgreSQL servers joined. Diagnostic run d60709 confirmed
the reason without weakening the gate: release=false, principal=true, live
fingerprint_matches=false, diagnostic queries successful. The current v33
readiness correctly refuses changed release functions; v53 readiness/registration
must be implemented, not replaced with a test bypass or updated old constant.
Existing worker-repository unit tests separately passed (4510dd); that does not
prove the new SQL integration or complete stop protocol.

### Prerequisite-lock deadline repair

The deterministic cached-worker upgrade regression reproduced the entry-only
gap (416fe9, exit 1): preparation created one plan and dispatch created one
effect after an observed prerequisite lock wait crossed the database deadline.
Both owned PostgreSQL servers joined. This worker was initialized before the
staged upgrade; the test separately confirms new worker construction still
rejects the changed predecessor fingerprint. It does not bypass readiness.

The draft now retains entry guards for organization-first locking and adds a
second check before the unique plan/effect INSERT in eleven explicit leaves.
Unexpected/missing mutation anchors reject installation. The original two
regressions passed under `-race` (8501a2, 17.450s); both owned servers joined.
Independent follow-up review approved this prerequisite-lock repair only, with
no new Critical/Important findings. Expanded grouped verification (3f2c80,
exit 0, 22.727s) passed all four expired/fresh preparation/dispatch cases under
`-race`. All four owned servers joined; no skips or race failures. Fresh cases
also observe the real prerequisite lock, then release it before expiration;
they create the expected plan or pending effect. This proves those SQL paths
still proceed, not actual external policy application or fresh-runtime readiness.

### Finding-target lock repair

The next grouped regression reproduced the remaining reachable finding defect
(84b98c): the v33 repository routes to v21 execution, which waited on its finding
and then returned remediated with one effect after the deadline. Its fresh
control passed. The attempted direct base-route cases instead failed before
the lock; diagnostic 2070d3 identified SQLSTATE42501. Migration v21 revoked that
worker grant, so the test now checks preserved denial and unchanged state,
without adding privileges to force the old body to execute.

The staged fragment now locks the fully scoped open finding at the trigger's
exact version before the final budget check and effect insertion. The existing
UPDATE retains its status/version predicate and runs while that target lock is
held. Both base/v21 definitions receive the defensive insertion; only reachable
v21 execution is exercised. Independent review approved this bounded repair
with no Critical/Important findings. Grouped run c085ff exited 0 in 36.459s:
all seven cases passed under `-race`, without skips or race failures; all seven
owned PostgreSQL servers joined. These include expired/fresh prepare, dispatch
and finding execution, plus the revoked base-route denial. Expired finding
execution leaves status=open/version=1 and creates no effect; its fresh control
reaches under_review/version=2 with one effect and a remediated run.

### Planner stop propagation

The expired/fresh planner acceptance regression loads real context before
holding a definition lock, then observes acceptance waiting past the database
deadline. RED a83ab7 persisted needs_human with no plan/effect but returned a
repository error: acceptance still labeled the stopped preparation accepted.
The fresh control passed. Both owned PostgreSQL servers joined.

Both staged v32/v33 acceptance functions now classify needs_human as
budget_stopped in their response and durable receipt. The receipt CHECK admits
that outcome; repeated delivery retains input/output digest, model and policy
matching and returns the original stopped response after its lease was cleared.
The Go adapter requires the claimed run, next version, needs_human, matching
summary, empty artifact strings and a boolean replay flag. Normal accepted-plan
validation remains in place. Focused race run 8060f2 passed both expired/fresh
cases plus repeat acceptance, in 11.833s; both servers joined.

Independent review approved this propagation slice and flagged null-to-zero
JSON decoding. Four negative tests reproduced that gap (3926f1). Non-null
pointer decoding now enforces literal artifact strings and replay boolean;
worker-repository race tests passed (cad7c1, 1.843s), including wrong run/version,
nonempty artifacts, mismatched outcome/state/summary and null fields. Independent
follow-up review approved the null fix. Consolidated database race run
96d199/6a9f52 exited 0 in 43.283s: all nine cases passed, with no skips/race
failures and all nine owned PostgreSQL servers joined. This remains local
staged-fragment evidence, not release activation or production proof.

### Planner organization/run lock ordering

The new planner_order regression holds admission's organization advisory lock,
observes the actual worker blocked on it, and probes the run row from a separate
transaction with FOR UPDATE NOWAIT. RED 0b2051 returned SQLSTATE55P03: acceptance
had already locked the run before requesting the organization guard. Cleanup
released the owned blocker and joined the worker and disposable server.

Both context versions now validate the registered principal and scoped inputs,
then acquire the organization advisory/row locks before their existing run-row
lock. Accept/fail delegate to context before their locking mutations. Focused
group 56473f passed expired/fresh acceptance with replay and the ordering probe
under `-race` in 13.778s; all three owned servers joined, no skips/race failures.
The lock-order behavioral proof covers the v33 repository route. The predecessor
context body receives the same source patch but is not separately exercised by
this case. Independent review approved the bounded ordering repair with no
Critical/Important findings. No context-budget permit is claimed.

### Pre-provider context boundary, RED history and staged repair

The context expired/fresh cases use the registered repository after a real
definition-row wait observed through the blocker PID and database deadline.
Run e774cd exited 1 in 10.823s: expired context returned usable actions/targets
and an input digest, leaving the run planning with no sticky stop. The fresh
control passed. Both owned PostgreSQL servers joined. The expired assertion
requires an unusable context plus a persisted needs_human/deadline stop and no
plan/effect. This is a confirmed authority gap, not an actual model-call trace.

The production processor calls Planner.Plan immediately after successful
LoadSecurityAgentPlannerContext. Repair requires a typed/tagged durable stop
result at context's return boundary, checked after prerequisite waits. Both
versions of accept and fail call context internally and must propagate that
result without interpreting missing context fields or raising an exception
that rolls back the stop. Go decoding must bind stop to the claimed run/version
and reject malformed/usable-context mixtures; the worker must treat it as a
normal stop and not dispatch the provider. Add worker no-call and nested
accept/fail tests alongside the authority negatives before claiming this fixed.
Deadline context rejection alone will not provide token/cost reservation or
close the elapsed gap between a successful context read and a provider start.
Independent review confirmed this RED reproducer and required stronger GREEN
assertions: replace its generic-error acceptance with the dedicated budget-stop
signal, assert completely unusable authority, and require a valid digest plus
allowed action/target in the fresh control. Do not claim complete propagation
from the current generic-error predicate. Stop results must carry exact scope,
run/attempt/version and reason; accept/fail receipts and replay must preserve
the stopped classification. Controlled-transport zero-call proof is separate.

The consumer-side contract is now staged: `budget_stop` is the sole envelope
field and contains exact organization/workspace/environment/run, attempt,
next version, needs_human state and a known budget reason. Only a valid bound
result yields ErrSecurityAgentBudgetStopped with an entirely zero context.
Malformed, foreign, extra-context and unknown-reason results stay unavailable.
The processor consumes the dedicated stop before Planner.Plan and does not
prepare, execute or report planner failure for it.

After correcting the new test claim to UTC, decoder RED c72930 rejected the
valid stop as unavailable; worker RED 4bad29 treated it as execution failure.
The implemented consumer group passed under `-race` (df0370, apiserver 2.066s,
worker 2.798s), including the literal tagged-result negative matrix and worker
dispatch suppression. These are adapter/processor tests using boundary doubles,
not composed transport or live-provider proof. Independent review approved the
consumer slice with no Critical/Important findings. It identified a remaining
composed check: a heartbeat racing the lease-clearing stop must not turn a
validated terminal outcome into errWorkerExecution. The stub test's long
heartbeat interval does not cover that race.

The actual PostgreSQL test now requires the dedicated stop signal and entirely
zero context, while fresh context must have a valid digest and exact permitted
action/target. Revalidation f6e4da remains RED (10.674s): expired context still
escapes, fresh passes, both servers join. SQL must now produce and propagate
the tagged stop through both context versions and nested accept/fail paths.
Do not describe consumer tests alone as completion of the context-boundary repair.

### Database context stop and nested caller propagation

Nested failure reporting was separately RED (13e152, 10.696s): expired work
became failed with no budget stop; fresh failure reporting passed. The SQL
fragment now checks budget after context prerequisites and returns a private,
scope-bound tagged stop through normal return. Accept branches before reading
the missing context/digest or preparing a plan, then stores its existing flat
budget_stopped receipt. Fail stores the tagged budget_stopped receipt and
returns before its failed-run mutation. Same-method retries return the stored
stop after lease clearing. The shared Go validator recognizes tagged stops in
Load and Fail. A worker failure-stop regression was RED (c3fb24); the processor
now consumes the Fail sentinel as normal completion. Consumer race group
1078bf passed (apiserver 2.644s, worker 2.177s).

Initial seven-case SQL group 125026 passed in 33.990s with all servers joined.
Independent review then identified Important cross-method replay ambiguity:
flat accept-stop and tagged fail-stop receipts shared outcome=budget_stopped.
Both new opposite-method cases reproduced unavailable errors (5e5c0d). The
repair binds stopped replay to its originating response shape and changes
accept's nullable output-digest comparison to IS DISTINCT FROM. An additional
failure-with-nonnull-output case isolates shape enforcement from NULL mismatch.
Independent follow-up review approved this bounded fix, not full release.

The first eight-case verification e07273 exposed a test-boundary mistake:
three assertions expected raw SQLSTATE23505 although PostgresJSONDatabase maps
conflicts to ErrRepositoryConflict. Five other cases passed, all eight servers
joined. Tests now assert that public repository contract. Corrected grouped run
383196 exited 0 in 41.322s: all eight cases passed under `-race`, no skips/race
failures, and all eight owned servers joined. Composed provider-call suppression,
heartbeat/stop concurrency, direct predecessor coverage and v53 release remain
open. This is not a token/cost spending permit or live provider proof.

### Worker heartbeat/typed-stop reconciliation

A channel-coordinated boundary test now forces context loading to be active
before heartbeat failure cancels its context, then returns the authoritative
operation outcome. After correcting its heartbeat interval to the supported
10ms minimum, RED d4640d reproduced a false worker failure for validated stop
plus lease conflict; unverified-operation/conflict and stop/unrelated-outage
controls passed.

The worker preserves the dedicated Load/Fail stop sentinel through processClaim
and reconciles it only after joining the heartbeat goroutine. A validated stop
with no heartbeat error or repository conflict completes normally; an unverified
operation or unrelated heartbeat outage remains an execution error. Grouped
worker/repository race tests passed (e97cf7, worker 2.191s, API 1.800s), with
independent review approval and no Critical/Important findings. The test also
asserts no planner, artifact-ID, prepare, execute or fail dispatch for the
context-stop case. No arbitrary sleep determines overlap.

This verifies processor decision logic with boundary doubles. PostgreSQL
commit-versus-cancellation timing and controlled-transport zero-call proof
are outside that matrix; the later composed checkpoint below covers one
deliberately scheduled real-database overlap. ErrRepositoryConflict also covers serialization and
deadlock errors; it is suppressed only with independently validated durable
stop authority, not assumed to prove lease loss by itself.

### Flat Execute/Accept terminal results

September16 consolidated PostgreSQL rerun: the complete
TestProductionSecurityAgentBudgetLegacyWorkerDeadlineDuringLock group passed
all 15 cases (4467b5; terminal 98c74e exit 0, package 76.223s). Prepare,
dispatch, finding-target, planner acceptance, organization-first lock ordering,
context and planner failure/replay checks ran together with their fresh controls
and legacy permission denial. All 15 owned PostgreSQL servers joined normally;
no skips or race failures were reported. This exercises cached v33 workers
against staged fragments and deliberately rejects fresh predecessor readiness.
It does not close v53 migration/readiness, actual provider or production gates.

RED 8952ed reproduced false worker errors for both flat stopped results when
heartbeat conflict canceled the operation context. Ten rejection controls
passed. The worker now promotes only error-free needs_human results bound to
the claimed run and next version, with every phase-specific artifact empty,
to the existing typed-stop reconciliation path. Errors, foreign runs, wrong
versions, nonterminal states and artifact-bearing responses are not promoted.

Independent review approved the bounded mapping without Critical/Important
findings and requested per-artifact negatives. Those were added: the flat
matrix now has 17 cases across Accept and Execute. Expanded worker/API race
group 09f26b passed (worker 2.521s, API 2.804s), including the existing typed
heartbeat matrix, processor/repository tests and strict bound-stop decoder.
Follow-up independent review confirmed all per-artifact negatives and bounded
evidence wording, with no new findings.
This is channel-coordinated boundary-double evidence, not PostgreSQL commit
timing, provider transport suppression or release readiness. Work continued in
the persistent worktree documented in [recovery evidence](2026-09-16-worktree-recovery.md).

External effect application, context budget permits and release
registration remain incomplete. The full boundary and combined suite remain
unapproved; this does not prove every possible wait or full deadline enforcement.

### Composed database/worker/provider checkpoint, September16

The new parent/child tests use an owned PostgreSQL fixture, actual registered
worker repository and pool, actual processor.process and actual planner with a
controlled outbound transport. The child initializes the repository before
installing the staged fragments, then explicitly verifies fresh predecessor
readiness fails. Claims use real SQL. The fixture owner expires only the
claimed budget before context loading; no repository outcomes are fabricated.

Three cases pass: expired makes zero provider calls and zero artifact IDs;
fresh makes one provider call and three IDs; heartbeat makes zero calls/IDs
and observes one actual repository lease conflict. The heartbeat instrument
delays delivery of the committed context-stop result until an actual heartbeat
against the cleared lease cancels the worker context. It changes scheduling,
not SQL/results. After the child joins, the parent independently checks sticky
needs_human, lease clearing and zero plans/steps/approvals/effects/receipts for
stops; the fresh control has waiting_approval, one plan/step/approval/receipt
and zero effects.

Initial grouped race pass d677c6 completed in20.830s. A deliberate mutation
disabling worker stop reconciliation failed the heartbeat case (68472b), with
worker execution unavailable and an uncanceled parent context. The mutation
was restored byte-for-byte (runtime SHA below), and the complete three-case
rerun passed fb2edd, exit0,15.693s. All children and all three PostgreSQL servers
joined normally with no skips or race failures. Independent source review
approved with no Critical/Important findings.

This closes the specific controlled-provider no-call and post-commit heartbeat
scenario. It does not exercise full RunOnce orchestration, arbitrary
mid-request expiry, every commit/cancellation ordering, live provider billing,
v53 readiness or production deployment. The fresh10ms-heartbeat control may
also expose a separate normal-success/lease-clear race; no such failure was
observed in these two runs. Direct v32 coverage, action application, reservation
and usage accounting, migration/readiness/rollback and release remain open.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetProviderSuppressionThroughWorker$' -count=1 -v
```

### Durable step reservation checkpoint, September16

RED00dbb2 reproduced an actual effect authorization with no durable step
reservation. The staged fragments now create an authority-owned, forced-RLS
reservation table keyed by organization/workspace/environment/run/step, with
foreign keys to both budget and step. The reservation binds action and input
digest and is never refunded merely because delivery is retried or an effect's
outcome is unknown. The cutover also locks the predecessor steps table.

The private reserve_step helper uses existing org/run/budget locks, validates
the authorized step, rechecks the deadline after lock acquisition and returns
the matching prior reservation without another count. A changed action/input
conflicts. A different step at the frozen limit commits budget_steps_exceeded
and needs_human through the normal stop path, without creating an effect.
Reservation and effect writes share the same transaction. The helper is wired
before effect INSERT in all five leaf bodies: base/v21 finding execution,
temporary-policy, connector-revocation and session-isolation dispatch. External
action-worker application remains a separate unfinished boundary.

Initial four-case actual-repository race group fa60be passed in11.528s for
exact limit, same reservation reuse, one-step overage and input mismatch.
The owner fixture supplies approval and prior usage, so this is not a full
multi-step planner/approval/restart proof. Independent source review approved
with no Critical/Important findings. Expanded coverage adds action mismatch,
unchanged reservation time, lease clearing and direct worker table/helper ACL
denials. The tightened helper-denial test passes75bc7e (4.512s), using valid
scoped arguments so malformed-input denial cannot mask an EXECUTE grant.
Expanded affected group c464ac passed all23 cases under the race detector in
101.585s:15 deadline-lock cases,3 composed provider/heartbeat cases and5 step
reservation cases. All23 owned PostgreSQL servers and the3 worker children
joined normally, with no skips or races. The batch binary preceded the final
helper-ACL assertion tightening;75bc7e separately verifies that exact-limit case
on the final test source. No production source changed between those runs.
Follow-up independent review confirmed the added ACL, action-conflict,
reservation-preservation and lease-state assertions, with no new findings.
The subsequent eight-case reservation group passed9e8d87 (22.290s), adding
observed duplicate-delivery contention and finding exact-limit/over-limit
behavior. Two independent registered worker connections submit the same valid
claim; an owner transaction holds the organization advisory lock until
pg_blocking_pids reports BOTH worker waits. Releasing the lock yields one
successful dispatch and one lease conflict, with one effect and one reservation.
Both operations are joined before connections close, including failure cleanup.
This is duplicate delivery of one step, not two distinct-step reservations.

The finding positive control changes open/version1 to under_review/version2;
the exhausted-budget case leaves open/version1 and creates no effect. Both use
the actual repository execution route. An initial finding fixture mistake
selected updated_by from definitions (66ef04); it failed before reaching product
behavior, was corrected to the existing scoped kill-switch row, and all eight
cases reran. All eight owned PostgreSQL servers joined with no skips or races.
No production SQL changed during this coverage expansion.
Independent review found no issues in the contention/cleanup, finding assertions
or bounded evidence. It approved this test checkpoint, not release readiness.

Distinct-step contention, explicit exhaustion on connector-revocation and
session-isolation routes, full retry/restart, external apply, token/cost
accounting and v53 release readiness remain open.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudget(StepReservation|LegacyWorkerDeadlineDuringLock|ProviderSuppressionThroughWorker)$' -count=1 -v
```

### Claimed action can still enqueue after expiry: RED checkpoint

The next regression uses actual registered planner and action repositories,
initialized before staged-fragment installation. It prepares a temporary-policy
run, supplies fixture approval, dispatches and claims the effect, then expires
only the persisted run budget while the effect lease remains valid. A signed
policy envelope is submitted through StoreTemporaryPolicyTarget.

Corrected two-case race run bf71d8 exits1 (6.373s): the expired case returns nil,
leaves the run running with no stop reason, stores one policy-source target and
advances deployment desired_generation from2 to3. The fresh control passes.
Both owned PostgreSQL servers joined normally. This is a real local source/
enqueue authorization counterexample, not a gateway application or live incident.
The first run94c4f4 also had an incorrect fresh expectation of an immediate
gateway bundle; v28 stores the source and queues deployment instead. The oracle
now checks stored targets and generation change, with zero bundles in both cases.

Independent RED-stage review found no Important test-validity findings. Source
review requires a distinct action-principal/leased-effect guard; the planner
guard requires a planning lease and cannot be reused unchanged. Current source
storage locks target then effect, claim locks effect then target, and cleanup
can hold effect while updating run. A blocking new run→effect order would create
a cycle. Normalize participating paths or use nonblocking effect acquisition
with retry conflict and no mutation. Keep cleanup exempt and recheck database
time after all blocking prerequisites, including deployment work/sequence locks,
before any new policy-source/enqueue mutation. Existing reservations/effects
must not be deleted or falsely treated as safely cleaned by a stop.

No production implementation changed in this probe. The apply guard, typed
action-stop decoding, action worker handling, delayed-lock tests, partial-effect
cleanup and full release verification are still unfinished.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudgetStopsClaimedPolicyApply$' -count=1 -v
```

Current draft identities:

```text
62b0daa8558fa14f51eb9eaa9b93926e789d9a1fa9ba620d710c45a0f6a9d4f9  security_agent_budget_admission.sql
a7b39513b2c486ce2335540d4bda6c8e8f5af041b983042baaeb14a8bcdb8a43  security_agent_budget_starts.sql
30803780ca995e02bd9dc702467734cf8ca80866183e5ffe1ac86f905c583626  security_agent_budget_steps_postgres_test.go
63f8f40580321943ad56baf7728189cf27e7dcad83f2e4f2cca7273b8edacca2  security_agent_budget_apply_postgres_test.go
04a603138688e0e3cd273953ae3b8d34209c64d4fe37a4ae334f2c062d99a51a  security_agent_budget_lock_postgres_test.go
7eb14ebc503b39de79cb14c0f34b866590bf478fec8e7168c1e3706c381ba136  security_agent_budget_start_postgres_test.go
c1a5b2fee873df07ae5999232cd839f3f547cd87243a9cc00c758ead512002d7  security_agent_worker_repository.go
593d4b578f9e4132e1e9a5bac4b88d079a045f81851ce0736b81173da182010d  security_agent_budget_stop_test.go
f5ad588bb1cfd7b7760d6993e1dc879e211042b3a2e81b1b59f7005a29aea8ff  security_agent_runtime.go
eb447e9bf931cceabdef68091f45ad4c9d839e4351b5616a433dbce7992f6e84  security_agent_budget_heartbeat_test.go
ac26aa92105c83a524920fb80bcda4c83152f65f83281b033744d647b451c35e  agentsec-worker/security_agent_budget_provider_postgres_test.go
88248570d7d0602424392186afa7da4c39282c3b33d6e8c61807cac38308b045  apiserver/security_agent_budget_provider_postgres_test.go
f445dc48b487522428a043068477178147eb371dc003a48dbbc71fa680fdaa5e  security_agent_runtime_test.go
3b073ede551ed8ae9c3bf945c46dfaeb32a3ba8f193d5565f7ddc5a8d82e8a4c  security_agent_worker_repository_test.go
```

## Legacy upgrade checkpoint

The pre-upgrade test starts a run through the original registered worker before
installing the fragment. Both known-limit and unavailable-limit cases failed
first (500654): no sticky stop was recorded for unaccounted prior usage.

The fragment now takes cutover table locks with NOWAIT in its transaction and
backfills authority through an owner-only, SECURITY DEFINER migration helper.
The helper uses forced RLS as the authority role, then is removed. Previously
started active runs receive a budget_usage_unknown stop and lose their old
worker lease. Recovered limits use the exact historical revision or matching
current revision; malformed/missing values stay NULL only on stopped rows.
The old creation time is retained as a conservative start, never reset. No
record of zero prior usage is invented.

Initial grouped verification passed twelve leaf cases (c9e891). Expanded run
7c8aa9/072ef2 passed all fourteen leaf cases under `-race`, five top-level tests,
in 36.032s with no skips or race failures; all fourteen owned PostgreSQL servers
joined. Four legacy cases cover known limits, historical limits after a current
revision change, unavailable old limits, and malformed/oversized numeric input.
They assert literal original limits or explicit NULLs, absent cost stays NULL,
and a database CHECK rejects clearing the stop on an incomplete snapshot
(SQLSTATE23514). Fixture-owned cleanup control bytes remain unchanged and a
forced legacy requeue cannot obtain another claim. This proves preservation of
that row, not cleanup execution or an actual policy effect.

Independent source and expanded-test reviews found no Critical or Important
issues in the staged backfill slice. Then-verified identities (f50f23), before
the combined-fixture guard integration:

```text
25b66c13c1db24e5182e6b38ffdc25f833bd2411d8e953a2c58a376d3078d24f  security_agent_budget_admission.sql
629cd6dc40e8fca57e761f2372be5afbd9d8b880f5fd30aee68e15e7e8498860  security_agent_budget_postgres_test.go
```

Still unproved: full v53 runner/up/down/readiness, a non-superuser migration
runner, explicit terminal/unstarted-queued upgrade cases, active effect cleanup,
and every deferred action/provider/release gate below. Old action routes are
not yet fenced by this fragment and can still act on pending effect work.
Therefore this fragment must not be activated as the complete budget release.

## Staged claim authority, local verification

`services/platform/migrations/sql/fragments/security_agent_budget_admission.sql`
adds forced-RLS authority-owned organization admission and scoped run-budget
tables. First admission snapshots definition limits and a database deadline;
reclaim cannot enlarge/reset them. Base/v22/v23 claim routes share the guard.
The function commits deadline stops before returning no work. Organization
admission uses the least incoming/active ceiling under a serialized guard.

Tests install this exact fragment after the existing v33 migrated fixture and
then invoke the registered worker repository. They do not claim that release
readiness or the v53 migration exists. The deadline fixture now moves the
persisted budget start/deadline, not unrelated legacy run timestamps.

The first draft passed deadline/admission cases (a68d9a) and snapshot/legacy/ACL
checks (80a320). Independent review found cross-tenant scheduling regressions.
Oldest-work and held-organization tests failed first (12a1e0); held-expired-run
and held-budget cases then reproduced blocking in bulk expiry updates (3a2c5a).
A held definition also blocked another tenant (6f5876). The repaired authority
orders organizations by oldest eligible work, tries organization admission
without waiting, and obtains run/budget/definition row locks nonblockingly.
Locked existing authority is distinguished from missing authority.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudget' -count=1 -v
```

Earlier claim-only grouped run dfecd2 exited 0 in 26.192s: four top-level tests, ten leaf
cases, no skips or race failures. All ten owned PostgreSQL servers joined.
Coverage includes both original failures and controls, five cross-organization
progress cases, direct worker access denied with SQLSTATE42501, unchanged
snapshots after increased definition limits/version and worker reclaim, and
sticky stops through each base/v22/v23 claim route after a fixture-owned requeue.
Independent follow-up review approved this staged slice with no remaining
Critical or Important findings. That review does not cover pending integration.

Earlier claim-only SHA-256 source identities (325f79), superseded above:

```text
c1bf7844a38c178d17acb4f79c2cdce4948945a277da5e23c44d85e5c779d35e  security_agent_budget_admission.sql
5342f4995fec7ccbee51cf57ed7a77870570ddf6530c0399f7334f94d4c83f54  security_agent_budget_postgres_test.go
```

Still required: actual v53 up/down/CLI registration, readiness and inherited
fingerprint compatibility, remaining legacy upgrade acceptance, action/prepare guards
and reservations, AI token/cost reservations and settlement, API/UI cost
configuration, cleanup/rollback and mixed-version acceptance, full release
gates and publication. The fragment is not imported by a production migration
yet; no default runtime behavior has been activated or pushed. Missing cost
limits remain absent in its snapshots, not authority for a paid call. The
full integration must gate paid calls before dispatch and preserve the
organization/run/budget lock discipline in every new accessor. No dedicated
terminal-budget-history test or live provider/deployment proof is claimed.

## Executed counterexample

`TestProductionSecurityAgentBudgetDeadlineStopsClaim` uses the registered
non-superuser/non-BYPASSRLS worker repository and real disposable PostgreSQL.
Its definition allows 300 seconds. The fresh-run control claims one planning
run. The negative case first claims the run, then the fixture owner ages its
creation/update timestamps by 301 seconds and expires its lease. Reclaim must
return no work and persist needs_human, without preparation/effects.

```sh
GOTOOLCHAIN=local GOPROXY=off go test ./apiserver -run '^TestProductionSecurityAgentBudgetDeadlineStopsClaim$' -count=1 -v
```

Run 958ffc exited 1: fresh control PASS; expired started run FAIL with claims=1,
state=planning, plans=0, steps=0, approvals=0, effects=0. Both owned PostgreSQL
servers joined normally. Earlier run f50439 reproduced missing queue-age
enforcement, but the strengthened probe removes ambiguity about a run that has
not started yet. This proves a claim/replanning boundary gap, not actual
postapproval execution or an external side effect. This test is intentionally
RED until durable enforcement exists. Do not push this batch as passing.

## Organization admission counterexample

`TestProductionSecurityAgentBudgetOrganizationAdmission` schedules two real
eligible runs, then releases two registered worker connections from one Go
barrier, each claiming at most one run. Two definitions in one organization
both have concurrency_limit=1. The expected result is one planning run and
one queued run. The independent-organization control expects two planning
runs, one in each organization. Both cases assert zero effects in PostgreSQL.
This exercises actual repository/SQL behavior with no mocked admission path.
The barrier issues concurrent calls; it does not prove a particular overlap
inside PostgreSQL or exhaust every locking interleaving.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver -run '^TestProductionSecurityAgentBudget(DeadlineStopsClaim|OrganizationAdmission)$' -count=1 -v
```

Combined run 07e111/ce619c/a45657 exited 1 after 11.528s. Same-organization
admission failed with claims=2, planning=2, queued=0, organizations=1, effects=0.
The different-organization control passed. The fresh deadline control passed;
the expired started-run case still failed with one planning claim. All four
owned PostgreSQL servers joined normally, and neither worker goroutine was
left running. No race-detector failure was reported. These are two unresolved
production-path budget defects reproduced locally, not proof of a live incident
or completed enforcement. No production implementation changed in this probe.

Independent `tenant_planner_review` approved this RED-stage checkpoint with no
Critical or Important findings. It confirmed real SQL execution, distinct
registered connections, durable-state assertions and joined operation cleanup.
That review is permission to continue the repair cycle, not merge approval.

## Source findings, independently reviewed

- Repository v33 claims through the v23 wrapper into v22 claim SQL, which
  requeues expired leases and claims queued rows without a run deadline check.
- `securityagent.BudgetManager` is process-local and referenced by component
  tests, not the production worker. Its exhausted branch does not store a
  terminal stop or the exceeded counters.
- The production planner ignores response token usage/cost. Its fixed
  per-request max_tokens is not the definition's cumulative AI budget.
- Trigger concurrency checks are scoped to definition/workspace/environment,
  not an organization-wide admission lock.
- Execution functions enforce leases, plan/approval expiration and kill
  switches, but not the full original step/time/AI-cost/token budget contract.

Independent `tenant_planner_review` supports the M7A-49 demotion and explicitly
limits the counterexample to claims. No downstream task is demoted solely for
depending on M7A-49. No live production incident is asserted.

OpenRouter documents token counts and account cost in the response's usage
object, with cost expressed as credits. The decoder currently drops those
fields. A returned usage record is accounting input, not pre-call spending
authorization. See [official usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting).
Do not assume a provider price preference alone is a durable per-run cost cap.

## Repair acceptance, no scope reduction

Persist immutable run budget/start/deadline and atomic organization admission.
Reserve step/token/cost authority before planning or dispatch; settle actual
usage exactly once by scoped reservation and response digest. Unknown outcomes
retain reservations and cannot blindly retry. Budget exhaustion persists a
sticky stop before any later start, including restart, approval delay and
concurrent workers. Keep cleanup/reconciliation available for existing controls.
Use exact monetary units with a declared provider unit; do not substitute token
counts for cost or default missing usage to zero.

Tests must independently breach each dimension, exercise exact boundaries,
replay and conflicting receipts, cross-tenant IDs, stale leases, two workers,
approved-but-expired execution, partial effects and cleanup after stop. Add
definition/API/UI cost configuration and budget-stop visibility; preserve
existing supervised safety floors. Forward migration, readiness, rollback,
mixed-version fail-closed behavior, real composed worker and UI acceptance,
independent review and verified publication are required before production
credit. The regression is the first failing acceptance, not completion of this
repair.

The ledger anti-overclaim regression failed first (3be419), then all 34 ledger
tests passed after classification/validator correction (d0584c). The isolated
dependency release candidate received the same metadata correction without the
runtime regression or unrelated WIP. Its matching v22 claim SQL was compared
byte-for-byte (001b0d); its own 29 ledger tests passed (e7a52b), then all 30
passed after adding its M7A-49 anti-overclaim regression (53b9e1). Separate source
notes preserve which worktree actually executed the counterexample.

Independent review approved the evidence correction without Critical or
Important findings. The historical Complete/source contract group also passed
(824c19, two files/three tests); it does not prove durable budget enforcement.

The full repair [design](2026-09-15-security-agent-budget-design.md) and
[implementation plan](2026-09-15-security-agent-budget-plan.md) preserve all
budget dimensions, cleanup, rollout and composed verification requirements.
They are implementation instructions, not evidence of completed enforcement.
