# Settlement polling implementation checkpoint

2026-09-19. Previous goal turn: progress (native/registered UTC diagnosis and
client fix). This turn implements Task2 polling in the existing worker RunOnce.

New agentsec-worker/security_agent_export_settlement_runtime.go checks the
optional export authority, probes availability, claims dedicated links and
performs at most two settlement attempts per claim. Each I/O has a five-second
context deadline. Both attempts retain identical lease/audit/correlation IDs.
No planner, parent heartbeat or artifact writer is called by this helper.
Malformed success receipts and exhausted retries fail the tick.

RED: cached Go test ./agentsec-worker -run
'^TestSecurityAgentExportPolling.*$' -count=1 -v, exit1,1.170s. Existing RunOnce
made no settlement calls and left both audit IDs unused. Then added polling
helper and mounted it before ordinary approval expiry/scheduling.

GREEN command from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker -run '^(TestSecurityAgentExportPolling.*|TestSecurityAgentProcessor.*)$' -count=1 -v
```

Exit0,2.445s, eight top-level PASS, zero SKIP, including lost-response stable
identity and existing planner/budget/heartbeat processor tests. git diff --check
exit0. The controlled authority simulates a committed lost response; this is
not network-loss or registered worker proof.

Not accepted yet. Production repository capability adapter is still missing,
so real repositories don't yet satisfy the optional polling interface. Missing
Task2 failure/cancel/availability coverage and independent review remain open.
Do not describe this as enabled production scheduling. Client registered rerun
still awaits the SQL implementer's coherent release58 checkpoint. Full original
scope and production publication gates remain unchanged.

## Production adapter and registered checkpoint

Added production repository/Postgres capability adapter. RED capability test
exit1,1.127s: production worker lacked adapter. Adapter now probes installed
release then exact compiled checksum/fingerprint readiness, rejects closed
database/outage/drift and skips absent release. The existing production worker
repository now satisfies the polling interface; no catalog admission implied.

Grouped cached native race command:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver ./agentsec-worker -run '^(TestSecurityAgentExportCapability.*|TestSecurityAgentExportSettlement.*|TestSecurityAgentExportPolling.*|TestSecurityAgentProcessor.*)$' -count=1 -v
```

Exit0: API six top-level PASS3.662s, worker eight top-level PASS3.140s,
zero SKIP. Full output settlement-capability-race.txt. Added absent/drift/
outage/cancelled polling tests, then scoped native race command with pattern
`^TestSecurityAgentExportPolling.*$` passed two top-level tests,exit0,2.437s.
git diff --check exit0.

Registered worker-process fixture now passes at SQL pin
91f1366f1cd86b34d4100b61c4b60e02a14dd374e1f491997081a3996aad03ae:
exit0,7.33s, both children PASS, owned PostgreSQL joined exit0. Full output
settlement-process-current.txt. Same owned network-none/read-only container
recipe as worker/process-green.md, newly crosscompiled API/worker binaries.
The extended test proves Go client claim/settle/replay and persisted parent
needs_human/export_available after restart. It does not run the parent polling
adapter in a separate OS process, simulate real lost network replies, or use
live AWS. Previous client review's native/registered conditions are met.

Independent review of capability and mounted polling dispatched. Failure-path
tests are component evidence, not deployment proof. Dispatch/planner/public
routes/UI and production acceptance still open. No original task reclassified.

Independent Task2 review: acceptable bounded component, no confirmed production
defect. Reviewer verified all five hashes and actual production composition;
prior client registered gate met. One P3 remains: controlled claim error and
in-flight cancellation/deadline tests (pre-cancel coverage alone is insufficient).
Root will close that coverage gap before batch completion. Registered polling
adapter execution remains separate from the passing direct-client fixture.

P3 follow-up: added controlled claim-error and cancellation after entry into
claim or settle I/O. Tests assert a live deadline no later than five seconds,
child context cancellation, prompt tick exit, no subsequent parent work and no
retry after cancellation. Existing same-ID lost-reply retries stay covered.
Scoped native race pattern ^TestSecurityAgentExportPolling.*$ passed three
top-level tests, zero SKIP,exit0,2.382s. Full output
settlement-polling-review-race.txt. Production unchanged; test hash
e1e69047646bb4434a2432964f20a03994697d5618adc55cd57b5d3b78a77338.
Scoped reviewer follow-up pending. These are in-process boundary tests, not
registered polling proof. git diff --check exit0.

Reviewer follow-up: P3 ADDRESSED, matching hash and retained three-test race
output verified. No new actionable issue. Mounted polling component review
accepted; registered polling and broader integration limits remain unchanged.
