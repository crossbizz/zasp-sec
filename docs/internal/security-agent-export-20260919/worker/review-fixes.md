# Worker review coverage fixes

Both P3 findings in review.md addressed by a single new test file:
services/platform/agentsec-worker/security_agent_export_worker_review_test.go.
SHA2560637f648d6b6e091897bea6b9eca95a10622e16be1a8e703e6bd8b1bf3e40606.
Fix diff review-fixes.patch SHA256
4a71bde82d62b5f451f911d101ba5becfb466d0fc19e07f9eb0c526447a85654.
No lasting production changes; original reviewed five-file hashes still apply.

Literal claim tests cover duplicate source_version keys, unknown selection
fields and malformed step IDs. The heartbeat test pauses capture, observes an
actual processor heartbeat, mutates the caller's original run/selection binding,
then verifies the immutable original manifest reaches storage and Finish.
Its callbacks use channels/mutexes, and the test always releases and joins the
processor on return. It does not claim PostgreSQL or OS-process acceptance.

Focused command from services/platform, environment GOTOOLCHAIN=local,
GOPROXY=off,GOSUMDB=off,GOCACHE=/private/tmp/zasp-budget-go-cache:

```sh
/opt/homebrew/bin/go test -race ./agentsec-worker -run '^TestSecurityAgentExportWorker(LiteralClaimKeys|IngressHeartbeatOwnership)$' -count=1 -v
```

review-fixes-race.txt exit0;2 top-level tests pass, no skips/race warnings.
These are regression additions for existing correct behavior, not a new product
fix requiring invented RED. To verify the ownership test catches its named
break, root temporarily removed processor ingress deep-copy, ran the ownership
test without-race, observed exit1 in review-ingress-mutation-red.txt, then restored
the exact original file (SHA256f7e4cfbd86dd96c24b84599b16499ad7203e7905e02152571cbb88a47fab4068).
The same focused race command then passed again, review-fixes-final-race.txt,
exit0,2 PASS and no skips/warnings. git diff --check passes.

Request scoped re-review of these two findings and new test file only. All
registered58, actual process restart, API/UI and production gates stay open.

Scoped re-review returned: both P3 findings ADDRESSED; no new actionable defect.
Reviewer verified fix patch/test hash and unchanged original five source hashes,
expected mutation failure and restored-source race output (2 PASS,0 SKIP).
No reruns or mutations. Component code review is clear; this does not close the
registered database/OS-process or connected acceptance gates.
