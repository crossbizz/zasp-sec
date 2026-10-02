# Export settlement client progress

2026-09-19, component in progress. Plan:
docs/internal/2026-09-19-security-agent-export-settlement-client-plan.md.

Created separate registered claim/settle methods in
services/platform/apiserver/security_agent_export_settlement.go. They carry
compiled release58 pins and validate closed identities and state/reason unions.
They don't use parent execution claims or label available exports remediated.
SQL owns expiry/replay decisions, so local clock expiry doesn't reject an
otherwise valid committed lost-reply response.

Focused RED command from services/platform:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./apiserver -run '^TestSecurityAgentExportSettlementClient$' -count=1 -v
```

After correcting the test double's missing JSONDatabase methods, behavioral
RED exit1: `valid claim refused: [] repository provider unavailable` against
fail-closed stubs. Implemented the client. Same command GREEN exit0,1.221s,
TestSecurityAgentExportSettlementClient PASS. This tests Go query arguments,
pins and receipt handling with a controlled database boundary, not SQL authority.

Malformed receipt tests now cover null booleans, duplicate fields, version
regression, wrong identities, illegal state/reason combinations, duplicate claims
and null/nonarray responses. Native race verification is running. Independent
review, registered Go/SQL integration and runtime composition remain open.
No original microtask has been marked production-available. No publication.

Source identity ruling sent to SQL implementer: existing_test/attack_lab IDs
are original linked step IDs in the same scoped parent run; versions are the
persisted step versions; association digests bind checked effect.result_digest.
The redacted public projection must verify kind/link/input and nonnull digest.
Missing retained proof is an explicit refusal. Do not admit cross-run evidence
to bypass the still-open single-step planner limitation.

## Malformed response RED/GREEN

Native race invocation (same cached environment above):
`go test -race ./apiserver -run '^TestSecurityAgentExportSettlement.*$' -count=1 -v`.
First exit1: replayed:null was accepted because encoding/json maps null into
the zero bool value. Added nonnull boolean checks. Next exit1: duplicate
settled fields were accepted by the existing map/struct helpers. Switched
claim and result envelopes to existing duplicate-rejecting
auditExportClosedObject. Both failures were observed before their fixes.

Final invocation exit0,2.696s:

```text
=== RUN   TestSecurityAgentExportSettlementRejectsMalformedReceipts
--- PASS: TestSecurityAgentExportSettlementRejectsMalformedReceipts (0.51s)
=== RUN   TestSecurityAgentExportSettlementClient
--- PASS: TestSecurityAgentExportSettlementClient (0.16s)
PASS
ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 2.696s
```

Zero skips. git diff --check exit0. No running root test process remains.
Client coverage still needs the other valid terminal unions, invalid caller
inputs and provider errors before independent review. Registered Go/SQL and
composed worker acceptance remain required; this is not a shipped feature.

## Expanded client and registered process checkpoint

Added valid pending/failed/stopped/cancelled/replayed result cases, invalid
caller refusals before database I/O, conflict/outage classification and empty
claim queues. Four native race groups passed, exit0,3.499s. Tests characterize
existing behavior; no new RED was claimed for these additions.

Extended the owned process fixture after resumed export completion to call the
actual Go client through PostgresJSONDatabase on the registered worker, then
settle, replay the receipt and read back needs_human/export_available. First
run failed at claim decode (8.76s,exit1), with both subprocesses PASS and owned
PostgreSQL shutdown joined exit0. The independent reviewer identified the same
UTC issue: PostgreSQL emits +00:00, while the client compared Location pointers.
The focused TestSecurityAgentExportSettlementPostgresUTCTimestamp reproduced
that rejection, exit1,1.167s. Changed validation to require zero UTC offset,
not a particular Go Location pointer. Native race and owned process reruns are
active. No new feature acceptance or publication claim.

Rerun results: five native race groups PASS, zero SKIP,exit0,3.492s.
Full output: settlement-race.txt. Owned process rerun failed before client
execution at Runner58 calibration: observed fingerprint
d4bf8ae97c367aab7d31948d95818630440f39af806a7d850c5e6a3b65d5666f,
exit1,5.54s, owned PostgreSQL joined exit0. Full output: settlement-process.txt.
SQL implementer is actively changing the draft migration; requested one
coherent-pin checkpoint before rerunning. This result doesn't establish a
client regression or a registered GREEN. The UTC fix has native evidence only
until the composed test can reach it again.

Current hashes sent to the independent reviewer:

```text
242ec548da0b3adf6b5f8af8f246b4b6922a7666766f7ec057c35ffe7412418d security_agent_export_settlement.go
9867f0e7e25dd4bb4d8b51a9b6fe4ba2992ec7aa362b7c5c982770e6002a9320 security_agent_export_settlement_test.go
711f8bc71668dd3e2191c393d0084548703de2d69bbd4e989f9bf7095abd877a security_agent_export_worker_process_postgres_test.go
```
