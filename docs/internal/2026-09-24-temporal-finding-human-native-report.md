# Human-origin finding execution

This is a test-only extension after the finding fix1 review passed. The earlier
frozen finding packets remain unchanged. The connected human-native check now
passes locally; independent review is still required before accepting the gap.

The case starts through the mounted human admission handler, replays that exact
request, and checks human78 actor/receipt/audit/command provenance. A distinct
active approver reads the complete proposed assignment, status and note before
deciding through HTTP. The finding has low severity, below the configured high
automatic threshold. Normal source capture remains active. No automatic event
ID is supplied, and no 77 admission occurrence or test executor owner is allowed.

Packet: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-finding-human-native/`.
`baseline/manifest.json` records the two existing test files before edits;
`plan.md` records the bounded checks. No production implementation change is
authorized in this batch.

The mounted identity and memberships, HTTPS provider response, FGA model-read
response, external readiness callback and local artifact storage are controlled
fixtures. The application constructor, PostgreSQL receipts and domain effect,
Temporal workflow/notification and public projections are actual. This is not
Stytch authentication, current P7 worker authorization, cloud storage or deployed
production proof.

The retained Temporal container was checked read-only before the native run:
`logs/server-identity.log` records container
`6db52bc67865bbc392c6cbea54bc4d686102ba49f8ae0312d2e707c15c04dfae`,
project `zasp-runtime-services`, the pinned server1.32.0 image digest and
loopback 7233. The test owns only its disposable database, namespace and worker
process. No server restart or retained-volume mutation is requested.

First verification: shared apiserver compile passed 1.110s after correcting an
intermediate ProductID.String fixture call. P7 saw that intermediate missing
helper/type failure; its owner received the compile-coherent checkpoint.
`logs/human-red1.log` is the first connected run against the existing
automatic-only worker fixture. Any refusal of human source provenance at that
fixture boundary is a coverage limitation, not a production defect.

That first run joined FAIL 243.086s (case 242.23s, child 181.409s). The old
automatic-only HTTPS fixture rejected the exact human request before approval;
the child later exhausted its unchanged 3-minute context while awaiting a control
decision. PostgreSQL 77355 joined normally. This is fixture coverage evidence.
The report does not infer a product failure from the later generic relay error.

The completed human branch keeps the automatic branch's occurrence check and
requires the human receipt/intent digest, initiating actor, audit digest and
matching 65/66 compatibility commands at the HTTPS boundary. The parent checks
exact admission replay, a distinct approver's complete proposal read, no
preapproval effect and exact decision replay. Final checks bind settled usage
and artifact versions, one response metadata/effect, approved actor provenance,
control delivery and exact public metadata. Normal source capture is retained.

`logs/harness-compile.log` passed API 1.043s and worker 1.851s, compile-only.
`logs/human-green1.log` stopped at compile before any database/child started:
P7's `authorization_statement.go:88` referenced an undefined
`migrations.ProductionComplianceSemanticFingerprint`. The failure is retained;
the P7 owner was asked for a compile-coherent checkpoint. P7 confirmed
its concurrent work does not alter constructor/current-worker behavior or this
missing-proof legacy fixture mode. That does not turn this test into P7 proof.

After P7's actual compile checkpoint (API 0.839s), the human-only test now builds
its worker executable before database/native setup. It checks the five named
worker/workflow source hashes before and after compilation and records the
executable SHA256. Existing automatic native cases keep their original runner.
`logs/human-green2.log` carries that checkpoint and the connected run. The
3-minute child and 4-minute fixture contexts remain unchanged.

The final command was:

```sh
cd services/platform
go test ./apiserver -run '^TestTemporalFindingResponseHumanNativePostgres$' -count=1 -v
```

`human-green2.log` joined exit 0: package 123.345s, case 122.28s and owned
worker 59.24s. PostgreSQL 79356 joined with both pg_ctl and server exit 0.
The worker executable hash was
`0e90309580c77d6fb797cb2de0b1911710daa11e3b2525a9b47c6697f474cd1e`.
No source changed after this acceptance run.

The requirement-to-evidence mapping is bounded to this human-origin scenario:

| Required boundary | Actual assertion in the passing case |
| --- | --- |
| Human admission and replay | Mounted `runSecurityAgent`, same 202 body, one initiating-actor receipt, intent/audit digest and matching 65/66/78 ownership/command binding. |
| Human authority at planner send | Actual HTTPS request matches persisted started job, credential digest and unsettled reservation; human actor/receipt/audit/command checks run before returning the controlled candidate. |
| Supervised decision | A distinct active member reads exact target, version, assignee, status and note through HTTP; source and effect tables remain unchanged before approval; exact decision replay returns the same body. |
| Native delivery | Actual constructor, start outbox, finding workflow, approved control ACK and wake signal in history. No invented source event is passed. |
| Accounting and result | One HTTPS planner call, two artifact writes, settled 20/10/30-token usage bound to provider digest and within persisted token/cost caps; one atomic effect and exact verified public metadata. |
| Origin and isolation | Human78 requester stays the initiating actor, one run for the source/definition, no 77 admission occurrence, no 74 owner and zero test runner calls. The 66 `legacy` tag remains compatibility metadata, not execution ownership. |
| Replay, privacy and shutdown | Exact completed start is accepted; all finding history payloads are inspected for note text, native workflow completes, worker close is called once and the owned child/database join. |

Changed source is three test files only: the API live fixture, the new human
helper and the worker live fixture. `review/source.diff` is relative to the
captured starting bytes; `review/source-manifest.json` includes those three and
this report. `review/evidence-manifest.json` binds logs, baseline and handoff
files. No P7 production hunk or automatic77 diagnostic edit belongs to this diff.
Automatic native cases were not rerun: their production routing did not change,
and their existing automatic occurrence assertions remain in the test branch.

Remaining gates stay separate: automatic77 later-occurrence first-error cause,
P7 current worker send/commit authorization, other responder families, deployment
and broader 728 acceptance. No commits, pushes or migration publication.
