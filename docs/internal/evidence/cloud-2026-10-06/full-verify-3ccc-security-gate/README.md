# Full verification at 3ccc1455 — security-gate refusal

The actual full `npm run verify` failed after 733 seconds at unchanged
3ccc145510ea90c751a66306b6bb1d39812d5c51. Fresh UI results are 246 files and
2,535 passing tests. Worker and gateway pass; typecheck, lint, production imports
and staging pass. Production release tests report 284 passes and one failure:
the unchanged full-history Gitleaks gate scanned 1,428 commits and found 546
findings. Hosted failure cause remains unknown; forbidden hosted logs cannot
be diagnosed from this local result.

Build, compiled imports and ledger validation were unreached in that full run.
They were then explicitly authorized and executed as separate local checks:
all pass; compiled graph has seven client/eight server chunks, and the ledger
retains 728 rows / 523 production-available categories / 144 component-only /
61 blocked-external / zero missing. These separate results do not turn the
retained full failure into a pass or clear release/security/deployment gates.

Exact commands, tools, before/after commits, full result, scoped check logs and
summaries are separate files. The compressed full log removes ANSI controls
and redacts all HTTP(S) URLs. The private raw log had zero findings in a scoped
Gitleaks scan; this does not clear the repository's 546 historical findings.
Earlier immutable failures and evidence directories remain unchanged.
