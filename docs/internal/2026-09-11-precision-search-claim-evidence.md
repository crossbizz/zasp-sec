# Old search claims must leave V3 work alone

Superpowers regression first reproduced both unwanted claims (pending and
expired leases) and exhaustion quarantine against actual PostgreSQL. The test
uses a real private precise finisher receipt and compares the entire queue row.

The unpublished schema50 claim now requires a succeeded projection V1/V2 stage
bound to the queue's organization, workspace, environment, batch and generation
in both selection loops. Measured schema fingerprint:
`a6f3e317cd99ef9890c7dff18487aa732b196349e133c687606e971c1456865d`.

Independent read-only review found no issues in this bounded change. UI build
passed. The actual PostgreSQL race run covering this regression, sandbox search
leases/backfill and legacy rollback/reinstall passed in76.501s (session63339,
exit0), with the new measured fingerprint.

This is pre-stage compatibility only. Migration51 still needs versioned claim
authority, cached-old mutation fences and registered readiness before V3
activation. No push or original task credit.
