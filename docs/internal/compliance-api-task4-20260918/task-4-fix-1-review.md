# Task4 fix1 independent re-review

Reviewer: /root/compliance_api_review.

1. Authoritative control freshness: ADDRESSED. SQL0056:209 computes the full
eligible-source deadline excluding seeded configuration; compliance_http.go349
preserves SQL freshness/deadline independently of the preview. Registered HTTP
regression covers fresh101st/all-stale/missing/seeded-only. Optional legacy
field decoding and disabled-service route behavior are preserved; frozen
formatter/envelope unchanged.
2. Default attachment limit: ADDRESSED. client.ts82 defaults attachments to4MiB,
preserves smaller explicit caps and ceiling, and leaves ordinary JSON1MiB.
Boundary/caller-cap regressions confirm this.
3. Audit-write-failure regression: ADDRESSED. compliance_http_postgres_test.go184
observes the actual audit INSERT relation-lock wait, cancels SQL, and proves
safe503/no attachment/private body, unconsumed grant/retained read lease and no
additional committed audit. This is write-path cancellation/rollback, not a
separate COMMIT-stage fault.

No new breakage. No new out-of-scope observation. Prior minor provider-error
classification and routine telemetry noise remain deferred.
Read complete13-file incremental patch, manifest, fix report, constraints and
accepted/diagnostic logs; checked blocked-query helper for lock observation,
cancellation and goroutine joining. No test reruns, network calls or mutations.

Verdict: all findings addressed, no new Critical/Important breakage. Task5
UI/composed-browser and live production gates remain open.
