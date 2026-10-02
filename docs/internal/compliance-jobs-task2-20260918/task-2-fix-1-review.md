# Task2 fix1 independent review

Reviewer: /root/compliance_jobs_review. Read-only; no test reruns.

All four Important findings and the five quota boundary evidence gaps are
ADDRESSED. Spec verdict: all scoped findings addressed. Quality verdict:
approved with no new Critical/Important breakage or new out-of-scope finding.

Evidence reviewed: complete incremental patch and frozen manifest, appended
report, controller sequencing ruling, exact commands, RED/focused/final SQL
logs and race output.

- Heartbeat SQL returns expiry/generation/attempt; adapter validates a replacement
  lease, the shared holder updates it and Finish obtains the current lease.
  Registered restart finishes after original expiry (worker replay test200-232).
- Grant issue checks authorization after job wait; read/consume check after job
  and grant waits. Observed blocker tests revoke scope and verify no disclosure
  or grant/read-lease mutation (API fix test173-215).
- Creation repeats freshness after policy/identity waits. Deadline-crossing
  regression returns28000 and creates no job (API fix test154-170).
- Real replay bridge uses persisted bytes and NewExport.Put. Two registered
  worker subprocesses prepare and replay, with zero changed-renderer calls and
  parent verification of completed state, bytes/revision/receipt. This satisfies
  the Task2 replay-boundary sequencing ruling; full formatter/poller/provider
  integration remains Task3, not waived or narrowed out of the feature.
- Concurrent registered clients contest the final slot at all five missing
  quota ceilings. Exactly one succeeds, one gets54000; principal grant case
  ends below per-job limit. Seeded counters prove numeric admission behavior,
  not physical16GiB storage or reference-load performance.

Task3 must reuse the bridge, integrate formatter/poller/provider, read-only
unknown-write reconciliation and exact-version cleanup. Task4 retains connected
grant/download proof. No live S3 or deployment claim follows from this review.
