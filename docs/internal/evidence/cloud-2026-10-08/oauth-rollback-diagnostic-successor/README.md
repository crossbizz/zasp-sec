# Direct native rollback refusal diagnostic

The prior exact `eb1e815e7f4921e2fc93ac8bf437316b36e5c0eb` authenticated run 37737618413 reached both original cases: genuine same-transaction enqueue and immutable enrichment passed; the rollback case failed its expected native 23505 assertion. The group failed (3 RUN, 1 PASS, 2 FAIL, 0 SKIP). No setup diagnostics were emitted, and no resource refusal, timeout or output cap occurred. Compile run 37737618320 and original nine-case run 37737618371 passed. These are component outcomes, not deployed production acceptance. Raw logs/artifacts remain inaccessible under the cloud network policy.

A separate push-triggered run of the **same exact commit**, 37737612165, passed all three named outcomes (1 top-level case and 2 subcases), with no skips or resource refusal. Both actual outcomes are retained: mixed results demonstrate an unresolved reliability issue, not stable acceptance.

This successor reports only validated five-character SQLSTATE and closed phase/statement/target categories for the direct competing-attempt query. Nil/non-PostgreSQL errors receive closed labels. It retains both original cases, original 23505 expectation and every rollback/no-write assertion; it prints no SQL, arguments, provider data, secrets or raw error text. No deadline, resource floor or authorization guard is relaxed.

The compatible installer retains the exact original v2 SQL name/body/checksum and strict catalog gates, as documented in the preceding compatibility checkpoint. This 32-source successor follows that preserved checkpoint and binds the diagnostic change. Actual successor verification is pending.
