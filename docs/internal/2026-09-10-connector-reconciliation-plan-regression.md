# Connector reconciliation plan regression

Status: unresolved. Found during schema-45 verification on September 10, 2026.
This is a production scaling concern, not a passing full API test run.

`TestConnectorAuthorizationPostgresReconciliationIndexesServeHundredThousandRowSkew`
failed in `/tmp/zasp-pairing45-api-full-green.log`. Despite that historical log
filename, the command exited 1 after 312.226 seconds. It was the only failed test
in that full API run. The test and schema-11 query/index definitions are unchanged
by the pairing branch, and this fixture applies only schema 11.

The failed candidate plan used a bitmap scan and sort instead of the ordered
partial candidate-lane index. It estimated 4,004 candidate rows per lane, then
only one survivor of the live-lease exclusion. It processed roughly 100,100
actual candidate rows across 101 lanes. Its top-level Shared Read Blocks was
2,481; the retained test bound is 2,048. The candidate-index assertion failed
first. Neither assertion has been weakened.

The fixture already analyzes effect rows, trigger-populated lane scopes and OAuth
attempts. That earlier correction did not make the plan deterministic. Review
identified sampled provider-cardinality estimates and a candidate-level live-lane
anti-join as a likely cost crossover. Sampling is a hypothesis, not yet a proven
complete cause.

The controlled experiment now confirms this cause: forcing the observed provider
cardinality of 25 made the installed query choose a bitmap scan/sort (largest
node 991.09 rows, 2,483 shared reads). With cardinality 101 it used the ordered
index. Moving global lane exclusion into a materialized eligible-lane CTE kept
the ordered index and a largest result of 101 rows for both estimates. Later
plans had warm caches, so zero reads are not cold-cache performance proof.
The diagnostic log is `/tmp/zasp-reconciliation46-diagnostic.log`.
PostgreSQL documents randomized ANALYZE statistics and resulting estimate
variation in its [EXPLAIN documentation](https://www.postgresql.org/docs/18/using-explain.html).

The isolated, unchanged base revision
`1aab7f58448f13e015ca398c8f483b58b53df5a5` reproduced the same failure: the
eight-repeat race command exited 1 after 262.777 seconds, with the failing case
again reading 2,481 shared blocks. Evidence is in
`/tmp/zasp-pairing45-base-index-reproduce.log`. Five repetitions on the pairing
branch passed in 198.286 seconds (`/tmp/zasp-pairing45-index-reproduce.log`).
Those passes do not prove that this intermittent defect is fixed. Baseline
reproduction establishes that pairing did not introduce it.

The proposed correction to investigate is excluding globally leased
provider/operation lanes before the ordered per-scope lateral candidate lookup.
Any product SQL correction requires a forward migration and must preserve
global lane exclusion, scope fairness, lease safety and all existing work bounds.
Do not force away other plan types or tune only the fixture to claim a product
fix. Verify the corrected production query under the observed skew and retained
history before acceptance.

This defect is next on the critical path, before frozen runtime candidate work.
No original task count is increased, and no launch-readiness or reference-load
performance claim is made. M45 can be assessed independently only after the
failure is demonstrated on the unchanged base and required CI passes, with this
exception disclosed. Independent review found no M45-specific dependency
requiring both changes in the same migration.

The forward schema-46 implementation and its outstanding verification are in
`2026-09-10-reconciliation-lane-plan.md`. The defect stays open until that fix
passes full verification and ships. No performance assertion was relaxed.
