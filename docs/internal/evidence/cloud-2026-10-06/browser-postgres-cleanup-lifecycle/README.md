# Private PostgreSQL cleanup lifecycle source candidate

This candidate fences PostgreSQL startup when harness cleanup begins and starts cancellation of an already registered PostgreSQL owner before waiting for unrelated resources. Cleanup catches that stop failure immediately, joins the same operation once, attempts the remaining resources, and retains files and original errors if any join fails.

Four source-extracted lifecycle regressions failed against unchanged committed81 source (0 PASS /4 FAIL), then passed after the private two-file fix (4/0). The selected orchestration groups passed27 tests including subtests; the complete owned-browser-postgres mock-boundary file passed16. Those43 include the four new regressions. Small Node child lifetime checks executed; Docker, Go, browser and actual PostgreSQL did not. Real signal integration tests are preserved and deferred, as are the broader project checks. The observed original Browser3 cause remains unknown.

The original source-extracted late-registration witness is retained independently of the new regressions. It establishes an orchestration gap under controlled command completion, not the timing or cause of the original browser failure.

Source origins, exact two-file diff, retained logs, manual command reconstruction and omission identities are bound here. Complete source bodies and seven unchanged dependency bodies remain private; this is neither a frozen build envelope nor deployed/runtime acceptance. Independent provider review is pending and will be retained separately. No security scanner result is claimed for this packet.
