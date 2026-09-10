# Actual API load runner

Status: merged through PR 38 as main `2540c7b4` after push CI 34521277124 and
PR CI 34521331499 passed. Main CI 34522254378 passed.
No original task classification changes. The authoritative count remains
535 production-available / 132 component-only / 61 external gates, total 728.

The previous API evaluator accepted arrays of supplied latencies, but no actual
load command was connected to product requests. This change adds CLI lint, HTTPS
execution and evaluation for a fixed bounded four-endpoint read workload.
It reuses the existing verified TLS/credential file boundary. There are no
mutations, arbitrary routes, insecure TLS, proxy forwarding or redirects.
The full specification and operation instructions are in
`docs/operations/api-reference-load.md`.

Test-first evidence:

- `/tmp/zasp-api-load-evaluator-red.log`: the requested real-artifact command
  failed because the command did not exist. Its implementation then passed
  `/tmp/zasp-api-load-evaluator-green.log` with race detection.
- `/tmp/zasp-api-load-runner-red.log`: the actual TLS run command was missing.
  The first implemented run exposed premature cancellation of its final request
  at the end of the offer window. The runner now permits bounded drain.
  Three race-enabled repetitions passed `/tmp/zasp-api-load-runner-green.log`.
- Independent review found that the previous drain allowance could accept a
  301-second measurement. `/tmp/zasp-api-load-bound-red.log` reproduced this.
  Absolute wall time above 300 seconds is now rejected, including drain.
- `/tmp/zasp-api-load-negative-tests.log` passed actual TLS unauthorized,
  redirect, HTML, oversized response, timeout, capacity and cancellation cases.
  Redirect destination traffic remained zero. Failed gates retained all samples.
- `/tmp/zasp-api-load-lint-red.log`: lint was missing before implementation.
  `/tmp/zasp-api-load-lint-green.log` passed with race detection in 10.027s.

The first composed browser run passed with exit 0 and complete owned-resource
cleanup in `/tmp/zasp-api-load-composed-chrome.log`. It measured 100 actual
authenticated reads, p95 15,754,166 ns. This is only the local composed dataset;
it is not the concurrent-retirement experiment or a reference-load result.

Review then identified malformed nonempty page records being counted as success,
unexpected 2xx statuses losing their failure report, and sample completions
extending beyond the recorded elapsed time. All three failed in
`/tmp/zasp-api-load-review-red.log`. The fixes validate canonical route-specific
record fields, retain unexpected HTTP status failures, and enforce each attempted
sample's scheduled offset plus latency within the measurement. The synthetic
percentile fixture now allows its final sample to complete at 5.05 seconds.
The complete CLI race suite passed in 12.028s, exit 0:
`/tmp/zasp-api-load-full-cli.log`. The initial composed run predates those fixes.
The final composed rerun passed with exit 0 and complete owned-resource cleanup
in `/tmp/zasp-api-load-composed-final.log`. All 100 actual authenticated reads
succeeded, with p95 10,202,041 ns. No reference-deployment claim is made.

Full UI/build verification passed with exit 0 in `/tmp/zasp-api-load-verify.log`,
196 files / 1,179 tests, contracts, types, lint, production build and ledger.
CI's existing production release gate now unconditionally runs the
full CLI race suite, including real TLS load tests. The full release gate passed
with exit 0 in `/tmp/zasp-api-load-release-gate.log`. The browser hook executes
100 actual authenticated reads, stores temporary local profile/measurement/gate
files and requires the evaluator to pass. Push, PR and main CI passed for the
shipped change; local success was not substituted for them.

Read-only review accepted the corrected implementation conditional on the final
composed run and shipping CI. Final evidence review inspected the completed logs
and approved bounded shipping, conditional on CI. Staged secret scanning passed in
`/tmp/zasp-api-load-secrets.log`. Privacy review reported 14 medium warnings and
zero high findings; inspected spans were public CI run IDs and the test fixture's
5,100,000,000-nanosecond duration, not personal data.

The original M8-36a/c remain component-only, and M8-36b/36 still require an
authorized reference deployment and retained acceptance evidence. A profile hash
and source SHA supplied by an operator do not attest the target. The output
marks provenance `operator-declared-unattested` and separates local/reference
declarations. No raw reconciliation-I/O or concurrent-load closure is claimed.
