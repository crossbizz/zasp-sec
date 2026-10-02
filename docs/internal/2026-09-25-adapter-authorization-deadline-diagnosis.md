# Adapter authorization deadline diagnosis

The signed HTTP handler currently fails before any target send. Its first
covering run failed543.590s; the HTTP child returned503 after8 forward Checks
and zero sends, credential reads or completions. Captured completion passed
separately, so that passing boundary did not prove handler integration.

The next owned diagnostic retained the original10s combined Authorize/Execute
deadline. Test-only tracing records operation labels, elapsed times and error
classes, never SQL arguments, provider bodies or proof contents. It deliberately
fails after reporting and attempts no provider IO.

Measured result from session34481, `worker-test74-adapter-http-timing.log`:

| Boundary | Observed result |
| --- | --- |
| Initial source read | 1.085s, succeeds |
| 17 revision reads | 343-418ms each, succeed |
| 8 OpenFGA calls | 4-19ms each, succeed |
| Second source read | 1.599s, succeeds |
| Authorize total | 8.965s, succeeds |
| Execute native invocation | Cancelled at1.034s by the shared deadline |

The diagnostic package intentionally failed196.546s (test195.65s). The owned
database stopped normally; root compared equal before/after source manifests.
This establishes deadline exhaustion in native Execute, with repeated database
revision/readiness work consuming most of the authorization budget. It does
not establish a provider, OpenFGA transport or native permission failure.

Source trace: `CheckRevision` reads before and after each permission Check.
Each adapter revision read validates current74 readiness, the worker catalog,
and the registered adapter principal. The journal currently wraps the full
authorization and native invocation in one10s context.

Ruling18 approves a request-local adapter revision bracket around the entire
mapped permission set. It must retain every user/task target and response
model/allow check, initial valid tenant/store/model/current revision, after-set
revision equality, second source read, final revision equality and native
locked source/revision validation. Monotonic desired/generation changes must
conflict. No cross-request cache, timeout increase, readiness relaxation or
human/non-adapter change is approved.

Verification remains required: failing/passing application tests for mutation
after early and last Checks, denial and malformed/pending/model/store cases,
native concurrent change, and actual HTTP completion within the original bound.
The diagnostic must require explicit opt-in so its intentional failure cannot
break normal package verification. No successful fix or production acceptance
is claimed by this report.

Implementation checkpoint: extracted old behavior failed the finite-reader
budget regression0.882s after only two permission Checks. The adapter-only
bracket then passed focused authorization1.860s/adapter1.281s. Expanded
scope/generation/store/model cases and retained human revision checks passed
authorization1.878s/adapter1.263s; root inspected the implementation and equal
source manifests. The second source read, final revision equality and native
locked checks remain. The diagnostic now requires explicit opt-in.

Native mid-Check revocation and the actual HTTP flow are the next required
verification. Unit success does not prove the handler fits its deadline.

Native follow-up63677 passed242.586s/test241.44s, actual HTTP child47.89s.
Both mid-Check1/8 membership changes refuse before any invocation, then normal
reconciliation restores authority. The handler completes one committed-start
controlled TLS send with one credential read; revoke-before-response and two
held retries pass without extra forward IO. The10s per-call limit is unchanged.
Root read the consumer and terminal evidence, compared equal source manifests
and confirmed normal owned database shutdown. This verifies the diagnosed
handler seam locally, not fresh-handler recovery or deployed acceptance.
