# Fresh semantic and precise provider proof

Final corrected owned provider run78940 exited0 on migration51 fingerprint
f22c0461b7ae0610e184e439c2c8b42fc2136ef5e293dc66b99faf01af7d9fdd.
Independent review accepted the final corrections with no remaining scoped
findings. Owned dependencies were cleaned up. No live cloud deployment occurred.

The proof is in
`services/platform/agentsec-worker/runtime_precision_combined_e2e_test.go`,
called by the existing runtime combined test and driven by
`scripts/production-combined-e2e.mjs`. Run with Node22.23.1 and PostgreSQL18 on
PATH and these flags:

```sh
ZASP_COMBINED_E2E_RUNTIME_PRECISION=true \
ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY=true \
ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH=true \
node scripts/production-combined-e2e.mjs
```

## What passed

The owned PostgreSQL, S3/KMS/SQS, OpenSearch and TLS-Neo4j dependencies exercised
actual ingest handling, outbox/coordinator and archive/index/correlation/
projection/completion/search workers. Fresh OTLP V1 committed tuple1/1/3/2/2;
precise Tetragon V2 committed2/2/4/3/3. No successful runtime stage, candidate
snapshot, receipt or checkpoint was seeded for those fresh results.

The precise input retained source/process nanoseconds and produced a sandbox-
bound Strong event plus an unattributed event without sandbox. Per-event API
repository readback and target2 source fields matched those outcomes. The proof
checked provider response loss/replay, durable HTTP/SQS replay, empty DLQ,
catching_up before indexing and current only after target2 checkpoint completion.

Independent review found and required two extra controls. Final run78940 proves
both fresh batches have zero legacy session-search outbox rows, and historical
target2 full document hits retain their bodies, versions and sequence metadata
after replay. Database snapshots also retain legacy search rows. Earlier runs
80945 and41328 passed before these final assertions; they don't replace78940.

## Fixture and verification limits

Identity/enrollment setup is declared synthetic setup. An initial run failed
because the new test sensors were still pending; correcting those fixtures to
active matched the existing harness. Production candidate validation was not
weakened. This does not prove real sensor activation or heartbeats.

The ingest HTTP server is an owned httptest handler; API readback uses the
production repository. The proof doesn't establish a browser session against
the product server. Canonical public event_time ordering is distinct from the
source nanoseconds used for correlation identity.

Script tests passed26 with two separate opt-in cleanup tests skipped; the actual
provider run required all provider markers and no skips. Final fixture race
passed2.269s. The next browser-checkpoint integration changes the harness after
this checkpoint and requires its own final provider/browser run and review.

This closes local delivery-finalization steps4-5. Browser acceptance, cloud IAM,
customer sensor evidence, serialized rollout enforcement, whole-change review
and main publication remain separate. No original microtask credit follows
solely from this document.

## Actual precise browser follow-up

On September12, four-flag run2555 exited0 against the completed root50910 web
build. It added `ZASP_COMBINED_E2E_RUNTIME_PRECISION_BROWSER=true` to the three
flags above. The exact final tool-output chunk0d3949 is preserved, without a
reconstructed summary, in [precision-browser-2555-terminal.log](evidence/precision-browser-2555-terminal.log).
This file is the terminal chunk, not the earlier startup output or a full raw Go
transcript; the parent checked the Go PASS/no-skip contract before printing the
provider success markers.

The actual product API, TLS proxy, fresh callback cookie and browser now read
the worker-written precise evidence. Pending target2 search showed catching_up
through HTTP and visible UI before the one-shot index release. Current status,
Strong with the retained sandbox/source sensor, and unattributed with absent
sandbox keys passed afterward. Timeline/evidence panels retained exact API time
strings and canonical instant/ID order across pages. Wrong-investigation and
foreign-tenant requests returned404; scope change closed the old evidence UI.
Runtime evidence snapshots stayed unchanged and browser exceptions stayed empty.
All earlier provider markers remained required. Owned cleanup reached file
removal without an error.

Earlier actual runs99412,71249 and57484 failed on harness assumptions about
inventory readiness, equivalent offset timestamps and omitted optional sandbox
keys. Each correction had reproduced RED tests and independent review. No
product API or authorization was weakened. Final Node checks passed53 tests
with2 existing opt-in cleanup skips; lint passed. The actual2555 provider proof
allowed no skipped Go tests.

This closes local precise API/browser acceptance in addition to the earlier
provider proof. It does not run the broad historical-count browser branch,
prove live Tetragon/customer enrollment, cloud IAM, serialized rollout or remote
CI, or grant original-task/publication credit. Identity/enrollment fixtures
remain declared setup; no successful runtime evidence was seeded.
