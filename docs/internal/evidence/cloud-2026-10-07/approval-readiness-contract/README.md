# Approval notification release readiness contract

Starting source: `1b7d6d8319e6065b8bcf5090025a502822c6c421`.

Hosted `Runnable UI` run 37613554521 failed its release contract: 292 tests, 291 passed, one failed (`release gives finding tickets exact API-only webhook egress and secret-read authority`). The source assertion expected the prior direct readiness calls. Production now invokes `approvalNotificationLifecycleReady` at both startup and probing, checking database metadata, the selected worker, and cancellation.

The replacement asserts both actual call sites, the helper guards, and the conditional native/legacy factory with shared webhook and secret dependencies. Existing network, IAM, secret and webhook assertions are unchanged. Independent source review: `da2072a1e32fa2c17fa9f8d176df3f0487f6c40f3f2d385a0550ef14c19325e1`.

ROOT ran the same extracted assertion suffix under Node 22.23.1: the unchanged assertion refused current source, the replacement accepted it, and seven source mutations were refused. All nine controls completed with supervisor exit 0; source and executable hashes matched before and after. `source-controls-result.json` is the original generated result; `source-controls.log` is the whole original stdout/stderr capture. This proves source-contract sensitivity only, not application or full release acceptance.

Local full release verification also failed: 202 tests, 106 passed and 96 failed because Helm is absent. This is not the hosted 292-test result. Original local capture remains `/tmp/release-contract-baseline-1b7d-hyx6a9eq/baseline.tap` with process observation `result.json`. Helm v3.19.0's official Linux-amd64 checksum is `a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496`; its download host `get.helm.sh` is outside the enforced cloud network policy. No full-suite local PASS is claimed. The hosted full release suite must pass before merging.

The 728-row ledger is unchanged. No deployment, production availability promotion, provider validation or activation is claimed.
