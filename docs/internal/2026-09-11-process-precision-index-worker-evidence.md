# Precise index worker checkpoint

Index V2 execution now requires the precise store capability, authorized worker
identity/token, a current lease and matching predecessor digest. It selects
ApplyPrecise explicitly and checks cancellation/lease validity before indexing,
before receipt persistence and before returning success. V2 emits a versioned
index receipt. Historical V1 dispatch uses a copied executor configuration.

Superpowers verification and review:

- Rejecting behavior failed the new capability, authorization and cancellation
  tests before implementation. The tests then passed with the implementation.
- The actual precise store and archive decoder feed a declared index driver.
  Assertions cover archive/effect bindings and absent semantic identity.
- Historical V1 receipt bytes match when drained by a V2-configured executor.
  An expired original lease succeeds only with the declared renewed window.
- `go test -C services/platform -race -count=1 ./agentsec-worker
  ./runtimeindex/...` exited 0: worker 15.619s, index 1.359s and OpenSearch
  driver 1.646s.
- Independent review found no implementation issues, with approval bounded by
  the race, historical-drain and renewal checks above.
- A fresh `npm run build` exited 0 and generated the standalone UI output.

The production factory already passes the concrete index store that supplies
this capability. These tests don't prove live provider execution, durable V2
claim routing, archive V2 execution, database finalization or production
activation. Those remain open. No push and no original microtask credit.

## Production reader composition

The archive reader needs no V2 index-read implementation change. A composed
test now replaces the worker's reader stub with runtimeArchiveExecutor and
passes V2 bytes through its real version/owner/KMS/metadata/checksum checks,
then the actual precise decoder/index store. The resulting receipt retains
the selected archive URI, object version, digest and index effect digest.
Altered HEAD evidence is rejected before GET, indexing or receipt persistence.
The focused race test passed in 2.308s. Independent Superpowers review found
no issues with this local compatibility evidence.

The expanded worker/index/driver race run also exited 0: worker 15.154s,
index 1.321s and OpenSearch driver 1.645s. Diff checks and the authoritative
728-row ledger validator passed after the evidence update.

S3 transport and the index driver remain declared test dependencies. This
doesn't prove cloud IAM, archive production or deployed execution. Inspected
runtime_config.go still requires archive-v1 and index-v1 in the respective
AWS-authority validators. V2 startup and durable routing must be connected
to complete migration readiness before activation.
