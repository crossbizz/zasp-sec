# Global operator shipping boundary

Read-only dependency check, not a staged candidate or release approval.

Main/shipping HEAD is `8733b16f8d939d38a8157dd2519e57fc6f630542`, with migrations
through51. Recovery HEAD is `ecc047ee2e90c36ec702ade129a2b08eae0a7a1a`, with dirty
candidate52 audit exports,53 budgets,54 run context and55 existing-test execution.
The clean shipping worktree had no local changes at inspection.

An offline `go list -deps` of `./agentsec-migrate` completed exit0 against the
recovery source. Its local production compilation graph includes two packages:
`migrations` (27 Go sources and137 embedded SQL files) and `agentsec-migrate`
(5 Go sources). This identifies compile inputs only, not a deployable bundle.

Runtime compatibility extends beyond that executable. Direct compiled55 consumers
include the API's existing-test read repository, budget-release database,
workflow repository and linked Red Team repository; the Red Team adapter's
production routing; and the worker's Security Agent test client. Deployment
rendering also selects schema55 and its worker/reconciler configuration. These
boundaries must remain compatible in an actual schema55 deployment.

The six-file operator CLI patch cannot be copied alone onto main: it consumes
the unpublished SQL/Runner chain. Nor does a standalone CLI compile prove the
API/worker/UI work with that schema. Build an explicit dependency-complete
candidate, inspect its exact diff and verify its compiled consumers, mounted
browser path, UI build/import/smoke and required release gates before pushing.
Use the isolated shipping worktree, with reviewed explicit paths; never stage
the entire recovery tree or mistake recovery-tree results for candidate results.

The current full release still lacks approved fresh advisory evidence, as
recorded in the existing release-gate checkpoint. That does not halt independent
implementation, but it must not be hidden by offline empty scan results or
removal of the fail-closed gate. This note changes no original-task availability.
