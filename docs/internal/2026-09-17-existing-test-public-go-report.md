# Go proof consumer, September 17

The Go consumer and its focused race tests pass. This report covers Go only;
it does not claim SQL integration, browser acceptance, or release readiness.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/budget-recovery-20260916`.
No commits, staging, pushes, SQL changes, pin changes, or web changes in this subtask.

## What changed

`services/platform/apiserver/security_agent_existing_test_public_projection.go`
defines the typed public proof and validates closed nested JSON objects before
decoding. It rejects duplicate/extra/missing keys and forbidden nulls, then checks
IDs, versions, digests, artifact bounds, exact outcome/reason pairs, attempts, and
the curated comparison rules. Public artifact identities contain hashed reference
metadata only, never raw storage references.

`services/platform/apiserver/security_agent_action_projection.go` adds optional
`ExistingTest`, recognizes the new exact DB step shape, rejects duplicate optional
fields, and attaches a validated proof. The older step shape still works and omits
`existing_test` from public JSON.

`services/platform/apiserver/security_agent_action_validation.go` checks the same
proof invariants for typed authority adapters before HTTP header filtering.

`services/platform/apiserver/security_agent_existing_test_public_projection_test.go`
exercises the real decoder, public struct validator, and HTTP response boundary.
Tests cover all eight outcome/reason pairs; pending and leased reconciliation;
cancellation uncertainty; safe absent compatibility; malformed nested fields;
artifact/version/digest bounds; all six allowed checks; stopped-parent evidence;
and the opt-in header, with malformed proof rejected even without that header.

This report is the fifth changed file. The two existing action projection and
validation files were already untracked inherited work; their earlier contents
were preserved apart from the scoped extension.

## Contract correction

The first design said `test_run_id == result.outcome_id`. Independent SQL review
found that the effect outcome is a separate `security_agent_effect` identity.
The main agent corrected the design and directed Go to remove that equality.

The consumer requires a present effect with a canonical outcome ID. SQL proves
the scoped step/effect/link association; Go binds definition/version to typed
arguments, `verification.after.run_id` to `test_run_id`, and `proof_digest` to
the displayed result digest. It does not compare parent terminal state with the
stored proof outcome.

I added `TestSecurityAgentExistingTestPublicEffectIdentityIsSeparate` first and
observed its RED failure, then removed the false equality. Its fixture uses
different canonical effect and test run IDs.

## Evidence

All commands below ran in the worktree above, with local tooling and offline
dependencies. These are explicit unit selections; `-skip Postgres` stays present.

Initial unit RED, before implementation:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform ./apiserver -run '^TestSecurityAgentExistingTestPublic' -skip Postgres -count=1
```

Exit 1. All nine valid proof variants failed with `valid bound proof rejected`;
five public struct association/state mutations and the bounds cases failed with
`public authority adapter bypassed proof validation` or `public struct bounds
bypassed`. The absent-compatibility test passed. No database fixture ran in this
explicitly skipped invocation.

Identity correction RED:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform ./apiserver -run '^TestSecurityAgentExistingTestPublicEffectIdentityIsSeparate$' -skip Postgres -count=1
```

Exit 1, `effect identity was confused with linked test run repository provider unavailable`.

Final proof-consumer race verification:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform -race ./apiserver -run '^TestSecurityAgentExistingTestPublic(AcceptsBoundProof|AbsentCompatibility|RejectsMalformedProof|NestedExactFields|StructValidation|Bounds|Applicability|EffectIdentityIsSeparate|BoundarySuccess|CancellationAndPending|HTTPBoundary)$' -skip Postgres -count=1
```

Exit 0: `ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 2.206s`.
The same exact selection without `-race` passed in 1.067s.

Existing action/HTTP regression race verification:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform -race ./apiserver -run '^TestSecurityAgentAction(ProjectionSeparatesEvidence|ProjectionRefusesUnboundEvidence|ProjectionPreservesTTLAndResult|ProjectionReachesRunDetail|ProjectionStoppedPartialCleanup|Arguments|ArgumentsRejectContradictions|DetailsHTTPNegotiation|DetailsHTTPRejectsUnsafeAuthority)$' -skip Postgres -count=1
```

Exit 0: `ok github.com/zasp-ai/zasp-sec/services/platform/apiserver 2.543s`.
All four Go files were formatted with `/opt/homebrew/bin/gofmt -w`.

## An unintended fixture run

The first supplied broad command used `-run '^TestSecurityAgentExistingTestPublic'`
without `-skip Postgres`. Concurrent work had added
`TestSecurityAgentExistingTestPublicProofPostgres`, so that prefix unexpectedly
selected a database-owning host fixture. The fixture ran and failed on missing
SQL public proof in all four action/mode combinations. Its cleanup log reported
owned PostgreSQL PID45388 joined, `pg_ctl exit=0 server Wait exit=0 normal-exit`.

I reported this immediately. It is not valid acceptance evidence for the assigned
Go-only work. Every later host test command explicitly excluded Postgres, and I
issued no manual database service start/stop commands.

Two initial race command attempts placed `-race` before `-C`; Go rejected both
with exit 2 before running tests. The successful commands above put `-C` first.

SQL provenance and real mounted API/worker/browser acceptance remain separate
gates. Keep production action enablement unchanged.
