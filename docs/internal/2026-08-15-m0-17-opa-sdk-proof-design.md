# M0-17 OPA SDK Proof Design

## Decision

Implement a self-contained Go proof that embeds one fixed internal Rego module,
prepares `data.zasp.runtime.allow` once with the official OPA Go SDK, and uses
that prepared query for deterministic Allow and Block evaluations. Pin
`github.com/open-policy-agent/opa` v1.17.0 at official tag commit
`64a3625d33bc6ad8e7c40df03b76ce2fb3ab4d21`, module sum
`h1:TMm6bCyb3CEL4wjXsXn1d/kBSBbjF+5sEIyzQvbJiEw=`, and Apache-2.0 license
SHA-256 `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`.

This directly proves the plan's embedded runtime-gateway boundary. It does not
start an OPA server or subprocess, accept customer Rego, read a bundle, call a
network service, or introduce OPA as a customer-visible product surface.

## Considered approaches

1. **Prepared low-level `rego` query — selected.** This exercises the exact
   synchronous in-process evaluation path with minimal lifecycle machinery and
   permits precise steady-state timing around `PreparedEvalQuery.Eval` only.
2. **High-level OPA SDK with discovery and bundles — rejected.** Its storage,
   plugin, configuration, and update lifecycle are outside M0-17 and would make
   the latency result measure unrelated machinery.
3. **OPA CLI or local server — rejected.** Process and transport overhead would
   violate the in-process Go SDK requirement and would not prove the intended
   runtime-gateway fast path.

## Scope and interfaces

Create `proofs/opa-sdk` as an independent Go module using Go 1.25 semantics and
the repository's `toolchain go1.26.5` convention. The package exposes a narrow
testable boundary:

```go
type DecisionInput struct {
    OrganizationID string `json:"organization_id"`
    WorkspaceID    string `json:"workspace_id"`
    Subject        string `json:"subject"`
    Action         string `json:"action"`
    Resource       string `json:"resource"`
    Environment    string `json:"environment"`
}

type ProofResult struct {
    AllowMatched          bool
    BlockMatched          bool
    Deterministic         bool
    WarmupPerDecision     int
    MeasuredPerDecision   int
    AllowP95              time.Duration
    BlockP95              time.Duration
}

func RunProof(ctx context.Context, options ProofOptions) (ProofResult, error)
```

Production options fix 100 warm-up evaluations and 1,000 measured evaluations
for each input. Tests may inject a monotonic clock and prepared-query boundary
to prove percentile arithmetic, result validation, cancellation, error
classification, and fixed output without weakening the production defaults.

## Policy and data flow

The embedded Rego module uses Rego v1 syntax, defaults to Block, and allows only
the exact six-field synthetic input:

- Organization `org_aaaaaaaaaaaaaaaa`
- Workspace `wsp_aaaaaaaaaaaaaaaa`
- Subject `agent:demo`
- Action `tool:read`
- Resource `resource:approved`
- Environment `test`

The Block input differs only in action (`tool:delete`). Preparation happens
once. The proof performs 100 warm-ups for Allow and 100 for Block, followed by
1,000 measured Allow evaluations and 1,000 measured Block evaluations. Every
result must contain exactly one expression whose value is the primitive Go
boolean expected for that input. `AllowMatched` and `BlockMatched` report that
the respective true and false decisions matched. Undefined, multiple,
non-boolean, mismatched, errored, canceled, or panicking evaluation fails
closed.

Measure only each prepared-query evaluation with a monotonic clock. Sort a
copy of each 1,000-sample duration set and use nearest-rank p95
`ceil(0.95*n)-1`. Both decision-specific p95 values must be at most 10 ms.
This is stronger and clearer than merging Allow and Block timings.

## Process boundary and failure handling

The CLI owns a 30-second context and catches panics around construction,
preparation, warm-up, measurement, and formatting. Success writes exactly:

```text
OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.
```

Failure writes exactly one fixed, data-free line selected from configuration,
policy, evaluation, latency, deadline, or panic categories. It never prints
policy source, raw OPA results, timings, stack traces, environment values, or
dependency paths.

## Verification

- Genuine tests-first RED for the absent evaluator and CLI.
- Strict unit and real-SDK tests for exact Allow/Block, prepared-once behavior,
  100/1,000 counts, nearest-rank p95, threshold equality/failure, malformed
  OPA results, nondeterminism, cancellation, panic containment, and fixed
  stdout/stderr.
- Six consecutive Go race runs of the focused proof.
- Two consecutive direct final-code CLI runs on the proof host; both must pass
  the fixed line and the 10 ms p95 gate.
- `go mod tidy -diff`, `go mod verify`, `go vet`, root proof contract, pinned
  repository verify, production audit, immutable OPA source/license audit,
  whitespace, and redacted secret scans.
- Completion may move only M0-17 to Complete and R-10 to PASS. M0-18 remains
  Pending; M0-09 and PROV-01 remain Blocked; R-03 remains incomplete.

## Self-review

The design has no placeholders or optional production paths. The prepared
query, sample counts, percentile formula, threshold, synthetic inputs, output,
failure categories, dependency authority, and status boundaries are exact.
The scope is one proof module and its repository wiring; it does not implement
the later runtime-gateway service or customer policy model.
