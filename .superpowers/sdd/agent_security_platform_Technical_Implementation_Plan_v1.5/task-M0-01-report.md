# M0-01 report — MVP risk register

## Result

Completed M0-01 only. Added the MVP external/OSS proof risk register and moved
M0-01 from In progress to Complete in the authoritative implementation status.
No M0 proof was run or claimed as passed.

## Files changed

- `docs/decisions/mvp-risk-register.md` — 11 proof-gate rows covering Stytch,
  Neon, LocalStack/real AWS, Cartography, Prowler, Tetragon, Nango free
  Auth+Proxy, Promptfoo, embedded OPA, OpenSearch/SQS, and Fargate. Every row
  supplies objective PASS and FAIL outcomes, an owner/decision consequence,
  and an initial `Not run` status.
- `docs/internal/implementation_status_v1.5.md` — updates M0-01 and the
  source-task/milestone status counts from In progress to Complete.

## Verification evidence

- `git diff --check` completed successfully.
- Required-name checklist completed successfully for: Stytch, Neon, LocalStack,
  real AWS, Cartography, Prowler, Tetragon, Nango, Promptfoo, OPA, OpenSearch,
  SQS, and Fargate.
- The register contains 11 risk rows and 11 `Not run` initial statuses.
- Manual review confirmed that LocalStack proof is not treated as real-AWS
  parity; Nango is limited to free self-hosted Auth + Proxy and excludes
  Functions/Webhooks/MCP; OPA is embedded/in-process; OpenSearch/SQS retain
  projection-versus-durable-queue roles; and Fargate includes isolation,
  egress, and cleanup criteria.

## Self-review

- PASS conditions name observable test outputs rather than vendor capability
  assertions.
- FAIL conditions are the inverse of the evidence required by their gate.
- Each owner has a decision consequence that blocks only dependent work, not
  unscoped implementation.
- Initial statuses make no claim that an external proof has executed.

## Concerns

None for this documentation-only microtask. The actual external and OSS proof
outcomes remain intentionally unresolved until their dependent M0 tasks run.

## Fix Round 1

### Files changed

- `docs/decisions/mvp-risk-register.md` — added explicit OTLP Collector,
  PostHog privacy, and OpenRouter/privacy-plus-bounded-planner proof rows;
  made OPA's local latency threshold measurable; and tightened Neon,
  OpenSearch, Nango, and Fargate acceptance criteria.
- `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-01-report.md` — appended this correction evidence.

### Verification commands and output

```text
$ git diff --check
(no output; exit 0)

$ for row in R-01 R-02 R-03 R-04 R-05 R-06 R-07 R-08 R-09 R-10 R-11 R-12 R-13 R-14; do rg -q "| $row" docs/decisions/mvp-risk-register.md || exit 1; done; printf 'All 14 risk rows: PASS\\n'; printf 'Initial Not run statuses: '; rg -c 'Not run —' docs/decisions/mvp-risk-register.md
All 14 risk rows: PASS
Initial Not run statuses: 14

$ for pattern in 'Stytch' 'Neon' 'LocalStack' 'real AWS' 'Cartography' 'Prowler' 'Tetragon' 'Nango.*free self-hosted.*Auth.*Proxy boundary' 'Promptfoo' 'Embedded OPA' 'OpenSearch.*SQS' 'EKS Fargate' 'OTLP Collector ingest.*bounded export' 'PostHog privacy filtering' 'OpenRouter privacy.*bounded Security Agent planning'; do rg -q "$pattern" docs/decisions/mvp-risk-register.md || exit 1; done; printf 'Comprehensive required-risk checklist: PASS\\n'
Comprehensive required-risk checklist: PASS
```

### Self-review

- Every M0 external/OSS proof task from M0-02 through M0-22 is now represented
  by a row, including the optional-dependency privacy gates and bounded planner
  boundary.
- OPA uses a fixed p95 threshold (`<= 10 ms`) with a fixed warm-up and sample
  count, so pass/fail is decidable before measurement.
- The Fargate proof names its scheduling signal, exact canary response,
  cleanup objects, allowlisted endpoint classes/ports, and denied direct-egress
  assertion.
- M0-01 remains Complete because this correction finishes its risk-register
  deliverable; all proof rows remain `Not run` and no later M0 task started.
