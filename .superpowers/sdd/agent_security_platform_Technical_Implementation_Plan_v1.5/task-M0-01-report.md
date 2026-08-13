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
