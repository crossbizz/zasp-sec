# Production Web/API Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> execute this plan. Use `superpowers:test-driven-development` for every
> behavior change and `superpowers:verification-before-completion` before every
> completion claim.

**Goal:** Deliver a production-usable Zasp application in which every visible
workflow uses the composed Go API and durable authorized state through one
public origin.

**Architecture:** The edge serves the web application and routes relative
`/api/v1/*` requests to one composed `agentsec-api`. The API authenticates the
human session, resolves tenant scope and authorization, dispatches exact
OpenAPI operations to durable domain services, and exposes health separately.
The frontend uses one generated-client transport and feature query modules;
production never falls back to `DEMO_STATE` or local product persistence.

**Tech stack:** React, strict TypeScript, Next.js standalone containers,
`openapi-fetch`, Go 1.25, PostgreSQL/Neon, OpenSearch, Neo4j, S3, SQS, Stytch
B2B, Kubernetes/Helm, Vitest, Testing Library, Go race tests, and browser E2E.

**Design:**
`docs/superpowers/specs/2026-08-18-production-web-api-integration-design.md`

## Delivery Rules

- Execute related microtasks in batches; do not stop between microtasks for
  approval.
- Start every behavior with a failing focused test and retain the regression.
- A route is visible in production only if every control it renders has an
  authorized durable API operation.
- Mapping, generated-client, fixture, or mocked-handler tests are not end-to-end
  evidence.
- Never use local product data, in-memory authoritative stores, or fake success
  in production.
- Preserve exact tenant scope, fixed error envelopes, audit correlation, and
  provider cleanup boundaries.
- Land small atomic commits inside each batch; run the batch gate at its end.

---

### Task 1: Batch 1 — Production transport, composed API, and core risk workflow

**Outcome:** A signed-in browser can load durable overview, agent inventory,
findings, and attack paths, perform a finding mutation, reload, and observe the
authoritative result.

**Primary files:**

- Create: `services/platform/apiserver/router.go`
- Create: `services/platform/apiserver/router_test.go`
- Create: `services/platform/apiserver/composition.go`
- Create: `services/platform/apiserver/composition_test.go`
- Modify: `services/platform/agentsec-api/main.go`
- Modify: `services/platform/agentsec-api/main_test.go`
- Modify: `openapi/openapi.yaml`
- Modify: `apps/web/api/client.ts`
- Modify: `apps/web/api/client.test.ts`
- Create: `app/api/APIProvider.tsx`
- Create: `app/api/query.ts`
- Create: `app/api/query.test.tsx`
- Create: `app/auth/SessionProvider.tsx`
- Create: `app/auth/SessionProvider.test.tsx`
- Modify: `app/components/ZaspApp.tsx`
- Modify: `app/features/overview/OverviewView.tsx`
- Modify: `app/features/agents/AgentSecurityView.tsx`
- Modify: corresponding focused component tests
- Create: `app/integration/core-risk-workflow.test.tsx`

### Microtasks 1–30

- [ ] 1. Add a failing API-router test for exact method/path dispatch, duplicate
  registrations, encoded paths, trailing slashes, unsupported methods, and the
  fixed not-found/method error envelopes.
- [ ] 2. Implement the minimal exact operation router without a permissive
  catch-all.
- [ ] 3. Add a failing composition parity test that reads the public OpenAPI and
  proves every mounted operation is unique and every required core operation is
  mounted.
- [ ] 4. Define the composition dependency struct and fail closed on nil,
  malformed, or duplicate handlers.
- [ ] 5. Mount identity/session bootstrap operations through the exact router.
- [ ] 6. Mount home summary and global-search operations.
- [ ] 7. Mount inventory agents/tools/identities/runtimes operations.
- [ ] 8. Mount findings, finding actions, attack paths, and break-option
  operations.
- [ ] 9. Add middleware tests for correlation IDs, request-size limits, content
  type, panic containment, and fixed product errors.
- [ ] 10. Add session-cookie authentication tests, exact same-origin mutation
  checks, CSRF validation, 401/403 separation, and tenant-nondisclosure.
- [ ] 11. Extend the OpenAPI contract with session bootstrap/callback/sign-out
  and the browser cookie/CSRF semantics; regenerate and check the client.
- [ ] 12. Add strict startup configuration for product/internal listen
  addresses, public origin, cookie policy, provider timeouts, and environment.
- [ ] 13. Split `agentsec-api` into bounded public `:8080` and internal `:8081`
  listeners while retaining exact health behavior.
- [ ] 14. Gate readiness on validated configuration, migration state,
  repositories, identity verification, and route composition.
- [ ] 15. Add independent bounded drain/close tests for both listeners, including
  panic, partial startup, cancellation, and cleanup-precedence cases.
- [ ] 16. Add a production-mode test that rejects every memory-store dependency.
- [ ] 17. Wire durable PostgreSQL repositories for session/scope and
  transactional core records, including organization-scoped reads and writes.
- [ ] 18. Wire existing OpenSearch/Neo4j readers for findings/search/paths and
  prove provider failure never returns fixtures.
- [ ] 19. Add migration-schema compatibility and restart-persistence integration
  tests for the first vertical slice.
- [ ] 20. Configure one application API client with relative base URL,
  same-origin credentials, bounded timeout, abort propagation, correlation ID,
  CSRF header, and fixed error decoding.
- [ ] 21. Add hostile client tests for cross-origin base URLs, redirect-like
  inputs, malformed success, HTML errors, oversized bodies, timeout, abort, and
  session expiry.
- [ ] 22. Implement `APIProvider` and a small typed query state machine covering
  idle/loading/empty/success/stale/forbidden/error and mutation invalidation.
- [ ] 23. Implement `SessionProvider` bootstrap, sign-in redirect, scope state,
  sign-out, expired-session cache clearing, and capability exposure.
- [ ] 24. Replace production `ZaspStoreProvider` composition with session/API
  providers; retain demo fixtures only behind an explicit development entry.
- [ ] 25. Generate navigation from server capabilities and prove unavailable or
  unauthorized routes and buttons are absent.
- [ ] 26. Convert Overview to `getHomeSummary` and global-search data, including
  loading, empty, degraded, stale, and retry states.
- [ ] 27. Convert Agents/Tools/Identities/Runtimes lists and details to inventory
  APIs with real filters, pagination, relationships, capabilities, and sessions.
- [ ] 28. Convert Findings and Attack Paths to APIs, including durable status,
  risk acceptance, ticket, break options, validation conflicts, and audit IDs.
- [ ] 29. Add a real-HTTP frontend/API integration test: authenticate, bootstrap,
  load overview, open agent/finding/path, mutate finding, restart the API,
  reload, and prove persistence and tenant isolation.
- [ ] 30. Run and record the Batch 1 gate:

```bash
go test -C services/platform -race -count=1 ./apiserver ./agentsec-api ./identity ./reconciliation
npm run openapi:generate
npm run openapi:check
npm test -- apps/web/api/client.test.ts app/api app/auth app/features/overview app/features/agents app/integration/core-risk-workflow.test.tsx
npm run typecheck
npm run lint
npm run build
git diff --check
```

---

### Task 2: Batch 2 — Policy, integrations, sensors, and security-agent workflow

**Outcome:** Operators can configure a real integration, observe sensor state,
create/simulate/roll out a policy, and plan/approve/run a security agent with
durable audit history.

### Microtasks 1–28

- [ ] 1. Add route-composition RED tests for policy, integration, sensor, and
  security-agent OpenAPI operations.
- [ ] 2. Construct and mount policy services with durable policy/decision stores.
- [ ] 3. Construct and mount integration catalog and connection services.
- [ ] 4. Construct and mount sensor enrollment, heartbeat, rotation, and coverage.
- [ ] 5. Construct and mount security-agent templates, plans, approvals, runs,
  verification, response, audit, and expiry operations.
- [ ] 6. Add organization/workspace/environment authorization tests for every
  mounted operation.
- [ ] 7. Add restart-persistence tests for policies, integrations, sensors,
  plans, approvals, runs, and audit state.
- [ ] 8. Add idempotency and ambiguous-provider-result reconciliation tests for
  all mutations.
- [ ] 9. Add bounded provider timeout, cancellation, and cleanup-precedence tests.
- [ ] 10. Add feature query modules and exact cache keys for the four domains.
- [ ] 11. Convert Policies list/detail from static/local state to API reads.
- [ ] 12. Convert policy create wizard to durable API validation and creation.
- [ ] 13. Convert simulation, rollout, disable, and decision history controls.
- [ ] 14. Convert connector catalog/list/detail views to API queries.
- [ ] 15. Convert connector create/update/delete/authorize/sync operations.
- [ ] 16. Add secret-field one-time-display, redaction, and browser-memory tests.
- [ ] 17. Convert sensor list/detail/coverage to API queries.
- [ ] 18. Convert sensor enrollment, update, delete, and token rotation.
- [ ] 19. Convert security-agent list/templates/detail to API queries.
- [ ] 20. Convert plan simulation and deterministic preview.
- [ ] 21. Convert approval queues with fresh-auth enforcement.
- [ ] 22. Convert run execution, progress polling, cancellation, verification,
  and cleanup outcomes.
- [ ] 23. Convert response automation and webhook status without exposing secrets.
- [ ] 24. Add capability-gated navigation and disabled/degraded provider states.
- [ ] 25. Add accessibility and keyboard tests for all dialogs/wizards.
- [ ] 26. Add real-HTTP integration tests for the complete policy and
  security-agent flows.
- [ ] 27. Add deployed persistence smoke tests for integration and policy state.
- [ ] 28. Run Go race, generated-client, focused UI, full type/lint/build,
  dependency, audit, and diff gates.

---

### Task 3: Batch 3 — Identity administration, sessions, compliance, and operations

**Outcome:** Administrators can manage scoped access and audit state, and users
can investigate sessions and produce durable compliance evidence/exports.

### Microtasks 1–28

- [ ] 1. Mount remaining identity, administration, session-control, compliance,
  data-control, external-flow, and system-health operations.
- [ ] 2. Replace concrete memory dependencies with durable repository interfaces.
- [ ] 3. Add exact deployment-mode behavior for SaaS and single-tenant profiles.
- [ ] 4. Add SSO callback/session refresh/sign-out and fresh-auth boundaries.
- [ ] 5. Add SCIM webhook verification and deprovision reconciliation wiring.
- [ ] 6. Add API-token creation, one-time display, hashing, rotation, revocation,
  permission, and audit wiring.
- [ ] 7. Add group mapping, role, scope, and principal persistence.
- [ ] 8. Add session/event projection and evidence linkage persistence.
- [ ] 9. Add compliance controls, evidence, export, and data-control persistence.
- [ ] 10. Add system component aggregation and external-flow inventory wiring.
- [ ] 11. Add tenant-isolation, stale-session, deprovision, and role-change tests.
- [ ] 12. Add durable restart and concurrent-update/version-conflict tests.
- [ ] 13. Convert organization/workspace/environment onboarding UI.
- [ ] 14. Convert members and built-in roles UI.
- [ ] 15. Convert SSO connection UI.
- [ ] 16. Convert SCIM connection UI.
- [ ] 17. Convert group mapping UI.
- [ ] 18. Convert API access UI.
- [ ] 19. Convert audit log/export UI.
- [ ] 20. Convert sessions list/detail/timeline UI.
- [ ] 21. Convert compliance controls/evidence/export UI.
- [ ] 22. Convert data retention/deletion UI.
- [ ] 23. Convert external data-flow UI.
- [ ] 24. Convert system health/degraded component UI.
- [ ] 25. Add capability/fresh-auth gating and secure one-time-value handling.
- [ ] 26. Add browser E2E for onboarding, access change, session investigation,
  export, reload persistence, and cross-tenant denial.
- [ ] 27. Add operator runbook checks for deprovision and export failure recovery.
- [ ] 28. Run the complete batch verification matrix.

---

### Task 4: Batch 4 — Red team, Attack Lab, reports, and remaining product surfaces

**Outcome:** Every remaining visible production route is API-backed; prototype
stores and duplicate/static route surfaces are removed from production code.

### Microtasks 1–27

- [ ] 1. Mount red-team tests/runs and Attack Lab operations with durable state.
- [ ] 2. Mount AI explanation and remaining response operations.
- [ ] 3. Define and mount report list/detail/export/schedule operations where the
  current OpenAPI lacks the prototype workflow.
- [ ] 4. Define and mount any remaining guardrail activity/control operations or
  explicitly merge them into policy/runtime-decision contracts.
- [ ] 5. Add job-queue wiring and idempotency for scans, exports, and schedules.
- [ ] 6. Add artifact-store wiring for reports and red-team evidence.
- [ ] 7. Add timeout, cancel, retry, late-apply reconciliation, and cleanup tests.
- [ ] 8. Add tenant-isolation and authorization tests for every new operation.
- [ ] 9. Convert red-team target/test configuration UI.
- [ ] 10. Convert red-team launch/progress/cancel/rerun UI.
- [ ] 11. Convert red-team result/finding/evidence UI.
- [ ] 12. Convert Attack Lab launch/status/cancel/rerun UI.
- [ ] 13. Convert guardrail dashboards/activity/policies/playground to contracted
  runtime-policy APIs.
- [ ] 14. Convert reports list/detail/export/schedule UI.
- [ ] 15. Remove duplicate demo/API component rendering in `RouteSurface`.
- [ ] 16. Remove product actions from `demoReducer` and product fields from local
  persistence.
- [ ] 17. Move permitted presentation preferences to a minimal preferences store.
- [ ] 18. Remove production imports of `DEMO_STATE`, seed records, and fixture APIs.
- [ ] 19. Add a build-time production fixture-import prohibition.
- [ ] 20. Reconcile the UI/API map against actual browser network operations.
- [ ] 21. Require all production routes to be API-backed or capability-hidden.
- [ ] 22. Add responsive desktop/tablet/mobile E2E for every visible route.
- [ ] 23. Add keyboard, focus, dialog, table, and form accessibility checks.
- [ ] 24. Add browser security tests for credential/cache/history leakage.
- [ ] 25. Add restart persistence and provider-degraded E2E for all workflows.
- [ ] 26. Delete obsolete demo reset copy/control from settings and README.
- [ ] 27. Run the complete frontend/API verification and production build matrix.

---

### Task 5: Batch 5 — Same-origin deployment, observability, resilience, and release

**Outcome:** Immutable web/API artifacts deploy behind one origin, pass real
browser-to-durable-store smoke tests, and can be operated safely.

### Microtasks 1–26

- [ ] 1. Add exact web and API production container builds with non-root users,
  read-only filesystems, health ports, and bounded resources.
- [ ] 2. Correct product/internal API service ports in local and staging charts.
- [ ] 3. Add one ingress/edge route: `/api/v1/*` to API, everything else to web.
- [ ] 4. Prove `/internal/*` and provider services are not publicly routed.
- [ ] 5. Add TLS, HSTS, CSP, frame, content-type, referrer, and permissions headers.
- [ ] 6. Add exact allowed-origin, trusted-proxy, host, and forwarded-header checks.
- [ ] 7. Add secret-manager wiring for Stytch, database, and provider credentials.
- [ ] 8. Add migration Job and require successful exact schema before rollout.
- [ ] 9. Add NetworkPolicies for web/API/providers and required egress only.
- [ ] 10. Add disruption budgets, topology spread, rolling update, and drain bounds.
- [ ] 11. Add structured redacted request, audit, provider, and lifecycle logs.
- [ ] 12. Add metrics for latency, errors, auth, provider state, jobs, and saturation.
- [ ] 13. Add traces spanning edge, web, API, repository, queue, and provider calls.
- [ ] 14. Add correlation ID presentation and operator lookup flow.
- [ ] 15. Add backup/restore and migration rollback procedures.
- [ ] 16. Add rate limits, request/body limits, abuse tests, and dependency budgets.
- [ ] 17. Add browser E2E against the deployed same-origin stack.
- [ ] 18. Add cross-tenant and privilege-escalation deployment tests.
- [ ] 19. Add restart, replica loss, provider outage, queue delay, and stale-read tests.
- [ ] 20. Add performance budgets for initial load and core API operations.
- [ ] 21. Add production synthetic health and critical-workflow canaries.
- [ ] 22. Add SBOM, license, dependency, image, and secret gates.
- [ ] 23. Update operator, deployment, authentication, recovery, and user docs.
- [ ] 24. Remove prototype production claims and publish exact supported workflows.
- [ ] 25. Run one clean deployed lifecycle with browser-to-durable-store evidence,
  restart persistence, cleanup, and immutable artifact fingerprints.
- [ ] 26. Push the exact reviewed SHA, require successful remote CI/deployment gates,
  and record the final production URL and evidence.

## Overall Completion Gate

The work is complete only when:

- every production-visible control performs an authorized durable API action;
- no production bundle imports demo product state or fixture APIs;
- the browser uses one public origin and internal/provider endpoints are private;
- authentication, tenant isolation, migrations, audit, observability, backups,
  and bounded shutdown are active;
- deployed E2E proves sign-in, core workflows, reload/restart persistence,
  degraded behavior, and cross-tenant denial;
- local and remote verification pass for the exact shipped commit.
