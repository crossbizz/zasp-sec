# Persisted Action Details Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline with feature-batched review. The user authorized autonomous execution and grouped testing.

**Goal:** Complete M7A-87's persisted, tenant-scoped step arguments, results, TTL, rollback and verification display without protected values.

**Architecture:** Extend the unpublished54 authority projection, validate its binding and fixed fields in Go, and expose independently negotiated action details. A strict generated client and RunDetail render persisted evidence without inventing success from run-level state.

**Tech Stack:** PostgreSQL18, Go1.25.6, OpenAPI, TypeScript, React, Vitest and the owned Chrome acceptance harness.

**Spec:** `docs/internal/2026-09-16-security-agent-action-details-design.md`

## Batch checkpoint

The implementation is local and unpublished. Recorded evidence is in
`2026-09-16-release-verification-checkpoint.md`; this plan's unchecked compound
acceptance items are intentionally not closed by narrower passing checks.
The harness continuation finished55 passed/0 failed/2 opt-in skips (55dbe1).
Independent follow-up review closed the mounted outcome/cleanup/expiry coverage
note with no blocking source finding. Publication and live execution are unproved.

Database refusal batch8140c3 now passes eight real API-role cases for tampered
content, rehashed step/action/index/scope mismatches, empty/malformed steps and
ambiguous controls. Existing code passed; these are acceptance characterizations.
Review found no blocking issue; full-scope fixture synchronization and case naming
were tightened. Post-review rerunaccbf6 passes with owned database cleanup.
Same-organization/workspace run/step collision coverage now passes5e2153 with
distinct arguments, TTLs, effects and control expiry across two environments.
Independent review found no Critical/Important issue. Recorded failure, unknown
outcome and pending cleanup now pass actual HTTP/mounted-browser282837, including
plan/control no-mutation checks. This is seeded single-step display evidence,
not live action execution. Affected harness48d472 passes55 with2 opt-in skips.
Next reconcile remaining compound acceptance items and release gates. Reuse
unchanged build evidence only while its production inputs remain unchanged.

## Global constraints

- Keep schema53 unchanged. Recalibrate the unpublished54 pin after SQL changes.
- Unknown evidence is unavailable, never successful or zero by default.
- Arguments are action-specific allowlists. Credentials and arbitrary strings never become public fields.
- Preserve unique step bindings and persisted plan order.
- Execute database-heavy acceptance serially because this host has limited shared-memory IDs.
- No live-provider, production or publication claim from local fixtures.
- Focused RED/GREEN during coding; affected integration/review and release checks at the feature boundary.

## 1. Validated projection and authority integration

Files: create `services/platform/apiserver/security_agent_action_details.go`,
`security_agent_action_details_test.go`, `security_agent_action_details_postgres_test.go`;
extend `security_agent_run_context_envelope.go`, `security_agent_handler.go`,
`security_agent_repository.go`, migration54's projection fragment and its compiled pin.

Interfaces: `decodeSecurityAgentActionArguments(action string, raw json.RawMessage)`
returns `(*SecurityAgentActionArguments, error)`. Only fixed typed fields exist:
target_id, expected_version, target_status, mode, scope, ttl_seconds, session_id,
device_id and integration_id. Null returns unavailable; other input requires the
exact fields for that action. `SecurityAgentActionDetail` binds step_id/action to
the existing plan and includes arguments, result, TTL, expiry, rollback and
verification. SQL strips unknown raw plan fields before Go validates the projection.

- [x] Write literal tests for all four action argument shapes, null legacy data,
  foreign keys, secret strings, malformed IDs, versions, TTL and extra keys.
  Example behavioral assertions:
  ```go
  got, err := decodeSecurityAgentActionArguments("update_finding_response", json.RawMessage(`{"target_id":"pid_78000005-0000-4000-8000-000000000005","expected_version":2,"target_status":"under_review"}`))
  if err != nil || got.ExpectedVersion != 2 { t.Fatal("persisted finding arguments lost") }
  _, err = decodeSecurityAgentActionArguments("update_finding_response", json.RawMessage(`{"target_id":"password=sentinel","expected_version":2,"target_status":"under_review"}`))
  if err != ErrRepositoryUnavailable { t.Fatal("unsafe argument accepted") }
  ```
- [ ] Run `go test -C services/platform ./apiserver -run '^TestSecurityAgentAction' -count=1`.
  Establish behavior RED before implementing fixed allowlists and validators.
- [x] Implement the argument decoder with `decodeStrictDiscovery`,
  `exactJSONFields`, `validProductID` and bounded integer checks. Errors always
  return `ErrRepositoryUnavailable` with no input bytes.
- [x] Add literal effect/target-count tests. Derive apply and cleanup verification
  independently: nonempty/all-verified counts are verified, partial are pending,
  missing are unavailable. Direct action verification uses the effect's actual
  state. Policy cleanup state cannot stand in for application evidence.
- [x] Extend the private envelope with full run/plan binding and ordered selected
  steps. Use `jsonb_build_object` with only action allowlisted keys; joins include
  organization/workspace/environment/run/step/action. Reject ambiguity or a plan
  hash mismatch with a fixed exception. No raw plan object crosses this boundary.
- [ ] Add actual PostgreSQL cases: four actions, two same-looking foreign scopes,
  duplicate/missing step bindings, matching effect and target histories, no active
  cleanup targets, no-plan legacy run, and protected sentinels. Assert the public
  serialized detail contains neither sentinels nor private field names.
- [x] Recalibrate54 and run affected registered release/retention and consumer
  readiness tests. Keep historical pin evidence separate from the new pin.

## 2. Negotiated API and complete UI

Files: `security_agent_handler.go`, new `security_agent_action_details_http_test.go`,
`openapi/openapi.yaml`, `apps/web/api/generated.ts`, `apps/web/api/decoders.ts`,
`apps/web/api/decoders.security-agent.test.ts`, the real API client and
`app/features/securityagents/SecurityAgentsView.tsx` plus its tests.

Interface: an optional top-level `action_details` array only for an exact, single
`X-Zasp-Action-Details: v1` header. Existing context and budget negotiation remain
independent. Public objects use explicit nullable evidence fields and fixed enums.

- [x] Add HTTP tests for absent, repeated, unsupported and exact headers while
  toggling the other headers. Assert HTTP status and decoded response keys.
  ```go
  if _, found := body["action_details"]; found != wantDetails {
      t.Fatal("action-details negotiation changed the legacy response")
  }
  ```
- [x] Implement exact header selection after validating the authority response;
  do not let an opt-out hide malformed authority data.
- [x] Add OpenAPI schemas for the four fixed argument shapes, nullable result,
  TTL/expiry, rollback and independent verification. Run `npm run openapi:generate`.
- [ ] Add strict decoder tests for each action and every enum, unknown keys,
  duplicate/mismatched steps, invalid evidence and old-server omission. The
  decoder must reject malformed details before React sees them.
- [x] Send the opt-in header from the actual run-detail API client. Add explicit
  labeled fields beneath each execution step in persisted plan order. Use React
  text rendering, never arbitrary JSON or HTML; show unavailable evidence clearly.
- [ ] Add mounted tests covering every action, absent evidence, recorded cleanup,
  unknown outcomes, TTL versus expiry, and secret absence. Test real RunDetail:
  ```tsx
  expect(screen.queryByText("protected-action-sentinel")).not.toBeInTheDocument();
  expect(screen.getByText("Application verification unavailable")).toBeInTheDocument();
  ```

## 3. Feature boundary, review and publication

Files: owned combined-browser harness, authoritative status ledger and release checkpoint.

- [x] Run the affected Go race, client/UI and OpenAPI groups once after integration;
  run typecheck and scoped lint. Resolve failures with focused reruns.
- [x] Build the actual UI, verify production imports, then run owned API/browser54
  acceptance for action arguments/results and unavailable/cleanup evidence. Capture
  screenshots, inspect them, assert no protected values in HTTP/DOM and no console
  errors. Label owner-seeded histories as fixtures, not live action execution.
- [x] Request one independent feature review covering SQL scopes, argument
  redaction, exact contract, UI evidence semantics, migration trust and rollback.
  Fix blocking findings and rerun affected checks only.
- [ ] Update all original task evidence without changing availability based on
  unshipped local tests. Run required release gates and UI build before explicit
  staging/commit/push. Fresh dependency advisory clearance remains an external
  release gate; do not bypass it or publish while it fails.

Self-review: the three tasks cover all M7A-87 fields, protected-argument refusal,
tenant/plan/step binding, old-client compatibility and production publication.
No step substitutes run-level verification for per-action evidence.
