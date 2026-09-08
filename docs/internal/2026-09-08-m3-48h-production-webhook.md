# M3-48h: production Generic Webhook setup

Status: implementation, independent review, full local release verification, Chrome E2E, and main CI complete.

Scope remains the 728-task v1.5 plan. This slice closes only M3-48h: configure,
test, and inspect signed Generic Webhook delivery through Connections. It does
not promote the remaining Security Agent response-webhook adapter or external
provider/deployment evidence.

## Implementation

- Migration 35 adds tenant-scoped test reservations, version/configuration
  binding, exact idempotent replay, a three-attempt lease fence, redacted status,
  audit records, forced RLS, and drift-checked readiness. Downgrade refuses to
  discard any delivery history. Prior discovery, workflow, and recovery
  readiness chains remain valid through v35.
- The product API accepts only `{}` at the saved integration's test endpoint.
  It requires the current version and an idempotency key. The service validates
  the fixed payload, tenant, resource, version, digest, destination, secret
  reference, and bounded lease before resolving secret material.
- Production composition uses the existing scoped Secrets Manager resolver and
  public-CIDR-pinned HTTPS sender. It signs exact bytes with HMAC-SHA256, rejects
  redirects, clears secret bytes, requires an empty HTTP 204 response, and
  durably records success or a stable redacted failure.
- Connections shows the durable test state instead of a discovery panel for
  Generic Webhook. Lost responses retain the exact intent/key and lock competing
  mutations. Reload reads the current configuration's status without sending.
- Signed/succeeded means Zasp signed and the endpoint accepted the request.
  It does not certify receiver-side signature verification. Failed/pending
  remain unconfirmed. A crash after delivery can cause a retry with the same
  delivery ID; receivers must deduplicate it.

## Verification evidence

- Superpowers test-driven-development and verification-before-completion
  practices: observed failing tests before implementation and fixes.
- Superpowers requesting-code-review: independent read-only Astra review found
  root URL and explicit-port validation drift, then caught an additional
  production transport path-normalization gap. Both were fixed with regressions.
- `TestIntegrationWebhookPostgresFencesTenantReplayVersionAndCompletion` passes
  using disposable PostgreSQL, actual up/down/re-up migration, tenant/version/
  token denial, immutable replay, and guarded rollback. It also runs the actual
  handler, service, PostgreSQL repository, production pinned round-tripper, and
  a trusted local TLS receiver. Root URLs and explicit port 443 each deliver once
  across exact retries; GET returns the persisted redacted result.
- Focused race tests pass for webhook service, signed transport, payload drift,
  status truth, and action-time URL rejection. UI/API tests prove retained
  retries, locked competing mutations, strict decoding, and secret redaction.
- Full API race suite passes (`go test -race ./apiserver -count=1`, 300.376s).
  Migration and migration-command suites pass, including v35 up/down/re-up.
- Full `npm run verify` passes: 184 Vitest files, 987 tests, type-check,
  lint, generated API contract, source and compiled production-import checks,
  release contracts, production build, and the 728-row ledger check.
- `npm run production:release:gate` passes the source SBOM, license,
  container, secret, resilience, and dependency checks. Built-image and
  deployment evidence remain external gates.
- The new installed-Chrome webhook flow passed twice: an unavailable signing
  secret records failed/unconfirmed through the actual API and PostgreSQL;
  response loss replays the same key/audit and reload creates no delivery.
  The broader run exposed an existing Home test race: its title wait matched
  navigation while the destination was still loading. An instrumented rerun
  confirmed the correct URL with loading=true. The harness now waits for an
  actual attack-path row and retains its authoritative-data assertion. The
  regression failed before the correction and passes after it; independent
  review approved the change.
- Fresh-build full Chrome rerun passes, including Home daily operations,
  automatic Security Agent execution, discovery retention, tenant denial,
  recovery, durable API restart/reload, and a clean browser exception stream.
- M3-48h is the only production-availability promotion in this slice:
  514 production-available, 153 component-only, 61 blocked/external, 0 missing.
  PR #8 merged as `7677cf2fde1a31fcd82a368091b5f1258f0bc3e4` on main.
  Main CI run `34286579436` passed the runnable UI and production release checks.

## Release boundary

Run schema v35 before rolling the API. Provision the exact approved public
destination CIDRs and signing secret as described in the deployment runbook.
No managed provider, production deployment, or customer usage is claimed by
the local verification above.
