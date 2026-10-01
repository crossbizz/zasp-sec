# API-token reveal correction: October 1, 2026

Independent product slice based on main
`9d5c52dd32aa641e9f05cf8cfdeb8cd3e83af853`. Only the expiry parser and its
regression tests change product code. No SQL, schema, module, UI, authorization
engine or orchestration change is included. Independent source/security review
approved the exact product payload with no critical or important blockers.
Final snapshot release verification precedes commit and push.

PostgreSQL can return a numeric UTC offset where Go formats the same instant
with `Z`. The former text-roundtrip check rejected valid encrypted reveal grants.
The correction accepts equivalent instants with strict syntax and nanosecond
precision while keeping UTC-normalized AES-GCM associated data unchanged.
Tenant, principal, operation, token and grant bindings remain authenticated;
SQL still enforces expiry, live-token status and one-time acknowledgement.

## Fresh isolated verification

Node22.23.1 and Go1.25.13; Go commands use `-mod=readonly`.

- Regression RED on unchanged main reproduced four equivalent-format refusals
  and two malformed-offset acceptances. The reviewed correction then passed
  the affected race group (3.422s), including create/rotate reveal, durable grant
  metadata, workflow handlers, timestamp validation and bounded grant cleanup.
- Exact-scope environment-target race controls passed separately (1.616s).
- Existing disposable PostgreSQL group passed all four cases with zero skips
  (6.168s): production migrations/create/rotate/restart, global expired-secret
  destruction, invalid-grant starvation and hostile administration keysets/scope.
  No production credentials or provider calls were used. The existing fixture
  owns cleanup; no stronger independently instrumented shutdown claim is made.
- Fresh local UI typecheck and production build passed through the release
  runner. All eight affected API-access UI tests passed (1.53s). No entire
  API-package or deployed-browser pass is claimed.

Independent review read the complete PostgreSQL log, verified both payload
blobs and checked the unchanged production HTTP/repository/SQL boundary.
It approved the two-file correction without critical or important findings.
The normal-stop status is not independently evidenced by the existing fixture:
it waits after stop or kill fallback but ignores those return errors. The terse
PASS log is not a separate clean-process or pg_ctl-status observation.

The private PostgreSQL log SHA256 is
`b457ad3f960bdfaeec180dcd9602327bf259223c6f312ba638123b039707bc0e`.
Product source Git blob:
`82942beb2e4fc556ac8620193f37be7de750ac44`; regression-test blob:
`bf0cc0b5119f493285e6fb541c63b4bc2168ea3e`.

This corrects an existing product endpoint, not the complete728-task launch.
Task availability classifications, Temporal/OpenFGA migration, full ordered
migration parity, provider deployment, real Stytch and production acceptance
remain unchanged and open. Artifact/refresh runner prerequisites on main stay
blocked until their separate reviewed generator batch lands. No model or global
configuration change is included.
