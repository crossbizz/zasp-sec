# Cloud continuation verification, October 2, 2026

The original 728 requirements remain binding. This is a reviewed development
batch and fresh blocker reassessment, not final production acceptance.

## Checkpoint and environment

Initial clean HEAD, fetched `origin/main` and GitHub main API all matched
`e13ccb95451b03107681ccb59b3fc6fe175a228f`. Current cloud observations reported
enforced restricted networking and ready injection for `STYTCH_PROJECT_ID`,
`STYTCH_SECRET`, `STYTCH_PUBLIC_TOKEN` and `GITHUB_TOKEN`. Presence checks and
actual authenticated GitHub repository/main and existing Stytch organization
search calls succeeded without printing credential values. GitHub returned
push/admin repository permissions; reading main branch protection returned 403.
Neither injection nor repository metadata establishes deployed acceptance.

Official Superpowers commit `8ca22dba9a94f28898bbce59f2537ff4d87c747d` was
installed in the cloud user's skill directory; all 15 SKILL.md files were
verified. TDD, systematic debugging, independent review and verification were
used. Node22.23.1, npm10.9.8 and Go1.25.13 were prepared explicitly, and locked
npm dependencies installed. Helm3.19 and gitleaks8.30.1 were prepared. Missing
Go modules were downloaded through an allowed checksum-verified mirror; TLS,
proxy, sum verification and refusal policies remain enabled.

The historical handoff manifest describes a different local checkpoint:
77,094 captured entries, 71,162 absent here and 46 changed relative to that
historical manifest. No deleted manifest entry remains. The merged main
continuation explicitly states that ignored archives and old runtime binaries
are not supplied by this checkout. They were not fabricated or treated as
current authority. The installed skills and private proof binaries are not
repository artifacts.

## Reviewed changes and fresh checks

- `6eeea16a`: [exact licensed Nexus successor](2026-10-02-nexus-license-successor.md),
  preserving all eight pre-existing archive files and the license policy.
- `92b8a0ac`: [companion import closure](2026-10-02-companion-source-closure.md),
  preserving historical packets and strict source/refusal boundaries.
- Test-only registration diagnostics now identify a failed statement using only
  its SHA256, closed phase and bounded SQLSTATE/error class. Original causes,
  query inputs, strict JSON refusals and the 4MiB cap remain. Grouped RED13
  refusals preceded implementation. Final race verification passed16 selected
  unit tests and18 diagnostic subcases, including contaminated driver fields,
  typed-nil errors, `%+#v`, cause identity and the exact byte boundary.
  Independent security review approved the exact two-file delta. No PostgreSQL
  reference or native capture was executed or promoted.

Fresh live Stytch JWT verification passed local and forced remote validation in
the existing Test project. A separate prebuilt application adapter passed
active-session acceptance, tampered-signature refusal and provider-confirmed
revocation refusal without skips. Both harnesses deleted only their newly
created, marker-verified disposable organizations; pre-existing identities
were preserved. The first adapter launch failed without a detailed diagnostic;
the subsequent prebuilt-binary run passed. This is real provider integration,
not deployed OAuth/SSO/browser acceptance.

Identity, authorization and orchestration race packages passed, as did the
affected Stytch application adapter race checks, twelve launch-runner tests,
dependency validation, UI typecheck and production build. An owned standalone
server returned HTTP200 for `/` and `/login` and was stopped and joined. The
configured production API endpoint itself remained unreachable.

The initial full UI run reported2525pass/10fail: nine five-second source-contract
timeouts and a Nango render check before Helm preparation. The affected267-test
source/dependency group and three Nango checks then passed. A second default
full run reported2534pass/1five-second timeout; the exact remaining source-family
case passed on focused retry (one pass,263 filtered skips). No timeout was
relabeled as a passing full suite or used as permission/native denial evidence.

The initial release suite lacked Helm. With Helm it reported283pass/2fail:
one cold offline Go-cache failure and a denied default module-download redirect.
After cache preparation, the compliance loader check hit its existing120s cold
build timeout. Preparing the test binaries separately and rerunning the unchanged
fixture then passed (one Node acceptance test, actual API/worker loader checks).
The complete release-source check advanced past licensing and failed the
unchanged full-history secret scanner:1413commits,322.18MB,538findings,10m22s.
The gate's log contains no finding metadata, so the538 findings remain
unclassified. A separate redacted JSON scan of the two new commits returned
zero findings; a separate scan of the two registration test files also returned
zero. Scanner rules and existing fingerprint exceptions were not changed.

An explicitly online exact-lock production npm advisory scan returned HTTP200
from the bulk advisory service and zero findings. Report SHA256:
`f30e96eff6d19505bad308a7a19cce337f9545e51ee08d85776e165d7fc8152e`.
Lock SHA256:
`d34f213a3222a5fd3cecea449bb4242ebe725bdb8a3c73a08d2eb3a66d687b01`.
This resolves advisory connectivity and supplies bounded npm production evidence;
it does not supply mandatory fresh Go/image scan evidence or an accepted full
scanner pipeline. The fail-closed release-advisory guard remains unchanged.

## Current blockers, classified from fresh evidence

| Gate | Fresh classification and next action |
| --- | --- |
| GitHub and Stytch credentials/connectivity | Resolved for the tested repository and existing Test-project APIs; do not repeat a missing-secret blocker. |
| Nexus exact-release license | Resolved by the verified licensed successor; the old tag remains historically unlicensed. |
| Full-history secret scan | Independent review classified538 baseline and two later documentation findings as noncredential data. Candidate435 exact fingerprints preserve existing exception bytes and pass synthetic new-commit/new-path detection controls. Full-history rescan passed1416commits/322.27MB/zero findings; subsequent source-copier/collation-fix range also passed. See reviewed-secret-scan evidence. |
| Release advisory acceptance | Incomplete implementation/evidence: npm production lookup works, but Go/image scan acceptance and exact-input pipeline remain open. Keep the guard. |
| API, app, Forgejo, artifact, Redis and Temporal services | Configured local endpoints refuse connections. Start the configured services or provide reachable deployed endpoints; injection readiness is not service health. |
| Flexprice | Denied access: HTTPS proxy CONNECT to `api.flexprice.io` returns403. Add this host through supported environment network configuration before its live check. |
| Database | Configured DSN exists, but no remote TCP grant is configured. Grant the configured database host/port through the supported environment workflow before testing credentials/TLS. No direct remote bypass was attempted. |
| OpenFGA/deployed API authority | Missing configuration: `ZASP_OPENFGA_URL`, `ZASP_OPENFGA_STORE_ID`, `ZASP_OPENFGA_MODEL_ID`, `ZASP_OPENFGA_TOKEN_FILE`, purpose-specific workflow/token-reveal keys, Stytch organization and webhook settings are absent. Supply the actual selected authority and secrets, without substituting unrelated injected keys. |
| Native authority | Incomplete acceptance: source closure and diagnostic prerequisites improved; reviewed successor A/B, Linux build/runtime binding, PG18.3/pgcrypto1.4 tools, registration reference, native379, portability and installed-worker gates remain. The B builder still expects its historical100-member seed and95-source roster; that is a successor implementation step, not an accepted current packet. |
| Legacy retirement | Incomplete acceptance: equivalent connected/cancellation/revocation/recovery receipts and native gates remain open. No legacy removal or routing/`current_ready() AND false` relaxation occurred. |

The production loader uses `ZASP_STYTCH_PROJECT_ID`, `ZASP_STYTCH_SECRET` and
`ZASP_STYTCH_PUBLIC_TOKEN`; the corresponding existing unprefixed inputs are
the correct command-scoped sources, with `test.stytch.com` for this Test project.
Likewise existing Temporal address/namespace inputs can populate their matching
`ZASP_TEMPORAL_*` fields, but task queues, TLS and OpenFGA authority still require
real configuration. A generic database DSN must not be mapped to both separately
privileged runtime roles, nor may session/service secrets be repurposed as
workflow, reveal or OpenFGA keys.

## Shipping and remaining work

[PR50](https://github.com/crossbizz/zasp-sec/pull/50) contains the reviewed
critical-path batches. Initial pushes succeeded and remote branch SHA was
checked; hosted checks are still separate evidence. Merge only after required
checks pass and repository permissions permit. A failing production gate did
not stop the independent diagnostic batch.

The authoritative TSV validator still reports728rows,523production-available
evidence categories,144component-only,61blocked/external and0missing. No row was
promoted. Next work is to capture/classify history-scan metadata while preparing
reviewed successor A/B and a Linux-bound registration bundle using the new safe
diagnostics, then retry native/connected acceptance with actual prerequisites.
The overall goal remains in progress; these remaining gates are not a claim that
all independent work is blocked or that all728conditions have passed.

## Later reviewed cloud batches and current receipts

The latest full local UI run passed2535/2535 tests across246files, superseding
the earlier failed full runs without erasing them. PR50 remains open; hosted
checks on the live-dispatch correction failed at Verify runnable UI. Its hosted
logs remain inaccessible through the environment proxy, so the step result is
not attributed to a specific local failure without evidence.

The [fixed cloud source copier](2026-10-02-cloud-source-regeneration.md) passed
89/89 on an independent coordinator rerun. Exactly171 inputs produce eight
deterministic source-only outputs;10052 source facts differ from the unchanged
historical10053 native expectation. Native adoption remains unaccepted.

Independent historical-blob review adjudicated538 baseline and two later
documentation scanner matches as noncredential data. The exact435 unique
commit/path/rule/line exceptions preserve all old bytes and scanner rules.
Synthetic canaries demonstrate detection for new commits and paths. The full
rescan passed1416commits with zero findings, followed by a clean bounded scan
of the two later batches; see [reviewed scan scope](2026-10-02-reviewed-secret-scan-findings.md).

The second immutable Linux original-registration attempt passed all seven
dispatch pins, sidecar pre/post verification and actual PG18.3 startup. It
failed SQLSTATE42703 at statement SHA256
`e61fd5bc920a9960e4586d0eb2a66d624cf02579899cd84a5ac37d800f9d92fc`.
Source-only query generation and the independently pinned PG18 bootstrap schema
identify the collation control witness's nonexistent collrules field; the real
field is collicurules. The [bounded correction](2026-10-02-pg18-collation-witness.md) passed RED/GREEN,
independent review and the coordinator grouped race rerun (18tests/40subtests). No reference output
was published; normal owned server shutdown and join passed, with no new PG
survivors. Two defunct processes from an earlier detached runtime smoke are
preserved as a historical cleanup limitation. No728 ledger row changes.
