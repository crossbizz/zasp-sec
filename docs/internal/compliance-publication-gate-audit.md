# Compliance publication gate audit

## September19 source revalidation

The browser prerequisite and CI-wiring gaps described below are historical.
Current source imports withBrowserPrerequisites before allocating its temporary
root. scripts/browser-prerequisites.mjs supports a validated explicit browser
path and platform-specific executable selection, with tool/compiled-UI checks
before setup. The current runnable-ui workflow provisions the exact browser
PostgreSQL digest, validates the selected browser and invokes the isolated
compliance browser mode explicitly at lines61-83.

This read-only inspection did not run hosted CI, pull an image or launch the
compliance flow. The declarations remove the earlier missing-wiring claim,
not the hosted execution gate. Do not implement that wiring a second time.
Current Attack Lab Task3 still needs its own connected acceptance path.

scripts/production-release-gate.mjs still ends with the explicit unavailable
advisory-evidence error after its local checks. Fresh approved dependency/image
scan evidence, exact-source hosted verification and live deployment acceptance
remain separate requirements. No scanner, release script or publication ran.

## Historical source inspection

Read-only controller inspection. No CI or release policy changed.

The sole checked-in workflow, `.github/workflows/runnable-ui.yml`, runs on push
and pull requests. It contains verification steps, not a deployment step. This
does not rule out external repository/deployment integrations; those were not
inspected and must not be inferred absent.

Its release-source step invokes `npm run production:release:gate`.
`scripts/production-release-gate.mjs` currently throws after preceding checks
because no approved fresh exact-lock advisory source is wired. No offline zero
count or local UI pass satisfies that gate. Do not bypass or call the pipeline
green while this remains unresolved.

Task5 made `production:combined-e2e:test` run legacy release48 compatibility and
the isolated current release56 compliance browser mode. However the checked-in
workflow and `npm run verify` do not invoke that actual combined browser command.
The workflow's Node harness tests inspect behavior/contracts; they are not a
browser execution. Existing Go API/worker checks cover some compliance
components, but do not substitute for this mounted current-source filter/export,
native download/restart/session-continuity flow.

Before connected release closure, explicitly wire the current compliance
browser acceptance into the appropriate CI/release path with its required
owned cached provider/database/browser prerequisites and bounded cleanup, or
record an external CI capability gate if those prerequisites are unavailable.
Preserve the separate legacy mode and all original acceptance obligations.
Do not use a static source assertion or opt-in default skip as hosted E2E proof.

The local final Task5 run and its reviewed fix remain valid local evidence.
Hosted CI execution and production deployment are separate unverified states.
The active API error-category fix is not responsible for this later CI wiring.

## Confirmed prerequisite gaps

Inspected the current harness and workflow on 2026-09-18. Adding the browser
command alone will not make the Ubuntu job runnable:

- `scripts/production-combined-e2e.mjs` assigns `chrome` to the macOS application
  executable at line 60 and passes it directly to the owned child launcher.
  The workflow selects `ubuntu-24.04`. There is no browser-path override at
  that assignment. The next implementation batch needs a validated executable
  selection and an early prerequisite check, before database creation or Go
  compilation. Preserve owned browser cleanup and do not silently skip a
  missing browser or weaken sandbox flags to get a green result.
- `scripts/owned-browser-postgres.mjs` creates the exact pinned PostgreSQL image
  with `--pull=never`. Installing PostgreSQL 18 client/server packages on the
  runner does not populate Docker's image cache. The workflow currently
  provisions a pinned LocalStack image but contains no provisioning step for
  the browser PostgreSQL digest. Any later hosted execution must explicitly
  provision and verify that exact image first; local inspection does not
  authorize a new local pull.
- The selected compliance mode builds the API test executable and worker test
  executable, uses `pg_config`/`psql`, creates its local TLS certificate with
  OpenSSL, and requires the compiled UI. Its provider is controlled test
  storage, not live AWS. Run this isolated mode once against the already-built
  UI at the feature boundary. Invoking the whole combined npm command here
  would rebuild the UI and also run the separate legacy compatibility flow.

Acceptance for the next batch must include executable-selection behavior tests,
fail-fast missing-prerequisite tests, preservation of bounded owned cleanup,
and an actual current compliance browser run. A local macOS pass cannot close
the hosted Linux execution gate. Retain existing legacy acceptance separately;
do not credit it as current release56 compliance acceptance.
