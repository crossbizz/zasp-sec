# Scoped history integration

Continue Task1 of the public-proof plan and design. Existing proof rendering is
implemented, but navigation/reload acceptance remains missing. Implement it with
Superpowers TDD. User authorization permits autonomous in-scope decisions.

Own these files only: app/domain/activity-links.ts and .test.ts;
app/features/securityagents/ActionDetails.tsx, ExistingTestEvidence.tsx and
ExistingTestEvidence.test.tsx; SecurityAgentsView.tsx and .test.tsx;
app/features/redteam/ProductionRedTeamView.tsx and .test.tsx;
app/components/ZaspProductionApp.tsx and .test.tsx;
docs/internal/2026-09-17-existing-test-proof-history-report.md.

Extend the strict existing activity link helper with kind test_run, route
/red-team/results. Do not add a backend activity-association kind. Preserve all
scope/ID validation and scope-mismatch rejection; links never switch tenants.
Pass the current ActivityScope, onNavigate and explicit red-team.read permission
from production SecurityAgentsView through RunDetail/ActionDetails to evidence.
Both normal and selected-run routes must propagate the permission. Show links to
the linked run and recorded before/after runs only when permitted, with current
scope in the exact helper URL. No provider/storage links or write requests.

ProductionRouteSurface must pass a parsed test_run selection into the real
ProductionRedTeamView. Opening or reloading that scoped URL must load the exact
test run through existing scoped getRun API and open its drawer, even when that
run isn't in the current list. Abort/ignore stale detail reads when selection or
scope changes/unmount; don't display prior-scope data. Preserve existing mutation
recovery, manual run selection and authorization/loading handling. No hooks after
early returns. Invalid IDs/foreign scope must not make detail requests.

Tests must cover emitted exact current-scope URLs, permission/no-scope absence,
deep-link/reload drawer selection, run absent from list, errors and stale detail
responses, plus existing activity parser boundaries. Observe RED before code.
Run affected focused web tests and typecheck once; controller owns grouped build,
independent review and full browser. No other files, staging, commit, push,
database, installs, network or subagents. Preserve dirty inherited changes.

Record exact RED/GREEN commands and results plus remaining limits in the report.
