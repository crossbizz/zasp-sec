# Test history links now open the stored run

The recorded-proof panel links its linked run and available before/after attempts
to `/red-team/results`. Each URL retains the current organization, workspace and
environment. The strict activity helper now accepts `test_run`; the backend
association kinds are unchanged.

I passed `canReadTests`, the active scope and the existing route callback through
both production Security Agent paths, the run drawer and `ActionDetails`. Without
Red Team read permission, scope or a route callback, the panel keeps the evidence
but emits no history link. Links are absent while a run cancellation is unresolved,
matching the existing drawer's route lock.

The Red Team surface reads `selectedID` through its existing scoped `getRun` API.
The selected run doesn't have to appear in the current list. Reloading the URL
opens its drawer again. The list's authorization/loading states still apply.

Detail requests abort on selection, scope, API authority or query-generation
changes and unmount. Returned detail belongs to a particular selection/query epoch
and API instance, so an old drawer isn't visible during the next effect. Existing
manual selection and mutation recovery still use the same surface and recovery
instance. Hooks run before the loading/error returns.

## Changed files

- `app/domain/activity-links.ts` and its tests.
- Evidence wiring: `app/features/securityagents/ActionDetails.tsx`, `ExistingTestEvidence.tsx`, `ExistingTestEvidence.test.tsx`, and `SecurityAgentsView.tsx`.
- I added selected-run handling and tests in `app/features/redteam/ProductionRedTeamView.tsx` and `ProductionRedTeamView.test.tsx`.
- `app/components/ZaspProductionApp.tsx` passes the parsed selection; its tests exercise the real provider/session/client flow.
- This report. I didn't need to edit `SecurityAgentsView.test.tsx`; its full existing suite ran with the affected tests.

## RED first

Commands ran from `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/budget-recovery-20260916`.
I followed the TDD and verification-before-completion skills.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/domain/activity-links.test.ts app/features/securityagents/ExistingTestEvidence.test.tsx app/features/redteam/ProductionRedTeamView.test.tsx -t 'test_run|history|selected|prior-scope'
```

Exit 1: 6 failed, 7 passed, 60 skipped. The helper rejected `test_run`, the proof
panel had no links, selected run detail was never loaded, and invalid selected
IDs had no explicit error. These were the missing behaviors.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/components/ZaspProductionApp.test.tsx -t 'Red Team history'
```

Exit 1: 3 failed, 1 passed, 17 skipped. Open/reload had no drawer, and a foreign
test-run link was classified as invalid because the route wasn't registered yet.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/components/ZaspProductionApp.test.tsx -t 'passes Red Team read permission'
```

The first run exposed a fixture omission: its effect ID had no paired result
digest, so the existing decoder correctly rejected it. I fixed the fixture,
then reran before changing permission propagation. Exit 1: 2 failed, 2 passed,
21 skipped. Both permitted routes rendered evidence but had no history link;
both denied routes passed.

## GREEN and final checks

After implementation:

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/domain/activity-links.test.ts app/features/securityagents/ExistingTestEvidence.test.tsx app/features/redteam/ProductionRedTeamView.test.tsx app/components/ZaspProductionApp.test.tsx -t 'test_run|history|selected|prior-scope|passes Red Team read permission'
```

Exit 0: 21 passed, 77 skipped.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/domain/activity-links.test.ts app/features/securityagents/ExistingTestEvidence.test.tsx app/features/securityagents/SecurityAgentsView.test.tsx app/features/redteam/ProductionRedTeamView.test.tsx app/components/ZaspProductionApp.test.tsx
```

Exit 0: all 166 tests passed across five files. These include exact link URLs,
permission and scope absence, stale selection responses, scope changes, unmount
aborts, malformed selection, missing detail, absent-list history, real-client
scope headers, reload selection, and the existing manual selection/recovery tests.
Production history tests made GET requests only; invalid and foreign URLs made no
detail request or scope mutation.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npm run typecheck
```

Exit 0. One typecheck run, as requested.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx eslint app/domain/activity-links.ts app/domain/activity-links.test.ts app/features/securityagents/ActionDetails.tsx app/features/securityagents/ExistingTestEvidence.tsx app/features/securityagents/ExistingTestEvidence.test.tsx app/features/securityagents/SecurityAgentsView.tsx app/features/redteam/ProductionRedTeamView.tsx app/features/redteam/ProductionRedTeamView.test.tsx app/components/ZaspProductionApp.tsx app/components/ZaspProductionApp.test.tsx
```

Exit 0, no diagnostics.

## Remaining checks belong to the controller

Independent review, grouped build gates and full browser acceptance remain open.
I didn't change backend contracts, capability enablement, storage access or the
existing Red Team artifact presentation. No database processes, installs, external
network calls, subagents, staging, commits or pushes. Inherited edits remain intact.
