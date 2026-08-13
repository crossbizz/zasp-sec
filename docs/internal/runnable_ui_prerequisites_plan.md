# Runnable UI Prerequisites Plan

**Status tracker:** `docs/internal/implementation_status_v1.5.md`

These prerequisites enforce the user's requirement that the existing UI remain
runnable at every push while the v1.5 technical plan replaces demo behavior
with product APIs. They do not mark any source-plan microtask complete.

## Global constraints

- Preserve the existing UI behavior and visual starting point.
- Use Node 22.23.1 and npm 10.9.8 reproducibly.
- Keep all 20 existing tests passing.
- Tests, type-check, lint, and production build must all pass before a push.
- Do not weaken or disable lint rules to make the baseline pass.
- Do not add placeholder APIs or claim browser-local state is a product API.

## Task 1: PRE-01 — restore a reproducible clean UI baseline

Status: In progress.

Deliverables:

- Pin the repository's local Node runtime to 22.23.1 and npm to 10.9.8.
- Add a documented install command that ignores host-global libvips so Sharp
  uses its locked platform binary.
- Fix the 37 existing lint errors without disabling rules or changing intended
  UI behavior.
- Add one root verification command that runs tests, type-check, lint, and the
  production build in that order.
- Update `docs/internal/implementation_status_v1.5.md` when the task completes.

Verification:

- Clean dependency install succeeds with the documented command.
- Existing test suite reports 20/20 passing with pristine output.
- Type-check reports no errors.
- Lint reports no errors or warnings.
- Production build exits successfully.

## Task 2: PRE-02 — enforce the runnable UI at every push

Status: Pending.

Depends on: Task 1.

Deliverables:

- Add a GitHub Actions workflow for pushes and pull requests.
- Use the pinned Node/npm versions and locked install.
- Run the root verification command.
- Add a focused workflow/configuration test that proves every required quality
  gate remains wired without asserting irrelevant source formatting.
- Update `docs/internal/implementation_status_v1.5.md` when the task completes.

Verification:

- The workflow configuration test passes.
- The full root verification command passes locally.
