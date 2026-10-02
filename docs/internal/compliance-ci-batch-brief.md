# Compliance browser CI batch

Status: queued, not implemented or verified. This extends the publication work
in the approved compliance plan, not the product scope. Execute after the active
API final-fix batch and its independent review.

Read `compliance-publication-gate-audit.md` first. The current-source browser
acceptance exists and has reviewed local evidence. The gap is reliable execution
in the checked-in Ubuntu workflow. User authorizes autonomous bounded choices
and one verification/review cycle per connected feature batch.

## Files and boundaries

Modify `scripts/production-combined-e2e.mjs` and its tests, package.json only if
needed for a dedicated current-mode command, and
`.github/workflows/runnable-ui.yml`. Extract browser prerequisite selection to a
small adjacent module with behavioral tests if that avoids importing the
side-effectful full harness. Do not change product API/UI/SQL behavior, storage
authorization, release pins, the legacy compatibility mode, or the advisory gate.

Capture current before/after source identities and a scoped patch. The shipping
worktree has unrelated inherited edits; HEAD alone is not this batch's baseline.
Do not stage or push from the implementer. No child agents or duplicate review.

## Required behavior

1. Select an executable Chrome path on macOS and Linux. Allow an explicit
   operator path, reject relative paths/control characters, verify the target is
   an executable regular file, and launch it using an argument array. Never
   evaluate a shell command supplied as a browser path. An invalid explicit path
   fails rather than silently falling back. Preserve the present macOS default.
2. Check the browser and required local tools before database creation and Go
   compilation. Errors must identify the missing prerequisite and exit nonzero.
   No default skip or automatic local dependency/image downloads. Keep browser
   ownership, isolated profiles, bounded shutdown and existing sandbox flags.
3. Add a hosted prerequisite step that explicitly provisions and checks the
   exact PostgreSQL digest already consumed by the owned-container helper.
   This is future CI configuration, not permission to pull an image locally.
   Validate the hosted browser executable and record its version in CI output.
   Do not claim Linux acceptance based only on helper tests or a macOS run.
4. Run the isolated `ZASP_COMBINED_E2E_COMPLIANCE=true` browser mode against the
   UI already built by `npm run verify`, before the currently failing advisory
   release gate. Use a bounded step timeout. Do not invoke the combined npm
   command here because it rebuilds the UI and runs the separate legacy flow.
   Preserve all existing verification commands and fail-closed release policy.
5. Preserve the actual browser assertions: current source/version conflict,
   durable export through worker/API restart, exact native download bytes,
   single-use grants, sibling/foreign denial with positive controls, and final
   signed-in scope/DOM continuity. Controlled storage remains component evidence.

## One verification boundary

Use focused failing tests for executable selection and fail-fast orchestration,
then implement and run the grouped affected Node harness tests once. Selection
cases: macOS default; valid explicit Linux path; relative or control-character
path; nonexistent file; nonexecutable file; directory; explicit invalid path
with otherwise valid fallback; missing prerequisite prevents the setup callback.
Tests must exercise behavior, not only search source strings.

Then run one actual isolated compliance browser acceptance on available owned
cached prerequisites, retaining exit status, safe diagnostics and final screen.
Reuse unchanged product UI/type/build evidence only with matching source inputs;
new UI source changes require fresh verification. Before publication, run the
full required UI/type/lint/build gates on the final assembled source state.

Report exact commands, source identities, results, cleanup state, any Linux
execution gap, and unresolved advisory/live-provider gates. Request one scoped
independent spec-and-quality review. No task availability promotion follows from
CI wiring alone. Root owns authoritative ledger updates and publication.
