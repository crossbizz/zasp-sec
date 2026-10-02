# Stored proof rendering is in place

I added the optional recorded-test panel to the real `ActionDetails` component.
It uses the generated public types and renders only their named fields. No API
calls, storage reads, download links, route changes, or capability changes.

The panel keeps test outcomes separate from the action's effect state and the
Security Agent run status. Pending has no invented result. Settled records show
the safe outcome/reason labels, proof digest, both stored attempts when present,
their input digests, and input/output artifact reference digests, version IDs,
SHA-256 checksums and byte sizes. A comparison table shows each recorded check,
its before/after protection and HTTP status, and prompt/assertion digests.

Missing attempts say "No recorded evidence." Unknown cancellation says execution
is unconfirmed; confirmed partial cancellation says prior work was not undone.
Older action details without `existing_test` keep their existing presentation.

## Files touched

- `app/features/securityagents/ActionDetails.tsx`: imports and mounts the optional panel.
- New panel: `app/features/securityagents/ExistingTestEvidence.tsx`.
- I added complete typed fixtures and real-component tests in `app/features/securityagents/ExistingTestEvidence.test.tsx`.
- This report, `docs/internal/2026-09-17-existing-test-proof-ui-report.md`.

## Test evidence

All commands ran from `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/budget-recovery-20260916`.

I followed the Superpowers TDD skill. First, I wrote the tests and ran:

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/features/securityagents/ExistingTestEvidence.test.tsx
```

RED: exit 1, 10 failed and 1 passed. Every new rendering case failed because
`ActionDetails` had no accessible "Recorded test evidence" region. The legacy
absence test passed. No mocked component or imported test-file fixture.

After adding the panel, I ran the same command.

GREEN: exit 0, all 11 passed. Cases cover pending, remediation with full artifact
identities and comparison direction, missing baseline, missing after evidence,
unknown cancellation, confirmed partial and pre-execution cancellation, all
remaining outcome/reason pairs, and absence compatibility.

The verification-before-completion skill prompted fresh focused checks:

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx eslint app/features/securityagents/ActionDetails.tsx app/features/securityagents/ExistingTestEvidence.tsx app/features/securityagents/ExistingTestEvidence.test.tsx
```

Exit 0, no diagnostics.

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/features/securityagents/SecurityAgentsView.test.tsx -t 'redacted run and approval detail|persisted run|recorded|persisted action'
```

Exit 0, 5 passed and 63 skipped. The last selector matched no argument cases,
so I expanded it explicitly:

```sh
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:$PATH npx vitest run app/features/securityagents/SecurityAgentsView.test.tsx -t 'redacted run and approval detail|persisted run|recorded|persisted safe arguments'
```

Exit 0, 9 passed and 59 skipped.

## What remains outside this subtask

The controller owns scoped history links, route/reload handling, independent
review and grouped gates. I did not run TypeScript, a build, browser acceptance,
database processes or broad test suites. The proof panel relies on the existing
strict API decoder for bounds and association checks; it doesn't re-evaluate
the stored proof in the browser.

All inherited work remains untouched. No staging, commits or pushes.
