# Public export UI packet, 2026-09-19

The browser can now create a one-action export draft from the live action catalog. It uses the existing public definition, activation, execution-control and manual-run clients. No setup endpoint, composite export template, static readiness promotion, or new export panel.

I used the TDD skill before product changes and verification-before-completion for the checks below. Work stayed in the assigned OpenAPI/client/UI files. The controller also authorized the two affected expectations in `openapi/openapi.test.mjs` after its old seven-key snapshot failed. Existing dirty worktree edits were preserved; a diff against HEAD includes earlier packets and is not this packet's change count.

## What changed

The catalog-backed choice is named "Run-scoped evidence export". It requires the exact current catalog metadata: key `create_evidence_export`, verification `export`, low risk, target types exactly `[evidence]`, approval floor `none`, reversible true. Supervised execution still supplies the approval boundary. All catalog templates containing export are filtered from this builder, including composites. The native choice submits only export, fixes the step limit at one, has no existing-test reference, and saves disabled with the authorized environment. The local choice ID is never sent as product authority.

OpenAPI's control enums and the generated client include export. The decoder accepts the exact sorted eight-key shape and rejects arbitrary subsets, duplicate keys, unknown keys, and order drift. Historical exact 2/3/4/6/7 shapes remain readable for rolling compatibility; none contains export or can produce its control button. Workflow operators can create drafts from the catalog without identity-admin control-read permission. Control changes still require the existing identity-admin surface.

The real control adapter now admits export through the existing PUT route with fresh auth, If-Match and receipts. The tests exercise enabling and safe disabling, including disabling while global/environment controls are off, lost responses and fresh-auth withdrawal.

Two existing UI faults appeared during the export tests. Manual-start controls stayed visibly enabled after workflow permission was withdrawn, even though the retained-mutation hook refused dispatch. The button now disables. The activation retry button also locked itself after a lost response; its lock now permits only its own authorized retained retry. Other mutations remain locked.

## RED, then GREEN

All Node commands used `/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin` first on PATH.

- Initial feature-boundary RED: 4 failures, 136 passes across four files. Failures were the eight-key decoder, export control-result decoder, real export control adapter, and builder exposing a composite export option.
- The schema RED had 1 failure and 10 passes in `openapi/identity-admin.test.mjs`: the current contract rejected the eight-key response and export enum.
- After the first implementation, the full schema batch had 42 passes and 1 failure at the old seven-key snapshot in `openapi/openapi.test.mjs:832`. The controller approved its minimal expectation update.
- One test-table mistake passed a catalog object instead of an array. I corrected the fixture wrapper. Typecheck and ESLint also caught a response-body type and unnecessary quote escapes in new tests; those test-only issues were corrected.
- Authority-withdrawal RED: 1 failure, 141 passes. The manual-start button remained enabled after permission removal.
- Retained-activation RED: 1 failure, 143 passes. The authorized retry button remained disabled after fresh auth was renewed.

Final focused command:

```sh
node node_modules/vitest/vitest.mjs run app/features/securityagents/SecurityAgentsView.test.tsx apps/web/api/decoders.security-agent-lifecycle.test.ts app/features/securityagents/ExportPanel.test.tsx app/features/securityagents/export-api.test.ts
```

144 tests passed in four files, zero failures or skips. SecurityAgentsView has 97 tests; lifecycle decoders have 12. Existing ExportPanel and export transport tests stayed in the batch.

The grouped OpenAPI command passed 43 tests, zero failures or skips:

```sh
node --test openapi/openapi.test.mjs openapi/internal-health.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs
npm run openapi:generate
npm run openapi:lint
npm run openapi:check
npm run typecheck
node node_modules/eslint/bin/eslint.js app/features/securityagents/SecurityAgentsView.tsx app/features/securityagents/SecurityAgentsView.test.tsx apps/web/api/decoders.ts apps/web/api/decoders.security-agent-lifecycle.test.ts
npm run build
git diff --check
```

Each listed check exited zero after corrections. The official generator is openapi-typescript 7.13.0. The fresh five-stage vinext/Vite 8.0.16 build generated `dist/standalone/`. No deployment ran.

## Frozen bytes for the next owner

SHA256 of complete files at handoff, including preserved earlier edits:

```text
faa23d67be1a7932acadb032200556113c8d9048255693bcbc3743508eed54bd  openapi/openapi.yaml
1250e9f43426106096540a4c3e0742a967dd3af8e210803b5ad90989b192490b  openapi/openapi.test.mjs
b3f5e2ff51ccb03933866ee16cf87b06c54651944dba8b2e37e30c11dbed17a2  openapi/identity-admin.test.mjs
3adc2cbe217614d0e07c1b668c3aea269fe15ba7f0e073332166f162a19671af  apps/web/api/generated.ts
52a35742330a180c81fdcc44a046a99de81b984f30030adb56f6a9f8e6ad5ed7  apps/web/api/decoders.ts
5e7f395fce3e3b8a651bf7a870c3f52c826aca08bc4150ed86d6bd871efd6f6a  apps/web/api/decoders.security-agent-lifecycle.test.ts
67595de3c2d57933245b9edb73f7e7e5ed965be59dec0be6d5824565916ff11e  app/features/securityagents/SecurityAgentsView.tsx
b31cd070a95b51d4a64769b9792ab6ccbab09de4d9c0845a3276f02061148e50  app/features/securityagents/SecurityAgentsView.test.tsx
```

## Still needs the connected flow

These are real UI/client tests with controlled HTTP transport, not registered PostgreSQL or browser authentication proof. The producer must supply the installed, connected export catalog gate, exact eight-key current58 controls with absent export disabled/version0, and unchanged public receipt/ETag shapes. Draft input uses finding/credential trigger defaults, export verification, one step and definition_version1; server admission must authorize the exact environment and reject unsupported intent.

Create/update continue using existing definition bodies and mutation headers. Activation returns the existing four-field state, control writes retain the existing receipt fields, manual start returns the existing version1 manual provenance with empty legacy evidence IDs. Retained reads, safe disabling, current permission checks and fresh-auth refusal still need the SQL/API owner's registered integration proof.

The existing ExportPanel stays mounted against the original run and export step. The feature batch checks that mount and its download transport, but it does not prove a public-created definition reached a live planner, provider approval, export artifact and native saved-file download in one authenticated browser. Hand that test to the integration owner and independent reviewer. No staging, commit, push, database mutation or deployment occurred in this packet.

## Review fix round: P2 and P3, 2026-09-19

The integrated review caught a producer mismatch. Export admission requires an explicit AI cost budget on draft creation and update, so the earlier blank-budget export fixture was invalid. This section supersedes that part of the handoff above.

P2 is fixed in both forms. Export create/update requires an integer from 1 through 1,000,000,000,000, and the help now says that export drafts cannot leave it blank. Existing non-export drafts can still omit or clear their budget. The real-client export creation test sends 1000000 and checks that all three lost-response/retry requests have the same body and idempotency key. A public PATCH test checks the same retained budget/version/key for export updates; its non-export case clears the budget and verifies omission. Blank, zero, fractional and over-limit export budgets block saving.

P3 is fixed in the strict controls decoder. An eight-key response with `create_evidence_export` enabled at version 0 is rejected, matching `security_agent_handler.go`. Disabled/version 0 remains readable; enabled/version 1 is accepted.

I used the receiving-code-review skill to check the feedback and TDD before these product edits. The four-file RED run had 3 failures and 144 passes: export blank-budget create, export blank-budget update, and enabled/version 0 decoding. After the scoped fixes, the same four-file batch passed 147 tests with zero failures/skips (99 SecurityAgentsView tests, 13 lifecycle decoder tests). Fresh typecheck, targeted ESLint, `git diff --check` and all five UI build stages exited zero with cached Node 22.23.1. The schema and generated client were untouched, so I did not rerun the OpenAPI batch in this round.

New complete-file SHA256 values replace only these four entries above:

```text
6bf399e5f3f6b079b14c91f84e29097e06873de919fb5370801f9dcb84cb7d9c  app/features/securityagents/SecurityAgentsView.tsx
12de0259bb519cd3ad5917190c78f539422869cd0a6669c7163d554a632b5e57  app/features/securityagents/SecurityAgentsView.test.tsx
2c3cd35d0adfee9a0e36d0bf25435a59f71b50ebb00bca2e4c1ef19775a046f1  apps/web/api/decoders.ts
48d6210ed05dc1340c0b214ba609141cf86abe92d4f1ba8b49ee60563f677425  apps/web/api/decoders.security-agent-lifecycle.test.ts
```

No Go, SQL, deployment or ledger edits. No commit or push. The connected public setup-to-download proof remains with the integration owner.
