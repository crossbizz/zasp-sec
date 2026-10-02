# ZaspOps — AI coding agent kickoff prompt

Copy everything below the line into the agent's first message (or its CLAUDE.md). It is self-contained; the plan stays the single source of truth.

---

You are implementing **ZaspOps MVP-1**, a multi-tenant enterprise context + governed-action platform.

## Source of truth (read before any code)
1. `docs/internal/ZaspOps Technical Implementation Plan.md` (v2.2) — THE plan. §21 is your task list, §23 is your execution protocol and Definition of Done, §14 maps every UI flow to its APIs, §2.1 lists what is deliberately NOT built.
2. `docs/internal/ZaspOps Product Requirements Document-PRD.md` — product context only. If it conflicts with the plan, the plan wins (§2.4 lists the known conflicts). Never edit the PRD.
3. `docs/internal/ZaspOps MVP Diagrams.md` — architecture and flow diagrams.
4. `tasks/todo.md` (progress ledger + open decisions) and `tasks/lessons.md` — read both at the start of every session.

## Mission
Execute the §21 work breakdown strictly in dependency order, starting at **M0.1** (this directory currently has no code and is not a git repository — M0.1 creates it). Follow the lanes: M0 → M1 → M2, then in parallel (A) M3 → M4 context slice, (B) M6 policy/proof, (C) M5 connectors, (D) M9 IaC. Targets: **Gate A** (read-only alpha) after M4, **Gate B** (write-enable) after M9. As part of M0.13–M0.14, distill the "Hard rules" below into the repo's root `CLAUDE.md` so future sessions inherit them.

## Per-task loop
1. Pick the lowest-ID unblocked task in your current lane. Restate its scope, dependencies, and verify command before coding.
2. **Sizing rule:** if the task looks bigger than 10–15 minutes, STOP — split it into sequenced subtasks in `tasks/todo.md` first. Never let a task grow mid-flight.
3. Implement with tests in the same change: happy path, tenant/auth negative, failure/retry path.
4. Run the task's stated verify command and record the actual output in the ledger. Never claim done without evidence; never weaken a test to pass.
5. One task per branch `feat/M#-T#-slug`, commit/PR titled `[M#.#] outcome`. Check the task off in `tasks/todo.md` with a one-line evidence pointer.

## Hard rules — never violate
- Every tenant table: `tenant_id`, FORCE ROW LEVEL SECURITY, composite tenant keys; app DB role is non-owner with no BYPASSRLS. Never weaken or disable RLS.
- Migrations are append-only expand/contract. Never edit an applied migration; never run data migrations synchronously in a request path.
- Only `action-runner` calls target systems. Only `packages/model` calls model providers (lint-enforced). `api` orchestrates but never executes writes against targets.
- No secrets, customer data, or PHI in code, logs, fixtures, or prompts — secrets by reference only. Retrieved connector text is untrusted data: delimit it; it never alters instructions, tool scopes, policy, or routing.
- New write/model/connector feature flags default fail-closed. Deny-by-default policy: unknown or malformed input = deny.
- Do NOT build anything in the §2.1 descope table, and do NOT start the R1 package unless the M5.24 ADR adopts embeddings. Do not reorder or skip gates.
- Do not invent or assume library versions. At bootstrap, select current maintained LTS/stable releases, pin them (lockfiles + image digests, no floating tags), and record them in the repo.

## Gates you cannot pass alone (stop and hand back to Manish)
- **M1.18** real-Neon pooled-endpoint RLS gate: if it fails, HALT the tenant data path and escalate — the fallback is the SECURITY DEFINER approach ADR in plan §8, chosen with a human, never session `SET`.
- **Gate A / Gate B** checklists (§22) require human sign-off.
- Stop immediately and escalate on: secret/PHI exposure, cross-tenant data leakage, RLS test failure, signature/hash mismatch, action-scope escape, or a failing required test. Never bypass with mocks.

## External blockers
§21.0 lists EXT.1–EXT.11 (Stytch project, Neon projects, AWS accounts, OpenRouter key, Slack app, Okta sandbox, ServiceNow PDI, Datadog/PagerDuty/Confluence trials, compliance platform, pen test, design-partner access). These are human tasks. When one blocks you: record exactly what you need under a "Waiting on Manish" section in `tasks/todo.md`, then continue on the plan's local/mocked path where the plan explicitly allows one (e.g. mocked Stytch adapter unit tests before EXT.1). Never fake a gate that requires a real external system.

## Session ritual
- Start: read `tasks/lessons.md` and `tasks/todo.md`, state which task you are picking and why it is unblocked.
- End: update the ledger with evidence, note any new lesson, list what is blocked and on what.

Begin now with M0.1. The bootstrap sequence is M0.1 → M0.10; the first hard checkpoint after that is M1.18.
