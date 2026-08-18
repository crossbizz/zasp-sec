# M1-35 Base Web Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the exact PRD MVP product shell, a dedicated left navigation component, and a fail-closed unauthenticated-route guard scaffold without claiming real authentication.

**Architecture:** Replace the prototype navigation catalog with one readonly nine-group/22-route product catalog, extract its presentation into `LeftNav`, and add a pure closed route-access state machine plus an injected presentational guard. Preserve matching demo surfaces and existing responsive chrome. M2-01/M2-02 remain responsible for Stytch and session middleware.

**Tech Stack:** React 19.2.6, TypeScript, Vinext/Vite, Testing Library, Vitest, Node.js 22.23.1, npm 10.9.8, pinned Gitleaks 8.30.1, GitHub Runnable UI.

**Spec:** `docs/internal/2026-08-18-m1-35-base-web-shell-design.md`

## Global constraints

- Preserve M1-34 exactly once in Complete and keep M1-36a Pending.
- Keep blockers exactly M0-09, M0-18, and M0-19.
- Render the exact nine PRD groups and 22 labels in exact order.
- Reuse matching existing demo page paths/surfaces; placeholders are bounded headings only.
- Do not render OSS/provider implementation labels in product navigation.
- Do not add Stytch/session/cookie/token/network behavior or claim authentication exists.
- Treat every path outside exact `/sign-in` as protected in the scaffold.
- Redirect only to closed literal `/` or `/sign-in`; never accept a return URL.
- Preserve the existing responsive product chrome, accessibility semantics, and browser-local demo.
- Add no runtime dependency.
- Use genuine tests-first RED/GREEN for production behavior and every review fix.
- Keep the UI runnable at every push and require exact-SHA Runnable UI success before closure.

---

### Task 1: Start M1-35 with exact source, design, and status contracts

**Files:**
- Create: `app/quality/base-web-shell-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-35 source row, selected design, M1-34 Complete state, and exact blocker set.
- Produces: exact M1-35 In-progress status at overall `652/1/72/3` and M1 `68/19/1/48/0`.

- [ ] **Step 1: Write the failing source/design/status contract**

  Parse the exact M1-35 source section and require dependency, deliverable,
  verification, and timebox. Bind the selected component/domain files, exact
  nine groups, 22 labels, negative provider-label catalog, route-guard state
  table, M2 deferrals, and no authentication claim.

- [ ] **Step 2: Witness focused status RED**

  Run the new M1-35 contract with the M1-34 contract. Require failure only
  because M1-35 is absent, counts remain `653/0/72/3`, and README says M1-35 is
  Pending.

- [ ] **Step 3: Move only M1-35 to In progress**

  Change overall counts to `652/1/72/3` and M1 to `68/19/1/48/0`. Add exactly
  one current M1-35 row. Preserve one completed M1-34, absent M1-36a, and exact
  blockers.

- [ ] **Step 4: Run focused and full status GREEN**

  Require exact 728-task arithmetic, active rows `['M1-35']`, 72 complete rows,
  M1-34 exactly once Complete, no active/complete M1-36a, and exact blockers.
  Run focused Vitest and full pinned `npm test`.

- [ ] **Step 5: Scan and commit the start transition**

  Run staged whitespace and pinned redacted secret scans. Commit only the
  status/README/quality slice as `docs: start M1-35 base web shell`.

---

### Task 2: Define the immutable IA and route-guard state machine tests-first

**Files:**
- Modify: `app/domain/types.ts`
- Modify: `app/domain/routes.ts`
- Modify: `app/domain/routes.test.ts`
- Create: `app/domain/route-guard.ts`
- Create: `app/domain/route-guard.test.ts`

**Interfaces:**
- Consumes: the exact PRD IA and injected session/path values.
- Produces: readonly `NAV_GROUPS`, `allRoutes`, deterministic route fallback, and closed `resolveRouteAccess` decisions.

- [ ] **Step 1: Write exact navigation RED**

  Replace the old registry snapshot expectation with the exact nine groups,
  group labels, 22 navigation labels, and 22 paths. Require unique group names,
  labels, and paths; absolute canonical paths; exact order; current matching
  surface paths; and case-insensitive absence of every negative provider label.

- [ ] **Step 2: Write route-guard compiler RED**

  Add the complete 3x2 state table for `loading`, `unauthenticated`, and
  `authenticated` across `/sign-in` and protected paths. Require unknown paths
  protected. Add hostile path/state cases and exact closed redirect targets.
  Run focused tests before creating the production module.

- [ ] **Step 3: Implement the minimal readonly route catalog**

  Use `as const satisfies readonly NavGroup[]`. Preserve only paths for matching
  current demo surfaces; assign fixed product paths for future surfaces. Keep
  Overview fallback and export readonly flattened routes without mutable casts.

- [ ] **Step 4: Implement the pure fail-closed guard resolver**

  Validate pathname bytes and session state before selecting the exact table.
  Invalid input returns pending. Do not parse URLs, decode percent escapes,
  accept return targets, read globals, or perform a redirect/network call.

- [ ] **Step 5: Run focused stability and commit**

  Run both domain tests six times, typecheck, lint, diff, and scans. Commit the
  exact domain slice as `feat: define base shell navigation boundary`.

---

### Task 3: Extract and verify the product left navigation

**Files:**
- Create: `app/components/LeftNav.tsx`
- Create: `app/components/LeftNav.test.tsx`
- Create: `app/components/UnauthenticatedRouteGuard.tsx`
- Create: `app/components/UnauthenticatedRouteGuard.test.tsx`
- Modify: `app/components/AppShell.tsx`
- Modify: `app/components/ZaspApp.test.tsx`

**Interfaces:**
- Consumes: readonly navigation, current route, bounded finding count, injected navigation/redirect callbacks, injected session state.
- Produces: accessible left nav, unchanged shell chrome, and inert route-guard presentation.

- [ ] **Step 1: Write rendered left-nav RED**

  Require all 22 links once and in order, all nine group labels, real `href`
  values, exact active state, bounded Findings badge, click navigation, mobile
  close behavior, and no negative provider label. Require invalid finding counts
  to render no badge rather than attacker-controlled text.

- [ ] **Step 2: Write guard component RED**

  Require children only for render, one fixed pending status for loading and
  redirect decisions, exactly one injected redirect call with a closed path,
  no redirect during render, callback replacement safety, and no provider/session
  detail in output.

- [ ] **Step 3: Extract `LeftNav` and preserve `AppShell`**

  Move sidebar markup without changing established class names. Keep store
  access in `AppShell`; pass only the validated count and callbacks. Preserve
  search, notifications, settings, overlay, and responsive behavior.

- [ ] **Step 4: Implement the inert guard component**

  Consume only `resolveRouteAccess`. Use an effect for redirects and render the
  fixed `Checking session` status until ownership transfers to the destination.
  Do not wire a fake session state into `ZaspApp`.

- [ ] **Step 5: Preserve working demo smoke paths**

  Update existing application tests to the product labels Agents, Identities,
  Findings, Red Team, Connections, and any retained working surface. Confirm
  navigation still reaches the expected existing headings/actions.

- [ ] **Step 6: Run focused stability and commit**

  Run component/domain/application tests six times, typecheck, lint, build,
  diff, and scans. Commit the component slice as
  `feat: add PRD-aligned product shell`.

---

### Task 4: Expose and document the hermetic shell contract

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/base-web-shell-contract.test.ts`

**Interfaces:**
- Consumes: reviewed shell/guard tests.
- Produces: exact `web:shell:test` root command and bounded product documentation.

- [ ] **Step 1: Write root/documentation RED**

  Require exactly one root command for the route, guard, left-nav, and app
  tests. Require README to list the nine groups, state 22 product labels/no OSS
  labels, explain the inert unauthenticated guard, and defer real auth to M2.

- [ ] **Step 2: Add wiring and documentation GREEN**

  Add only the exact package script and README section. Run focused contract,
  root shell command, full pinned repository verification, production audit,
  dependency validation, and whitespace checks.

- [ ] **Step 3: Scan and commit the wiring slice**

  Commit only package/README/quality changes as
  `docs: expose base web shell contract`.

---

### Task 5: Review, complete, push, and close M1-35

**Files:**
- Modify: `app/quality/base-web-shell-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`
- Modify after successful completion CI: `docs/internal/2026-08-18-m1-35-base-web-shell-implementation-plan.md`

**Interfaces:**
- Consumes: the complete M1-35 range and evidence.
- Produces: zero-finding review, Complete status, exact-SHA CI evidence, and closed plan.

- [ ] **Step 1: Obtain zero-finding whole-range review**

  Review from the exact pre-M1-35 base through implementation head. Resolve
  every Critical, Important, and Minor finding tests-first in separate commits.

- [ ] **Step 2: Run the final matrix**

  Run six shell-test passes, full pinned repository verification, typecheck,
  lint, build, production audit, dependency validation, diff checks, and exact
  range/per-commit/history/ignored-evidence secret scans.

- [ ] **Step 3: Write completion-contract RED**

  Change only the M1-35 status test to expect overall `652/0/73/3`, M1
  `68/19/0/49/0`, no active row, exactly one completed M1-34 and M1-35, absent
  M1-36a, and exact blockers. Witness failure while tracker remains In progress.

- [ ] **Step 4: Transition only M1-35 to Complete**

  Update README, tracker, and current count/status fixtures mechanically. Run
  focused GREEN and full pinned verification. Commit the transition as
  `docs: complete M1-35 base web shell`.

- [ ] **Step 5: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [ ] **Step 6: Close the plan and verify closure**

  Change every checkbox in this plan to `[x]`, commit only this plan as
  `docs: close M1-35 base web shell plan`, push it, and require a second
  exact-SHA Runnable UI success. Record both runs in ignored evidence and leave
  the tracked tree/index clean and synchronized.
