# M1-27 Raw Fetch Lint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tested frontend ESLint rule that rejects raw Fetch calls outside
the exact generated-client boundary.

**Architecture:** A dependency-free local ESLint rule inspects call-expression
callees. ESLint flat config scopes it to normal frontend files and exempts only
the two reviewed generated-client files. Node tests prove the rule and the
real flat-config scope; quality contracts bind status, documentation, and root
verification wiring.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, ESLint 9.39.4 flat config,
TypeScript ESLint 8.59.3, Node test runner, Vitest 4.1.10.

## Global Constraints

- Work only on M1-27. M1-28a remains Pending.
- M0-09, M0-18, and M0-19 remain Blocked.
- The rule covers `app/**` and `apps/web/**` JavaScript/TypeScript source.
- Exempt exactly `apps/web/api/client.ts` and `apps/web/api/generated.ts`.
- Add no dependency and do not change `package-lock.json`.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1 and npm 10.9.8 for every repository gate.
- Do not mark M1-27 Complete before whole-range review is Critical 0,
  Important 0, Minor 0, Ready Yes.
- Completion requires exact-SHA Runnable UI success for both the completion
  commit and the plan-only closure commit.

---

### Task 1: Start M1-27 with an exact status contract

**Files:**
- Create: `app/quality/raw-fetch-lint-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`

**Interfaces:**
- Consumes: the M1-27 source row and M1-26 Complete state.
- Produces: an exact M1-27 In-progress contract at overall `668/1/56/3` and M1
  `68/35/1/32/0`.

- [x] **Step 1: Write the failing status contract**

Add a Vitest contract that extracts tracker tables structurally and asserts:

```ts
expect(active.filter(([task]) => task === "M1-27")).toHaveLength(1);
expect(complete.filter(([task]) => task === "M1-27")).toHaveLength(0);
expect(tracker).toContain("`668/1/56/3`");
expect(milestoneM1).toEqual(["M1", "68", "35", "1", "32", "0"]);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
expect(readme).toContain("M1-27 is In progress");
expect(readme).toContain("M1-28a remains Pending");
```

Bind the source row's dependency, deliverable, and seeded-violation verify
sentence, plus the committed design's exact scope and rule name.

- [x] **Step 2: Run the focused test and witness RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/raw-fetch-lint-contract.test.ts
```

Expected: only stale README/tracker assertions fail; source and design
assertions pass.

- [x] **Step 3: Move only M1-27 to In progress**

Update tracker arithmetic to overall `668/1/56/3` and M1
`68/35/1/32/0`. Add exactly one M1-27 In-progress row. Preserve M1-26 in
Complete, M1-28a outside active/complete, and the three blocker rows. Update
README with M1-27 In progress and M1-28a Pending.

- [x] **Step 4: Run focused and complete quality GREEN**

Run the focused contract, its neighboring M1-24 through M1-26 contracts, then
all `app/quality` tests under pinned Node. Require zero failures.

- [x] **Step 5: Scan and commit the start transition**

Run `git diff --check`, a pinned redacted Gitleaks staged scan, then commit
exactly the contract, README, and tracker as:

```text
docs: start M1-27 raw fetch lint
```

---

### Task 2: Implement and wire the local ESLint rule

**Files:**
- Create: `eslint-rules/no-raw-fetch.test.mjs`
- Create: `eslint-rules/no-raw-fetch.mjs`
- Modify: `eslint.config.mjs`
- Modify: `package.json`

**Interfaces:**
- Produces: default export `noRawFetchRule`, an ESLint rule with message ID
  `useGeneratedClient` and no options.
- Produces: `npm run raw-fetch:test`.
- Consumes: ESLint flat config and the existing `npm run lint`/`verify` gates.

- [x] **Step 1: Write the absent-rule tests first**

Create a Node test that imports `./no-raw-fetch.mjs`, constructs an ESLint
`Linter`, and verifies exact error counts/messages. Include:

```js
const invalid = [
  'fetch("/api/v1/home/summary")',
  'globalThis.fetch(path)',
  'window["fetch"]?.(new Request(path))',
  'self.fetch.call(null, path)',
  'fetch.apply(null, [path])',
];
const valid = [
  'client.GET("/api/v1/home/summary")',
  'const documentation = "/api/v1/home/summary"',
];
```

Use ESLint's real config API to lint seeded files named
`app/seeded-raw-fetch.ts`, `apps/web/page.tsx`,
`apps/web/api/client.ts`, and `apps/web/api/generated.ts`. The first two must
fail and the exact two boundary files must pass.

- [x] **Step 2: Run the focused test and witness RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  node --test eslint-rules/no-raw-fetch.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND` for the absent production rule.

- [x] **Step 3: Implement the minimal AST rule**

Implement static-property helpers and callee recognition:

```js
function staticPropertyName(node) {
  if (!node.computed && node.property.type === "Identifier") return node.property.name;
  if (node.computed && node.property.type === "Literal" && typeof node.property.value === "string") return node.property.value;
  return undefined;
}

function isFetchReference(node) {
  if (node.type === "Identifier") return node.name === "fetch";
  if (node.type !== "MemberExpression") return false;
  const property = staticPropertyName(node);
  if (["call", "apply", "bind"].includes(property ?? "")) return isFetchReference(node.object);
  return property === "fetch" && node.object.type === "Identifier" &&
    ["globalThis", "window", "self"].includes(node.object.name);
}
```

On each `CallExpression`, unwrap a `ChainExpression` callee if present, report
once when `isFetchReference` is true, and emit only `useGeneratedClient`.

- [x] **Step 4: Wire exact frontend scope and commands**

Import the rule into `eslint.config.mjs` and add one flat-config object:

```js
{
  files: ["app/**/*.{js,jsx,ts,tsx,mjs,cjs}", "apps/web/**/*.{js,jsx,ts,tsx,mjs,cjs}"],
  ignores: ["apps/web/api/client.ts", "apps/web/api/generated.ts"],
  plugins: { zasp: { rules: { "no-raw-fetch": noRawFetchRule } } },
  rules: { "zasp/no-raw-fetch": "error" },
}
```

Add `raw-fetch:test` to `package.json` and insert it into `verify` immediately
before `npm test`. Do not alter dependency pins or the lockfile.

- [x] **Step 5: Run focused RED-to-GREEN and six stability passes**

Run `npm run raw-fetch:test` and `npm run lint`, then run the focused rule test
six consecutive times. Require the seeded violation to report
`zasp/no-raw-fetch`, valid generated-client calls to pass, and all existing
frontend code to lint cleanly.

- [x] **Step 6: Run full pinned verification and commit**

Run `npm run verify`, `npm run build:repo`, `npm audit --omit=dev`, the
unchanged development audit, syntax checks, `git diff --check`, and redacted
staged/all-history scans. Commit the four exact files as:

```text
feat: forbid raw frontend fetch requests
```

---

### Task 3: Document and independently review M1-27

**Files:**
- Modify: `README.md`
- Modify: `app/quality/raw-fetch-lint-contract.test.ts`
- Modify: this implementation plan
- Create ignored evidence under
  `.superpowers/sdd/2026-08-16-m1-27-raw-fetch-lint-implementation-plan/`

**Interfaces:**
- Produces: documented commands, scope, generated-client exception, and
  deliberate seeded-violation result.

- [ ] **Step 1: Write the README contract before prose**

Require an extracted README section to contain exact standalone commands
`npm run raw-fetch:test` and `npm run lint`, both frontend roots, both exact
exempt files, the rule ID, and M1-27 In progress / M1-28a Pending.

- [ ] **Step 2: Witness documentation RED, write prose, and reach GREEN**

Run the focused contract before editing README and require the missing-section
failure. Add the bounded documentation, then rerun the focused test and all
related M1-24 through M1-27 contracts.

- [ ] **Step 3: Review the whole design-to-head range**

Audit every changed file against the source row and design. Re-run seeded
direct/member/optional/call/apply violations, exact exceptions, config scope,
lockfile non-change, and root verify wiring. Record Critical, Important, and
Minor counts plus Ready Yes/No.

- [ ] **Step 4: Fix every valid review finding tests-first**

For each finding, add a focused failing case, witness RED, make the minimal
production change, rerun focused and adjacent tests, and commit separately.
Repeat review until the result is Critical 0, Important 0, Minor 0, Ready Yes.

- [ ] **Step 5: Record review evidence**

Run six final focused passes, full pinned verification, repository builds,
audits, diff/syntax checks, and redacted source/evidence/history scans. Update
ignored task/progress reports and commit tracked README/contract/plan changes
as:

```text
docs: record M1-27 raw fetch lint review
```

---

### Task 4: Complete, push, and close M1-27

**Files:**
- Modify: `README.md`
- Modify: `app/quality/raw-fetch-lint-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: this implementation plan
- Update ignored task and authoritative reports.

- [ ] **Step 1: Capture completion status RED**

Change only the contract expectations to overall `668/0/57/3`, M1
`68/35/0/33/0`, M1-27 exactly once in Complete and absent from active, and
M1-28a Pending. Run it before README/tracker changes and require only the stale
status assertions to fail.

- [ ] **Step 2: Move only M1-27 to Complete and run final gates/scans**

Update README/tracker and all exact aggregate fixtures. Run six focused rule
and completion passes, full pinned verification, repository builds, audits,
syntax/diff checks, and redacted staged/history/evidence scans. Commit as:

```text
docs: complete M1-27 raw fetch lint
```

- [ ] **Step 3: Push completion commit and require exact-SHA Runnable UI success**

Push `codex/zasp-implementation`, locate the Runnable UI run whose `headSha`
equals the completion commit, and wait for its job to finish successfully.
Record run ID, job ID, URL, and exact SHA.

- [ ] **Step 4: Push plan-only closure and require exact-SHA Runnable UI success**

Mark this plan closed, commit only the plan as
`docs: close M1-27 raw fetch lint`, push, and require a second successful
Runnable UI run for that exact SHA. Finish with local/upstream/origin equality,
clean tracked state, all-history/evidence scans, M1-28a Pending, overall
`668/0/57/3`, and M1 `68/35/0/33/0`.
