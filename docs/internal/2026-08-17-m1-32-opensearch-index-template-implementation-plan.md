# M1-32 OpenSearch Index Template Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one exact scoped session/runtime event index-template contract whose closed OpenSearch mapping rejects dynamic mapping explosion.

**Architecture:** A dependency-free `services/platform/eventindex` package owns one immutable version-1 template, deterministic JSON serialization, and exact document-field admission. Repository contracts expose the hermetic root command and status boundary without applying a provider template or weakening the later M1-39 Organization scope guard.

**Tech Stack:** Go 1.25.6 standard library, existing platform domain/eventstore contracts, Node.js 22.23.1, npm 10.9.8, Vitest, pinned Gitleaks 8.30.1, GitHub Runnable UI.

**Spec:** `docs/internal/2026-08-17-m1-32-opensearch-index-template-design.md`

## Global Constraints

- Preserve M1-31 exactly once in Complete and keep M1-33 Pending.
- Keep blockers exactly M0-09, M0-18, and M0-19.
- Use only the exact 12-field M1-14 driver-document projection.
- Use `dynamic: strict` plus `index.mapping.total_fields.limit=12`; do not add a dynamic template.
- Every keyword field has an explicit `ignore_above`; the timestamp is the only date field.
- Do not construct or call AWS, OpenSearch, Docker, Kubernetes, credential, environment, filesystem, clock, or random boundaries.
- Return only fixed `ErrTemplate` or `ErrDocument` rejections without rejected content.
- No provider apply, live lifecycle, tenant-isolation claim, or M1-33 work belongs to M1-32.
- Use genuine tests-first RED/GREEN for every production behavior and every review fix.
- Keep the UI runnable at every push and require exact-SHA Runnable UI success before closure.

---

### Task 1: Start M1-32 with exact source and status contracts

**Files:**
- Create: `app/quality/event-index-template-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-32 source row, committed design, M1-31 Complete state, and exact blocker set.
- Produces: exact M1-32 In-progress status at overall `655/1/69/3` and M1 `68/22/1/45/0`.

- [x] **Step 1: Write the failing source, design, and status contract**

Create `app/quality/event-index-template-contract.test.ts`. Parse the M1-32
source section and require:

```ts
expect(section).toContain("Depends on: `M1-31`");
expect(section).toContain("Deliverable: Create scoped session/runtime event index template with bounded keyword fields.");
expect(section).toContain("Verify: Template rejects dynamic mapping explosion fixture.");
expect(section).toContain("Timebox: <=15 minutes.");
```

Bind the selected dependency-free package, exact pattern/version/priority,
12-field closed mapping, `dynamic: strict`, total-field limit, keyword bounds,
fixed errors, no provider I/O, M1-39 scope deferral, and M1-33 deferral. Require
M1-32 as the sole active row, M1-31 exactly once in Complete, M1-33 absent from
active and complete rows, and blockers exactly M0-09, M0-18, and M0-19.

- [x] **Step 2: Witness status RED**

Run:

```sh
npm exec vitest run \
  app/quality/event-index-template-contract.test.ts \
  app/quality/aws-client-factory-contract.test.ts
```

Expected: the new contract fails only because M1-32 is absent, counts remain
`656/0/69/3`, and README does not document active M1-32. The completed M1-31
contract stays green.

- [x] **Step 3: Move only M1-32 to In progress**

Change overall `656/0/69/3` to `655/1/69/3` and M1 `68/23/0/45/0` to
`68/22/1/45/0`. Add exactly one current row:

```markdown
| M1-32 | August 17, 2026 | Adding one exact scoped session/runtime event index template with closed mappings, bounded keyword fields, and dynamic-field rejection. |
```

Add an M1-32 README sentence without claiming implementation completion.
Update only current status/count fixtures mechanically. Preserve historical
mutation fixtures and every Complete or Blocked row.

- [x] **Step 4: Run focused and full quality GREEN**

Run the new contract, the M1-31 contract, and `npm test`. Require 728-task
arithmetic, active rows exactly `['M1-32']`, 69 complete rows, one complete
M1-31 row, no complete M1-32 or active/complete M1-33 row, and the exact
blocker set.

- [x] **Step 5: Scan and commit the start transition**

Run staged whitespace and pinned redacted Gitleaks checks. Commit only the
status, README, and quality-contract slice as:

```text
docs: start M1-32 OpenSearch index template
```

---

### Task 2: Build the immutable template tests-first

**Files:**
- Create: `services/platform/eventindex/template_test.go`
- Create: `services/platform/eventindex/template.go`

**Interfaces:**
- Consumes: the exact M1-14 `eventstore.DriverDocument` field names and the committed M1-32 design.
- Produces: `SessionRuntimeTemplate`, immutable `Template`, copied `Field` metadata, deterministic `JSON`, and `ValidateDocumentFields`.

- [x] **Step 1: Write the compiler-failing public contract tests**

Create `template_test.go` in package `eventindex`. Assert that this code
compiles and exposes the wished-for API:

```go
template := SessionRuntimeTemplate()
if template.Validate() != nil {
    t.Fatal("canonical template rejected")
}
if template.Pattern() != "zasp-session-runtime-events-v1-*" ||
    template.Priority() != 100 || template.Version() != 1 {
    t.Fatal("template identity drifted")
}
fields := template.Fields()
if len(fields) != 12 {
    t.Fatalf("field count = %d", len(fields))
}
```

Also assert `Template{}.Validate`, `Template{}.JSON`, and
`Template{}.ValidateDocumentFields` return their fixed rejection errors and
all zero-value accessors return zero values.

- [x] **Step 2: Witness absent-package RED**

Run:

```sh
go test -C services/platform ./eventindex -count=1
```

Expected: FAIL because `services/platform/eventindex` and its production API
do not exist. Record the exact compiler or package-not-found failure before
creating `template.go`.

- [x] **Step 3: Write exact mapping and fresh-copy tests**

Require `Fields()` to return these exact values in canonical order:

```go
[]Field{
    {Name: "organization_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "workspace_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "environment_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "event_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "session_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "agent_id", Type: "keyword", IgnoreAbove: 40},
    {Name: "source", Type: "keyword", IgnoreAbove: 32},
    {Name: "source_event_id", Type: "keyword", IgnoreAbove: 256},
    {Name: "event_class", Type: "keyword", IgnoreAbove: 32},
    {Name: "action", Type: "keyword", IgnoreAbove: 64},
    {Name: "decision", Type: "keyword", IgnoreAbove: 16},
    {Name: "event_time", Type: "date", Format: "strict_date_time"},
}
```

Mutate every returned field and prove the next call is unchanged. Run the same
test concurrently under the race detector.

- [x] **Step 4: Write deterministic JSON RED**

Require exact compact JSON plus one trailing newline. Decode it with a
duplicate-key-rejecting test helper and assert exact keys at every level:

```json
{
  "index_patterns": ["zasp-session-runtime-events-v1-*"],
  "priority": 100,
  "version": 1,
  "template": {
    "settings": {"index.mapping.total_fields.limit": 12},
    "mappings": {
      "dynamic": "strict",
      "_meta": {"zasp_contract": "session_runtime_events", "zasp_contract_version": 1},
      "properties": {}
    }
  }
}
```

Populate `properties` with only the 12 exact field definitions. Call `JSON`
twice, mutate the first returned bytes, and prove the second remains exact.

- [x] **Step 5: Write dynamic-field rejection RED**

Start with the 12 valid names. Prove their order permutations pass. Then add
1,024 unique names `attacker_field_0000` through `attacker_field_1023` and
require exactly `ErrDocument`.

Add independent table cases for missing, duplicate, one unknown at a valid
count, empty, dotted, nested-looking, control-bearing, invalid UTF-8, and
oversized names. Ensure rejected names never appear in `err.Error()`.

- [x] **Step 6: Implement the minimal immutable value**

Create `template.go` with private constants, a private `[12]Field` array inside
`Template`, and the two fixed errors. `SessionRuntimeTemplate` copies the exact
canonical array into a valid private value. `Validate` compares every scalar
and field against the canonical definition.

`Fields` returns a copied slice only after validation. `ValidateDocumentFields`
rejects non-12 lengths before allocating a bounded 12-entry seen set, validates
each name, and requires the exact set without depending on order.

- [x] **Step 7: Implement deterministic serialization**

Build fresh private JSON structs after `Validate`. For keyword fields, emit
only `type` and `ignore_above`; for the date field, emit only `type` and
`format`. Use `json.Marshal`, append one newline to fresh output, and return
only `ErrTemplate` on invalid state or impossible serialization failure.

Do not expose internal maps or slices and do not accept caller-supplied template
configuration.

- [x] **Step 8: Run focused race and stability gates**

Run:

```sh
for run in 1 2 3 4 5 6; do
  go test -C services/platform ./eventindex -race -count=1
done
go test -C services/platform -race -count=1 ./...
go -C services/platform mod tidy -diff
go -C services/platform mod verify
go vet -C services/platform ./...
```

All six focused runs and every full platform gate must pass. `go.mod` and
`go.sum` must remain unchanged because this package is standard-library-only.

- [x] **Step 9: Self-review and commit the package slice**

Review every public method, exact byte, zero/forged state, fresh-copy boundary,
error string, and hostile case. Add tests-first fixes for any gap. Run staged
whitespace and pinned Gitleaks checks, then commit only the two package files:

```text
feat: add strict OpenSearch event index template
```

---

### Task 3: Expose the root and documentation boundary

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/event-index-template-contract.test.ts`

**Interfaces:**
- Consumes: the reviewed `eventindex` package and exact M1-32 design.
- Produces: root `event:index-template:test` and bounded operator documentation.

- [x] **Step 1: Write integration RED**

Extend the quality contract to require:

```ts
expect(scripts["event:index-template:test"]).toBe(
  "go test -C services/platform -race -count=1 ./eventindex",
);
```

Require a `## OpenSearch session/runtime event template` README section to
state the exact pattern, 12-field limit, `dynamic: strict`, keyword bounds,
mapping-explosion rejection, no provider apply/I/O, no isolation claim,
M1-31 Complete, M1-39 scope deferral, and M1-33 Pending.

- [x] **Step 2: Witness integration RED**

Run:

```sh
npm exec vitest run app/quality/event-index-template-contract.test.ts
```

Expected: FAIL only because the root script and completed README boundary are
absent. Source, design, package, and active-status assertions remain green.

- [x] **Step 3: Add the exact root command**

Add one script entry to `package.json`:

```json
"event:index-template:test": "go test -C services/platform -race -count=1 ./eventindex"
```

Do not add a run/apply command because M1-32 performs no provider operation.

- [x] **Step 4: Document the exact boundary**

Add the README section immediately after the M1-31 client-factory section.
Explain that the artifact is a product-owned deterministic template contract,
not a deployed index, domain, cross-Organization authorization proof, dynamic
customer schema, or LocalStack/OpenSearch parity claim.

- [x] **Step 5: Run integration and repository GREEN**

Run:

```sh
npm run event:index-template:test
npm exec vitest run app/quality/event-index-template-contract.test.ts
npm run dependencies:check
node --test scripts/validate-dependencies.test.mjs
npm run verify
npm audit --omit=dev
git diff --check
```

Use pinned Node 22.23.1, npm 10.9.8, and Go 1.25.6. The dependency inventory
must remain unchanged and production audit must report zero vulnerabilities.

- [x] **Step 6: Scan and commit the integration slice**

Run pinned redacted Gitleaks over staged changes and the ignored Task 3 evidence.
Commit only package wiring, README, and the contract test as:

```text
docs: expose OpenSearch event index template
```

---

### Task 4: Review, complete, push, and close M1-32

**Files:**
- Modify only if review finds a defect: files in the exact M1-32 range
- Modify: `app/quality/event-index-template-contract.test.ts`
- Modify: current status/count fixtures under `app/quality/`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/2026-08-17-m1-32-opensearch-index-template-implementation-plan.md`
- Create ignored evidence under `.superpowers/sdd/2026-08-17-m1-32-opensearch-index-template-implementation-plan/`

**Interfaces:**
- Consumes: the complete M1-32 commit range and all task reports.
- Produces: zero-finding reviewed implementation, exact Complete status, successful exact-SHA CI, and a closed plan.

- [x] **Step 1: Obtain a zero-finding whole-range review**

Review the exact M1-32 base-to-head range against the source row, design, plan,
implementation, tests, root command, README, tracker, dependency inventory, and
fixed errors. Review specifically for:

- mutable template/field/JSON aliases;
- extra, missing, duplicate, or dynamically admitted fields;
- inconsistent keyword bounds or date format;
- nondeterministic or structurally ambiguous JSON;
- false Organization-isolation or provider-application claims;
- ambient authority, provider I/O, secret exposure, or dependency drift; and
- weak tests that inspect source without exercising public behavior.

For every finding, verify it, write a focused failing regression, witness RED,
make the minimal fix, run GREEN, and commit separately. Repeat review until
Critical 0, Important 0, Minor 0.

- [x] **Step 2: Run the final gate matrix**

Run six focused race passes, full platform race/tidy/verify/vet, the root
template command, focused and full pinned repository tests, typecheck, lint,
build, dependency validation, production audit, whitespace checks, and pinned
Gitleaks scans of the range, each commit, tracked HEAD, history, and ignored
evidence. Require a clean tracked tree and index.

- [x] **Step 3: Write completion-contract RED**

Change only the M1-32 quality contract to expect:

- overall `655/0/70/3`;
- M1 `68/22/0/46/0`;
- no active row;
- exactly 70 Complete rows;
- exactly one M1-32 and M1-31 Complete row;
- M1-33 absent from active and complete rows; and
- blockers exactly M0-09, M0-18, and M0-19.

Run the focused test and record its failure against the still-In-progress
tracker before changing production documentation.

- [x] **Step 4: Transition only M1-32 to Complete**

Move the exact M1-32 row from In progress to Complete, update source/M1 counts,
README status, and current count fixtures mechanically. Preserve every other
task row and historical mutation fixture. Run focused and full gates again.
Commit as:

```text
docs: complete M1-32 OpenSearch index template
```

- [x] **Step 5: Push completion and verify exact-SHA CI**

Push `codex/zasp-implementation`, prove local/origin/tracking SHAs are equal,
and watch the Runnable UI workflow for the exact completion SHA to terminal
success. Record the run and job URLs in ignored evidence. Do not close the plan
before that success.

- [x] **Step 6: Close, push, and verify the plan**

Mark all implementation-plan checkboxes complete in one plan-only commit:

```text
docs: close M1-32 OpenSearch index template plan
```

Push, require successful Runnable UI for the exact closure SHA, and prove final
local/origin/tracking equality, `655/0/70/3` arithmetic, M1 `68/22/0/46/0`,
M1-33 Pending, exact blockers, complete plan, zero Gitleaks findings, and a
clean tracked tree/index.
