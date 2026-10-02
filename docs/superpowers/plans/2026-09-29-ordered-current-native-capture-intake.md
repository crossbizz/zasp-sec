# Ordered-Current Native Capture Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind the reviewed direct-frame, missing-reference, and private-successor local-native evidence through one closed intake, then reconcile its three separately typed fact sets into the dormant ordered-current development generator without enabling installation or runtime routing.

**Architecture:** One source-pinned intake validates a fixed composition manifest and the exact three packet/capture authorities. It returns direct facts, missing-reference facts, and private facts as separate collections with their original provenance. The development generator may reconcile these collections only against source-declared rules and existing facts; it remains noninstallable until the wider current-integrity, portability, capacity, and deployment gates pass.

**Tech Stack:** Node.js ESM, strict JSON, SHA-256, existing ordered-current compiler/intake modules, Go 1.25 embedded generated artifacts.

**Spec:** `docs/internal/2026-09-26-ordered-current-integrity-plan.md`, constrained by `docs/internal/2026-09-22-temporal-openfga-design.md` and `docs/internal/2026-09-22-temporal-openfga-execution-plan.md`.

## Global Constraints

- Preserve all 728 original requirements and the authoritative status ledger.
- Keep `installable:false`, current runtime routing disabled, and every external/deployment gate open.
- Treat the direct packet as source-derived expected-fact authority validated by native execution; never derive expected facts from the native log.
- Treat missing-reference and private captures as fixed reviewed artifacts. Reject caller-selected paths, hashes, frames, SQL, or rule sets.
- Keep direct, missing-reference, and private outputs separate through intake. Reconcile them only through source-declared rules in the generator.
- Do not import private routine observations as expected facts. Validate their 22-row parity, and import only the 35 non-routine facts.
- Preserve lossless JSON, duplicate-key refusal, safe integers, explicit NULLs, exact field sets, exact row counts, canonical identities, frame/rollback/restoration controls, cumulative byte bounds, and mode-0600 provenance.
- Do not call `.env`, providers, network services, or paid models. Use deterministic local tests.
- Preserve the runnable UI and unrelated dirty work. Do not commit, push, or activate production routing in these tasks.

---

### Task 1: Fixed native composition intake

**Files:**
- Create: `services/platform/migrations/tools/ordered-current-capture-intake-v1.mjs`
- Create: `services/platform/migrations/tools/ordered-current-capture-intake-v1.test.mjs`
- Modify: `services/platform/migrations/tools/ordered-current-private-successor-reference.mjs`
- Modify: `services/platform/migrations/tools/ordered-current-private-successor-reference.test.mjs`
- Modify: `services/platform/migrations/tools/ordered-current-missing-reference-native-packet.mjs`
- Modify: `services/platform/migrations/tools/ordered-current-missing-reference-native-packet.test.mjs`
- Create generated evidence: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-native-composition-manifest-v1.json`
- Create generated evidence: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-missing-reference-capture-v1.json`
- Create generated evidence: `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-private-successor-reference-v1.json`

**Interfaces:**
- Consumes exact packet hashes: direct `c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab`; missing `23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287`; private `5071a729bbd87d1489b3ae9f4f608f73a011281525f26ae889d5d4148dcba75c`.
- Consumes exact capture hashes: missing `76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39`; private `f114dc58c8a235902466bf1f9cee82f0a5eea5b93427589d8aaaf53b83281679`.
- Binds composition log hash `2a875ddd77d36971fa5f66921d45b69ae3f8f9165be95c070fc159327948100a` as evidence metadata only, never expected-fact input.
- Produces `admitOrderedCurrentCaptureBundleV1()` returning a frozen object with exactly `directFacts`, `missingFacts`, `privateFacts`, `provenance`, `installable:false`, and `captureStatus:'LOCAL-NATIVE-VERIFIED-UNBOUND'`.

- [ ] **Step 1: Preserve exact reviewed capture bytes and write the manifest**

Copy the missing and private capture bytes to the two fixed evidence paths without reserializing them. Emit a closed manifest with the packet hashes, capture hashes, composition-log hash, source authority, row/control counts, and `installable:false`. Refuse overwrite unless the existing file is byte-identical.

- [ ] **Step 2: Write failing intake tests**

Tests must require exact file/hash authority, closed envelopes, 1,600 direct facts, 204 missing facts, 35 private non-routine facts, 22 validated private routine rows, canonical identity composition, and separate provenance. Add negative controls for a changed capture byte, duplicate JSON key, missing/extra observation, duplicate canonical identity, changed frame/restoration/publication control, changed packet pin, old private predecessor capture, caller-supplied hash/path, unsafe integer, and any attempt to mark output installable.

- [ ] **Step 3: Run RED**

Run:

```sh
node --test services/platform/migrations/tools/ordered-current-capture-intake-v1.test.mjs
```

Expected: fail because the intake exports do not exist.

- [ ] **Step 4: Implement the minimal closed intake**

Reuse existing strict parsers and source-bound packet builders where practical. The direct packet's expected rows are source-derived inputs; native log text is not parsed. Missing identities must be canonical `[ruleId, capturedIdentity]` keys using the source contract's kind/field schema. Private intake validates all 57 rows but returns only the 35 non-routine facts. Reject any cross-set duplicate `(kind, identity)` whose fact bytes disagree; report exact equal overlaps separately in provenance rather than silently overwriting.

- [ ] **Step 5: Run GREEN and existing affected suites**

Run:

```sh
node --test \
  services/platform/migrations/tools/ordered-current-capture-intake-v1.test.mjs \
  services/platform/migrations/tools/ordered-current-private-successor-reference.test.mjs \
  services/platform/migrations/tools/ordered-current-missing-reference-contract-v1.test.mjs \
  services/platform/migrations/tools/ordered-current-missing-reference-native-packet.test.mjs \
  services/platform/migrations/tools/ordered-current-direct-frame-acceptance-packet.test.mjs
```

Use the existing explicit fixed-artifact environment flags so required tests run with zero skips.

- [ ] **Step 6: Write the task report**

Record RED/GREEN commands, exact hashes, tests, admitted counts, overlap counts, and limits in the SDD report. Do not claim installation, production, deployment, Variant B, or live-provider evidence.

### Task 2: Dormant generator reconciliation

**Files:**
- Modify: `services/platform/migrations/tools/build-ordered-current-development.mjs`
- Modify: `services/platform/migrations/tools/ordered-current-development.test.mjs`
- Modify generated files under: `services/platform/migrations/ordered_current/`
- Modify generated pins only: `services/platform/migrations/production_authorization_worker_ordered_current.go`
- Modify tests: `services/platform/migrations/production_authorization_worker_ordered_current_test.go`

**Interfaces:**
- Consumes only `admitOrderedCurrentCaptureBundleV1()` from Task 1.
- Produces a deterministic noninstallable development manifest/module/checkpoint that records each admitted collection, exact equality overlaps, newly supplied facts, and remaining source/runtime blockers.

- [ ] **Step 1: Write failing generator reconciliation tests**

Require the generator to validate equal existing facts, add only source-declared missing facts, refuse conflicting duplicates, retain original opaque/live obligations, import no private routine observations, and record exact bundle hashes/counts. Require `installable:false`, `nativeVerified:false` for the full product, and unchanged runtime source refusal.

- [ ] **Step 2: Run RED**

Run the development generator tests and confirm failure because the admitted bundle is not consumed.

- [ ] **Step 3: Implement reconciliation**

Replace predecessor-only private reference authority with the Task 1 successor intake. Reconcile direct and missing facts by their source-declared rule IDs and types. Preserve separate source provenance and remaining blockers. Never use target capture values to invent a selector, rule, expected field, or runtime route.

- [ ] **Step 4: Regenerate twice and prove byte stability**

Run `--write`, `--check`, and another `--write`/hash comparison. Update only generated file pins required by the existing Go refusal boundary.

- [ ] **Step 5: Run affected Node and Go suites**

Run the Task 1 suites, `ordered-current-development.test.mjs`, affected manifest/compiler suites, and focused `TestOrderedCurrent` Go tests. The Go source loader must still return the noninstallable error.

- [ ] **Step 6: Update evidence and authoritative ledger**

Record exact facts added/validated, remaining blockers, report/review hashes, and keep all 728 rows present. Run `node scripts/implementation-status-check.mjs`.
