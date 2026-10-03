# Installed upgrade catalog comparison component — 2026-10-03

This batch publishes the independently reviewed comparator and its 75 synthetic controls. Run `node --test scripts/installed-upgrade/paired-catalog.test.mjs` using the repository-pinned Node 22.23.1. Root verification passed with actual exit 0, and targeted lint is checked before shipping. The helper compares supplied buffers; it does not admit catalog provenance or authorize an upgrade.

The original FROM/TO captures are already recorded as local components. Their exact raw buffers and compiler provenance remain unavailable in the reviewed locations, so the actual recorded pair has not been compared. Native authority, a distinct installed upgrade transaction, deployed retirement, release acceptance, and original 728 requirement acceptance remain unproven. There are zero ledger promotions. Existing installer behavior and immutable evidence are preserved.

The preparation report below is retained verbatim as historical implementation and TDD evidence. References to private files and no live changes describe its preparation phase. Root's subsequent Node 22 verification is recorded separately in `/workspace/scratch/installed-upgrade-paired-catalog-root-node22-v2.receipt.json`.

---

# PRIVATE paired installed-worker catalog verifier preparation v1

Exactly three NEW files in this private directory; no live repository changes. Root authorized independent retirement critical-path implementation. This is a functional supplied-catalog comparator and synthetic controls, NOT actual native/upgrade/deployed acceptance. Existing fresh installer, runtime_ready AND false, original37910089 guards, historical migrations and728ledger remain untouched. No Go, PG, copies, install, keys, network, source routing or identity changes.

## Reference availability and admission

The recorded local FROM native68543 is60.423s with catalog19,736,229B SHA6a6af2cc58ca57524ffe338aea55bc48f1b4d24ffb1b7501c6650b31317d7443 and ff7b2990b6bb507d3fe60780ef54306e35e02fa1789c089eb414087bb254668c compiler checksum. Recorded source50d1c3065ed09da35d810890421e22094ccce5cbd9e290b18e71bcc3d7101d1a; compiled artifact794b6c269b2e2f81fae2fbbc54f52773e0adb5187156eed19f522e5297539216. TO native1401 is60.061s with catalog19,741,242B SHA036c92946205f854600cd0ef0e7ebbd1f8bc672c1a5e23d070ef198959abebec and e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960 compiler checksum. The historical ledger records these local component captures; those counts are not raw bytes or deployed allowlists.

Bounded filename searches across repository/scratch/shared/tmp/home did not locate the exact FROM/TO raw catalogs, result receipts (ordered69-predecessor-catalog-only2-result.md and ordered-current-effective-catalog1-result.md), or full TO compiler artifact/source provenance. Existing checked-in effective-catalog1.json is19,522,469B SHAb13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077, not either target hash; it is explicitly NOT substituted. Searches do not claim global absence. Availability of exact FROM+TO raw buffers/receipts/source compiler provenance and independent Root reference admission remains mandatory before ANY actual recorded-pair comparison. No actual frozen pair comparison was performed. There is no accepted pair API, input path/env discovery, source repinning or caller-admission boolean in the verifier.

## Concrete behavior

All26 literal exporter categories are required with exact record fields. Recursive bounded UTF8 JSON parsing refuses duplicate decoded keys at every level, unknown/missing fields, trailing syntax, unsafe malformed numbers/depth/size, invalid identities and registration binding. Numeric tokens retain exact source representation, avoiding silent integer rounding. NULL, empty arrays and strings remain distinct. Row ordering is ignored only as a catalog bag; duplicates/multiplicity in dependency bags and ordered string-valued arrays are retained. Unique object identities refuse duplicate rows. Changed categories return their ENTIRE before/after canonical lossless record bags and complete changed identity roster; every category retains before/after counts/digests. No body stripping, field exclusion, broad ignore, permission exception, OID normalization or allowed-transition inference exists. Compiled checksum changes remain explicit header fields and registration differences.

Top-level dependency category limit32768, all other categories20000 and64MiB per input match existing exporter boundaries. Parser additionally bounds64levels/2million nodes. Full32768-record synthetic dependency case compares all rows and reports both changed edge identities. Changed identity grouping uses maps, not quadratic whole-category scans. Full differences can contain private source/catalog content; API errors expose only fixed codes. No CLI, console output, installer or publisher exists. Every result has acceptance/production/native/upgradeInstalled/deployed/ledgerPromoted=false regardless equality. Function accepts supplied buffers solely for consistency and does not authenticate producer/reference authority.

## TDD and verification

Tests preceded implementation. Initial JSON.parse-only baseline produced an actual missing-expected-exception RED for escaped duplicate format key (1test/1fail/exit1); baseline compare returned empty differences and extended72-control run was RED. Initial baseline source:
```js
export const FIELDS = {};
export function parseCatalog(raw) { return JSON.parse(raw.toString()); }
export function compareCatalogs() { return { differences: [] }; }
```
A separate nonfinite numeric token control was added before its guard and produced missing-expected-exception RED1fail/exit1, then passed after finite-range guard. Controlled mutants below are isolated in-memory data-URL modules; no live/private source mutation or additional files. Mutant stdout/stderr bounded assertions are recorded here; full data-URL stack source is not reproduced.

Schema observation source SHA256 1b98ebf38779184a8f890f76291ebb92858b36372d2dd3e14e8ccb2c3e958408; historical status observation SHA256 c0530e53a1ecc3719570aa91880ac8520a4d5b65ed1bf278c35639a22a614f3a.

Final source SHA256 f9034fe39e26b0182d3b831300c05608abb1d4e70b588c9c9e3010c44f41b78b; test SHA256 fcdee578c62c706732dab26915133282fbf5d54ae37bc35d92ceec38955d9b12.

### Behavioral RED duplicate-key-guard

{"name": "duplicate-key-guard", "exit": 1, "mutantSHA256": "8c5ca137a2f7193f26346b5aaf0d982015a0e30c234ede8326acc1a6b8b55e0b", "logSHA256": "e72dbaa0812b88e4be80c845f0c4e31239bf59afce900eac4c63c0ea8ea206e5"}

```text
node:internal/modules/run_main:107
    triggerUncaughtException(
    ^

AssertionError [ERR_ASSERTION]: Missing expected exception.
    at file:///workspace/[eval1]:1:16272 {
  generatedMessage: false,
  code: 'ERR_ASSERTION',
  actual: undefined,
  expected: /duplicate-key/,
  operator: 'throws',
  diff: 'simple'
}

Node.js v24.19.0

```

### Behavioral RED dependency-category-loss

{"name": "dependency-category-loss", "exit": 1, "mutantSHA256": "5e16ff8ce6b3cbd0285212b5ef9397b8029bf2c3a02dc703803d55b60763d858", "logSHA256": "18caa98234ff18f53fb00513305b227a3b9079b043d7c8782e749cb5604a43ee"}

```text
node:internal/modules/run_main:107
    triggerUncaughtException(
    ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:

false !== true

    at file:///workspace/[eval1]:1:16274 {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: false,
  expected: true,
  operator: 'strictEqual',
  diff: 'simple'
}

Node.js v24.19.0

```

### Final complete private suite

Actual exit0; stdout/stderr SHA256 ab233dc0d9e3b41a4d41cdc73628820b0326a7eba87fe5b59a30f78127caad2d. Full raw combined log retained verbatim below.

```text
✔ duplicate decoded JSON key refuses rather than keeping last value (2.045054ms)
✔ equal observations report every category and no authority (4.219631ms)
✔ full difference retained for functions (3.539902ms)
✔ full difference retained for schemas (1.166174ms)
✔ full difference retained for relations (2.081563ms)
✔ full difference retained for columns (1.132416ms)
✔ full difference retained for constraints (1.189025ms)
✔ full difference retained for indexes (1.521615ms)
✔ full difference retained for triggers (1.382118ms)
✔ full difference retained for policies (1.489597ms)
✔ full difference retained for roles (1.281169ms)
✔ full difference retained for memberships (1.035156ms)
✔ full difference retained for saved_functions (1.521628ms)
✔ full difference retained for saved_views (0.917739ms)
✔ full difference retained for registrations (1.189616ms)
✔ full difference retained for saved_constraints (1.324941ms)
✔ full difference retained for saved_triggers (0.853205ms)
✔ full difference retained for static_sources (1.138159ms)
✔ full difference retained for types (0.90064ms)
✔ full difference retained for enum_values (1.214288ms)
✔ full difference retained for domain_constraints (0.969273ms)
✔ full difference retained for ranges (0.884145ms)
✔ full difference retained for default_acls (1.132221ms)
✔ full difference retained for rewrite_rules (1.07428ms)
✔ full difference retained for dependencies (1.226418ms)
✔ full difference retained for shared_dependencies (1.063307ms)
✔ full difference retained for extensions (1.139044ms)
✔ full difference retained for role_settings (1.84835ms)
✔ causal mutation functions.acl (1.695432ms)
✔ causal mutation functions.definition (1.766344ms)
✔ causal mutation saved_functions.definition (1.386049ms)
✔ causal mutation registrations.fingerprint (1.514861ms)
✔ causal mutation dependencies.referenced (2.104118ms)
✔ causal mutation default_acls.acl (1.367227ms)
✔ causal mutation roles.bypass_rls (1.888647ms)
✔ causal mutation role_settings.settings_sha256 (1.431164ms)
✔ NULL differs from empty array and literal string null (3.979567ms)
✔ bag multiplicity is retained even for identical dependency records (1.781284ms)
✔ category row ordering is immaterial but array-valued fields remain ordered (3.191935ms)
✔ missing category refuses functions (0.616395ms)
✔ missing category refuses schemas (0.51226ms)
✔ missing category refuses relations (0.390575ms)
✔ missing category refuses columns (0.793858ms)
✔ missing category refuses constraints (0.48449ms)
✔ missing category refuses indexes (0.539879ms)
✔ missing category refuses triggers (0.20167ms)
✔ missing category refuses policies (0.254002ms)
✔ missing category refuses roles (0.186537ms)
✔ missing category refuses memberships (0.171627ms)
✔ missing category refuses saved_functions (0.163145ms)
✔ missing category refuses saved_views (0.165537ms)
✔ missing category refuses registrations (0.204896ms)
✔ missing category refuses saved_constraints (0.450643ms)
✔ missing category refuses saved_triggers (0.215914ms)
✔ missing category refuses static_sources (0.228891ms)
✔ missing category refuses types (0.166637ms)
✔ missing category refuses enum_values (0.164306ms)
✔ missing category refuses domain_constraints (0.160324ms)
✔ missing category refuses ranges (0.167336ms)
✔ missing category refuses default_acls (0.159824ms)
✔ missing category refuses rewrite_rules (0.20501ms)
✔ missing category refuses dependencies (0.224976ms)
✔ missing category refuses shared_dependencies (0.517007ms)
✔ missing category refuses extensions (0.331791ms)
✔ missing category refuses role_settings (0.413526ms)
✔ duplicate unique object identity refuses (0.566462ms)
✔ unknown field refuses (0.394913ms)
✔ missing identity refuses (0.445076ms)
✔ registration binding refuses (0.51406ms)
✔ numeric precision is not silently collapsed (1.513338ms)
✔ malformed/trailing/deep JSON refuses with bounded diagnostic (0.273761ms)
✔ historical checksum change is explicit, never normalized out (1.164249ms)
✔ full dependency bound preserves every record and identifies one changed edge (628.861879ms)
✔ nested duplicate record field refuses (0.45875ms)
✔ nonfinite numeric token refuses (0.330801ms)
ℹ tests 75
ℹ suites 0
ℹ pass 75
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 805.038396
```

## Next required admission work

Recover exact immutable raw inputs/receipts/source authorities and verify all byte/hash/profile correspondences before comparing historical pair. Then review every actual difference without inventing native10089 facts. A paired structural diff cannot prove data preservation: prepare a distinct versioned installed-upgrade transaction and scoped durable data/effect/audit/outbox snapshots, rollback and named-operation/raw-denial tests; execute later only under independently approved owned native fixture. Old binary deployed inventory/drain and original379 actual capture remain separate gates. No 728 row or acceptance is promoted. Independent review of these three files remains pending.
