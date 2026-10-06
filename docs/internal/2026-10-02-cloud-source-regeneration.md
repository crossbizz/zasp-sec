# Cloud development source regeneration, October 2, 2026

A separately versioned source copier now regenerates the development builder's eight outputs from exactly 171 authenticated inputs: 159 fixed cloud-A sources, eleven specifically selected legacy-pinned supplementary reads, and one unchanged legacy inventory. The existing A/B packets, legacy output pins and native expectations remain unchanged.

The first actual regeneration reproduced a missing supplementary contract. TDD added the minimal eleven-input join, exact consumed-buffer checks, topology refusals and final drift validation. Independent review approved the frozen two-file delta. Focused verification passed 89/89 checks with no failures or skips, including two actual deterministic regenerations. This is source-only evidence; no PostgreSQL execution or production promotion follows.

The copier binds Linux/x64 Node22.23.1 to its exact executable digest, uses an internally owned empty temporary repository and sanitized child environment, and refuses caller arguments, source substitutions, extra authority, invalid paths, changed runtime, child failure and output drift. The 84-entry historical inventory is metadata authority for the eleven selected inputs; it is not a general fallback.

## Exact supplement and authority table

| Repository-relative input | Bytes | SHA256 |
| --- | ---: | --- |
| `services/platform/migrations/sql/0072_production_temporal_discovery.up.sql` | 125871 | `e51eecf1201f930449ea508838e94dd5344262f92a4d23768999d93697f2c940` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json` | 4017762 | `c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json` | 925457 | `76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/missing-reference-native-packet.json` | 325638 | `23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/native-composition-manifest.json` | 1476 | `742061cb79130a9e866daa63babe914cf1052e4958ba40c798b8e030c1dd7899` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/private-successor-packet.json` | 90223 | `6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0` |
| `services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/private-successor-reference.json` | 48507 | `b8694163c33accd304e85324bddda311bf4ab4704e898823bb2814c1647c0d80` |
| `services/platform/migrations/tools/ordered-current-native379-packet-v1-artifacts/source-inputs.json` | 11114 | `34e3dfdfdd00c316eb9ad7300f8624f1b21543c95ed108578b739bb60e1e3229` |
| `services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/private-reference-alias-contract.json` | 134929 | `59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63` |
| `services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/remaining-reference-packet-manifest.json` | 3502 | `338026bf79be5535bf0f57206b679e5846526da676fee6b0adac75186083d7ea` |
| `services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/supplementary-query-contract2.json` | 210828 | `6b8fc25c4d5d0a379735d686fe1d6cde8245663a47d346dbf8cf1c11dd33418f` |
| `services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/supplementary-query-contract3.json` | 592661 | `2334ebbbad1382db7eafa47f81eec5b59f7721aaafa34b6b0d51311d959538ce` |

## Exact source-only outputs

The new copier pins the fresh eight outputs below. These pins appear only in the two new files; stale legacy output pins remain unchanged. Effective-contract4 and reference-select bytes are identical to legacy, providing fixed-source continuity.

| Repository-relative output | Bytes | SHA256 |
| --- | ---: | --- |
| `services/platform/migrations/ordered_current/consolidated-reference-contract.json` | 1278073 | `d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff` |
| `services/platform/migrations/ordered_current/consolidated-reference-select.sql` | 47653 | `23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57` |
| `services/platform/migrations/ordered_current/development-admission.sql` | 5914 | `999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef` |
| `services/platform/migrations/ordered_current/development-checkpoint.json` | 7962818 | `905664791351c9714bfa4769ab94a6c11c6f1744c11ff56c165536fc71d13705` |
| `services/platform/migrations/ordered_current/development-collector.sql` | 341172 | `97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f` |
| `services/platform/migrations/ordered_current/development-manifest.json` | 20154797 | `4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9` |
| `services/platform/migrations/ordered_current/development-module.sql` | 10359778 | `4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74` |
| `services/platform/migrations/ordered_current/effective-contract4.json` | 10618112 | `06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0` |

All eight output buffers, deterministic receipt and semantic summary are privately saved under `/workspace/scratch/cloud-source-copy-reviewed-output-v1` (directories0500, files0400). Detailed safe delta is `/workspace/scratch/cloud-source-copy-semantic-detail.json` (0400). No output was published into a legacy/native pathway.

## Semantic delta and limits of acceptance

Fresh output flags: manifest.installable=false, checkpoint.nativeVerified=false, dormantEvaluator.installable=false and nativeVerified=false. The new receipt is SOURCE-REGENERATION-ONLY with installable/nativeVerified/executableReplacementVerified/captureAuthority all false. A's sourceFrameVersion remains1, its exact contract stays fixed, effective-contract4 is byte-identical, and the fresh reference contract differs only in its module provenance. Private source evidence reports8 compiler-derived routines,35 continuity facts,0 imported routine observations, and eight declarations. Existing builder calls compileOrderedPrecisionPrivateRoutinesV1, attaches/asserts that source authority, and includes the precision-resolver admission expression; the copier changes none of those producer bytes.

Fresh source derivation differs from the unchanged historical10053-fact native expectation and remains unaccepted. It contains10052 facts: removes two temporal72:trigger facts and adds one private-routines fact. All379 rule IDs remain identical; only expectedFacts metadata changes private-routines7→8 and temporal72:trigger4→2. Eight same-key values change: five gateway constraint pretty definitions, one ordered trigger pretty definition, private catalog source and build provenance. The source builder explicitly isolates direct temporal72 aliases and enforces the exact-two equalExisting reconciliation. These are source-derived changes; no PostgreSQL/native private8 behavior was asserted by this copier.

Changed reference module provenance:
- `ordered-current-worker-edge-projections.mjs`: `84def24449db6f49514c2d60de101eed2bdb5a2c80a5467a5c9e6bc03e602220` → `b66ca401a660094dafe30adf48b762224c9ae7f71fa33bb95bd614dffce41fab`.
- `ordered-current-transform-compiler.mjs`: `63e64805a02b1f3fa46cde06395c8f16a29174bd0302e98b148d73cc701edc1b` → `a4be3198e8277c338636c8ec1f206908def94996114cba46d35d82c5670ab2a3`.
- `ordered-current-catalog.mjs`: `0901442f9885352359aae1065f12c5457a16176b2e13b487efea39719ccab840` → `4a05085b7bf6beb712b80007804eee01c07d018ea9d1e160357b3c0d9b05400b`.

Detailed field/key/rule hashes are in the retained safe reports, without raw SQL/arguments/DSN/credential output. Full native379, source-result adoption, private8 runtime admission, varied-login/OID portability, connected workers and728 production acceptance remain separate/open.

## Review and retained verification

Reviewed copier SHA256: `b27db0c0c4ee8eae75488371fb003f77f865977ddf88db23191e83cecce1d2d4`.
Reviewed test SHA256: `46661c418b53a337a846c2eda5074e3feef578d41786d7e460a003c75ed9bb65`.
The coordinator independently reran the focused suite before committing. Failed missing-source and stale-output attempts remain private evidence rather than acceptance.

The eight private outputs were retained for semantic review. Source facts change from 10053 to 10052: two temporal-trigger facts are removed and one private-routine fact is added. All 379 rule identities remain, but two expected-fact counts and eight same-key values change. Those differences require native validation before adoption. Existing native counts, pins and guards are preserved. No original requirement ledger row changes.
