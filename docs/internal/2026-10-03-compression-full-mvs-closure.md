# Compression module graph closure, 2026-10-03

Add the normal checksum-verified `github.com/klauspost/compress v1.18.7` indirect requirement to platform and its two normal checksums. No other lock, source, module minimum, compiler or replacement changes. The existing 1.18.5 checksums remain; license policy is unchanged.

The actual platform and gateway-control full module graphs previously selected 1.18.5 through OPA. The fixed official GO-2026-5841 record describes SEMVER [1.16.0, 1.18.7); the recorded inventory range diagnostic is affected at 1.18.5 and unaffected at the exact 1.18.7 boundary. It does not establish complete advisory or severity clearance. The normal 1.18.7 ZIP and GoMod h1 checksums verify, the module minimum is 1.24, and its 16,733-byte LICENSE is byte-identical to 1.18.5 (SHA256 `0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf`).

## Actual checks

The live sanitized, pinned Go1.25.13 run passed 30 sequential checks: full-MVS JSON, readonly package closure and `go mod verify` in each of platform, event-ingest, gateway-control, runtime-gateway, sensor-agent, neon-pooled, neo4j-graphstore, localstack-sqs, localstack-storage and opensearch-event. All existing lock bytes and absent-lock states were unchanged by these checks, all stderr was empty and every child joined. The run completed in approximately 18 seconds.

All ten graphs now select compression1.18.7. Platform195 and gateway161 change only its prior1.18.5 selection; seven consumer graphs add only1.18.7. Runtime164 remains unchanged. Actual package inventories confirm no compression imports in the nine changed graphs; runtime's existing eleven imports through Badger are unchanged. Thus this batch changes unused-module inventory and requires no additional compilation/race assertion. No new build or codec coverage is claimed.

Dependency policy validation passed. The first direct regression run passed eight tests and failed the owned esbuild process-group cleanup check in this workspace's nonreaping-init environment. The unchanged original command then passed all nine tests under the previously verified Linux child reaper, which reaped one adopted descendant. No test, process guard or source implementation changed. The initial ten-root wrapper also failed before invoking Go because it assumed opensearch-event had a go.sum; the successor preserves its actual absent state and completed all30 checks. Failed attempts remain recorded.

## Evidence and boundaries

Private predecessor evidence: `/workspace/scratch/compress-full-mvs-prerequisite`; source/candidate roster SHA256 `e7e0f9cfa9bfbc8ce5931302e09b824f35e86b5b43254a2fc2808034c810619b`.

Live actual bundle: `/workspace/scratch/compression-root-readonly-ten-v2`; receipt SHA256 `cc97ed22aee88a46e49c470440df92b2df3dfc5b29e778396cbd1e2fdbf0a63c`. Actual graph/import summary SHA256 `e34834ecc2fcf8bb4ddcb2f7dd9b3dc4c5913eabf4642a80e594ca202256c4ae`. Dependency reaper receipt/log: `/workspace/scratch/compression-dependencies-check-subreaper-receipt-v1.json` and `/workspace/scratch/compression-dependencies-check-subreaper-green-v1.log`.

The previously accepted d255 seven-root advisory component predates these lock changes and must not be reused as current input authority. Its immutable receipts remain historical evidence; a successor requires a new reviewed input manifest and fresh scans. Three crypto advisories, UNKNOWN severity, full-MVS policy, shipping-image license/advisory acceptance, native379, deployed identity/provider and legacy retirement remain open. No original 728 row is promoted, and production release guards remain unchanged. Independent review approved the exact two-lock change, all30 bound logs and ten actual package inventories. It independently replayed complete baseline/candidate MVS pairs for platform and gateway; the remaining eight current graph counts/selections match the retained private summaries. No independent replay of eight unavailable raw baseline pairs is claimed.
