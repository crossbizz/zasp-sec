# Release probe trace identifier validation

The production read-only probe previously accepted an all-zero span identifier when the trace identifier was valid. It now refuses either zero identifier, preserving the existing protocol, authenticated API, correlation, performance and token-redaction checks.

An owned local HTTP server reproduced the missing rejection before the source change. The focused grouped run passes eight tests after the change, including sampled and unsampled valid traces, zero span, zero trace, malformed span, token redaction and the existing release policy. Scoped ESLint and `git diff --check` pass. The release sources/SBOM integration test was filtered from this focused run; no result for that test is claimed here. Original RED and GREEN logs and their hashes are retained in [the evidence manifest](evidence/cloud-2026-10-07/release-trace-guard/manifest.json).

This is release-probe component evidence, not deployed identity/provider or launch acceptance. Ledger validation retains all 728 original IDs: 523 recorded production-available, 144 component-only, 61 externally blocked and zero missing. No task is promoted. The hosted compliance browser gate, approval/connector background authorization, native admission and deployed end-to-end requirements remain open.
