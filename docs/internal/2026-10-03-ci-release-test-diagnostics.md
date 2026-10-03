# Bounded release-test failure diagnostics — 2026-10-03

Fresh GitHub check annotations for pushed checkpoint `72c0a10d37b9329f86e44e9c66b034d9cabf4920` identify `production:release:test` as the latest observed npm phase. They do not identify the failed assertion. The corresponding job-log request returned GitHub HTTP302, followed by environment-proxy CONNECT403 at `productionresultssa0.blob.core.windows.net`. This is a log-transport denial, not missing GitHub credentials or an established release-test cause.

The existing bounded failure helper now recognizes exact fixed top-level test names from the nineteen original release-test files. It emits at most four observed failed names and a complete, bounded numeric test summary. Missing or malformed data remains unavailable. Unknown names, assertion text, stacks, paths, arbitrary child output, and credential values are never interpolated into annotations. Every npm package header resets diagnostic state. These are observed log diagnostics, not acceptance evidence or a causal diagnosis.

The canonical npm verification chain, workflow shell, test deadlines, fail-fast behavior, secret guards, license checks, and full-history scans are unchanged. The shell still returns the original npm exit status even if diagnostics fail.

TDD against the predecessor produced three causal failures while its seven existing controls passed. The successor passes ten Node22 controls with zero skips, including phase resets, hostile log content, name/counter caps, actual shell exit37, diagnostic fallback29, and unchanged workflow/TypeScript contracts.

Private frozen source preparation: `/workspace/scratch/ci-release-test-diagnostic-preparation-v1/freeze.json`, SHA256 `4d97f63bfcb5e720f9b10e6d2c0b6d9581dd0128a9f088b133dbe2043304101c`. Original failing hosted runs and their evidence remain unchanged. No ledger promotions or release, native, deployed-provider, advisory-policy, or original728 acceptance are claimed.
