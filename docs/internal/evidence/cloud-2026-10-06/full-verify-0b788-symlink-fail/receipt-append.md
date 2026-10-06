## Detached full verification at 0b788520 failed at the SBOM prerequisite

The actual full `npm run verify` ran from 03:31:21 to 03:43:56 UTC and FAILED
after 755 seconds. The new owned detached worktree stayed clean at exact
`0b788520159170a825a925a3f639b0b1d63169f5` before/after completion. Pinned
Node 22.23.1 / npm 10.9.8 / Go 1.25.13 / Tini 0.19.0, umask 0077 and an owned
0700 workspace TMPDIR are bound. No package install or guard skip occurred.
The existing root node_modules symlink, exact package/lock and observed shared
module-lock identities are unchanged and disclosed; these observations do not
establish a complete immutable dependency-file closure.

The full health-contract phase passed: API 8.993s, worker race package 387.221s
and gateway 4.233s. The earlier API characterization/callback failures did not
recur. OpenAPI, tenancy/graph/RLS, UI API, raw-fetch and all 246 UI files / 2,535
tests passed, followed by typecheck, root lint, production imports and staging.
Production release tests reported 284 passes / one failure / zero skips or
cancellations. The exact source-gate failure is `npm sbom --omit=dev
--sbom-format spdx --json`: npm returned ESBOMPROBLEMS with 207 missing dependency
requirement lines. Safe package/version diagnostics are retained; the cause
requires separate prerequisite diagnosis, with no guard weakening or presumed
hosted cause. Build, compiled imports and ledger validation were unreached.

The sealed private packet binds exact source/tool/command/runtime identities,
actual result, scanned bounded sanitized gzip and transformation counts, SBOM
diagnostics and dependency-sharing limits. Existing M1-28/M1-28b health-command
and M8-45/M8-54 SBOM/release task links retain their original acceptance scope.
All 728 rows and 523/144/61 evidence categories remain unchanged. Original
512/6af/997 full failures and native 205/224s failures are preserved. Current
health/UI success does not turn this full failure into a pass or clear approved-
advisory availability, installed/native/varied-login or deployed authority gates.
No online audit, disclosure, provider mutations or root source edits by this
recorder. Independent publication review precedes repository adoption.
