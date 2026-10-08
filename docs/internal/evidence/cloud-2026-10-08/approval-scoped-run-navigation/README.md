# Approval-to-run navigation component

Approvals already use real generated APIs. The production approvals route omitted its existing navigation handler, and approval details displayed the related run as text. The change passes the handler and adds Open run using existing scoped activityLink, current read capability, and pending-decision/context guards. Backend authority, fresh-auth, version and idempotency checks remain.

Task relationships: M7A-88, M7A-89 and M7A-90 UI monitoring/approval behavior. This is a component improvement; it does not complete those tasks' deployed acceptance or promote any ledger row. Main's seven T10-product-ui rows remain component-only.

ROOT independently checked the author source, then executed the existing two security-agent/ordered-UI groups: 137 PASS, 0 FAIL, 12.01 seconds; scoped ESLint and diff checks pass. The initial full typecheck aborted at its 256 MiB V8 heap limit (exit134), so full type safety is not claimed from that attempt. A first Vitest command used unsupported --minWorkers and ran zero tests; the corrected existing-group invocation passed. These outcomes remain recorded.

A dedicated contents-read hosted component job performs locked install, full typecheck, the same existing groups, scoped lint and runnable UI build. It leaves the original release workflow unchanged and introduces no new per-edit tests. Hosted verification is pending. No real Stytch/provider end-to-end or production launch acceptance is claimed.
