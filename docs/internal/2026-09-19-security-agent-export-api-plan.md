# Agent export API integration plan

> **For agentic workers:** Use Superpowers TDD and independent review, feature-batched verification. Root owns new Go repository/HTTP files. Database implementer owns release58 SQL.

**Goal:** Expose scoped export status and original stored bytes to currently authorized browser users.

**Architecture:** SecurityAgentExportsRepository uses the registered release58 get/grant functions. A separate HTTP handler reuses immutable artifact reading but never browser-compliance permissions. SQL checks current source permissions and real session/CSRF at issue/read/final consume. Bytes are sent only after successful consume.

**Tech Stack:** Existing Go JSONDatabase, session middleware and artifactstore.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md.

## Constraints

Preserve all728 original tasks. No private locator/version in public status.
No current-source rerendering. SQL source permissions aren't interchangeable
with view_compliance or run-view. SQL errors remain authentication/forbidden/
conflict/unavailable, never success. Existing compliance routes stay unchanged.
No publication until full browser verification and external gates pass.

## Task 1: Scoped grant repository

Create apiserver/security_agent_exports_repository.go and its test under
services/platform. Constructor NewSecurityAgentExportsRepository(JSONDatabase).
Private grantAction(ctx,identity,digest,run,step,token,format,operation) returns
complianceGrantResult. Private readGrant with same arguments except operation
returns securityAgentExportReadReceipt.

- [ ] Literal issue/read/consume fixtures must reach exact SQL
  `SELECT public.zasp_sa_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`.
  Arguments are scope3,run,step,principal,cloned session digest,CSRF,token,
  format,operation,compiled checksum,fingerprint. RED before implementation.
- [ ] Validate nonnil live context/database, browser identity with CSRF,
  nonzero32-byte session digest, canonical run/step,64-lowerhex token,
  json/csv/readable format and operation issue/read/consume/integrity_failure.
  No extra view_compliance requirement. Reject invalid inputs before SQL.
- [ ] Closed issue/consume result keys expires_at,consumed. Require nonnull
  bool and consumed exactly for consume/integrity_failure, nonzero expiry.
  Disallow calling grantAction for read.
- [ ] Read result exact fields reference,version,size,sha256,renderer_revision,
  read_expires_at,binding. Bound64KiB, size1..8MiB, canonical digest/version,
  agent renderer revision, future read deadline, independent binding run/step
  matching route,1..100 ordered closed typed selections. Reject nested duplicate
  or unknown fields before decoding. Private receipt is not public API JSON.
- [ ] Tests include foreign run/step, malformed nested bindings, null flags,
  expiry, rejected caller credentials and SQL errors. Group focused native
  race tests, retain evidence and obtain independent review.

## Connected work, not completed by Task1

Mounted route paths are `/api/v1/security-agent-runs/{id}/steps/{stepId}/export`
(GET), `/export/download-grants` and `/export/download` (POST). Operation IDs:
getSecurityAgentExport, createSecurityAgentExportDownloadGrant,
downloadSecurityAgentExport. New optional composition constructor accepts
separate audit/compliance/agent surfaces without changing default routes.
Use browser-only middleware with view as initial route permission; registered
SQL still checks all selected source permissions. No caller-provided export ID
is authority: readGrant supplies the independently bound export reference.
Production constructor/configuration and OpenAPI registration remain required.

Implement typed public status (get contract in database plan), mount scoped
run/step GET status and POST grant/download routes in actual router/OpenAPI,
regenerate client types, and add native UI download action. Follow existing
compliance handler's single session cookie and exact CSRF/header/body checks.
Read immutable bytes under grant deadline; record integrity failure only for
verified mismatch; consume before setting attachment/nosniff response and
writing bytes. Test revocation during storage I/O and no-byte failures through
the mounted handler. Browser and registered SQL evidence are required before
acceptance. Planner/dispatch remains a separate connected critical path.
