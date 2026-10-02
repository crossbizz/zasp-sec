# Agent export immutable download decoder plan

> **For agentic workers:** Use Superpowers TDD and independent review. Root executes this non-overlapping API decoder batch while the database implementer owns release58.

**Goal:** Validate and return original stored agent-export formats against an independently authorized grant binding, without relaxing browser compliance decoding.

**Architecture:** A separate API decoder consumes the existing immutable artifact reader and a typed agent read receipt. It validates locator/version/media/size/hash, the closed package/manifest, full scope, parent run/step and ordered selected records before returning bytes. Grant issue/read/consume authority and HTTP/UI wiring remain a connected follow-on, not inferred from decoder tests.

**Tech Stack:** Existing Go API, artifactstore and bounded JSON helpers; no dependency or provider additions.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md and the get/grant contracts in docs/internal/2026-09-19-security-agent-export-database-plan.md.

## Global constraints

- All728 original tasks remain in scope. Decoder tests are component evidence, not current source permissions, registered grants or live provider proof.
- Do not edit the live database implementer's files, accepted renderer, browser compliance decoder or worker files awaiting registered acceptance.
- No new queue/store/provider; no external calls, installs, secrets, git mutations or publication.
- The independently authorized binding comes from the grant, never from the package being checked. Original source IDs are preserved, including64-lowercase-hex manual IDs.
- Limits match the accepted renderer: package8MiB, each format4MiB,1..100 unique ordered selections, content object64KiB, JSON depth32. Reject missing, duplicate, unknown and trailing fields/data.
- Original prepared bytes are authoritative. Never fetch current sources, rerender formats, silently omit records or claim remediation.
- Use focused tests then one independent frozen-batch review. Retain exact source/test evidence and explicitly unresolved authority gates.

### Task 1: Bound immutable agent package decoding

**Files:** Create services/platform/apiserver/security_agent_export_download.go and security_agent_export_download_test.go. Existing compliance_download.go, compliance_http_test.go and renderer are read-only references. Evidence: docs/internal/security-agent-export-20260919/download/.

**Interfaces:** Define typed API values with exact JSON tags:

```go
type SecurityAgentExportSelection struct {
    Kind string `json:"source_kind"`
    ID string `json:"source_id"`
    Version int64 `json:"source_version"`
    AssociationDigest string `json:"association_digest"`
}
type SecurityAgentExportBinding struct {
    RunID string `json:"run_id"`
    StepID string `json:"step_id"`
    Selection []SecurityAgentExportSelection `json:"selection"`
}
type securityAgentExportReadReceipt struct {
    complianceReadReceipt
    Binding SecurityAgentExportBinding `json:"binding"`
}
func readSecurityAgentExportDownload(ctx context.Context, reader complianceArtifactReader,
    identity RequestIdentity, exportID, format string,
    pin securityAgentExportReadReceipt) ([]byte,error)
```

- [ ] Write behavioral tests with the real reader/decoder boundary and a controlled artifact reader. Use a literal scoped finding manifest, independent content/package SHA256 values, and stored CSV/readable strings. Require exact JSON/CSV/human bytes. The receipt revision must equal security-agent-evidence-envelope-v1, reference must equal exportID and immutable version must be nonempty valid. Test malformed binding before any reader call.
- [ ] Test valid stored bytes with independently wrong run/step/source identity/version/association/order, foreign scope, duplicate/unknown manifest fields, wrong mapping/renderer revisions, noncanonical snapshot time, corrupt record hash and invalid content object. Recompute only package hash for tampered-manifest tests so outer integrity cannot mask the semantic boundary being exercised.
- [ ] Test wrong locator/version/media/body length/hash from storage, expired read lease, cancellation during Get, unknown format, and provider errors. No returned bytes on failure. Provider failure is unavailable, while verified mismatches join artifactstore.ErrIntegrity with repository unavailability; preserve the distinction used by integrity_failure grants.
- [ ] Implement source selection validation with canonical product IDs for finding/attack_path/runtime_decision/run_audit/existing_test/attack_lab, and64-lowercase-hex manual identity. Source version1..9007199254740991, association_digest sha256:+64lowerhex. Each kind/ID unique and exact array ordering preserved.
- [ ] Require the package keys version,id,json,csv,human, version1 and requested exportID. Require manifest mapping_revision,snapshot_at,organization_id,workspace_id,environment_id,run_id,step_id,records,renderer_revision. Canonical UTC RFC3339Nano time must round-trip exactly. Every record has source_kind,source_id,source_version,association_digest,content_sha256,content_json. Validate content_sha256 against the exact UTF-8 content_json bytes and a bounded JSON object; do not treat the association digest as the content checksum.
- [ ] Return cloned manifest RawMessage for json, original CSV bytes for csv, original escaped readable bytes for human. Validate all package formats before returning any one. The HTTP follow-on must use attachment/no-sniff and current grant consume before sending these bytes; this helper alone authorizes no response.
- [ ] Run focused RED/GREEN in services/platform with cached Go environment, then one combined native race invocation:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./apiserver -run '^(TestSecurityAgentExportDownload.*|TestCompliancePersisted.*)$' -count=1 -v
```

- [ ] Freeze new-file patch/hashes, record exact commands/output/exits, self-review and obtain independent spec/quality review. Keep original M7A-23 component-only.

## Required connected follow-on

Add registered grant/status repository, mounted scoped run/step routes, OpenAPI
and generated types, native UI download action. Browser credential/CSRF and every
selected source permission must be checked at issue/read/final consume. No
bytes may reach HTTP before consume succeeds after storage I/O. Preserve normal
compliance owner/session semantics and grant expiry/read-lease-aware cleanup.
The planner, dispatch, settlement loop, runtime readiness and full browser flow
remain required. No task or production completion follows from this decoder.
