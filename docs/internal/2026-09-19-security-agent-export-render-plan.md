# Run-evidence export rendering implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. This is the rendering batch of original M7A-23, not completion of that task.

**Goal:** Produce bounded, deterministic JSON/CSV/readable packages from the exact trusted run-evidence snapshot, using the existing export worker's prepared-artifact interface.

**Architecture:** A pure renderer consumes a database-authorized snapshot and an independently supplied run/step binding. It returns the existing compliancePreparedArtifact type. It does not collect sources, authorize membership, call storage, or enable the action; the subsequent admission/runtime batch must supply those boundaries.

**Tech Stack:** Go1.25.6 standard library; existing agentsec-worker package and domain.Scope.

**Spec:** docs/internal/2026-09-19-security-agent-evidence-export-design.md, with the wire contract below defining this batch's exact representation.

## Global Constraints

- Preserve all728 original tasks. M7A-23 remains component-only until connected and production gates are proved.
- Keep browser-origin jobs on their existing session-bound authorization path.
- Selections are nonempty, unique and bounded to100 references.
- The manifest includes full scope, parent run/step, exact selected source kinds, IDs, versions/digests, snapshot time and renderer revision.
- Export completion means the immutable package is available, not that a finding is safe/remediated.
- No provider/advisory calls, downloads, uncached images, secret access, commit or push in this batch. Existing external publication gates remain.
- Work only in /Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917. Preserve inherited changes. Apply patches for edits.
- Run focused RED/GREEN while implementing. Review this batch once; database/browser acceptance belongs to the connected feature batch, not each renderer helper.

## Wire and trust boundary

Snapshot fields, all required and exclusive:
`mapping_revision`, `snapshot_at`, `organization_id`, `workspace_id`,
`environment_id`, `run_id`, `step_id`, `records`.
Revision is `security-agent-run-evidence-v1`. Time is canonical UTC RFC3339Nano.
Run, step and scope IDs use domain.ParseProductID. Source IDs use the same
parser except manual, whose original trigger ID is exactly64 lowercase hex
characters, as persisted by the legacy run admission. Scope must equal the
lease; run and step must equal the independent binding. The binding includes
the exact ordered selection so the renderer refuses omissions, additions and
reordering. Ordering is selected/frozen by the collector, not sorted at render.

Each record has exactly `source_kind`, `source_id`, `source_version`,
`association_digest`, `content_sha256`, `content_json`.
Kinds: finding, attack_path, runtime_decision, run_audit, existing_test,
attack_lab, manual. This vocabulary does not make an unresolved manual source
exportable. Source version is1..9007199254740991. Association digest is
`sha256:` followed by64 lowercase hex characters. Content SHA256 is64 lowercase
hex characters, over the exact UTF-8 bytes of content_json. The association
digest is not a checksum of the source content.

content_json is a nonempty JSON object serialized as a string, maximum65536
bytes, valid UTF-8. Reject duplicate keys, invalid UTF-8, trailing data and
nesting greater than32 in the outer snapshot and content. This is a private
trusted collector output, never an API accepting caller-supplied evidence.
The collector must apply source-specific redaction before this interface;
this renderer cannot prove membership or infer whether a JSON field is secret.
Retain the exact content string to preserve the checksum across all formats.

Maximum snapshot4MiB, each rendered format4MiB, final package8MiB. Reject excess
atomically, never truncate. Existing compliance renderer and runtime are
unchanged, so this batch does not let a browser compliance job masquerade as
an agent job.

### Task 1: Render a frozen run-evidence package

**Files:**
- Create: services/platform/agentsec-worker/security_agent_export_render.go
- Create: services/platform/agentsec-worker/security_agent_export_render_test.go
- Evidence: docs/internal/security-agent-export-20260919/render/
- Read only: services/platform/agentsec-worker/compliance_export_database.go, compliance_export_render.go, compliance_export_runtime_test.go

**Interfaces:**

```go
type securityAgentExportSelection struct {
    Kind string
    ID string
    Version int64
    AssociationDigest string
}
type securityAgentExportBinding struct {
    RunID string
    StepID string
    Selection []securityAgentExportSelection
}
func renderSecurityAgentEvidenceExportPackage(
    ctx context.Context,
    lease complianceExportLease,
    binding securityAgentExportBinding,
    raw json.RawMessage,
) (compliancePreparedArtifact, error)
```

The existing compliancePreparedArtifact has Bytes, RendererRevision, Reference,
SHA256, Size and FormatSizes. Return an empty value plus errWorkerExecution on
any rejection. Require nonnil, noncancelled context, valid scope and export ID.
No goroutines, process-global state, database or provider calls.

- [ ] Preserve before/source ownership metadata, create the evidence directory and write focused tests first. The regression to catch is exporting a different run, omitted source, changed content, unsafe CSV/readable text or oversized package despite a valid-looking snapshot.
- [ ] Use the existing complianceRuntimeLease(t) fixture. Implement a test-local snapshot helper with literal source content `{"summary":"=1+1 <script>"}`, compute its digest independently with crypto/sha256, and supply one finding reference. Example test body (helper name defined here as test-local fixture, returning raw snapshot plus binding):

```go
func TestSecurityAgentExportRenderBindsScopeAndSelection(t *testing.T) {
    l := complianceRuntimeLease(t)
    raw, binding := securityAgentExportSnapshotFixture(t, l)
    foreign := binding
    foreign.RunID = "pid_20000001-0000-4000-8000-000000000001"
    if p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, foreign, raw); err == nil || len(p.Bytes) != 0 {
        t.Fatal("foreign run rendered")
    }
    omitted := binding
    omitted.Selection = nil
    if p, err := renderSecurityAgentEvidenceExportPackage(context.Background(), l, omitted, raw); err == nil || len(p.Bytes) != 0 {
        t.Fatal("selection omitted")
    }
}
```

- [ ] Observe RED before implementing. A missing symbol is only initial setup RED; once the function exists, record behavioral RED for a deliberately unimplemented validation or render branch before adding it. Run from services/platform with:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test ./agentsec-worker -run '^TestSecurityAgentExportRender' -count=1 -v
```

- [ ] Implement the closed snapshot/record decoding and exact independent binding checks. Define private wire structs with the exact JSON tags above. Validate bounds before allocations, then validate every record. Reject duplicate kind/ID pairs even when versions differ. Every selected entry must match the record at the same index in all four selection fields. Check context again before returning bytes.
- [ ] Emit the same outer envelope shape as existing compliance exports:

```go
body, err := json.Marshal(struct {
    Version int `json:"version"`
    ID string `json:"id"`
    JSON json.RawMessage `json:"json"`
    CSV string `json:"csv"`
    Human string `json:"human"`
}{1, lease.ExportID, manifestJSON, csvText, readableText})
```

Here manifestJSON is the validated snapshot re-encoded with an additional
`renderer_revision` field equal to `security-agent-evidence-envelope-v1`.
Preserve record order and exact content_json strings. Set RendererRevision to
that same value, Reference to lease.ExportID, SHA256 to lowercase SHA256 of
body, Size to byte length, and FormatSizes to exact json/csv/readable lengths.

- [ ] CSV contains a header and one row per record, with full scope, run, step,
snapshot_at, renderer_revision and all six record fields. Use encoding/csv;
prefix any cell beginning with `=`, `+`, `-`, `@`, TAB, CR or LF with an
apostrophe, including after leading ASCII spaces. This rule applies to every
cell, not just a human summary. Readable output is explicit HTML with escaped
untrusted values (html.EscapeString), showing the manifest and each record's
exact content string in a preformatted block. Do not mark raw content as HTML.
Add fixed explanatory copy that export does not establish remediation.
- [ ] Tests parse actual output JSON and encoding/csv rows, inspect readable
escaping, recompute package/content hashes, compare bytes from repeated
renders, and verify input/binding are not mutated. A zero/mismatched hash, a
wrong record version/kind/ID, each scope dimension, duplicate selection,
unknown field, duplicate JSON field, malformed JSON, invalid UTF-8, null
record/content, trailing data, invalid time, empty/101 selections, non-object
content, overlong content, overdeep content, nil/cancelled context and invalid
export ID must return an empty artifact and error. Include all seven source
kinds, preserve pending/failed/cleanup text without claiming remediation, and
show association digest differs from content digest without rejecting it.
- [ ] Include accepted exact-boundary fixtures (100 records,65536-byte content)
and rejection at every size boundary. Fixture construction may calculate byte
lengths; expected identity and semantic values must not call production
helpers. Prove package expansion is bounded as JSON escaping can exceed raw
snapshot size. Exercise formula-leading content within valid JSON through
CSV parsing and test the escaping helper's dangerous prefixes directly.
- [ ] Run focused GREEN, then the existing compliance renderer regression plus
the new tests in one race batch:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race ./agentsec-worker -run '^(TestSecurityAgentExportRender|TestComplianceRuntimeRendersFrozenSnapshot)' -count=1 -v
```

- [ ] Self-review and retain command/cwd/output/exit, task-only patch and before/
after hashes. No commit/push. Report exact evidence, limitations and concerns
to root for one independent review. Do not spawn subagents.

## Required continuation after this batch

This is not the full M7A-23 implementation plan. The next connected batch must
add additive schema after57, agent job origin and checked principal binding,
all source collectors and source-specific redaction/permissions, registered
planner/dispatch/worker linkage, prepared-byte replay, publication/cancellation
fencing, native downloads and UI. Then run real registered PostgreSQL/race and
mounted browser/download/restart acceptance, independent feature review, and
publication gates. The renderer cannot be enabled before these exist.

## Plan self-review

The rendering requirement is covered by Task1; membership, authority and user
workflow requirements are explicitly outside this batch and remain pending.
No existing lease or browser function changes. The only output interface is
compliancePreparedArtifact, already consumed by the durable export pipeline.
The selection/binding types are fully specified above. Content digest and
association digest have distinct formats/meanings; future collectors must
honor this wire contract. All size bounds are byte counts.
