package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// Synthetic component fixtures live outside every harness product tenant. The
// preceding proof covers actual worker-committed PG/S3 evidence. This matrix
// isolates all selector semantics in the real OpenSearch engine, not an API or
// production principal/correlation attestation.
func proveRuntimeStructuredSearchSelectors(t *testing.T, ctx context.Context, index *opensearchdriver.SessionIndex) {
	t.Helper()
	id := func(n int) domain.ProductID {
		return workerID(t, fmt.Sprintf("pid_9100%04d-0000-4000-8000-%012d", n, n))
	}
	scope, err := domain.NewScope(id(1), id(2), id(3))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	metadata := runtimemetadata.Fields{PrincipalID: id(21).String(), CredentialID: id(22).String(), Decision: "block"}
	metadata.ProcessDigest, _ = runtimemetadata.DigestSelector("process", "/usr/bin/agent")
	metadata.FileDigest, _ = runtimemetadata.DigestSelector("file", "/etc/shadow")
	metadata.DomainDigest, _ = runtimemetadata.DigestSelector("domain", "api.example.com")
	metadata.ResourceDigest, _ = runtimemetadata.DigestSelector("resource", "bucket/object")
	put := func(tenant domain.Scope, batch int, event string, session domain.ProductID, fields runtimemetadata.Fields) {
		archive, err := json.Marshal(map[string]any{"source": "otlp", "events": []any{map[string]any{
			"event_time": when.Format("2006-01-02T15:04:05.000Z"), "evidence_id": id(23).String(), "search_metadata": fields,
			"attributes": map[string]string{"event.id": event, "event.class": "tool", "event.action": "invoke", "agent.id": id(6).String(), "session.id": session.String(), "task.id": "task-1", "tool.id": "shell", "sandbox.id": "sandbox-1", "trace.id": "11111111111111111111111111111111", "span.id": "1111111111111111"},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := runtimeevent.DecodeArchivedBatch(tenant, archive)
		if err != nil || len(decoded.Records) != 1 {
			t.Fatal(err)
		}
		correlation := runtimecorrelation.Result{EventID: decoded.Records[0].ID, AgentID: id(6), SessionID: session, Confidence: domain.EvidenceConfidenceExact}
		projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: tenant, BatchID: id(batch), Generation: 1, ArchiveReference: "s3://zasp-filter-fixture/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), Body: archive, Correlations: []runtimecorrelation.Result{correlation}})
		if err != nil {
			t.Fatal(err)
		}
		receipt, receiptDigest, _, err := runtimeprojection.EncodeReceipt(runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: tenant, BatchID: id(batch), Generation: 1, InputReference: "s3://zasp-filter-fixture/correlation.json", InputVersionID: "correlation-v1", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: "s3://zasp-filter-fixture/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), EffectDigest: projected.ContentDigest, Items: projected.Items})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := index.Apply(ctx, sessionsearch.ReceiptBinding{Scope: tenant, BatchID: id(batch), Generation: 1, ReceiptDigest: receiptDigest}, receipt, archive); err != nil {
			t.Fatalf("structured fixture write: %v", err)
		}
	}
	put(scope, 30, "all-selectors", id(7), metadata)
	// Exact same event in another valid batch retains provenance without adding
	// another investigation bucket or overwriting the first occurrence.
	put(scope, 31, "all-selectors", id(7), metadata)
	other := metadata
	other.FileDigest, _ = runtimemetadata.DigestSelector("file", "/other")
	other.DomainDigest, _ = runtimemetadata.DigestSelector("domain", "other.example.com")
	other.Decision = "allow"
	put(scope, 32, "different-same-session", id(7), other)
	put(scope, 33, "second-session", id(8), other)
	foreign, err := domain.NewScope(id(41), id(42), id(43))
	if err != nil {
		t.Fatal(err)
	}
	foreignMetadata := metadata
	foreignMetadata.FileDigest, _ = runtimemetadata.DigestSelector("file", "/foreign")
	put(foreign, 34, "foreign-selectors", id(7), foreignMetadata)
	all := sessionsearch.Filters{AgentID: id(6).String(), PrincipalID: id(21).String(), Tool: "shell", Process: "/usr/bin/agent", File: "/etc/shadow", Domain: "API.EXAMPLE.COM", Credential: id(22).String(), Resource: "bucket/object", Decision: "block", From: when, To: when}
	page, err := index.Search(ctx, scope, all, "", 25)
	if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != id(7).String() {
		t.Fatalf("all structured selectors failed: %#v %v", page, err)
	}
	for name, change := range map[string]func(*sessionsearch.Filters){
		"agent": func(f *sessionsearch.Filters) { f.AgentID = id(99).String() }, "principal": func(f *sessionsearch.Filters) { f.PrincipalID = id(99).String() },
		"tool": func(f *sessionsearch.Filters) { f.Tool = "missing-tool" }, "process": func(f *sessionsearch.Filters) { f.Process = "/missing" },
		"file": func(f *sessionsearch.Filters) { f.File = "/missing" }, "domain": func(f *sessionsearch.Filters) { f.Domain = "missing.example.com" },
		"credential": func(f *sessionsearch.Filters) { f.Credential = id(99).String() }, "resource": func(f *sessionsearch.Filters) { f.Resource = "missing/object" },
		"decision": func(f *sessionsearch.Filters) { f.Decision = "allow" }, "time": func(f *sessionsearch.Filters) { f.From = when.Add(time.Nanosecond); f.To = when.Add(time.Second) },
	} {
		filters := all
		change(&filters)
		page, err := index.Search(ctx, scope, filters, "", 25)
		if err != nil || len(page.InvestigationIDs) != 0 {
			t.Fatalf("selector %s broadened results: %#v %v", name, page, err)
		}
	}
	if page, err := index.Search(ctx, scope, sessionsearch.Filters{Domain: "api.example.com", Decision: "allow"}, "", 25); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("selectors incorrectly joined different events within one session: %#v %v", page, err)
	}
	if page, err := index.Search(ctx, scope, sessionsearch.Filters{File: "/foreign"}, "", 25); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("foreign selector leaked: %#v %v", page, err)
	}
	if page, err := index.Search(ctx, foreign, sessionsearch.Filters{File: "/foreign"}, "", 25); err != nil || len(page.InvestigationIDs) != 1 {
		t.Fatalf("foreign positive control absent: %#v %v", page, err)
	}
	after := ""
	for _, want := range []string{id(7).String(), id(8).String()} {
		page, err := index.Search(ctx, scope, sessionsearch.Filters{}, after, 1)
		if err != nil || len(page.InvestigationIDs) != 1 || page.InvestigationIDs[0] != want {
			t.Fatalf("composite pagination incomplete: %#v %v", page, err)
		}
		after = page.After
	}
	if page, err := index.Search(ctx, scope, sessionsearch.Filters{}, after, 1); err != nil || len(page.InvestigationIDs) != 0 {
		t.Fatalf("composite pagination duplicated events: %#v %v", page, err)
	}
	t.Log("real OpenSearch selector matrix passed: all ten structured filter kinds, same-event conjunction, millisecond bounds, cross-batch deduplication, two-page completeness and foreign-tenant positive/negative controls; synthetic component fixtures only")
}
