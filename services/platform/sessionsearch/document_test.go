package sessionsearch

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func searchDocumentFixture(t *testing.T, confidence domain.EvidenceConfidence, metadata bool) (ReceiptBinding, []byte, []byte) {
	t.Helper()
	scope := searchScope(t)
	selector := ""
	if metadata {
		digest, _ := runtimemetadata.DigestSelector("file", "/etc/shadow")
		selector = `,"search_metadata":{"file_digest":"` + digest + `"}`
	}
	archive := []byte(`{"source":"tetragon","events":[{"event_id":"search-file-1","class":"file","action":"write","workload_id":"runtime-a","event_time":"2026-09-09T10:00:00.000Z","evidence_id":"pid_00000008-0000-4000-8000-000000000008","content":{"path_digest":"redacted"}` + selector + `}]}`)
	return searchReceiptForArchive(t, scope, archive, confidence)
}

func searchReceiptForArchive(t *testing.T, scope domain.Scope, archive []byte, confidence domain.EvidenceConfidence) (ReceiptBinding, []byte, []byte) {
	t.Helper()
	decoded, err := runtimeevent.DecodeArchivedBatch(scope, archive)
	if err != nil {
		t.Fatal(err)
	}
	correlation := runtimecorrelation.Result{EventID: decoded.Records[0].ID, Confidence: confidence}
	if confidence == domain.EvidenceConfidenceExact || confidence == domain.EvidenceConfidenceStrong {
		correlation.AgentID = scope.OrganizationID()
		correlation.SessionID = scope.WorkspaceID()
	}
	batchID := scope.EnvironmentID()
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: scope, BatchID: batchID, Generation: 1, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), Body: archive, Correlations: []runtimecorrelation.Result{correlation}})
	if err != nil {
		t.Fatal(err)
	}
	receipt := runtimeprojection.Receipt{ImplementationVersion: "runtime-projection-v1", Scope: scope, BatchID: batchID, Generation: 1, InputReference: "s3://zasp-evidence/correlation.json", InputVersionID: "correlation-v1", InputDigest: sha256.Sum256([]byte("correlation")), ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: sha256.Sum256(archive), EffectDigest: projected.ContentDigest, Items: projected.Items}
	body, digest, _, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return ReceiptBinding{Scope: scope, BatchID: batchID, Generation: 1, ReceiptDigest: digest}, body, archive
}

func TestSearchDocumentsUseCommittedProjectionAndObservedMetadata(t *testing.T) {
	for _, confidence := range []domain.EvidenceConfidence{domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong, domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed} {
		t.Run(confidence.String(), func(t *testing.T) {
			binding, receipt, archive := searchDocumentFixture(t, confidence, true)
			documents, err := BuildDocuments(binding, receipt, archive)
			if err != nil || len(documents) != 1 {
				t.Fatalf("documents=%v error=%v", documents, err)
			}
			doc := documents[0]
			encoded, err := json.Marshal(doc)
			if err != nil || bytes.Contains(encoded, []byte("/etc/shadow")) || bytes.Contains(encoded, []byte("path_digest")) || bytes.Contains(encoded, []byte("redacted")) {
				t.Fatal("retained provider content in search document")
			}
			var wire map[string]any
			if json.Unmarshal(encoded, &wire) != nil || wire["record_type"] != "runtime_session_event" || wire["organization_id"] != binding.Scope.OrganizationID().String() || wire["workspace_id"] != binding.Scope.WorkspaceID().String() || wire["environment_id"] != binding.Scope.EnvironmentID().String() || wire["confidence"] != confidence.String() {
				t.Fatalf("authority drift: %s", encoded)
			}
			expectedInvestigation := "unattributed"
			if confidence == domain.EvidenceConfidenceExact || confidence == domain.EvidenceConfidenceStrong {
				expectedInvestigation = binding.Scope.WorkspaceID().String()
				if wire["agent_id"] != binding.Scope.OrganizationID().String() {
					t.Fatal("lost correlated agent")
				}
			} else if wire["agent_id"] != nil {
				t.Fatal("invented agent for weak correlation")
			}
			digest, _ := runtimemetadata.DigestSelector("file", "/etc/shadow")
			if wire["investigation_id"] != expectedInvestigation || wire["file_digest"] != digest || wire["observed_principal_id"] != nil || wire["credential_id"] != nil || wire["decision"] != nil || wire["metadata_version"] != float64(1) {
				t.Fatalf("invented or missing metadata: %s", encoded)
			}
			again, err := BuildDocuments(binding, receipt, archive)
			replayed, _ := json.Marshal(again)
			original, _ := json.Marshal(documents)
			if err != nil || !bytes.Equal(original, replayed) {
				t.Fatal("search replay is not deterministic")
			}
		})
	}
}

func TestSearchDocumentsCarrySemanticSelectorsWithoutUpgradingCorrelation(t *testing.T) {
	scope := searchScope(t)
	metadata := runtimemetadata.Fields{PrincipalID: scope.OrganizationID().String(), CredentialID: scope.EnvironmentID().String(), Decision: "monitor"}
	metadata.ProcessDigest, _ = runtimemetadata.DigestSelector("process", "/usr/bin/agent")
	metadata.FileDigest, _ = runtimemetadata.DigestSelector("file", "/tmp/result")
	metadata.DomainDigest, _ = runtimemetadata.DigestSelector("domain", "api.example.com")
	metadata.ResourceDigest, _ = runtimemetadata.DigestSelector("resource", "bucket/object")
	archive, err := json.Marshal(map[string]any{"source": "otlp", "events": []any{map[string]any{
		"event_time": "2026-09-09T10:00:00.000Z", "evidence_id": scope.EnvironmentID().String(), "search_metadata": metadata,
		"attributes": map[string]string{"event.id": "semantic-search-1", "event.class": "tool", "event.action": "invoke", "agent.id": scope.OrganizationID().String(), "session.id": scope.WorkspaceID().String(), "task.id": "task-1", "tool.id": "shell", "sandbox.id": "sandbox-1", "trace.id": "11111111111111111111111111111111", "span.id": "1111111111111111"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	// Semantic input IDs are observations; the committed correlation remains weak.
	binding, receipt, archive := searchReceiptForArchive(t, scope, archive, domain.EvidenceConfidenceProbable)
	documents, err := BuildDocuments(binding, receipt, archive)
	if err != nil || len(documents) != 1 {
		t.Fatal(err)
	}
	doc := documents[0]
	if doc.ToolID != "shell" || doc.ObservedPrincipalID != metadata.PrincipalID || doc.CredentialID != metadata.CredentialID || doc.Decision != "monitor" || doc.ProcessDigest != metadata.ProcessDigest || doc.FileDigest != metadata.FileDigest || doc.DomainDigest != metadata.DomainDigest || doc.ResourceDigest != metadata.ResourceDigest {
		t.Fatal("semantic selectors dropped or altered")
	}
	if doc.AgentID != "" || doc.InvestigationID != "unattributed" || doc.Confidence != "probable" {
		t.Fatal("semantic IDs overrode the committed weak correlation")
	}
}

func TestSearchDocumentsDoNotInventLegacyMetadata(t *testing.T) {
	binding, receipt, archive := searchDocumentFixture(t, domain.EvidenceConfidenceUnattributed, false)
	documents, err := BuildDocuments(binding, receipt, archive)
	if err != nil || len(documents) != 1 {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(documents[0])
	var wire map[string]any
	if json.Unmarshal(encoded, &wire) != nil || wire["metadata_version"] != float64(0) || wire["file_digest"] != nil {
		t.Fatalf("legacy content silently promoted into structured metadata: %s", encoded)
	}
}

func TestSearchDocumentsPreserveCrossBatchOccurrencesWithoutConflictingEventKeys(t *testing.T) {
	binding, receiptBody, archive := searchDocumentFixture(t, domain.EvidenceConfidenceExact, true)
	first, err := BuildDocuments(binding, receiptBody, archive)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtimeprojection.DecodeReceipt(receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL permits an identical event in another committed batch. Rebuild
	// that batch's legitimate receipt without altering any canonical event facts.
	receipt.BatchID = binding.Scope.OrganizationID()
	correlations := []runtimecorrelation.Result{{EventID: receipt.Items[0].EventID, AgentID: receipt.Items[0].AgentID, SessionID: receipt.Items[0].SessionID, Confidence: receipt.Items[0].Confidence}}
	projected, err := runtimeprojection.Project(runtimeprojection.Batch{Scope: receipt.Scope, BatchID: receipt.BatchID, Generation: receipt.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: archive, Correlations: correlations})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Items, receipt.EffectDigest = projected.Items, projected.ContentDigest
	secondBody, digest, _, err := runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDocuments(ReceiptBinding{Scope: receipt.Scope, BatchID: receipt.BatchID, Generation: receipt.Generation, ReceiptDigest: digest}, secondBody, archive)
	if err != nil || len(second) != 1 {
		t.Fatal(err)
	}
	if first[0].EventID != second[0].EventID || first[0].InvestigationID != second[0].InvestigationID || first[0].DocumentID == second[0].DocumentID {
		t.Fatal("valid cross-batch occurrence collides with another immutable document")
	}
}

func TestSearchDocumentsRejectUnboundReceiptsAndArchiveTampering(t *testing.T) {
	binding, receipt, archive := searchDocumentFixture(t, domain.EvidenceConfidenceExact, true)
	for name, mutate := range map[string]func(*ReceiptBinding, *[]byte, *[]byte){
		"scope":      func(b *ReceiptBinding, _, _ *[]byte) { b.Scope = domain.Scope{} },
		"batch":      func(b *ReceiptBinding, _, _ *[]byte) { b.BatchID = b.Scope.OrganizationID() },
		"generation": func(b *ReceiptBinding, _, _ *[]byte) { b.Generation++ },
		"digest":     func(b *ReceiptBinding, _, _ *[]byte) { b.ReceiptDigest[0] ^= 1 },
		"receipt":    func(_ *ReceiptBinding, r, _ *[]byte) { *r = append(bytes.Clone(*r), ' ') },
		"archive": func(_ *ReceiptBinding, _, a *[]byte) {
			*a = bytes.Replace(*a, []byte("search-file-1"), []byte("search-file-2"), 1)
		},
		"missing archive": func(_ *ReceiptBinding, _, a *[]byte) { *a = nil },
	} {
		t.Run(name, func(t *testing.T) {
			b, r, a := binding, receipt, archive
			mutate(&b, &r, &a)
			if documents, err := BuildDocuments(b, r, a); !errors.Is(err, ErrDocument) || documents != nil {
				t.Fatalf("unbound evidence admitted: %#v %v", documents, err)
			}
		})
	}
}
