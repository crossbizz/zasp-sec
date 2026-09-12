package sessionsearch

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func preciseSearchFixture(t *testing.T, confidence domain.EvidenceConfidence) (ReceiptBinding, []byte, []byte) {
	t.Helper()
	binding, body, archive := searchDocumentFixture(t, confidence, true)
	receipt, err := runtimeprojection.DecodeReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	var typed struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}
	var legacy struct {
		Source string
		Events []sensoradapter.RuntimeEvent
	}
	if err := json.Unmarshal(archive, &legacy); err != nil {
		t.Fatal(err)
	}
	typed.Source = legacy.Source
	for _, event := range legacy.Events {
		lineage := runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64)}, SourceEventTime: "2026-09-09T10:00:00.000000002Z"}
		typed.Events = append(typed.Events, sensoradapter.PreciseRuntimeEvent{RuntimeEvent: event, ObservedLineage: lineage})
	}
	typed.Version = "runtime-archive-v2"
	archive, err = json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	item := receipt.Items[0]
	correlation := runtimecorrelation.Result{EventID: item.EventID, AgentID: item.AgentID, SessionID: item.SessionID, Confidence: confidence}
	if confidence == domain.EvidenceConfidenceStrong {
		correlation.SandboxID = "precise-sandbox"
		correlation.SandboxSourceSensorID = binding.Scope.EnvironmentID()
	}
	receipt.ArchiveDigest = sha256.Sum256(archive)
	projected, err := runtimeprojection.ProjectPrecise(runtimeprojection.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: archive, Correlations: []runtimecorrelation.Result{correlation}})
	if err != nil {
		t.Fatal(err)
	}
	receipt.ImplementationVersion, receipt.Items, receipt.EffectDigest = "runtime-projection-v3", projected.Items, projected.ContentDigest
	body, binding.ReceiptDigest, _, err = runtimeprojection.EncodePreciseReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return binding, body, archive
}

func TestPreciseSearchDocumentsBindArchiveAndKeepIdentity(t *testing.T) {
	for _, confidence := range []domain.EvidenceConfidence{domain.EvidenceConfidenceStrong, domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed} {
		t.Run(confidence.String(), func(t *testing.T) {
			binding, receipt, archive := preciseSearchFixture(t, confidence)
			documents, err := BuildPreciseDocuments(binding, receipt, archive)
			if err != nil || len(documents) != 1 {
				t.Fatal("precise search rejected", err)
			}
			doc := documents[0]
			if doc.Source != "tetragon" || doc.EventClass != "file" || doc.Action != "write" || doc.EventTime != "2026-09-09T10:00:00.000Z" || doc.Confidence != confidence.String() || doc.MetadataVersion != 1 || doc.FileDigest == "" {
				t.Fatal("document facts lost", doc)
			}
			if confidence == domain.EvidenceConfidenceStrong {
				if doc.SandboxID != "precise-sandbox" || doc.SandboxSourceSensorID != binding.Scope.EnvironmentID().String() || doc.AgentID != binding.Scope.OrganizationID().String() || doc.InvestigationID != binding.Scope.WorkspaceID().String() {
					t.Fatal("binding lost")
				}
			} else if doc.SandboxID != "" || doc.AgentID != "" || doc.InvestigationID != "unattributed" {
				t.Fatal("weak identity promoted")
			}
			again, err := BuildPreciseDocuments(binding, receipt, archive)
			firstBytes, _ := json.Marshal(documents)
			againBytes, _ := json.Marshal(again)
			if err != nil || !bytes.Equal(firstBytes, againBytes) {
				t.Fatal("replay changed")
			}
			if docs, err := BuildDocuments(binding, receipt, archive); err == nil || docs != nil {
				t.Fatal("legacy path accepted precise receipt")
			}
			nanosecondDrift := bytes.Replace(archive, []byte(".000000002Z"), []byte(".000000003Z"), 1)
			if bytes.Equal(nanosecondDrift, archive) {
				t.Fatal("missing precise timestamp fixture")
			}
			if docs, err := BuildPreciseDocuments(binding, receipt, nanosecondDrift); err == nil || docs != nil {
				t.Fatal("nanosecond archive drift accepted")
			}
			archive = bytes.Replace(archive, []byte("search-file-1"), []byte("search-file-2"), 1)
			if docs, err := BuildPreciseDocuments(binding, receipt, archive); err == nil || docs != nil {
				t.Fatal("archive drift accepted")
			}
		})
	}
}

func TestPreciseSearchRejectsLegacyAndWrongCommitBinding(t *testing.T) {
	binding, receipt, archive := searchDocumentFixture(t, domain.EvidenceConfidenceStrong, true)
	if docs, err := BuildPreciseDocuments(binding, receipt, archive); err != ErrDocument || docs != nil {
		t.Fatal("precise path accepted legacy receipt", err)
	}
	for _, field := range []string{"scope", "batch", "generation", "digest"} {
		t.Run(field, func(t *testing.T) {
			binding, receipt, archive := preciseSearchFixture(t, domain.EvidenceConfidenceStrong)
			switch field {
			case "scope":
				binding.Scope = domain.Scope{}
			case "batch":
				binding.BatchID = binding.Scope.OrganizationID()
			case "generation":
				binding.Generation++
			case "digest":
				binding.ReceiptDigest[0] ^= 1
			}
			if docs, err := BuildPreciseDocuments(binding, receipt, archive); err != ErrDocument || docs != nil {
				t.Fatal("unbound receipt accepted", err)
			}
		})
	}
}
