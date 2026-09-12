package sessionsearch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

func sandboxSearchFixture(t *testing.T, confidence domain.EvidenceConfidence, known bool) (ReceiptBinding, []byte, []byte) {
	t.Helper()
	binding, body, archive := searchDocumentFixture(t, confidence, true)
	receipt, err := runtimeprojection.DecodeReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	item := receipt.Items[0]
	correlation := runtimecorrelation.Result{EventID: item.EventID, AgentID: item.AgentID, SessionID: item.SessionID, Confidence: item.Confidence}
	if known {
		correlation.SandboxID, correlation.SandboxSourceSensorID = "sandbox-a", binding.Scope.EnvironmentID()
	}
	projected, err := runtimeprojection.ProjectSandbox(runtimeprojection.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: archive, Correlations: []runtimecorrelation.Result{correlation}})
	if err != nil {
		t.Fatal(err)
	}
	receipt.ImplementationVersion, receipt.Items, receipt.EffectDigest = "runtime-projection-v2", projected.Items, projected.ContentDigest
	body, binding.ReceiptDigest, _, err = runtimeprojection.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return binding, body, archive
}

func TestSearchSandboxDocumentsRetainQualifiedBinding(t *testing.T) {
	for _, confidence := range []domain.EvidenceConfidence{domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong} {
		t.Run(confidence.String(), func(t *testing.T) {
			binding, receipt, archive := sandboxSearchFixture(t, confidence, true)
			documents, err := BuildDocuments(binding, receipt, archive)
			if err != nil || len(documents) != 1 {
				t.Fatal("sandbox search projection rejected", err)
			}
			encoded, _ := json.Marshal(documents[0])
			var wire map[string]any
			if json.Unmarshal(encoded, &wire) != nil || wire["sandbox_id"] != "sandbox-a" || wire["sandbox_source_sensor_id"] != binding.Scope.EnvironmentID().String() || wire["confidence"] != confidence.String() || wire["investigation_id"] != binding.Scope.WorkspaceID().String() {
				t.Fatal("qualified identity lost", string(encoded))
			}
		})
	}
}

func TestSearchSandboxDocumentsKeepUnknownAndAmbiguousIdentityEmpty(t *testing.T) {
	for _, confidence := range []domain.EvidenceConfidence{domain.EvidenceConfidenceStrong, domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed} {
		t.Run(confidence.String(), func(t *testing.T) {
			binding, receipt, archive := sandboxSearchFixture(t, confidence, false)
			documents, err := BuildDocuments(binding, receipt, archive)
			if err != nil || len(documents) != 1 {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(documents[0])
			if bytes.Contains(encoded, []byte("sandbox")) {
				t.Fatal("invented unknown sandbox", string(encoded))
			}
			if confidence != domain.EvidenceConfidenceStrong && (documents[0].AgentID != "" || documents[0].InvestigationID != "unattributed") {
				t.Fatal("ambiguous identity upgraded")
			}
		})
	}
}

func TestSearchSandboxDocumentsRejectUnboundEvidence(t *testing.T) {
	for _, scenario := range []string{"digest", "scope", "archive", "sandbox"} {
		t.Run(scenario, func(t *testing.T) {
			binding, receipt, archive := sandboxSearchFixture(t, domain.EvidenceConfidenceStrong, true)
			switch scenario {
			case "digest":
				binding.ReceiptDigest[0] ^= 1
			case "scope":
				binding.Scope = domain.Scope{}
			case "archive":
				archive = bytes.Replace(archive, []byte("search-file-1"), []byte("search-file-2"), 1)
			case "sandbox":
				receipt = bytes.Replace(receipt, []byte("sandbox-a"), []byte("sandbox-b"), 1)
				binding.ReceiptDigest = sha256.Sum256(receipt)
			}
			if documents, err := BuildDocuments(binding, receipt, archive); !errors.Is(err, ErrDocument) || documents != nil {
				t.Fatal("unbound sandbox evidence admitted", err)
			}
		})
	}
}

func TestSearchHistoricalDocumentBytes(t *testing.T) {
	binding, receipt, archive := searchDocumentFixture(t, domain.EvidenceConfidenceStrong, true)
	documents, err := BuildDocuments(binding, receipt, archive)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(documents)
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != "624b8e5470849d0e258da00ba869b9114aa2a09f68a76c714ee428d4b2c44b02" {
		t.Fatal("historical search document bytes changed")
	}
}
