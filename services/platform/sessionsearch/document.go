package sessionsearch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeprojection"
)

var ErrDocument = errors.New("runtime session search evidence rejected")

// ReceiptBinding must come from committed PostgreSQL projection authority, not
// a search request or the receipt being checked. It pins the immutable S3 bytes.
type ReceiptBinding struct {
	Scope         domain.Scope
	BatchID       domain.ProductID
	Generation    int64
	ReceiptDigest [sha256.Size]byte
}

// Document represents one committed batch occurrence, not a distinct event.
// EventID identifies the canonical event. Queries group by investigation ID;
// OpenSearch doc_count must never be reported as the session's event count.
// Canonical session counts and authorization remain PostgreSQL-owned.
type Document struct {
	RecordType            string `json:"record_type"`
	DocumentID            string `json:"document_id"`
	OrganizationID        string `json:"organization_id"`
	WorkspaceID           string `json:"workspace_id"`
	EnvironmentID         string `json:"environment_id"`
	BatchID               string `json:"batch_id"`
	Generation            int64  `json:"generation"`
	ReceiptDigest         string `json:"receipt_digest"`
	ArchiveDigest         string `json:"archive_digest"`
	EventID               string `json:"event_id"`
	InvestigationID       string `json:"investigation_id"`
	AgentID               string `json:"agent_id,omitempty"`
	SandboxID             string `json:"sandbox_id,omitempty"`
	SandboxSourceSensorID string `json:"sandbox_source_sensor_id,omitempty"`
	Confidence            string `json:"confidence"`
	Source                string `json:"source"`
	EventClass            string `json:"event_class"`
	Action                string `json:"action"`
	EventTime             string `json:"event_time"`
	ToolID                string `json:"tool_id,omitempty"`
	MetadataVersion       int    `json:"metadata_version"`
	ObservedPrincipalID   string `json:"observed_principal_id,omitempty"`
	ProcessDigest         string `json:"process_digest,omitempty"`
	FileDigest            string `json:"file_digest,omitempty"`
	DomainDigest          string `json:"domain_digest,omitempty"`
	CredentialID          string `json:"credential_id,omitempty"`
	ResourceDigest        string `json:"resource_digest,omitempty"`
	Decision              string `json:"decision,omitempty"`
}

// BuildDocuments joins a digest-bound committed correlation projection to its
// exact raw archive. It reprojects the archive to reject even internally valid
// receipts whose items don't match the archived event facts. Missing selectors
// remain absent; metadata_version reports availability, not identity assurance.
func BuildDocuments(binding ReceiptBinding, receiptBody, archiveBody []byte) ([]Document, error) {
	return buildDocuments(binding, receiptBody, archiveBody, false)
}

func buildDocuments(binding ReceiptBinding, receiptBody, archiveBody []byte, precise bool) ([]Document, error) {
	if binding.Scope.Validate() != nil || binding.BatchID.IsZero() || binding.Generation < 1 || binding.ReceiptDigest == ([sha256.Size]byte{}) || len(receiptBody) < 1 || len(receiptBody) > 4<<20 || sha256.Sum256(receiptBody) != binding.ReceiptDigest {
		return nil, ErrDocument
	}
	decode := runtimeprojection.DecodeReceipt
	if precise {
		decode = runtimeprojection.DecodePreciseReceipt
	}
	receipt, err := decode(receiptBody)
	if err != nil || receipt.Scope != binding.Scope || receipt.BatchID != binding.BatchID || receipt.Generation != binding.Generation {
		return nil, ErrDocument
	}
	correlations := make([]runtimecorrelation.Result, len(receipt.Items))
	for i, item := range receipt.Items {
		correlations[i] = runtimecorrelation.Result{EventID: item.EventID, AgentID: item.AgentID, SessionID: item.SessionID, Confidence: item.Confidence, SandboxID: item.SandboxID, SandboxSourceSensorID: item.SandboxSourceSensorID}
	}
	batch := runtimeprojection.Batch{Scope: binding.Scope, BatchID: binding.BatchID, Generation: binding.Generation, ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: receipt.ArchiveDigest, Body: archiveBody, Correlations: correlations}
	var projected runtimeprojection.ProjectedBatch
	switch receipt.ImplementationVersion {
	case "runtime-projection-v1":
		projected, err = runtimeprojection.Project(batch)
	case "runtime-projection-v2":
		projected, err = runtimeprojection.ProjectSandbox(batch)
	case "runtime-projection-v3":
		if !precise {
			return nil, ErrDocument
		}
		projected, err = runtimeprojection.ProjectPrecise(batch)
	default:
		return nil, ErrDocument
	}
	if err != nil || projected.ContentDigest != receipt.EffectDigest || len(projected.Items) != len(receipt.Items) {
		return nil, ErrDocument
	}
	for i := range projected.Items {
		if projected.Items[i] != receipt.Items[i] {
			return nil, ErrDocument
		}
	}
	var archive runtimeevent.ArchivedBatch
	if precise {
		var decoded runtimeevent.PreciseArchivedBatch
		decoded, err = runtimeevent.DecodePreciseArchivedBatch(binding.Scope, archiveBody)
		for _, record := range decoded.Records {
			archive.Records = append(archive.Records, record.Record)
		}
	} else {
		archive, err = runtimeevent.DecodeArchivedBatch(binding.Scope, archiveBody)
	}
	if err != nil {
		return nil, ErrDocument
	}
	records := make(map[domain.ProductID]runtimeevent.Record, len(archive.Records))
	for _, record := range archive.Records {
		if _, duplicate := records[record.ID]; duplicate {
			return nil, ErrDocument
		}
		records[record.ID] = record
	}
	documents := make([]Document, len(receipt.Items))
	for i, item := range receipt.Items {
		record, found := records[item.EventID]
		if !found || !record.SearchMetadata.Valid(item.Source) {
			return nil, ErrDocument
		}
		investigation := "unattributed"
		if !item.SessionID.IsZero() {
			investigation = item.SessionID.String()
		}
		metadataVersion := 0
		metadata := record.SearchMetadata
		if metadata != (runtimemetadata.Fields{}) {
			metadataVersion = 1
		}
		// Distinct committed batch occurrences retain their own receipt provenance.
		// The same receipt replay still produces byte-identical document keys/body.
		identity := "zasp.runtime-session-search.occurrence.v1\x00" + binding.Scope.OrganizationID().String() + "\x00" + binding.Scope.WorkspaceID().String() + "\x00" + binding.Scope.EnvironmentID().String() + "\x00" + binding.BatchID.String() + "\x00" + strconv.FormatInt(binding.Generation, 10) + "\x00" + item.EventID.String()
		digest := sha256.Sum256([]byte(identity))
		documents[i] = Document{
			RecordType: "runtime_session_event", DocumentID: hex.EncodeToString(digest[:]),
			OrganizationID: binding.Scope.OrganizationID().String(), WorkspaceID: binding.Scope.WorkspaceID().String(), EnvironmentID: binding.Scope.EnvironmentID().String(),
			BatchID: binding.BatchID.String(), Generation: binding.Generation, ReceiptDigest: hex.EncodeToString(binding.ReceiptDigest[:]), ArchiveDigest: hex.EncodeToString(receipt.ArchiveDigest[:]),
			EventID: item.EventID.String(), InvestigationID: investigation, AgentID: item.AgentID.String(), Confidence: item.Confidence.String(),
			SandboxID: item.SandboxID, SandboxSourceSensorID: item.SandboxSourceSensorID.String(),
			Source: item.Source, EventClass: item.EventClass, Action: item.Action, EventTime: item.EventTime, ToolID: record.ToolID,
			MetadataVersion: metadataVersion, ObservedPrincipalID: metadata.PrincipalID, ProcessDigest: metadata.ProcessDigest, FileDigest: metadata.FileDigest,
			DomainDigest: metadata.DomainDigest, CredentialID: metadata.CredentialID, ResourceDigest: metadata.ResourceDigest, Decision: metadata.Decision,
		}
	}
	return documents, nil
}
