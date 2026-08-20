package runtimeprojection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
)

const receiptSchema = "runtime-projection-receipt-v1"

type Receipt struct {
	ImplementationVersion string
	Scope                 domain.Scope
	BatchID               domain.ProductID
	Generation            int64
	InputReference        string
	InputVersionID        string
	InputDigest           [sha256.Size]byte
	ArchiveReference      string
	ArchiveVersionID      string
	ArchiveDigest         [sha256.Size]byte
	EffectDigest          [sha256.Size]byte
	Items                 []Item
}

type receiptWire struct {
	Schema                string     `json:"schema"`
	ImplementationVersion string     `json:"implementation_version"`
	OrganizationID        string     `json:"organization_id"`
	WorkspaceID           string     `json:"workspace_id"`
	EnvironmentID         string     `json:"environment_id"`
	BatchID               string     `json:"batch_id"`
	Generation            int64      `json:"generation"`
	InputReference        string     `json:"input_reference"`
	InputVersionID        string     `json:"input_version_id"`
	InputDigest           string     `json:"input_digest"`
	ArchiveReference      string     `json:"archive_reference"`
	ArchiveVersionID      string     `json:"archive_version_id"`
	ArchiveDigest         string     `json:"archive_digest"`
	EffectDigest          string     `json:"effect_digest"`
	Items                 []itemWire `json:"items"`
}

func EncodeReceipt(receipt Receipt) ([]byte, [sha256.Size]byte, domain.EvidenceRef, error) {
	if !validReceipt(receipt) {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	body, err := json.Marshal(receiptToWire(receipt))
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	digest := sha256.Sum256(body)
	id, err := receiptProductID(receipt.Scope.OrganizationID().String() + "\x00" + receipt.Scope.WorkspaceID().String() + "\x00" + receipt.Scope.EnvironmentID().String() + "\x00" + receipt.BatchID.String() + "\x00project\x00" + fmt.Sprint(receipt.Generation) + "\x00" + hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	reference, err := domain.NewEvidenceRef(id)
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	return body, digest, reference, nil
}

func DecodeReceipt(body []byte) (Receipt, error) {
	if len(body) < 1 || len(body) > 4<<20 || !utf8.Valid(body) {
		return Receipt{}, ErrInput
	}
	var wire receiptWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Receipt{}, ErrInput
	}
	receipt, ok := receiptFromWire(wire)
	if !ok {
		return Receipt{}, ErrInput
	}
	canonical, _, _, err := EncodeReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, body) {
		return Receipt{}, ErrInput
	}
	receipt.Items = append([]Item(nil), receipt.Items...)
	return receipt, nil
}

func validReceipt(receipt Receipt) bool {
	if receipt.Scope.Validate() != nil || receipt.BatchID.IsZero() || receipt.Generation < 1 || !validRequired(receipt.ImplementationVersion, 64) || !validReference(receipt.InputReference) || !validVersion(receipt.InputVersionID) || receipt.InputDigest == ([sha256.Size]byte{}) || !validReference(receipt.ArchiveReference) || !validVersion(receipt.ArchiveVersionID) || receipt.ArchiveDigest == ([sha256.Size]byte{}) || receipt.EffectDigest == ([sha256.Size]byte{}) || !validItems(receipt) {
		return false
	}
	expected, err := projectionDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.Items)
	return err == nil && expected == receipt.EffectDigest
}

func validItems(receipt Receipt) bool {
	if len(receipt.Items) < 1 || len(receipt.Items) > 1000 {
		return false
	}
	previous := ""
	for _, item := range receipt.Items {
		if item.EventID.IsZero() || item.EventID.String() <= previous || item.EvidenceID.IsZero() || item.ArchiveReference != receipt.ArchiveReference || item.ArchiveVersionID != receipt.ArchiveVersionID || !validRiskID(item.ID) {
			return false
		}
		previous = item.EventID.String()
		severity, title, ok := classify(item.Source, item.EventClass, item.Action)
		if !ok || severity != item.Severity || title != item.Title {
			return false
		}
		expectedID := riskID(Batch{Scope: receipt.Scope, BatchID: receipt.BatchID, ArchiveDigest: receipt.ArchiveDigest}, item.EventID, runtimeCorrelation(item))
		if item.ID != expectedID || !validItemCorrelation(item) || !validCanonicalTime(item.EventTime) {
			return false
		}
	}
	return true
}

func runtimeCorrelation(item Item) runtimecorrelation.Result {
	return runtimecorrelation.Result{EventID: item.EventID, SessionID: item.SessionID, AgentID: item.AgentID, Confidence: item.Confidence}
}

func validItemCorrelation(item Item) bool {
	switch item.Confidence {
	case domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong:
		return !item.SessionID.IsZero() && !item.AgentID.IsZero()
	case domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed:
		return item.SessionID.IsZero() && item.AgentID.IsZero()
	default:
		return false
	}
}

func validCanonicalTime(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}

func validRiskID(value string) bool {
	if len(value) != len("rsk_")+sha256.Size*2 || !strings.HasPrefix(value, "rsk_") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "rsk_"))
	return err == nil && len(decoded) == sha256.Size && "rsk_"+hex.EncodeToString(decoded) == value
}

func receiptToWire(receipt Receipt) receiptWire {
	return receiptWire{Schema: receiptSchema, ImplementationVersion: receipt.ImplementationVersion, OrganizationID: receipt.Scope.OrganizationID().String(), WorkspaceID: receipt.Scope.WorkspaceID().String(), EnvironmentID: receipt.Scope.EnvironmentID().String(), BatchID: receipt.BatchID.String(), Generation: receipt.Generation, InputReference: receipt.InputReference, InputVersionID: receipt.InputVersionID, InputDigest: hex.EncodeToString(receipt.InputDigest[:]), ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: hex.EncodeToString(receipt.ArchiveDigest[:]), EffectDigest: hex.EncodeToString(receipt.EffectDigest[:]), Items: itemsToWire(receipt.Items)}
}

func receiptFromWire(wire receiptWire) (Receipt, bool) {
	organization, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	batchID, batchErr := domain.ParseProductID(wire.BatchID)
	inputDigest, inputErr := parseDigest(wire.InputDigest)
	archiveDigest, archiveErr := parseDigest(wire.ArchiveDigest)
	effectDigest, effectErr := parseDigest(wire.EffectDigest)
	if wire.Schema != receiptSchema || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || batchErr != nil || inputErr != nil || archiveErr != nil || effectErr != nil {
		return Receipt{}, false
	}
	items := make([]Item, len(wire.Items))
	for index, value := range wire.Items {
		eventID, eventErr := domain.ParseProductID(value.EventID)
		evidenceID, evidenceErr := domain.ParseProductID(value.EvidenceID)
		confidence, confidenceErr := domain.ParseEvidenceConfidence(value.Confidence)
		var agentID, sessionID domain.ProductID
		var agentErr, sessionErr error
		if value.AgentID != "" {
			agentID, agentErr = domain.ParseProductID(value.AgentID)
		}
		if value.SessionID != "" {
			sessionID, sessionErr = domain.ParseProductID(value.SessionID)
		}
		if eventErr != nil || evidenceErr != nil || confidenceErr != nil || agentErr != nil || sessionErr != nil {
			return Receipt{}, false
		}
		items[index] = Item{ID: value.ID, EventID: eventID, Source: value.Source, EventClass: value.EventClass, Action: value.Action, Severity: value.Severity, Title: value.Title, AgentID: agentID, SessionID: sessionID, Confidence: confidence, EvidenceID: evidenceID, EventTime: value.EventTime, ArchiveReference: value.ArchiveReference, ArchiveVersionID: value.ArchiveVersionID}
	}
	receipt := Receipt{ImplementationVersion: wire.ImplementationVersion, Scope: scope, BatchID: batchID, Generation: wire.Generation, InputReference: wire.InputReference, InputVersionID: wire.InputVersionID, InputDigest: inputDigest, ArchiveReference: wire.ArchiveReference, ArchiveVersionID: wire.ArchiveVersionID, ArchiveDigest: archiveDigest, EffectDigest: effectDigest, Items: items}
	return receipt, validReceipt(receipt)
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, ErrInput
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return digest, nil
}

func receiptProductID(value string) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte(value))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	encoded := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]))
}

func validRequired(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
