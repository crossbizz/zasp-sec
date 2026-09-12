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
const sandboxReceiptSchema = "runtime-projection-receipt-v2"

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
	return encodeReceiptProfile(receipt, false)
}

func encodeReceiptProfile(receipt Receipt, precise bool) ([]byte, [sha256.Size]byte, domain.EvidenceRef, error) {
	if !validReceiptProfile(receipt, precise) {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	wire := receiptToWire(receipt)
	if precise {
		wire.Schema = "runtime-projection-receipt-v3"
	}
	body, err := json.Marshal(wire)
	if err != nil || precise && len(body) > 4<<20 {
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
	return decodeReceiptProfile(body, false)
}

func decodeReceiptProfile(body []byte, precise bool) (Receipt, error) {
	if len(body) < 1 || len(body) > 4<<20 || !utf8.Valid(body) {
		return Receipt{}, ErrInput
	}
	var wire receiptWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Receipt{}, ErrInput
	}
	receipt, ok := receiptFromWireProfile(wire, precise)
	if !ok {
		return Receipt{}, ErrInput
	}
	canonical, _, _, err := encodeReceiptProfile(receipt, precise)
	if err != nil || !bytes.Equal(canonical, body) {
		return Receipt{}, ErrInput
	}
	receipt.Items = append([]Item(nil), receipt.Items...)
	return receipt, nil
}

func validReceipt(receipt Receipt) bool {
	return validReceiptProfile(receipt, false)
}

func validReceiptProfile(receipt Receipt, precise bool) bool {
	if precise && receipt.ImplementationVersion != "runtime-projection-v3" || !precise && receipt.ImplementationVersion != "runtime-projection-v1" && receipt.ImplementationVersion != "runtime-projection-v2" {
		return false
	}
	if receipt.Scope.Validate() != nil || receipt.BatchID.IsZero() || receipt.Generation < 1 || !validRequired(receipt.ImplementationVersion, 64) || !validReference(receipt.InputReference) || !validVersion(receipt.InputVersionID) || receipt.InputDigest == ([sha256.Size]byte{}) || !validReference(receipt.ArchiveReference) || !validVersion(receipt.ArchiveVersionID) || receipt.ArchiveDigest == ([sha256.Size]byte{}) || receipt.EffectDigest == ([sha256.Size]byte{}) || !validItemsProfile(receipt, precise) {
		return false
	}
	digestDomain := contentDigestDomain
	if receipt.ImplementationVersion == "runtime-projection-v2" {
		digestDomain = "zasp.runtime-projection.batch.v2"
	}
	if precise {
		digestDomain = "zasp.runtime-projection.batch.v3"
	}
	expected, err := projectionDigestDomain(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.Items, digestDomain)
	return err == nil && expected == receipt.EffectDigest
}

func validItems(receipt Receipt) bool {
	return validItemsProfile(receipt, false)
}

func validItemsProfile(receipt Receipt, precise bool) bool {
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
		if precise || receipt.ImplementationVersion == "runtime-projection-v2" {
			if !validSandboxCorrelation(runtimeCorrelation(item)) {
				return false
			}
			expectedID = sandboxRiskID(Batch{Scope: receipt.Scope, BatchID: receipt.BatchID, ArchiveDigest: receipt.ArchiveDigest}, item.EventID, runtimeCorrelation(item))
			if precise {
				if item.Source != "tetragon" || item.Confidence == domain.EvidenceConfidenceExact {
					return false
				}
				digest := sha256.Sum256([]byte("zasp.runtime-risk.v3\x00" + expectedID))
				expectedID = "rsk_" + hex.EncodeToString(digest[:])
			}
		} else if item.SandboxID != "" || !item.SandboxSourceSensorID.IsZero() {
			return false
		}
		if item.ID != expectedID || !validItemCorrelation(item) || !validCanonicalTime(item.EventTime) {
			return false
		}
	}
	return true
}

func runtimeCorrelation(item Item) runtimecorrelation.Result {
	return runtimecorrelation.Result{EventID: item.EventID, SessionID: item.SessionID, AgentID: item.AgentID, Confidence: item.Confidence, SandboxID: item.SandboxID, SandboxSourceSensorID: item.SandboxSourceSensorID}
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
	schema := receiptSchema
	if receipt.ImplementationVersion == "runtime-projection-v2" {
		schema = sandboxReceiptSchema
	}
	return receiptWire{Schema: schema, ImplementationVersion: receipt.ImplementationVersion, OrganizationID: receipt.Scope.OrganizationID().String(), WorkspaceID: receipt.Scope.WorkspaceID().String(), EnvironmentID: receipt.Scope.EnvironmentID().String(), BatchID: receipt.BatchID.String(), Generation: receipt.Generation, InputReference: receipt.InputReference, InputVersionID: receipt.InputVersionID, InputDigest: hex.EncodeToString(receipt.InputDigest[:]), ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: hex.EncodeToString(receipt.ArchiveDigest[:]), EffectDigest: hex.EncodeToString(receipt.EffectDigest[:]), Items: itemsToWire(receipt.Items)}
}

func receiptFromWire(wire receiptWire) (Receipt, bool) {
	return receiptFromWireProfile(wire, false)
}

func receiptFromWireProfile(wire receiptWire, precise bool) (Receipt, bool) {
	organization, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	batchID, batchErr := domain.ParseProductID(wire.BatchID)
	inputDigest, inputErr := parseDigest(wire.InputDigest)
	archiveDigest, archiveErr := parseDigest(wire.ArchiveDigest)
	effectDigest, effectErr := parseDigest(wire.EffectDigest)
	versionMatches := wire.Schema == receiptSchema && wire.ImplementationVersion == "runtime-projection-v1" || wire.Schema == sandboxReceiptSchema && wire.ImplementationVersion == "runtime-projection-v2"
	if precise {
		versionMatches = wire.Schema == "runtime-projection-receipt-v3" && wire.ImplementationVersion == "runtime-projection-v3"
	}
	if !versionMatches || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || batchErr != nil || inputErr != nil || archiveErr != nil || effectErr != nil {
		return Receipt{}, false
	}
	items := make([]Item, len(wire.Items))
	for index, value := range wire.Items {
		eventID, eventErr := domain.ParseProductID(value.EventID)
		evidenceID, evidenceErr := domain.ParseProductID(value.EvidenceID)
		confidence, confidenceErr := domain.ParseEvidenceConfidence(value.Confidence)
		var agentID, sessionID, sandboxSource domain.ProductID
		var agentErr, sessionErr, sandboxSourceErr error
		if value.AgentID != "" {
			agentID, agentErr = domain.ParseProductID(value.AgentID)
		}
		if value.SessionID != "" {
			sessionID, sessionErr = domain.ParseProductID(value.SessionID)
		}
		if value.SandboxSourceSensorID != "" {
			sandboxSource, sandboxSourceErr = domain.ParseProductID(value.SandboxSourceSensorID)
		}
		if eventErr != nil || evidenceErr != nil || confidenceErr != nil || agentErr != nil || sessionErr != nil || sandboxSourceErr != nil {
			return Receipt{}, false
		}
		items[index] = Item{ID: value.ID, EventID: eventID, Source: value.Source, EventClass: value.EventClass, Action: value.Action, Severity: value.Severity, Title: value.Title, AgentID: agentID, SessionID: sessionID, Confidence: confidence, EvidenceID: evidenceID, EventTime: value.EventTime, ArchiveReference: value.ArchiveReference, ArchiveVersionID: value.ArchiveVersionID}
		items[index].SandboxID, items[index].SandboxSourceSensorID = value.SandboxID, sandboxSource
	}
	receipt := Receipt{ImplementationVersion: wire.ImplementationVersion, Scope: scope, BatchID: batchID, Generation: wire.Generation, InputReference: wire.InputReference, InputVersionID: wire.InputVersionID, InputDigest: inputDigest, ArchiveReference: wire.ArchiveReference, ArchiveVersionID: wire.ArchiveVersionID, ArchiveDigest: archiveDigest, EffectDigest: effectDigest, Items: items}
	return receipt, validReceiptProfile(receipt, precise)
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
