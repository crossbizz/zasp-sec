package runtimecorrelation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const receiptSchema = "runtime-correlation-receipt-v1"
const frozenReceiptSchema = "runtime-correlation-receipt-v2"
const sandboxReceiptSchema = "runtime-correlation-receipt-v3"

type Receipt struct {
	ImplementationVersion   string
	Scope                   domain.Scope
	BatchID                 domain.ProductID
	Generation              int64
	InputReference          string
	InputVersionID          string
	InputDigest             [sha256.Size]byte
	ArchiveReference        string
	ArchiveVersionID        string
	ArchiveDigest           [sha256.Size]byte
	EffectDigest            [sha256.Size]byte
	Results                 []Result
	CandidateSnapshotDigest [sha256.Size]byte
}

type receiptWire struct {
	Schema                  string       `json:"schema"`
	ImplementationVersion   string       `json:"implementation_version"`
	OrganizationID          string       `json:"organization_id"`
	WorkspaceID             string       `json:"workspace_id"`
	EnvironmentID           string       `json:"environment_id"`
	BatchID                 string       `json:"batch_id"`
	Generation              int64        `json:"generation"`
	InputReference          string       `json:"input_reference"`
	InputVersionID          string       `json:"input_version_id"`
	InputDigest             string       `json:"input_digest"`
	ArchiveReference        string       `json:"archive_reference"`
	ArchiveVersionID        string       `json:"archive_version_id"`
	ArchiveDigest           string       `json:"archive_digest"`
	EffectDigest            string       `json:"effect_digest"`
	Results                 []resultWire `json:"results"`
	CandidateSnapshotDigest string       `json:"candidate_snapshot_digest,omitempty"`
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
		wire.Schema = "runtime-correlation-receipt-v4"
		wire.CandidateSnapshotDigest = hex.EncodeToString(receipt.CandidateSnapshotDigest[:])
	}
	body, err := json.Marshal(wire)
	if err != nil || (precise && len(body) > 1<<20) {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrInput
	}
	digest := sha256.Sum256(body)
	id, err := deterministicProductID(receipt.Scope.OrganizationID().String() + "\x00" + receipt.Scope.WorkspaceID().String() + "\x00" + receipt.Scope.EnvironmentID().String() + "\x00" + receipt.BatchID.String() + "\x00correlate\x00" + fmt.Sprint(receipt.Generation) + "\x00" + hex.EncodeToString(digest[:]))
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
	if len(body) < 1 || len(body) > 1<<20 || !utf8.Valid(body) {
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
	receipt.Results = append([]Result(nil), receipt.Results...)
	return receipt, nil
}

func validReceipt(receipt Receipt) bool {
	return validReceiptProfile(receipt, false)
}

func validReceiptProfile(receipt Receipt, precise bool) bool {
	if precise != (receipt.ImplementationVersion == "runtime-correlation-v4") {
		return false
	}
	if receipt.Scope.Validate() != nil || receipt.BatchID.IsZero() || receipt.Generation < 1 || !validRequired(receipt.ImplementationVersion, 64) || !validReference(receipt.InputReference) || !validReference(receipt.ArchiveReference) || !validVersion(receipt.InputVersionID) || !validVersion(receipt.ArchiveVersionID) || receipt.InputDigest == ([sha256.Size]byte{}) || receipt.ArchiveDigest == ([sha256.Size]byte{}) || receipt.EffectDigest == ([sha256.Size]byte{}) || !validResults(receipt.Results) {
		return false
	}
	var expected [sha256.Size]byte
	var err error
	if precise {
		if receipt.CandidateSnapshotDigest == ([sha256.Size]byte{}) || !validSandboxResults(receipt.Results) {
			return false
		}
		for _, result := range receipt.Results {
			if result.Confidence == domain.EvidenceConfidenceExact {
				return false
			}
		}
		expected, err = versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v4", receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.CandidateSnapshotDigest, receipt.Results)
	} else if receipt.ImplementationVersion == "runtime-correlation-v3" {
		if receipt.CandidateSnapshotDigest == ([sha256.Size]byte{}) || !validSandboxResults(receipt.Results) {
			return false
		}
		expected, err = sandboxCorrelationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.CandidateSnapshotDigest, receipt.Results)
	} else if receipt.ImplementationVersion == "runtime-correlation-v2" {
		if receipt.CandidateSnapshotDigest == ([sha256.Size]byte{}) {
			return false
		}
		expected, err = frozenCorrelationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.CandidateSnapshotDigest, receipt.Results)
	} else {
		if receipt.CandidateSnapshotDigest != ([sha256.Size]byte{}) {
			return false
		}
		expected, err = correlationDigest(receipt.Scope, receipt.BatchID, receipt.Generation, receipt.ArchiveDigest, receipt.Results)
	}
	if !precise && receipt.ImplementationVersion != "runtime-correlation-v3" {
		for _, result := range receipt.Results {
			if result.SandboxID != "" || !result.SandboxSourceSensorID.IsZero() {
				return false
			}
		}
	}
	return err == nil && expected == receipt.EffectDigest
}

func validResults(results []Result) bool {
	if len(results) < 1 || len(results) > 1000 {
		return false
	}
	previous := ""
	for _, result := range results {
		if result.EventID.IsZero() || result.EventID.String() <= previous {
			return false
		}
		previous = result.EventID.String()
		switch result.Confidence {
		case domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong:
			if result.SessionID.IsZero() || result.AgentID.IsZero() {
				return false
			}
		case domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed:
			if !result.SessionID.IsZero() || !result.AgentID.IsZero() {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func receiptToWire(receipt Receipt) receiptWire {
	wire := receiptWire{Schema: receiptSchema, ImplementationVersion: receipt.ImplementationVersion, OrganizationID: receipt.Scope.OrganizationID().String(), WorkspaceID: receipt.Scope.WorkspaceID().String(), EnvironmentID: receipt.Scope.EnvironmentID().String(), BatchID: receipt.BatchID.String(), Generation: receipt.Generation, InputReference: receipt.InputReference, InputVersionID: receipt.InputVersionID, InputDigest: hex.EncodeToString(receipt.InputDigest[:]), ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: hex.EncodeToString(receipt.ArchiveDigest[:]), EffectDigest: hex.EncodeToString(receipt.EffectDigest[:]), Results: resultsToWire(receipt.Results)}
	if receipt.ImplementationVersion == "runtime-correlation-v2" {
		wire.Schema = frozenReceiptSchema
		wire.CandidateSnapshotDigest = hex.EncodeToString(receipt.CandidateSnapshotDigest[:])
	} else if receipt.ImplementationVersion == "runtime-correlation-v3" {
		wire.Schema = sandboxReceiptSchema
		wire.CandidateSnapshotDigest = hex.EncodeToString(receipt.CandidateSnapshotDigest[:])
	}
	return wire
}

func receiptFromWire(wire receiptWire) (Receipt, bool) {
	return receiptFromWireProfile(wire, false)
}

func receiptFromWireProfile(wire receiptWire, precise bool) (Receipt, bool) {
	if precise != (wire.ImplementationVersion == "runtime-correlation-v4") {
		return Receipt{}, false
	}
	organization, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	batchID, batchErr := domain.ParseProductID(wire.BatchID)
	inputDigest, inputErr := parseDigest(wire.InputDigest)
	archiveDigest, archiveErr := parseDigest(wire.ArchiveDigest)
	effectDigest, effectErr := parseDigest(wire.EffectDigest)
	expectedSchema := receiptSchema
	var snapshotDigest [sha256.Size]byte
	if precise || wire.ImplementationVersion == "runtime-correlation-v2" || wire.ImplementationVersion == "runtime-correlation-v3" {
		expectedSchema = frozenReceiptSchema
		if wire.ImplementationVersion == "runtime-correlation-v3" {
			expectedSchema = sandboxReceiptSchema
		}
		if precise {
			expectedSchema = "runtime-correlation-receipt-v4"
		}
		var snapshotErr error
		snapshotDigest, snapshotErr = parseDigest(wire.CandidateSnapshotDigest)
		if snapshotErr != nil || snapshotDigest == ([sha256.Size]byte{}) {
			return Receipt{}, false
		}
	} else if wire.CandidateSnapshotDigest != "" {
		return Receipt{}, false
	}
	if wire.Schema != expectedSchema || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || batchErr != nil || inputErr != nil || archiveErr != nil || effectErr != nil {
		return Receipt{}, false
	}
	results := make([]Result, len(wire.Results))
	for index, value := range wire.Results {
		eventID, eventErr := domain.ParseProductID(value.EventID)
		confidence, confidenceErr := domain.ParseEvidenceConfidence(value.Confidence)
		var sessionID, agentID, sandboxSource domain.ProductID
		var sessionErr, agentErr, sandboxSourceErr error
		if value.SessionID != "" {
			sessionID, sessionErr = domain.ParseProductID(value.SessionID)
		}
		if value.AgentID != "" {
			agentID, agentErr = domain.ParseProductID(value.AgentID)
		}
		if value.SandboxSourceSensorID != "" {
			sandboxSource, sandboxSourceErr = domain.ParseProductID(value.SandboxSourceSensorID)
		}
		if eventErr != nil || confidenceErr != nil || sessionErr != nil || agentErr != nil || sandboxSourceErr != nil {
			return Receipt{}, false
		}
		results[index] = Result{EventID: eventID, SessionID: sessionID, AgentID: agentID, Confidence: confidence, SandboxID: value.SandboxID, SandboxSourceSensorID: sandboxSource}
	}
	receipt := Receipt{ImplementationVersion: wire.ImplementationVersion, Scope: scope, BatchID: batchID, Generation: wire.Generation, InputReference: wire.InputReference, InputVersionID: wire.InputVersionID, InputDigest: inputDigest, ArchiveReference: wire.ArchiveReference, ArchiveVersionID: wire.ArchiveVersionID, ArchiveDigest: archiveDigest, EffectDigest: effectDigest, Results: results, CandidateSnapshotDigest: snapshotDigest}
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

func deterministicProductID(value string) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte(value))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	text := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", text[:8], text[8:12], text[12:16], text[16:20], text[20:32]))
}

func validReference(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.String() == value && parsed.Scheme == "s3" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" && strings.HasPrefix(parsed.Path, "/") && !strings.Contains(parsed.Path, "..")
}

func validVersion(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validRequired(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
