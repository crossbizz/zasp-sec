package runtimeevent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrPipeline = errors.New("runtime pipeline evidence rejected")

const stageReceiptSchema = "runtime-stage-receipt-v1"

var (
	receiptVersionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)
	receiptItemPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{1,15}_[0-9a-f]{64}$`)
)

type StageReceipt struct {
	Stage                 RuntimeStage
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
	ItemIDs               []string
}

type stageReceiptWire struct {
	Schema                string   `json:"schema"`
	Stage                 string   `json:"stage"`
	ImplementationVersion string   `json:"implementation_version"`
	OrganizationID        string   `json:"organization_id"`
	WorkspaceID           string   `json:"workspace_id"`
	EnvironmentID         string   `json:"environment_id"`
	BatchID               string   `json:"batch_id"`
	Generation            int64    `json:"generation"`
	InputReference        string   `json:"input_reference"`
	InputVersionID        string   `json:"input_version_id"`
	InputDigest           string   `json:"input_digest"`
	ArchiveReference      string   `json:"archive_reference"`
	ArchiveVersionID      string   `json:"archive_version_id"`
	ArchiveDigest         string   `json:"archive_digest"`
	EffectDigest          string   `json:"effect_digest"`
	ItemIDs               []string `json:"item_ids"`
}

func EncodeStageReceipt(receipt StageReceipt) ([]byte, [sha256.Size]byte, domain.EvidenceRef, error) {
	if !validStageReceipt(receipt) {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrPipeline
	}
	wire := stageReceiptToWire(receipt)
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrPipeline
	}
	digest := sha256.Sum256(body)
	id, err := deterministicID(receipt.Scope.OrganizationID().String() + "\x00" + receipt.Scope.WorkspaceID().String() + "\x00" + receipt.Scope.EnvironmentID().String() + "\x00" + receipt.BatchID.String() + "\x00" + string(receipt.Stage) + "\x00" + fmt.Sprint(receipt.Generation) + "\x00" + hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrPipeline
	}
	reference, err := domain.NewEvidenceRef(id)
	if err != nil {
		return nil, [sha256.Size]byte{}, domain.EvidenceRef{}, ErrPipeline
	}
	return body, digest, reference, nil
}

func DecodeStageReceipt(body []byte) (StageReceipt, error) {
	if len(body) == 0 || len(body) > 1<<20 || !utf8.Valid(body) || !uniqueProductionJSON(body) {
		return StageReceipt{}, ErrPipeline
	}
	var wire stageReceiptWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return StageReceipt{}, ErrPipeline
	}
	receipt, ok := stageReceiptFromWire(wire)
	if !ok {
		return StageReceipt{}, ErrPipeline
	}
	canonical, _, _, err := EncodeStageReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, body) {
		return StageReceipt{}, ErrPipeline
	}
	receipt.ItemIDs = append([]string(nil), receipt.ItemIDs...)
	return receipt, nil
}

func validStageReceipt(receipt StageReceipt) bool {
	if receipt.Scope.Validate() != nil || receipt.BatchID.IsZero() || receipt.Generation < 1 || !receiptVersionPattern.MatchString(receipt.ImplementationVersion) || !validReceiptReference(receipt.InputReference) || !validReceiptReference(receipt.ArchiveReference) || !validReceiptVersion(receipt.InputVersionID) || !validReceiptVersion(receipt.ArchiveVersionID) || receipt.InputDigest == ([sha256.Size]byte{}) || receipt.ArchiveDigest == ([sha256.Size]byte{}) || receipt.EffectDigest == ([sha256.Size]byte{}) || len(receipt.ItemIDs) > 1000 {
		return false
	}
	switch receipt.Stage {
	case RuntimeStageIndex, RuntimeStageCorrelate, RuntimeStageProject, RuntimeStageComplete:
	default:
		return false
	}
	previous := ""
	for _, item := range receipt.ItemIDs {
		if !receiptItemPattern.MatchString(item) || item <= previous {
			return false
		}
		previous = item
	}
	return true
}

func stageReceiptToWire(receipt StageReceipt) stageReceiptWire {
	return stageReceiptWire{Schema: stageReceiptSchema, Stage: string(receipt.Stage), ImplementationVersion: receipt.ImplementationVersion, OrganizationID: receipt.Scope.OrganizationID().String(), WorkspaceID: receipt.Scope.WorkspaceID().String(), EnvironmentID: receipt.Scope.EnvironmentID().String(), BatchID: receipt.BatchID.String(), Generation: receipt.Generation, InputReference: receipt.InputReference, InputVersionID: receipt.InputVersionID, InputDigest: hex.EncodeToString(receipt.InputDigest[:]), ArchiveReference: receipt.ArchiveReference, ArchiveVersionID: receipt.ArchiveVersionID, ArchiveDigest: hex.EncodeToString(receipt.ArchiveDigest[:]), EffectDigest: hex.EncodeToString(receipt.EffectDigest[:]), ItemIDs: append([]string(nil), receipt.ItemIDs...)}
}

func stageReceiptFromWire(wire stageReceiptWire) (StageReceipt, bool) {
	organization, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	batchID, batchErr := domain.ParseProductID(wire.BatchID)
	inputDigest, inputErr := parseReceiptDigest(wire.InputDigest)
	archiveDigest, archiveErr := parseReceiptDigest(wire.ArchiveDigest)
	effectDigest, effectErr := parseReceiptDigest(wire.EffectDigest)
	if wire.Schema != stageReceiptSchema || organizationErr != nil || workspaceErr != nil || environmentErr != nil || scopeErr != nil || batchErr != nil || inputErr != nil || archiveErr != nil || effectErr != nil {
		return StageReceipt{}, false
	}
	receipt := StageReceipt{Stage: RuntimeStage(wire.Stage), ImplementationVersion: wire.ImplementationVersion, Scope: scope, BatchID: batchID, Generation: wire.Generation, InputReference: wire.InputReference, InputVersionID: wire.InputVersionID, InputDigest: inputDigest, ArchiveReference: wire.ArchiveReference, ArchiveVersionID: wire.ArchiveVersionID, ArchiveDigest: archiveDigest, EffectDigest: effectDigest, ItemIDs: append([]string(nil), wire.ItemIDs...)}
	return receipt, validStageReceipt(receipt)
}

func parseReceiptDigest(value string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, ErrPipeline
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return digest, nil
}

func validReceiptReference(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.String() == value && parsed.Scheme == "s3" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" && strings.HasPrefix(parsed.Path, "/") && !strings.Contains(parsed.Path, "..")
}

func validReceiptVersion(value string) bool {
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
