package opensearchdriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

const maximumStageDocuments = 1_000

var (
	documentIDPattern = regexp.MustCompile(`^inv_[0-9a-f]{64}$`)
	kindPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	attributePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	secretNamePattern = regexp.MustCompile(`(^|_)(access_token|api_key|credential|password|private_key|refresh_token|secret|token)($|_)`)
)

type bulkAction struct {
	Create *bulkActionTarget `json:"create,omitempty"`
	Delete *bulkActionTarget `json:"delete,omitempty"`
}

type bulkActionTarget struct {
	Index string `json:"_index"`
	ID    string `json:"_id"`
}

type storedAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type storedDocument struct {
	RecordType     string            `json:"record_type"`
	OrganizationID string            `json:"organization_id"`
	WorkspaceID    string            `json:"workspace_id"`
	EnvironmentID  string            `json:"environment_id"`
	IntegrationID  string            `json:"integration_id"`
	SnapshotID     string            `json:"snapshot_id"`
	Generation     int64             `json:"generation"`
	InputDigest    string            `json:"input_digest"`
	ContentDigest  string            `json:"content_digest"`
	DocumentID     string            `json:"document_id"`
	EntityID       string            `json:"entity_id"`
	Kind           string            `json:"kind"`
	DisplayName    string            `json:"display_name"`
	Attributes     []storedAttribute `json:"attributes"`
}

type bulkResponse struct {
	Errors bool       `json:"errors"`
	Took   int        `json:"took"`
	Items  []bulkItem `json:"items"`
}

type bulkItem struct {
	Create bulkItemResult `json:"create"`
}

type bulkItemResult struct {
	Index         string         `json:"_index"`
	ID            string         `json:"_id"`
	Version       int            `json:"_version,omitempty"`
	Result        string         `json:"result,omitempty"`
	Status        int            `json:"status"`
	Sequence      int64          `json:"_seq_no,omitempty"`
	PrimaryTerm   int64          `json:"_primary_term,omitempty"`
	Shards        responseShards `json:"_shards,omitempty"`
	ForcedRefresh *bool          `json:"forced_refresh,omitempty"`
	Error         *bulkError     `json:"error,omitempty"`
}

type bulkError struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type multiGetRequest struct {
	IDs []string `json:"ids"`
}

type multiGetResponse struct {
	Documents []multiGetDocument `json:"docs"`
}

type multiGetDocument struct {
	Index       string         `json:"_index"`
	ID          string         `json:"_id"`
	Version     int            `json:"_version,omitempty"`
	Sequence    int64          `json:"_seq_no,omitempty"`
	PrimaryTerm int64          `json:"_primary_term,omitempty"`
	Found       bool           `json:"found"`
	Source      storedDocument `json:"_source,omitempty"`
}

func (driver *Driver) Stage(ctx context.Context, input inventorysearch.DriverStage) (inventorysearch.DriverStaged, error) {
	if !driver.usable() || ctx == nil || ctx.Err() != nil || !validStage(input) {
		if ctx != nil && ctx.Err() != nil {
			return inventorysearch.DriverStaged{}, inventorysearch.ErrCanceled
		}
		return inventorysearch.DriverStaged{}, inventorysearch.ErrRejected
	}
	if len(input.Documents) == 0 {
		return stagedResult(input, false), nil
	}
	body, expected, ok := bulkCreateBody(input, driver.config.MaximumRequestBytes)
	if !ok {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrRejected
	}
	query := url.Values{"refresh": {"wait_for"}, "timeout": {fmt.Sprintf("%ds", int(driver.config.RequestTimeout/time.Second))}}
	result, err := driver.request(ctx, http.MethodPost, "/"+indexName+"/_bulk?"+query.Encode(), "application/x-ndjson", body, true)
	if err != nil {
		if errors.Is(err, inventorysearch.ErrUnknownOutcome) {
			return driver.reconcileStage(ctx, input, expected)
		}
		return inventorysearch.DriverStaged{}, err
	}
	if classified := classifyStatus(result.status, true); classified != nil {
		if errors.Is(classified, inventorysearch.ErrUnknownOutcome) {
			return driver.reconcileStage(ctx, input, expected)
		}
		return inventorysearch.DriverStaged{}, classified
	}
	var response bulkResponse
	if decodeExact(result.body, &response) != nil || response.Took < 0 || len(response.Items) != len(input.Documents) {
		return driver.reconcileStage(ctx, input, expected)
	}
	needsReconcile := response.Errors
	for index, item := range response.Items {
		value := item.Create
		if value.Index != indexName || value.ID != input.Documents[index].DocumentID {
			needsReconcile = true
			continue
		}
		switch value.Status {
		case http.StatusCreated:
			if value.Error != nil || value.Version != 1 || value.Result != "created" || !validMutationMetadata(value) {
				needsReconcile = true
			}
		case http.StatusConflict:
			needsReconcile = true
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return inventorysearch.DriverStaged{}, inventorysearch.ErrRetryable
		case http.StatusUnauthorized, http.StatusForbidden:
			return inventorysearch.DriverStaged{}, inventorysearch.ErrDenied
		case http.StatusBadRequest, http.StatusNotFound:
			return inventorysearch.DriverStaged{}, inventorysearch.ErrRejected
		default:
			needsReconcile = true
		}
	}
	if needsReconcile {
		return driver.reconcileStage(ctx, input, expected)
	}
	return stagedResult(input, false), nil
}

func (driver *Driver) reconcileStage(ctx context.Context, input inventorysearch.DriverStage, expected []storedDocument) (inventorysearch.DriverStaged, error) {
	if ctx.Err() != nil {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
	}
	ids := documentIDs(input.Documents)
	body, err := json.Marshal(multiGetRequest{IDs: ids})
	if err != nil || len(body) > driver.config.MaximumRequestBytes {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
	}
	result, requestErr := driver.request(ctx, http.MethodPost, "/"+indexName+"/_mget", "application/json", body, false)
	if requestErr != nil || result.status != http.StatusOK {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
	}
	var response multiGetResponse
	if decodeExact(result.body, &response) != nil || len(response.Documents) != len(expected) {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
	}
	for index, document := range response.Documents {
		if document.Index != indexName || document.ID != ids[index] || !document.Found {
			return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
		}
		if document.Version < 1 || document.Sequence < 0 || document.PrimaryTerm < 1 || !reflect.DeepEqual(document.Source, expected[index]) {
			return inventorysearch.DriverStaged{}, inventorysearch.ErrDrift
		}
	}
	return stagedResult(input, true), nil
}

func validStage(input inventorysearch.DriverStage) bool {
	if !validSnapshot(input.Snapshot) || len(input.Documents) > maximumStageDocuments {
		return false
	}
	previousEntity := ""
	seenDocuments := make(map[string]struct{}, len(input.Documents))
	for _, document := range input.Documents {
		if document.Snapshot != input.Snapshot || !validDriverDocument(document) || document.EntityID <= previousEntity {
			return false
		}
		if _, duplicate := seenDocuments[document.DocumentID]; duplicate {
			return false
		}
		seenDocuments[document.DocumentID] = struct{}{}
		previousEntity = document.EntityID
	}
	return true
}

func validSnapshot(input inventorysearch.DriverSnapshot) bool {
	organization, organizationErr := domain.ParseProductID(input.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(input.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(input.EnvironmentID)
	_, integrationErr := domain.ParseProductID(input.IntegrationID)
	_, snapshotErr := domain.ParseProductID(input.SnapshotID)
	_, scopeErr := domain.NewScope(organization, workspace, environment)
	return organizationErr == nil && workspaceErr == nil && environmentErr == nil && integrationErr == nil && snapshotErr == nil && scopeErr == nil && input.Generation >= 1 && input.InputDigest != [sha256.Size]byte{} && input.ContentDigest != [sha256.Size]byte{}
}

func validDriverDocument(document inventorysearch.DriverDocument) bool {
	if !validSnapshot(document.Snapshot) || !documentIDPattern.MatchString(document.DocumentID) || !kindPattern.MatchString(document.Kind) || !validText(document.DisplayName, 256) || len(document.Attributes) > 128 {
		return false
	}
	if _, err := domain.ParseProductID(document.EntityID); err != nil {
		return false
	}
	previous := ""
	bytes := len(document.DisplayName) + len(document.Kind) + 512
	for _, attribute := range document.Attributes {
		trimmed := strings.TrimSpace(attribute.Value)
		nested := len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed))
		if !attributePattern.MatchString(attribute.Name) || secretNamePattern.MatchString(attribute.Name) || attribute.Name <= previous || !validText(attribute.Value, 2_048) || nested {
			return false
		}
		previous = attribute.Name
		bytes += len(attribute.Name) + len(attribute.Value) + 8
		if bytes > 65_536 {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func bulkCreateBody(input inventorysearch.DriverStage, maximum int) ([]byte, []storedDocument, bool) {
	var buffer bytes.Buffer
	expected := make([]storedDocument, len(input.Documents))
	for index, document := range input.Documents {
		action, err := json.Marshal(bulkAction{Create: &bulkActionTarget{Index: indexName, ID: document.DocumentID}})
		if err != nil {
			return nil, nil, false
		}
		stored := storedFromDriver(document)
		source, err := json.Marshal(stored)
		if err != nil || buffer.Len()+len(action)+len(source)+2 > maximum {
			return nil, nil, false
		}
		buffer.Write(action)
		buffer.WriteByte('\n')
		buffer.Write(source)
		buffer.WriteByte('\n')
		expected[index] = stored
	}
	return buffer.Bytes(), expected, true
}

func storedFromDriver(document inventorysearch.DriverDocument) storedDocument {
	attributes := make([]storedAttribute, len(document.Attributes))
	for index, attribute := range document.Attributes {
		attributes[index] = storedAttribute{Name: attribute.Name, Value: attribute.Value}
	}
	return storedDocument{
		RecordType: "document", OrganizationID: document.Snapshot.OrganizationID, WorkspaceID: document.Snapshot.WorkspaceID, EnvironmentID: document.Snapshot.EnvironmentID,
		IntegrationID: document.Snapshot.IntegrationID, SnapshotID: document.Snapshot.SnapshotID, Generation: document.Snapshot.Generation,
		InputDigest: hex.EncodeToString(document.Snapshot.InputDigest[:]), ContentDigest: hex.EncodeToString(document.Snapshot.ContentDigest[:]), DocumentID: document.DocumentID,
		EntityID: document.EntityID, Kind: document.Kind, DisplayName: document.DisplayName, Attributes: attributes,
	}
}

func driverFromStored(document storedDocument) (inventorysearch.DriverDocument, bool) {
	inputDigest, inputErr := decodeDigest(document.InputDigest)
	contentDigest, contentErr := decodeDigest(document.ContentDigest)
	attributes := make([]inventorysearch.Attribute, len(document.Attributes))
	for index, attribute := range document.Attributes {
		attributes[index] = inventorysearch.Attribute{Name: attribute.Name, Value: attribute.Value}
	}
	result := inventorysearch.DriverDocument{
		Snapshot:   inventorysearch.DriverSnapshot{OrganizationID: document.OrganizationID, WorkspaceID: document.WorkspaceID, EnvironmentID: document.EnvironmentID, IntegrationID: document.IntegrationID, SnapshotID: document.SnapshotID, Generation: document.Generation, InputDigest: inputDigest, ContentDigest: contentDigest},
		DocumentID: document.DocumentID, EntityID: document.EntityID, Kind: document.Kind, DisplayName: document.DisplayName, Attributes: attributes,
	}
	return result, inputErr == nil && contentErr == nil && document.RecordType == "document" && validDriverDocument(result)
}

func stagedResult(input inventorysearch.DriverStage, replayed bool) inventorysearch.DriverStaged {
	return inventorysearch.DriverStaged{Snapshot: input.Snapshot, DocumentIDs: documentIDs(input.Documents), Replayed: replayed}
}

func documentIDs(documents []inventorysearch.DriverDocument) []string {
	ids := make([]string, len(documents))
	for index, document := range documents {
		ids[index] = document.DocumentID
	}
	return ids
}

func decodeDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
		return result, inventorysearch.ErrDrift
	}
	copy(result[:], decoded)
	return result, nil
}

func classifyStatus(status int, mutation bool) error {
	switch status {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusTooManyRequests:
		return inventorysearch.ErrRetryable
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if mutation {
			return inventorysearch.ErrUnknownOutcome
		}
		return inventorysearch.ErrRetryable
	case http.StatusUnauthorized, http.StatusForbidden:
		return inventorysearch.ErrDenied
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge:
		return inventorysearch.ErrRejected
	default:
		if mutation {
			return inventorysearch.ErrUnknownOutcome
		}
		return inventorysearch.ErrUnavailable
	}
}
