package runtimeprojection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

var ErrInput = errors.New("runtime projection input rejected")

const contentDigestDomain = "zasp.runtime-projection.batch.v1"

type Batch struct {
	Scope            domain.Scope
	BatchID          domain.ProductID
	Generation       int64
	ArchiveReference string
	ArchiveVersionID string
	ArchiveDigest    [sha256.Size]byte
	Body             []byte
	Correlations     []runtimecorrelation.Result
}

type Item struct {
	ID               string
	EventID          domain.ProductID
	Source           string
	EventClass       string
	Action           string
	Severity         string
	Title            string
	AgentID          domain.ProductID
	SessionID        domain.ProductID
	Confidence       domain.EvidenceConfidence
	EvidenceID       domain.ProductID
	EventTime        string
	ArchiveReference string
	ArchiveVersionID string
}

type ProjectedBatch struct {
	BatchID       domain.ProductID
	Generation    int64
	ArchiveDigest [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	Items         []Item
}

func Project(input Batch) (ProjectedBatch, error) {
	if input.Scope.Validate() != nil || input.BatchID.IsZero() || input.Generation < 1 || input.ArchiveDigest == ([sha256.Size]byte{}) || len(input.Body) < 1 || len(input.Body) > 64<<20 || sha256.Sum256(input.Body) != input.ArchiveDigest || !validReference(input.ArchiveReference) || !validVersion(input.ArchiveVersionID) || len(input.Correlations) < 1 || len(input.Correlations) > 1000 {
		return ProjectedBatch{}, ErrInput
	}
	batch, err := runtimeevent.DecodeArchivedBatch(input.Scope, input.Body)
	if err != nil || len(batch.Records) != len(input.Correlations) {
		return ProjectedBatch{}, ErrInput
	}
	correlations := make(map[domain.ProductID]runtimecorrelation.Result, len(input.Correlations))
	for _, correlation := range input.Correlations {
		if correlation.EventID.IsZero() || !validCorrelation(correlation) {
			return ProjectedBatch{}, ErrInput
		}
		if _, exists := correlations[correlation.EventID]; exists {
			return ProjectedBatch{}, ErrInput
		}
		correlations[correlation.EventID] = correlation
	}
	items := make([]Item, len(batch.Records))
	for index, record := range batch.Records {
		correlation, ok := correlations[record.ID]
		if !ok {
			return ProjectedBatch{}, ErrInput
		}
		severity, title, ok := classify(record.Source, record.Class, record.Action)
		if !ok {
			return ProjectedBatch{}, ErrInput
		}
		items[index] = Item{ID: riskID(input, record.ID, correlation), EventID: record.ID, Source: record.Source, EventClass: record.Class, Action: record.Action, Severity: severity, Title: title, AgentID: correlation.AgentID, SessionID: correlation.SessionID, Confidence: correlation.Confidence, EvidenceID: record.Event.Evidence.ArtifactID(), EventTime: record.EventTime.Format("2006-01-02T15:04:05.000Z"), ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].EventID.String() < items[j].EventID.String() })
	contentDigest, err := projectionDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, items)
	if err != nil {
		return ProjectedBatch{}, ErrInput
	}
	return ProjectedBatch{BatchID: input.BatchID, Generation: input.Generation, ArchiveDigest: input.ArchiveDigest, ContentDigest: contentDigest, Items: append([]Item(nil), items...)}, nil
}

func validCorrelation(result runtimecorrelation.Result) bool {
	switch result.Confidence {
	case domain.EvidenceConfidenceExact, domain.EvidenceConfidenceStrong:
		return !result.SessionID.IsZero() && !result.AgentID.IsZero()
	case domain.EvidenceConfidenceProbable, domain.EvidenceConfidenceUnattributed:
		return result.SessionID.IsZero() && result.AgentID.IsZero()
	default:
		return false
	}
}

func classify(source, class, action string) (string, string, bool) {
	if source == "otlp" && class == "tool" && action == "invoke" {
		return "medium", "Agent tool invocation", true
	}
	if source != "tetragon" {
		return "", "", false
	}
	switch class + "\x00" + action {
	case "process\x00exec":
		return "medium", "Runtime process execution", true
	case "process\x00exit":
		return "low", "Runtime process exit", true
	case "file\x00read":
		return "low", "Runtime file read", true
	case "file\x00write":
		return "high", "Runtime file write", true
	case "network\x00connect":
		return "high", "Runtime network connection", true
	case "network\x00accept":
		return "medium", "Runtime network acceptance", true
	default:
		return "", "", false
	}
}

func riskID(input Batch, eventID domain.ProductID, correlation runtimecorrelation.Result) string {
	value := input.Scope.OrganizationID().String() + "\x00" + input.Scope.WorkspaceID().String() + "\x00" + input.Scope.EnvironmentID().String() + "\x00" + input.BatchID.String() + "\x00" + eventID.String() + "\x00" + correlation.Confidence.String() + "\x00" + hex.EncodeToString(input.ArchiveDigest[:])
	digest := sha256.Sum256([]byte(value))
	return "rsk_" + hex.EncodeToString(digest[:])
}

type itemWire struct {
	ID               string `json:"id"`
	EventID          string `json:"event_id"`
	Source           string `json:"source"`
	EventClass       string `json:"event_class"`
	Action           string `json:"action"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
	AgentID          string `json:"agent_id"`
	SessionID        string `json:"session_id"`
	Confidence       string `json:"confidence"`
	EvidenceID       string `json:"evidence_id"`
	EventTime        string `json:"event_time"`
	ArchiveReference string `json:"archive_reference"`
	ArchiveVersionID string `json:"archive_version_id"`
}

func itemsToWire(items []Item) []itemWire {
	wire := make([]itemWire, len(items))
	for index, item := range items {
		wire[index] = itemWire{ID: item.ID, EventID: item.EventID.String(), Source: item.Source, EventClass: item.EventClass, Action: item.Action, Severity: item.Severity, Title: item.Title, AgentID: item.AgentID.String(), SessionID: item.SessionID.String(), Confidence: item.Confidence.String(), EvidenceID: item.EvidenceID.String(), EventTime: item.EventTime, ArchiveReference: item.ArchiveReference, ArchiveVersionID: item.ArchiveVersionID}
	}
	return wire
}

func projectionDigest(scope domain.Scope, batchID domain.ProductID, generation int64, archiveDigest [sha256.Size]byte, items []Item) ([sha256.Size]byte, error) {
	wire := struct {
		Domain         string     `json:"domain"`
		OrganizationID string     `json:"organization_id"`
		WorkspaceID    string     `json:"workspace_id"`
		EnvironmentID  string     `json:"environment_id"`
		BatchID        string     `json:"batch_id"`
		Generation     int64      `json:"generation"`
		ArchiveDigest  string     `json:"archive_digest"`
		Items          []itemWire `json:"items"`
	}{contentDigestDomain, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), generation, hex.EncodeToString(archiveDigest[:]), itemsToWire(items)}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return [sha256.Size]byte{}, ErrInput
	}
	return sha256.Sum256(encoded), nil
}

func decodeBatch(scope domain.Scope, body []byte) ([]domain.ProductID, error) {
	batch, err := runtimeevent.DecodeArchivedBatch(scope, body)
	if err != nil {
		return nil, ErrInput
	}
	ids := make([]domain.ProductID, len(batch.Records))
	for index, record := range batch.Records {
		ids[index] = record.ID
	}
	return ids, nil
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
