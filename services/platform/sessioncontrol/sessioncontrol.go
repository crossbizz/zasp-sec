package sessioncontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var ErrRejected = errors.New("session control operation rejected")

type Confidence string

const (
	ConfidenceExact        Confidence = "exact"
	ConfidenceStrong       Confidence = "strong"
	ConfidenceProbable     Confidence = "probable"
	ConfidenceUnattributed Confidence = "unattributed"
)

type SessionEvent struct {
	ID         string     `json:"id"`
	SessionID  string     `json:"session_id"`
	Class      string     `json:"class"`
	Label      string     `json:"label"`
	EvidenceID string     `json:"evidence_id"`
	Source     string     `json:"source"`
	Confidence Confidence `json:"confidence"`
	At         time.Time  `json:"at"`
}

type Session struct {
	ID          string         `json:"id"`
	AgentID     string         `json:"agent_id"`
	PrincipalID string         `json:"principal_id"`
	Events      []SessionEvent `json:"events"`
}

type Projector struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewProjector() *Projector { return &Projector{sessions: map[string]Session{}} }

func (p *Projector) Project(ctx context.Context, sessionID, agentID, principalID string, input []SessionEvent) (Session, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !bounded(sessionID, 128) || !bounded(agentID, 128) || !bounded(principalID, 128) || len(input) == 0 || len(input) > 1000 {
		return Session{}, ErrRejected
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current, exists := p.sessions[sessionID]
	if exists && (current.AgentID != agentID || current.PrincipalID != principalID) {
		return Session{}, ErrRejected
	}
	byID := map[string]SessionEvent{}
	for _, event := range current.Events {
		byID[event.ID] = event
	}
	for _, event := range input {
		if event.SessionID != sessionID || !validEvent(event) {
			return Session{}, ErrRejected
		}
		if previous, found := byID[event.ID]; found && previous != event {
			return Session{}, ErrRejected
		}
		byID[event.ID] = event
	}
	events := make([]SessionEvent, 0, len(byID))
	for _, event := range byID {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].ID < events[j].ID
		}
		return events[i].At.Before(events[j].At)
	})
	value := Session{ID: sessionID, AgentID: agentID, PrincipalID: principalID, Events: events}
	p.sessions[sessionID] = value
	return cloneSession(value), nil
}

func (p *Projector) Get(ctx context.Context, id string) (Session, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !bounded(id, 128) {
		return Session{}, ErrRejected
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	value, ok := p.sessions[id]
	if !ok {
		return Session{}, ErrRejected
	}
	return cloneSession(value), nil
}

func (p *Projector) List(ctx context.Context) ([]Session, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	values := make([]Session, 0, len(p.sessions))
	for _, value := range p.sessions {
		values = append(values, cloneSession(value))
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, nil
}

type SessionFilter struct {
	AgentID, PrincipalID, Tool, Process, File, Domain, Credential, Resource, Decision, RawQuery string
	From, To                                                                                    time.Time
}

func BuildSessionFilter(value SessionFilter) (map[string]string, error) {
	if value.RawQuery != "" || (!value.From.IsZero() && !value.To.IsZero() && value.From.After(value.To)) {
		return nil, ErrRejected
	}
	result := map[string]string{}
	fields := []struct{ key, value string }{{"agent_id", value.AgentID}, {"principal_id", value.PrincipalID}, {"tool", value.Tool}, {"process", value.Process}, {"file", value.File}, {"domain", value.Domain}, {"credential", value.Credential}, {"resource", value.Resource}, {"decision", value.Decision}}
	for _, field := range fields {
		if field.value != "" {
			if !bounded(field.value, 256) {
				return nil, ErrRejected
			}
			result[field.key] = field.value
		}
	}
	if !value.From.IsZero() {
		if value.From.Location() != time.UTC {
			return nil, ErrRejected
		}
		result["from"] = value.From.Format(time.RFC3339Nano)
	}
	if !value.To.IsZero() {
		if value.To.Location() != time.UTC {
			return nil, ErrRejected
		}
		result["to"] = value.To.Format(time.RFC3339Nano)
	}
	return result, nil
}

type ComplianceControl struct {
	ID          string    `json:"id"`
	Framework   string    `json:"framework"`
	Name        string    `json:"name"`
	EvidenceIDs []string  `json:"evidence_ids"`
	FreshUntil  time.Time `json:"fresh_until"`
}
type EvidenceRecord struct {
	ID      string    `json:"id"`
	AssetID string    `json:"asset_id"`
	Source  string    `json:"source"`
	At      time.Time `json:"at"`
}
type ComplianceEvidence struct {
	Control   ComplianceControl `json:"control"`
	Evidence  []EvidenceRecord  `json:"evidence"`
	Freshness string            `json:"freshness"`
}

func AssembleComplianceEvidence(controls []ComplianceControl, records []EvidenceRecord, now time.Time) ([]ComplianceEvidence, error) {
	if len(controls) == 0 || len(controls) > 500 || now.Location() != time.UTC {
		return nil, ErrRejected
	}
	byID := map[string]EvidenceRecord{}
	for _, record := range records {
		if !bounded(record.ID, 128) || !bounded(record.AssetID, 128) || !bounded(record.Source, 64) || record.At.Location() != time.UTC {
			return nil, ErrRejected
		}
		if _, ok := byID[record.ID]; ok {
			return nil, ErrRejected
		}
		byID[record.ID] = record
	}
	result := make([]ComplianceEvidence, 0, len(controls))
	for _, control := range controls {
		if !bounded(control.ID, 128) || !bounded(control.Framework, 64) || !bounded(control.Name, 256) || len(control.EvidenceIDs) == 0 || len(control.EvidenceIDs) > 100 || control.FreshUntil.Location() != time.UTC {
			return nil, ErrRejected
		}
		item := ComplianceEvidence{Control: cloneControl(control), Freshness: "fresh"}
		for _, id := range control.EvidenceIDs {
			record, ok := byID[id]
			if !ok {
				item.Freshness = "missing"
				continue
			}
			item.Evidence = append(item.Evidence, record)
		}
		if item.Freshness != "missing" && now.After(control.FreshUntil) {
			item.Freshness = "stale"
		}
		result = append(result, item)
	}
	return result, nil
}

type ComplianceExport struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Formats []string `json:"formats"`
	JSON    []byte   `json:"-"`
	CSV     []byte   `json:"-"`
	Human   string   `json:"-"`
}

func BuildComplianceExport(id string, values []ComplianceEvidence) (ComplianceExport, error) {
	if !bounded(id, 128) || len(values) == 0 || len(values) > 500 {
		return ComplianceExport{}, ErrRejected
	}
	jsonBytes, err := json.Marshal(values)
	if err != nil || len(jsonBytes) > 4*1024*1024 {
		return ComplianceExport{}, ErrRejected
	}
	var csvText strings.Builder
	writer := csv.NewWriter(&csvText)
	_ = writer.Write([]string{"control_id", "framework", "freshness", "evidence_count"})
	for _, value := range values {
		if !bounded(value.Control.ID, 128) || !contains([]string{"fresh", "stale", "missing"}, value.Freshness) {
			return ComplianceExport{}, ErrRejected
		}
		_ = writer.Write([]string{value.Control.ID, value.Control.Framework, value.Freshness, strconv.Itoa(len(value.Evidence))})
	}
	writer.Flush()
	if writer.Error() != nil {
		return ComplianceExport{}, ErrRejected
	}
	human := "Evidence package for review. This export reports collected evidence and freshness; it does not attest compliance."
	return ComplianceExport{ID: id, Status: "completed", Formats: []string{"json", "csv", "human"}, JSON: jsonBytes, CSV: []byte(csvText.String()), Human: human}, nil
}

type complianceExportPackage struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	JSON    json.RawMessage `json:"json"`
	CSV     string          `json:"csv"`
	Human   string          `json:"human"`
}

func WriteComplianceExportArtifact(ctx context.Context, store artifactstore.ArtifactStore, scope domain.Scope, reference domain.EvidenceRef, value ComplianceExport) (artifact artifactstore.Artifact, resultErr error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(store) || scope.Validate() != nil || reference.Validate() != nil ||
		!bounded(value.ID, 128) || value.Status != "completed" || len(value.Formats) != 3 || value.Formats[0] != "json" ||
		value.Formats[1] != "csv" || value.Formats[2] != "human" || len(value.JSON) == 0 || len(value.JSON) > 4*1024*1024 ||
		!json.Valid(value.JSON) || len(value.CSV) == 0 || len(value.CSV) > 4*1024*1024 || len(value.Human) == 0 ||
		len(value.Human) > 4096 || containsCertificationLanguage(value.Human) {
		return artifactstore.Artifact{}, ErrRejected
	}
	body, err := json.Marshal(complianceExportPackage{Version: 1, ID: value.ID, JSON: json.RawMessage(bytes.Clone(value.JSON)), CSV: string(value.CSV), Human: value.Human})
	if err != nil || len(body) == 0 || len(body) > 8*1024*1024 {
		return artifactstore.Artifact{}, ErrRejected
	}
	locator := artifactstore.Locator{Scope: scope, Reference: reference}
	request := artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: bytes.Clone(body)}
	defer func() {
		if recover() != nil {
			artifact = artifactstore.Artifact{}
			resultErr = ErrRejected
		}
	}()
	returned, err := store.Put(ctx, request)
	if err != nil || returned.Locator != locator || returned.MediaType != request.MediaType || returned.Size != int64(len(body)) ||
		returned.SHA256 != sha256.Sum256(body) || !bytes.Equal(returned.Body, body) {
		return artifactstore.Artifact{}, ErrRejected
	}
	return returned, nil
}

func containsCertificationLanguage(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "certified") || strings.Contains(lower, "certification")
}

type DataControls struct {
	EnvironmentID    string `json:"environment_id"`
	EnvironmentClass string `json:"environment_class"`
	CollectionMode   string `json:"collection_mode"`
	RetentionDays    int    `json:"retention_days"`
	DeletionEnabled  bool   `json:"deletion_enabled"`
}
type DataControlStore struct {
	mu     sync.RWMutex
	values map[string]DataControls
}

func NewDataControlStore() *DataControlStore {
	return &DataControlStore{values: map[string]DataControls{}}
}
func (s *DataControlStore) Update(ctx context.Context, value DataControls) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !bounded(value.EnvironmentID, 128) || !contains([]string{"development", "test", "staging", "production"}, value.EnvironmentClass) || !contains([]string{"metadata_only", "extended"}, value.CollectionMode) || value.RetentionDays < 1 || value.RetentionDays > 3650 || (value.EnvironmentClass == "production" && value.CollectionMode != "metadata_only") {
		return ErrRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[value.EnvironmentID] = value
	return nil
}
func (s *DataControlStore) Get(ctx context.Context, id string) (DataControls, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !bounded(id, 128) {
		return DataControls{}, ErrRejected
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[id]
	if !ok {
		return DataControls{}, ErrRejected
	}
	return value, nil
}

func validEvent(value SessionEvent) bool {
	return bounded(value.ID, 128) && bounded(value.Label, 256) && bounded(value.EvidenceID, 128) && bounded(value.Source, 64) && contains([]string{"tool", "runtime", "network", "file", "credential", "policy"}, value.Class) && contains([]Confidence{ConfidenceExact, ConfidenceStrong, ConfidenceProbable, ConfidenceUnattributed}, value.Confidence) && !value.At.IsZero() && value.At.Location() == time.UTC
}
func bounded(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Pointer || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Slice || kind == reflect.Func || kind == reflect.Chan) && reflect.ValueOf(value).IsNil()
}
func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func cloneSession(value Session) Session {
	value.Events = append([]SessionEvent(nil), value.Events...)
	return value
}
func cloneControl(value ComplianceControl) ComplianceControl {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	return value
}
