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
	ID       string                      `json:"id"`
	AssetID  string                      `json:"asset_id"`
	Source   string                      `json:"source"`
	At       time.Time                   `json:"at"`
	Target   *ComplianceEvidenceTarget   `json:"target,omitempty"`
	Metadata *ComplianceEvidenceMetadata `json:"metadata,omitempty"`
}

type ComplianceEvidenceTarget struct {
	SourceKind    string `json:"source_kind"`
	SourceID      string `json:"source_id"`
	SourceVersion int64  `json:"source_version"`
}

// Captured metadata is a typed allowlist, never provider/audit arbitrary JSON.
type ComplianceEvidenceMetadata struct {
	Action            string   `json:"action,omitempty"`
	Status            string   `json:"status,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	EvidenceIDs       []string `json:"evidence_ids,omitempty"`
	Verification      string   `json:"verification,omitempty"`
	MigrationSeeded   *bool    `json:"migration_seeded,omitempty"`
	DefinitionID      string   `json:"definition_id,omitempty"`
	DefinitionVersion int64    `json:"definition_version,omitempty"`
	ReceiptSHA256     string   `json:"receipt_sha256,omitempty"`
	ReceiptVersion    string   `json:"receipt_version,omitempty"`
	ReceiptSize       int64    `json:"receipt_size,omitempty"`
}
type ComplianceEvidence struct {
	Control         ComplianceControl          `json:"control"`
	Evidence        []EvidenceRecord           `json:"evidence"`
	Freshness       string                     `json:"freshness"`
	SnapshotContext *ComplianceSnapshotContext `json:"snapshot_context,omitempty"`
}

type ComplianceSnapshotContext struct {
	OrganizationID  string    `json:"organization_id"`
	WorkspaceID     string    `json:"workspace_id"`
	EnvironmentID   string    `json:"environment_id"`
	MappingRevision string    `json:"mapping_revision"`
	SnapshotAt      time.Time `json:"snapshot_at"`
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
	var human strings.Builder
	human.WriteString("Evidence package for review. This export reports collected evidence and freshness; it does not attest compliance.\n")
	writer := csv.NewWriter(&csvText)
	attributed := false
	contextual := false
	for _, value := range values {
		if value.SnapshotContext != nil {
			contextual = true
		}
	}
	for _, value := range values {
		for _, record := range value.Evidence {
			if record.Target != nil || record.Metadata != nil {
				attributed = true
			}
		}
	}
	header := []string{"control_id", "framework", "freshness", "evidence_count", "evidence_id", "asset_id", "source", "at"}
	if attributed {
		header = append(header, "source_kind", "source_id", "source_version", "metadata")
	}
	if contextual {
		header = append(header, "organization_id", "workspace_id", "environment_id", "mapping_revision", "snapshot_at")
	}
	_ = writer.Write(header)
	for _, value := range values {
		if value.SnapshotContext != nil && !validComplianceSnapshotContext(*value.SnapshotContext) {
			return ComplianceExport{}, ErrRejected
		}
		if !bounded(value.Control.ID, 128) || len(value.Control.Framework) == 0 || len(value.Control.Framework) > 64 ||
			len(value.Control.Name) == 0 || len(value.Control.Name) > 256 || len(value.Control.EvidenceIDs) > 100 ||
			len(value.Evidence) > 100 || !contains([]string{"fresh", "stale", "missing"}, value.Freshness) {
			return ComplianceExport{}, ErrRejected
		}
		for _, evidenceID := range value.Control.EvidenceIDs {
			if !bounded(evidenceID, 128) {
				return ComplianceExport{}, ErrRejected
			}
		}
		for _, record := range value.Evidence {
			if record.Target != nil && (!bounded(record.Target.SourceKind, 64) || !bounded(record.Target.SourceID, 128) || record.Target.SourceID != record.ID || record.Target.SourceVersion < 1) {
				return ComplianceExport{}, ErrRejected
			}
			if record.Metadata != nil && !validComplianceMetadata(*record.Metadata) {
				return ComplianceExport{}, ErrRejected
			}
			if !bounded(record.ID, 128) || !bounded(record.AssetID, 128) ||
				len(record.Source) == 0 || len(record.Source) > 64 || record.At.IsZero() {
				return ComplianceExport{}, ErrRejected
			}
		}
		prefix := []string{complianceCSVText(value.Control.ID), complianceCSVText(value.Control.Framework), value.Freshness, strconv.Itoa(len(value.Evidence))}
		human.WriteString("\nControl " + strconv.Quote(value.Control.ID) + " | " + strconv.Quote(value.Control.Framework) + " | " + strconv.Quote(value.Control.Name) + "\n")
		if value.SnapshotContext != nil {
			c := value.SnapshotContext
			human.WriteString("Captured scope: " + c.OrganizationID + " / " + c.WorkspaceID + " / " + c.EnvironmentID + " | mapping: " + c.MappingRevision + " | snapshot_at: " + c.SnapshotAt.UTC().Format(time.RFC3339Nano) + "\n")
		}
		human.WriteString("Freshness: " + value.Freshness + "; fresh until: " + value.Control.FreshUntil.UTC().Format(time.RFC3339Nano) + "\n")
		human.WriteString("Expected evidence IDs:")
		for _, evidenceID := range value.Control.EvidenceIDs {
			human.WriteString(" " + strconv.Quote(evidenceID))
		}
		human.WriteString("\n")
		if len(value.Evidence) == 0 {
			row := append(prefix, "", "", "", "")
			if attributed {
				row = append(row, "", "", "", "")
			}
			if contextual {
				row = append(row, complianceContextCSV(value.SnapshotContext)...)
			}
			_ = writer.Write(row)
			human.WriteString("No collected evidence.\n")
		}
		for _, record := range value.Evidence {
			at := record.At.UTC().Format(time.RFC3339Nano)
			row := append(prefix, complianceCSVText(record.ID), complianceCSVText(record.AssetID), complianceCSVText(record.Source), at)
			if attributed {
				kind, id, version, meta := "", "", "", ""
				if record.Target != nil {
					kind = record.Target.SourceKind
					id = record.Target.SourceID
					version = strconv.FormatInt(record.Target.SourceVersion, 10)
				}
				if record.Metadata != nil {
					b, _ := json.Marshal(record.Metadata)
					meta = string(b)
				}
				row = append(row, complianceCSVText(kind), complianceCSVText(id), version, complianceCSVText(meta))
				if record.Target != nil {
					human.WriteString("Target source_kind: " + strconv.Quote(kind) + " | source_id: " + strconv.Quote(id) + " | source_version: " + version + "\n")
				}
				if meta != "" {
					human.WriteString("Captured metadata: " + meta + "\n")
				}
			}
			if contextual {
				row = append(row, complianceContextCSV(value.SnapshotContext)...)
			}
			_ = writer.Write(row)
			human.WriteString("Evidence " + strconv.Quote(record.ID) + " | asset " + strconv.Quote(record.AssetID) + " | source " + strconv.Quote(record.Source) + " | at " + at + "\n")
		}
		writer.Flush()
		if writer.Error() != nil || csvText.Len() > 4*1024*1024 || human.Len() > 4*1024*1024 {
			return ComplianceExport{}, ErrRejected
		}
	}
	writer.Flush()
	if writer.Error() != nil {
		return ComplianceExport{}, ErrRejected
	}
	result := ComplianceExport{ID: id, Status: "completed", Formats: []string{"json", "csv", "human"}, JSON: jsonBytes, CSV: []byte(csvText.String()), Human: human.String()}
	packageBytes, err := json.Marshal(complianceExportPackage{Version: 1, ID: id, JSON: jsonBytes, CSV: string(result.CSV), Human: result.Human})
	if err != nil || len(packageBytes) > 8*1024*1024 {
		return ComplianceExport{}, ErrRejected
	}
	return result, nil
}

// CSV parsers remove quoting before spreadsheets interpret formulas. Prefix
// dangerous text cells, retaining original data in the canonical JSON payload.
func complianceCSVText(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.ContainsAny(value, "\t\r\n") || (len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + value
	}
	return value
}

func validComplianceMetadata(m ComplianceEvidenceMetadata) bool {
	for _, v := range []string{m.Action, m.Status, m.Severity, m.Verification, m.DefinitionID, m.ReceiptSHA256, m.ReceiptVersion} {
		if len(v) > 1024 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return false
		}
	}
	if len(m.EvidenceIDs) > 100 || m.DefinitionVersion < 0 || m.ReceiptSize < 0 {
		return false
	}
	for _, id := range m.EvidenceIDs {
		if !bounded(id, 128) {
			return false
		}
	}
	return true
}

func validComplianceSnapshotContext(c ComplianceSnapshotContext) bool {
	org, err := domain.ParseProductID(c.OrganizationID)
	if err != nil {
		return false
	}
	workspace, err := domain.ParseProductID(c.WorkspaceID)
	if err != nil {
		return false
	}
	environment, err := domain.ParseProductID(c.EnvironmentID)
	if err != nil {
		return false
	}
	_, err = domain.NewScope(org, workspace, environment)
	return err == nil && c.MappingRevision == "product-evidence-v1" && !c.SnapshotAt.IsZero()
}
func complianceContextCSV(c *ComplianceSnapshotContext) []string {
	if c == nil {
		return []string{"", "", "", "", ""}
	}
	return []string{c.OrganizationID, c.WorkspaceID, c.EnvironmentID, c.MappingRevision, c.SnapshotAt.UTC().Format(time.RFC3339Nano)}
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
		len(value.Human) > 4*1024*1024 {
		return artifactstore.Artifact{}, ErrRejected
	}
	// Only persist reports generated from this exact canonical evidence. Quoted
	// labels may legitimately mention certification; they are not product claims.
	var evidence []ComplianceEvidence
	if err := json.Unmarshal(value.JSON, &evidence); err != nil {
		return artifactstore.Artifact{}, ErrRejected
	}
	canonical, err := BuildComplianceExport(value.ID, evidence)
	if err != nil || !bytes.Equal(value.JSON, canonical.JSON) || !bytes.Equal(value.CSV, canonical.CSV) || value.Human != canonical.Human {
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
	if err != nil || returned.Scope != locator.Scope || returned.Reference != locator.Reference ||
		len(returned.VersionID) > 1024 || strings.IndexFunc(returned.VersionID, func(character rune) bool { return character < 0x21 || character == 0x7f }) >= 0 ||
		returned.MediaType != request.MediaType || returned.Size != int64(len(body)) ||
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
