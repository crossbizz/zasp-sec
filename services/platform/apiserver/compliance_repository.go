package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresComplianceReadySQL = `SELECT to_jsonb(public.zasp_compliance_api_ready($1,$2))`
const postgresComplianceReadSQL = `SELECT public.zasp_compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`

var ErrComplianceForbidden = errors.New("compliance source permission denied")
var ErrComplianceSourceChanged = errors.New("compliance source_changed")

type ComplianceTarget struct {
	SourceKind    string `json:"source_kind"`
	SourceID      string `json:"source_id"`
	SourceVersion int64  `json:"source_version"`
}
type ComplianceEvidence struct {
	ID             string             `json:"id"`
	Asset          string             `json:"asset"`
	Source         string             `json:"source"`
	Timestamp      string             `json:"timestamp"`
	OrganizationID string             `json:"organization_id"`
	WorkspaceID    string             `json:"workspace_id"`
	EnvironmentID  string             `json:"environment_id"`
	Target         ComplianceTarget   `json:"target"`
	Freshness      string             `json:"freshness"`
	Metadata       ComplianceMetadata `json:"metadata"`
}
type ComplianceMetadata struct {
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
type ComplianceRepository struct {
	database              JSONDatabase
	checksum, fingerprint string
}
type ComplianceListOptions struct {
	Framework string          `json:"framework,omitempty"`
	ControlID string          `json:"control_id,omitempty"`
	Limit     int             `json:"limit,omitempty"`
	Cursor    json.RawMessage `json:"cursor,omitempty"`
}
type ComplianceEvidencePage struct {
	MappingRevision string               `json:"mapping_revision"`
	CollectedAt     string               `json:"collected_at"`
	Items           []ComplianceEvidence `json:"items"`
	NextCursor      json.RawMessage      `json:"next_cursor"`
}
type ComplianceControl struct {
	Framework         string   `json:"framework"`
	ControlID         string   `json:"control_id"`
	Label             string   `json:"label"`
	RequiredSources   []string `json:"required_sources"`
	MaximumAgeSeconds int      `json:"maximum_age_seconds"`
	Freshness         string   `json:"freshness"`
	FreshUntil        string   `json:"fresh_until"`
}
type ComplianceControlPage struct {
	MappingRevision string              `json:"mapping_revision"`
	CollectedAt     string              `json:"collected_at"`
	Items           []ComplianceControl `json:"items"`
	NextCursor      json.RawMessage     `json:"next_cursor"`
}

func NewComplianceRepository(database JSONDatabase) (*ComplianceRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil || version != ProductionRecoverySchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	r := &ComplianceRepository{database: database, checksum: migrations.ProductionCompliance().Checksum(), fingerprint: migrations.ComplianceFingerprint()}
	if r.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return r, nil
}
func (r *ComplianceRepository) Ready(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil {
		return ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, err := currentAuthorizationSourceReady(ctx, r.database, 56, r.checksum, r.fingerprint); current {
		return err
	}
	raw, err := r.database.QueryJSON(ctx, postgresComplianceReadySQL, r.checksum, r.fingerprint)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (r *ComplianceRepository) read(ctx context.Context, identity RequestIdentity, digest []byte, operation string, params any) (json.RawMessage, error) {
	if r == nil || nilInterface(r.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) {
		return nil, ErrRepositoryOperation
	}
	for _, permission := range []string{"view", "view_audit", "view_compliance"} {
		if !currentRequestHasPermission(ctx, identity, permission) {
			return nil, ErrComplianceForbidden
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(params)
	if err != nil || len(body) > 4096 {
		return nil, ErrRepositoryOperation
	}
	raw, err := r.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresComplianceReadSQL, `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(digest), operation, json.RawMessage(body), r.checksum, r.fingerprint)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, complianceRepositoryError(err)
	}
	if len(raw) > 1<<20 {
		return nil, ErrRepositoryUnavailable
	}
	return raw, nil
}
func complianceRepositoryError(err error) error {
	if errors.Is(err, ErrComplianceSourceChanged) {
		return ErrComplianceSourceChanged
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "42501":
			return ErrComplianceForbidden
		}
	}
	return auditExportRepositoryError(err)
}
func (r *ComplianceRepository) GetEvidence(ctx context.Context, identity RequestIdentity, digest []byte, target ComplianceTarget) (ComplianceEvidence, error) {
	if !validComplianceTarget(target, false) {
		return ComplianceEvidence{}, ErrRepositoryOperation
	}
	params := map[string]any{"source_kind": target.SourceKind, "source_id": target.SourceID}
	if target.SourceVersion > 0 {
		params["source_version"] = target.SourceVersion
	}
	raw, err := r.read(ctx, identity, digest, "getEvidence", params)
	if err != nil {
		return ComplianceEvidence{}, err
	}
	value, err := decodeComplianceEvidence(raw, identity)
	if err != nil || value.Target.SourceKind != target.SourceKind || value.Target.SourceID != target.SourceID || target.SourceVersion > 0 && value.Target.SourceVersion != target.SourceVersion {
		return ComplianceEvidence{}, ErrRepositoryUnavailable
	}
	return value, nil
}
func (r *ComplianceRepository) ListEvidence(ctx context.Context, identity RequestIdentity, digest []byte, options ComplianceListOptions) (ComplianceEvidencePage, error) {
	if !validComplianceList(identity, options, "listEvidence") {
		return ComplianceEvidencePage{}, ErrRepositoryOperation
	}
	raw, err := r.read(ctx, identity, digest, "listEvidence", options)
	if err != nil {
		return ComplianceEvidencePage{}, err
	}
	var page ComplianceEvidencePage
	items, next, stamp, err := decodeCompliancePage(raw, identity, options, "listEvidence")
	if err != nil {
		return page, err
	}
	page.MappingRevision = "product-evidence-v1"
	page.CollectedAt = stamp
	page.NextCursor = next
	page.Items = make([]ComplianceEvidence, 0, len(items))
	previous := ""
	for _, item := range items {
		value, err := decodeComplianceEvidence(item, identity)
		key := value.Target.SourceKind + "\x00" + value.Target.SourceID
		if err != nil || key <= previous {
			return ComplianceEvidencePage{}, ErrRepositoryUnavailable
		}
		previous = key
		page.Items = append(page.Items, value)
	}
	return page, nil
}
func (r *ComplianceRepository) ListControls(ctx context.Context, identity RequestIdentity, digest []byte, options ComplianceListOptions) (ComplianceControlPage, error) {
	if !validComplianceList(identity, options, "listControls") {
		return ComplianceControlPage{}, ErrRepositoryOperation
	}
	raw, err := r.read(ctx, identity, digest, "listControls", options)
	if err != nil {
		return ComplianceControlPage{}, err
	}
	var page ComplianceControlPage
	items, next, stamp, err := decodeCompliancePage(raw, identity, options, "listControls")
	if err != nil {
		return page, err
	}
	page.MappingRevision = "product-evidence-v1"
	page.CollectedAt = stamp
	page.NextCursor = next
	page.Items = make([]ComplianceControl, 0, len(items))
	previous := ""
	for _, item := range items {
		if _, ok := existingTestPublicObject(item, nil, "framework", "control_id", "label", "required_sources", "maximum_age_seconds", "freshness", "fresh_until"); !ok {
			return ComplianceControlPage{}, ErrRepositoryUnavailable
		}
		var value ComplianceControl
		if json.Unmarshal(item, &value) != nil || !validComplianceTime(value.FreshUntil) {
			return ComplianceControlPage{}, ErrRepositoryUnavailable
		}
		if decodeStrictDiscovery(item, &value) != nil || !validComplianceFramework(value.Framework) || !validComplianceControl(value.ControlID, value.Framework) || len(value.RequiredSources) != 1 || !stringIn(value.RequiredSources[0], "audit", "finding", "policy", "test", "configuration") || value.MaximumAgeSeconds != 86400 || !stringIn(value.Freshness, "fresh", "stale", "missing") || !complianceSafeText(value.Label, 128) {
			return ComplianceControlPage{}, ErrRepositoryUnavailable
		}
		key := value.Framework + "\x00" + value.ControlID
		if key <= previous {
			return ComplianceControlPage{}, ErrRepositoryUnavailable
		}
		previous = key
		page.Items = append(page.Items, value)
	}
	return page, nil
}
func decodeCompliancePage(raw json.RawMessage, identity RequestIdentity, options ComplianceListOptions, operation string) ([]json.RawMessage, json.RawMessage, string, error) {
	object, err := auditExportClosedObject(raw, 1<<20, "mapping_revision", "collected_at", "items", "next_cursor")
	if err != nil {
		return nil, nil, "", ErrRepositoryUnavailable
	}
	var revision, stamp string
	var items []json.RawMessage
	if json.Unmarshal(object["mapping_revision"], &revision) != nil || revision != "product-evidence-v1" || json.Unmarshal(object["collected_at"], &stamp) != nil || !validComplianceTime(stamp) || bytes.Equal(object["items"], []byte("null")) || json.Unmarshal(object["items"], &items) != nil || len(items) > 100 || options.Limit > 0 && len(items) > options.Limit {
		return nil, nil, "", ErrRepositoryUnavailable
	}
	next := object["next_cursor"]
	if bytes.Equal(next, []byte("null")) {
		next = nil
	} else if len(items) == 0 || !validComplianceCursor(next, identity, options, operation) {
		return nil, nil, "", ErrRepositoryUnavailable
	}
	return items, next, stamp, nil
}
func validComplianceTime(value string) bool {
	stamp, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && strings.HasSuffix(value, "Z") && !stamp.IsZero()
}
func validComplianceFramework(value string) bool { return value == "soc2_security" || value == "hipaa" }
func validComplianceControl(value, framework string) bool {
	for _, f := range []string{"soc2_security", "hipaa"} {
		if framework != "" && framework != f {
			continue
		}
		for _, c := range []string{"audit", "findings", "policies", "tests", "configuration"} {
			if value == f+"-"+c {
				return true
			}
		}
	}
	return false
}
func validComplianceList(identity RequestIdentity, options ComplianceListOptions, operation string) bool {
	return options.Limit >= 0 && options.Limit <= 100 && (options.Framework == "" || validComplianceFramework(options.Framework)) && (options.ControlID == "" || validComplianceControl(options.ControlID, options.Framework)) && (len(options.Cursor) == 0 || validComplianceCursor(options.Cursor, identity, options, operation))
}
func validComplianceCursor(raw json.RawMessage, identity RequestIdentity, options ComplianceListOptions, operation string) bool {
	object, err := auditExportClosedObject(raw, 4096, "organization_id", "workspace_id", "environment_id", "operation", "framework", "control_id", "source_kind", "source_id")
	if err != nil {
		return false
	}
	values := map[string]string{}
	for key, value := range object {
		var text string
		if json.Unmarshal(value, &text) != nil || bytes.Equal(value, []byte("null")) {
			return false
		}
		values[key] = text
	}
	if values["organization_id"] != identity.Scope.OrganizationID().String() || values["workspace_id"] != identity.Scope.WorkspaceID().String() || values["environment_id"] != identity.Scope.EnvironmentID().String() || values["operation"] != operation || values["framework"] != options.Framework || values["control_id"] != options.ControlID {
		return false
	}
	if operation == "listControls" {
		return validComplianceFramework(values["source_kind"]) && validComplianceControl(values["source_id"], values["source_kind"])
	}
	return validComplianceTarget(ComplianceTarget{SourceKind: values["source_kind"], SourceID: values["source_id"]}, false)
}

var compliancePolicyID = regexp.MustCompile(`^policy-[a-z0-9][a-z0-9-]{0,120}$`)
var complianceAuditID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validComplianceTarget(value ComplianceTarget, requireVersion bool) bool {
	if value.SourceVersion < 0 || value.SourceVersion > 999999999999999 || requireVersion && value.SourceVersion == 0 {
		return false
	}
	switch value.SourceKind {
	case "policy":
		return compliancePolicyID.MatchString(value.SourceID)
	case "administration", "workflow_policy", "red_team_mutation":
		return complianceAuditID.MatchString(value.SourceID)
	case "finding", "red_team_test", "attack_lab_test", "configuration":
		return validProductID(value.SourceID)
	}
	return false
}
func complianceSafeText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) })
}
func decodeComplianceEvidence(raw json.RawMessage, identity RequestIdentity) (ComplianceEvidence, error) {
	var value ComplianceEvidence
	object, ok := existingTestPublicObject(raw, nil, "id", "asset", "source", "timestamp", "organization_id", "workspace_id", "environment_id", "target", "freshness", "metadata")
	if !ok {
		return value, ErrRepositoryUnavailable
	}
	if _, ok := existingTestPublicObject(object["target"], nil, "source_kind", "source_id", "source_version"); !ok || decodeStrictDiscovery(raw, &value) != nil {
		return ComplianceEvidence{}, ErrRepositoryUnavailable
	}
	if !validComplianceTarget(value.Target, true) || value.ID != value.Target.SourceID || value.Asset != value.ID || value.OrganizationID != identity.Scope.OrganizationID().String() || value.WorkspaceID != identity.Scope.WorkspaceID().String() || value.EnvironmentID != identity.Scope.EnvironmentID().String() || !validComplianceTime(value.Timestamp) || !stringIn(value.Freshness, "fresh", "stale") {
		return ComplianceEvidence{}, ErrRepositoryUnavailable
	}
	var fields []string
	family := ""
	valid := true
	m := value.Metadata
	switch value.Target.SourceKind {
	case "administration", "workflow_policy", "red_team_mutation":
		family = "audit"
		fields = []string{"action", "status"}
		valid = complianceSafeText(m.Action, 128) && stringIn(m.Status, "succeeded", "rejected", "failed") && value.Target.SourceVersion == 1
	case "finding":
		family = "finding"
		fields = []string{"status", "severity", "evidence_ids"}
		valid = stringIn(m.Status, "open", "under_review", "resolved", "accepted") && stringIn(m.Severity, "critical", "high", "medium", "low") && m.EvidenceIDs != nil && len(m.EvidenceIDs) <= 64
		seen := map[string]bool{}
		for _, id := range m.EvidenceIDs {
			if !validProductID(id) || seen[id] {
				valid = false
			}
			seen[id] = true
		}
	case "policy":
		family = "policy"
		fields = []string{"verification"}
		valid = m.Verification == "definition_only"
	case "configuration":
		family = "configuration"
		fields = []string{"verification", "migration_seeded"}
		valid = m.MigrationSeeded != nil && ((*m.MigrationSeeded && m.Verification == "unverified") || (!*m.MigrationSeeded && m.Verification == "configured")) && value.ID == value.EnvironmentID
	case "red_team_test", "attack_lab_test":
		family = "test"
		fields = []string{"status", "definition_id", "definition_version", "receipt_sha256", "receipt_version", "receipt_size"}
		valid = value.Target.SourceVersion <= 5 && validProductID(m.DefinitionID) && m.DefinitionVersion >= 1 && m.DefinitionVersion <= 1000000 && validExistingTestPublicDigest(m.ReceiptSHA256) && complianceSafeText(m.ReceiptVersion, 512) && m.ReceiptSize > 0 && m.ReceiptSize <= 67108864
		if value.Target.SourceKind == "red_team_test" {
			valid = valid && stringIn(m.Status, "pass", "fail", "engine_error")
		} else {
			valid = valid && stringIn(m.Status, "verified", "not_reproduced", "inconclusive")
		}
	}
	if _, ok := existingTestPublicObject(object["metadata"], nil, fields...); !ok || !valid || family != value.Source {
		return ComplianceEvidence{}, ErrRepositoryUnavailable
	}
	return value, nil
}
