package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sessioncontrol"
)

type complianceFrozenSnapshot struct {
	Revision     string    `json:"mapping_revision"`
	At           time.Time `json:"snapshot_at"`
	Organization string    `json:"organization_id"`
	Workspace    string    `json:"workspace_id"`
	Environment  string    `json:"environment_id"`
	Controls     []struct {
		Framework string   `json:"framework"`
		ID        string   `json:"control_id"`
		Label     string   `json:"label"`
		Required  []string `json:"required_sources"`
		Age       int64    `json:"maximum_age_seconds"`
		Records   []struct {
			Kind     string                                    `json:"source_kind"`
			ID       string                                    `json:"source_id"`
			Version  int64                                     `json:"source_version"`
			Family   string                                    `json:"source_family"`
			At       time.Time                                 `json:"source_time"`
			Valid    bool                                      `json:"source_valid"`
			Metadata sessioncontrol.ComplianceEvidenceMetadata `json:"metadata"`
		} `json:"records"`
	} `json:"controls"`
}

func renderComplianceExportPackage(ctx context.Context, l complianceExportLease, raw json.RawMessage) (compliancePreparedArtifact, error) {
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > 4<<20 || l.Scope.Validate() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	var snapshot complianceFrozenSnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&snapshot) != nil || d.Decode(new(any)) != io.EOF || snapshot.Revision != "product-evidence-v1" || snapshot.At.IsZero() || snapshot.Organization != l.Scope.OrganizationID().String() || snapshot.Workspace != l.Scope.WorkspaceID().String() || snapshot.Environment != l.Scope.EnvironmentID().String() || len(snapshot.Controls) < 1 || len(snapshot.Controls) > 500 {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	values := make([]sessioncontrol.ComplianceEvidence, 0, len(snapshot.Controls))
	seen := map[string]bool{}
	for _, c := range snapshot.Controls {
		if c.Age < 1 || c.Age > 31536000 || len(c.Required) < 1 || len(c.Required) > 5 || len(c.Records) > 100 || !slices.Contains([]string{"soc2_security", "hipaa"}, c.Framework) || seen[c.ID] {
			return compliancePreparedArtifact{}, errWorkerExecution
		}
		seen[c.ID] = true
		item := sessioncontrol.ComplianceEvidence{Control: sessioncontrol.ComplianceControl{ID: c.ID, Framework: c.Framework, Name: c.Label, FreshUntil: snapshot.At}, Freshness: "fresh", Evidence: []sessioncontrol.EvidenceRecord{}, SnapshotContext: &sessioncontrol.ComplianceSnapshotContext{OrganizationID: snapshot.Organization, WorkspaceID: snapshot.Workspace, EnvironmentID: snapshot.Environment, MappingRevision: snapshot.Revision, SnapshotAt: snapshot.At.UTC()}}
		familyTimes := map[string]time.Time{}
		records := map[string]bool{}
		for _, r := range c.Records {
			family := map[string]string{"administration": "audit", "workflow_policy": "audit", "red_team_mutation": "audit", "finding": "finding", "policy": "policy", "red_team_test": "test", "attack_lab_test": "test", "configuration": "configuration"}[r.Kind]
			key := r.Kind + "/" + r.ID
			if !r.Valid || family == "" || family != r.Family || !slices.Contains(c.Required, r.Family) || r.Version < 1 || r.At.IsZero() || r.At.After(snapshot.At) || records[key] {
				return compliancePreparedArtifact{}, errWorkerExecution
			}
			records[key] = true
			item.Evidence = append(item.Evidence, sessioncontrol.EvidenceRecord{ID: r.ID, AssetID: r.ID, Source: r.Family, At: r.At.UTC(), Target: &sessioncontrol.ComplianceEvidenceTarget{SourceKind: r.Kind, SourceID: r.ID, SourceVersion: r.Version}, Metadata: &r.Metadata})
			item.Control.EvidenceIDs = append(item.Control.EvidenceIDs, r.ID)
			if (r.Metadata.MigrationSeeded == nil || !*r.Metadata.MigrationSeeded) && r.At.After(familyTimes[r.Family]) {
				familyTimes[r.Family] = r.At
			}
		}
		first := true
		requiredSeen := map[string]bool{}
		for _, family := range c.Required {
			if !slices.Contains([]string{"audit", "finding", "policy", "test", "configuration"}, family) || requiredSeen[family] {
				return compliancePreparedArtifact{}, errWorkerExecution
			}
			requiredSeen[family] = true
			at := familyTimes[family]
			if at.IsZero() {
				item.Freshness = "missing"
				continue
			}
			until := at.Add(time.Duration(c.Age) * time.Second)
			if first || until.Before(item.Control.FreshUntil) {
				item.Control.FreshUntil = until
				first = false
			}
			if snapshot.At.After(until) && item.Freshness != "missing" {
				item.Freshness = "stale"
			}
		}
		values = append(values, item)
	}
	rendered, err := sessioncontrol.BuildComplianceExport(l.ExportID, values)
	if err != nil || ctx.Err() != nil {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	body, err := json.Marshal(struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		JSON    json.RawMessage `json:"json"`
		CSV     string          `json:"csv"`
		Human   string          `json:"human"`
	}{1, l.ExportID, rendered.JSON, string(rendered.CSV), rendered.Human})
	if err != nil || len(body) > 8<<20 {
		return compliancePreparedArtifact{}, errWorkerExecution
	}
	hash := sha256.Sum256(body)
	return compliancePreparedArtifact{Bytes: body, RendererRevision: "compliance-envelope-v1", Reference: l.ExportID, Size: int64(len(body)), SHA256: hex.EncodeToString(hash[:]), FormatSizes: map[string]int64{"json": int64(len(rendered.JSON)), "csv": int64(len(rendered.CSV)), "readable": int64(len(rendered.Human))}}, nil
}
