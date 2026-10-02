package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

func cloneComplianceExportLease(l complianceExportLease) complianceExportLease {
	if l.AgentBinding != nil {
		binding := *l.AgentBinding
		binding.Selection = append([]securityAgentExportSelection(nil), binding.Selection...)
		l.AgentBinding = &binding
	}
	return l
}

func renderExportPackageByOrigin(ctx context.Context, l complianceExportLease, raw json.RawMessage) (compliancePreparedArtifact, error) {
	revision, err := complianceLeaseRendererRevision(l)
	if err != nil {
		return compliancePreparedArtifact{}, err
	}
	if revision == securityAgentExportRendererRevision {
		return renderSecurityAgentEvidenceExportPackage(ctx, l, *l.AgentBinding, raw)
	}
	return renderComplianceExportPackage(ctx, l, raw)
}

// The immutable link supplies this binding independently of captured evidence.
// Browser claims retain their original exact field set.
func decodeComplianceClaimOrigin(raw json.RawMessage) (string, *securityAgentExportBinding, error) {
	keys := []string{"organization_id", "workspace_id", "environment_id", "export_id", "generation", "attempt", "lease_expires_at", "lane", "captured", "prepared", "reference", "version", "size", "sha256"}
	var discriminator map[string]json.RawMessage
	if json.Unmarshal(raw, &discriminator) != nil {
		return "", nil, errWorkerExecution
	}
	_, agent := discriminator["job_origin"]
	if agent {
		keys = append(keys, "job_origin", "binding")
	}
	fields, err := auditExportWorkerObject(raw, 65536, keys...)
	if err != nil {
		return "", nil, errWorkerExecution
	}
	if !agent {
		return "", nil, nil
	}
	var origin string
	if json.Unmarshal(fields["job_origin"], &origin) != nil || origin != "agent_run" {
		return "", nil, errWorkerExecution
	}
	bindingFields, err := auditExportWorkerObject(fields["binding"], 65536, "run_id", "step_id", "selection")
	if err != nil {
		return "", nil, errWorkerExecution
	}
	var b securityAgentExportBinding
	if json.Unmarshal(bindingFields["run_id"], &b.RunID) != nil || json.Unmarshal(bindingFields["step_id"], &b.StepID) != nil || !securityAgentExportProductID(b.RunID) || !securityAgentExportProductID(b.StepID) {
		return "", nil, errWorkerExecution
	}
	var entries []json.RawMessage
	if json.Unmarshal(bindingFields["selection"], &entries) != nil || len(entries) < 1 || len(entries) > 100 {
		return "", nil, errWorkerExecution
	}
	for _, entry := range entries {
		f, err := auditExportWorkerObject(entry, 1024, "source_kind", "source_id", "source_version", "association_digest")
		if err != nil {
			return "", nil, errWorkerExecution
		}
		var s securityAgentExportSelection
		if json.Unmarshal(f["source_kind"], &s.Kind) != nil || json.Unmarshal(f["source_id"], &s.ID) != nil || json.Unmarshal(f["source_version"], &s.Version) != nil || json.Unmarshal(f["association_digest"], &s.AssociationDigest) != nil {
			return "", nil, errWorkerExecution
		}
		b.Selection = append(b.Selection, s)
	}
	if !validAgentExportWorkerBinding(&b) {
		return "", nil, errWorkerExecution
	}
	return origin, &b, nil
}

func validAgentExportWorkerBinding(b *securityAgentExportBinding) bool {
	if b == nil || !securityAgentExportProductID(b.RunID) || !securityAgentExportProductID(b.StepID) || len(b.Selection) < 1 || len(b.Selection) > 100 {
		return false
	}
	seen := make(map[string]bool, len(b.Selection))
	for _, s := range b.Selection {
		validID := securityAgentExportProductID(s.ID)
		if s.Kind == "manual" {
			validID = securityAgentExportDigest(s.ID)
		}
		key := s.Kind + "/" + s.ID
		if !slices.Contains([]string{"finding", "attack_path", "runtime_decision", "run_audit", "existing_test", "attack_lab", "manual"}, s.Kind) || !validID || s.Version < 1 || s.Version > 9007199254740991 || !strings.HasPrefix(s.AssociationDigest, "sha256:") || !securityAgentExportDigest(strings.TrimPrefix(s.AssociationDigest, "sha256:")) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func complianceLeaseRendererRevision(l complianceExportLease) (string, error) {
	if l.JobOrigin == "" && l.AgentBinding == nil {
		return "compliance-envelope-v1", nil
	}
	if l.JobOrigin == "agent_run" && validAgentExportWorkerBinding(l.AgentBinding) {
		return securityAgentExportRendererRevision, nil
	}
	return "", errWorkerExecution
}

func validateAgentExportWorkerSnapshot(l complianceExportLease, raw json.RawMessage) error {
	if !validAgentExportWorkerBinding(l.AgentBinding) || securityAgentExportCheckJSON(raw, securityAgentExportFormatLimit, "snapshot") != nil {
		return errWorkerExecution
	}
	var snapshot securityAgentExportSnapshot
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.Revision != "security-agent-run-evidence-v1" || snapshot.Organization != l.Scope.OrganizationID().String() || snapshot.Workspace != l.Scope.WorkspaceID().String() || snapshot.Environment != l.Scope.EnvironmentID().String() || snapshot.RunID != l.AgentBinding.RunID || snapshot.StepID != l.AgentBinding.StepID || len(snapshot.Records) != len(l.AgentBinding.Selection) {
		return errWorkerExecution
	}
	for i, r := range snapshot.Records {
		s := l.AgentBinding.Selection[i]
		if r.Kind != s.Kind || r.ID != s.ID || r.Version != s.Version || r.AssociationDigest != s.AssociationDigest {
			return errWorkerExecution
		}
	}
	return nil
}
