package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/compliancemap"
)

const frameworkExportCreateSQL = `SELECT zasp_authorization80.framework_export_create($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)`

func init() {
	productStatementRules[frameworkExportCreateSQL] = productStatementRule{operations: []string{"createComplianceExport"}, arguments: 10, scope: 1, actor: 4, browserOnly: true, fresh: true, check: func(g RequestAuthorization, args []any) bool {
		digest, ok := args[4].([]byte)
		return ok && bytes.Equal(digest, g.Credential.Digest[:]) && addonEnvAllowed(g, args)
	}}
}
func (r *ComplianceExportsRepository) createFrameworkExport(ctx context.Context, i RequestIdentity, digest []byte, key string, input ComplianceExportRequest) (ComplianceExportJob, error) {
	if !validRequestIdentity(i, true) || !i.FreshAuthenticated || !complianceIdempotencyKey.MatchString(key) || input.AgentID != "" || input.PilotCohort != "" || input.DeviceID != "" || input.EndpointSessionRef != "" || input.ControlID != "" {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	q := url.Values{"framework": {input.Framework}, "edition": {input.Edition}}
	if input.Upstream != "" {
		q.Set("upstream_id", input.Upstream)
	}
	if input.EvidenceKind != "" {
		q.Set("evidence_kind", input.EvidenceKind)
	}
	f, ok := parseCoverageFilter(q, false)
	if !ok {
		return ComplianceExportJob{}, ErrRepositoryOperation
	}
	data, err := r.source.frameworkEvidence(ctx, i, "createComplianceExport", f)
	if err != nil {
		return ComplianceExportJob{}, err
	}
	f.limit = len(compliancemap.EditionCatalog()) + len(data) + 1
	selector := compliancemap.ReportSelector{Framework: f.framework, Edition: f.edition, Upstream: f.upstream, EvidenceKind: f.kind}
	rows, _ := evidencePage(f, data)
	pack := compliancemap.FrozenReport{Schema: "framework-coverage.v1", Organization: i.Scope.OrganizationID().String(), Workspace: i.Scope.WorkspaceID().String(), Environment: i.Scope.EnvironmentID().String(), Selector: selector, Coverage: buildCoveragePage(f, data, time.Now().UTC()), Evidence: rows}
	for n, row := range pack.Coverage.Items {
		pack.Coverage.Items[n].VerificationStatus = compliancemap.VerificationFreshness(row.Verified, pack.Coverage.Collected)
	}
	encoded, err := json.Marshal(pack)
	if err != nil || len(encoded) > 3<<20 {
		return ComplianceExportJob{}, ErrComplianceCapacity
	}
	selectors, _ := json.Marshal(selector)
	return r.job(ctx, i, digest, frameworkExportCreateSQL, key, string(selectors), string(encoded))
}
