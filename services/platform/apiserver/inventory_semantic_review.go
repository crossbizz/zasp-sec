package apiserver

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

const inventoryReviewSQL = "SELECT zasp_authorization80.inventory_semantic_review($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb)"

var inventoryReviewPurposes = map[string]aigateway.Purpose{
	"verifyAgentDiscovery": aigateway.PurposeDiscoveryVerify, "draftAgentPurpose": aigateway.PurposeDraft, "deepScanAddonVersion": aigateway.PurposeAddonAudit,
}

func init() {
	productStatementRules[inventoryReviewSQL] = productStatementRule{operations: []string{"verifyAgentDiscovery", "draftAgentPurpose", "deepScanAddonVersion"}, arguments: 9, scope: 1, actor: 4, object: 5, browserOnly: true, fresh: true, check: func(g RequestAuthorization, args []any) bool {
		p, ok := inventoryReviewPurposes[g.OperationID]
		if !ok || args[6] != string(p) {
			return false
		}
		if p == aigateway.PurposeAddonAudit {
			return addonEnvAllowed(g, args)
		}
		agent, ok := args[4].(string)
		return ok && authorizationNativeTargetAllowed(g, "agent", agent)
	}}
}

type semanticReceipt struct {
	Target   string            `json:"target_id"`
	Purpose  aigateway.Purpose `json:"purpose"`
	Degraded *bool             `json:"coverage_degraded"`
	Result   json.RawMessage   `json:"result"`
}
type evidenceSummary struct {
	References []string            `json:"evidence_refs"`
	Tools      []string            `json:"tool_ids"`
	Findings   []addonFindingCount `json:"findings"`
	Ruleset    string              `json:"ruleset"`
}

func serveInventoryReview(db JSONDatabase, model *analystChat, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := IdentityFromRequest(r)
	if !ok || actor.CredentialKind != CredentialBrowserSession || !actor.FreshAuthenticated {
		writeWorkflowMutationError(w, r, ErrRepositoryAuthorization)
		return
	}
	p, valid := inventoryReviewPurposes[route.OperationID]
	id := route.PathParameters["id"]
	keys := r.Header.Values("Idempotency-Key")
	var raw json.RawMessage
	if !valid || !validProductID(id) || r.Method != http.MethodPost || r.URL.RawQuery != "" || len(keys) != 1 || !validPublicIdempotency(keys[0]) || decodeProductionJSON(r, &raw) != nil || !exactJSONFields(raw) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	binding := "null"
	if model != nil {
		b, _ := json.Marshal(model.binding)
		binding = string(b)
	}
	sc := actor.Scope
	args := []any{sc.OrganizationID().String(), sc.WorkspaceID().String(), sc.EnvironmentID().String(), actor.PrincipalID.String(), id, keys[0], string(p), binding, nil}
	body, err := db.QueryJSON(r.Context(), inventoryReviewSQL, args...)
	var job struct {
		Lease   string          `json:"lease"`
		Summary json.RawMessage `json:"summary"`
	}
	if err == nil && json.Unmarshal(body, &job) == nil && job.Lease != "" {
		result := runInventoryReview(r, model, p, job.Summary)
		finish, _ := json.Marshal(map[string]any{"lease": job.Lease, "result": result})
		args[8] = string(finish)
		body, err = db.QueryJSON(r.Context(), inventoryReviewSQL, args...)
	}
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	if string(body) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	if string(body) == `"conflict"` {
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var receipt semanticReceipt
	if json.Unmarshal(body, &receipt) != nil || receipt.Target != id || receipt.Purpose != p || receipt.Degraded == nil || (*receipt.Degraded != (string(receipt.Result) == "null")) || (!*receipt.Degraded && !aigateway.ValidateSemanticOutput(p, receipt.Result)) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, body, nil)
}

// Tier: 3 | Purpose: static discovery, draft purpose or add-on review.
// Model: qualified private Bedrock model under a purpose-scoped lease.
// Authority: redacted catalog evidence only; a reviewer owns each declaration.
// Fallback: unbound citations, outage and timeout preserve the stored declaration.
func runInventoryReview(r *http.Request, model *analystChat, p aigateway.Purpose, data json.RawMessage) json.RawMessage {
	if model == nil {
		return nil
	}
	var facts evidenceSummary
	if json.Unmarshal(data, &facts) != nil || facts.References == nil || len(facts.References) == 0 {
		return nil
	}
	tags := []string{}
	for _, f := range facts.Findings {
		for _, ref := range addonevidence.References(f.Rule, facts.Ruleset) {
			if !slices.Contains(tags, ref.UpstreamID) {
				tags = append(tags, ref.UpstreamID)
			}
		}
	}
	if p == aigateway.PurposeAddonAudit {
		var fields map[string]any
		if json.Unmarshal(data, &fields) != nil {
			return nil
		}
		fields["framework_tags"] = tags
		data, _ = json.Marshal(fields)
	}
	out, err := model.driver.Evaluate(r.Context(), p, data)
	if err != nil || !aigateway.ValidateSemanticOutput(p, out) {
		return nil
	}
	var parsed struct {
		Refs       []string `json:"evidence_refs"`
		Mismatches []string `json:"iam_mismatches"`
		Citations  []string `json:"citations"`
		Tools      []string `json:"allowed_tool_ids"`
		Tags       []string `json:"tags"`
	}
	if json.Unmarshal(out, &parsed) != nil {
		return nil
	}
	if (p == aigateway.PurposeDiscoveryVerify && len(parsed.Refs) == 0) || (p == aigateway.PurposeAddonAudit && len(parsed.Citations) == 0) {
		return nil
	}
	for _, item := range append(append(parsed.Refs, parsed.Citations...), parsed.Mismatches...) {
		if !slices.Contains(facts.References, item) {
			return nil
		}
	}
	for _, tool := range parsed.Tools {
		if !slices.Contains(facts.Tools, tool) {
			return nil
		}
	}
	for _, tag := range parsed.Tags {
		if !slices.Contains(tags, tag) {
			return nil
		}
	}
	return out
}
