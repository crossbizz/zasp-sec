package reconciliation

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type RiskService struct {
	findings *FindingStore
	paths    *AttackPathStore
	search   *SearchService
	home     HomeSummaryInput
	secret   []byte
	webhook  TicketWebhook
}

func NewRiskService(findings *FindingStore, paths *AttackPathStore, search *SearchService, home HomeSummaryInput, secret []byte, webhook TicketWebhook) (*RiskService, error) {
	if !findings.usable() || paths == nil || paths.values == nil || search == nil || home.Scope.Validate() != nil || len(secret) < 16 || len(secret) > 256 || webhook == nil {
		return nil, ErrInventoryConfiguration
	}
	if _, err := BuildHomeSummary(context.Background(), home); err != nil {
		return nil, ErrInventoryConfiguration
	}
	return &RiskService{findings: findings, paths: paths, search: search, home: home, secret: append([]byte(nil), secret...), webhook: webhook}, nil
}

type RiskHTTPHandler struct {
	service   *RiskService
	authorize InventoryAuthorizer
}

func NewRiskHTTPHandler(service *RiskService, authorize InventoryAuthorizer) (*RiskHTTPHandler, error) {
	if service == nil || authorize == nil {
		return nil, ErrInventoryConfiguration
	}
	return &RiskHTTPHandler{service: service, authorize: authorize}, nil
}

func (handler *RiskHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.service == nil || request == nil || request.URL == nil {
		writeInventoryError(writer, ErrInventoryConfiguration)
		return
	}
	scope, err := inventoryAuthorize(handler.authorize, request)
	if err != nil || scope.Validate() != nil {
		writeInventoryError(writer, ErrInventoryForbidden)
		return
	}
	status, payload, err := handler.dispatch(request, scope)
	if err != nil {
		writeInventoryError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func (handler *RiskHTTPHandler) dispatch(request *http.Request, scope domain.Scope) (int, any, error) {
	path := request.URL.EscapedPath()
	if path != request.URL.Path || strings.HasSuffix(path, "/") {
		return 0, nil, ErrInventoryInvalid
	}
	switch path {
	case "/api/v1/findings":
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			return 0, nil, ErrInventoryNotFound
		}
		values, err := handler.service.findings.List(request.Context(), scope, FindingFilter{VisibleByDefault: true})
		return http.StatusOK, map[string]any{"items": findingJSONs(values)}, err
	case "/api/v1/attack-paths":
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			return 0, nil, ErrInventoryNotFound
		}
		values, err := handler.service.paths.List(request.Context(), scope)
		return http.StatusOK, map[string]any{"items": attackPathJSONs(values)}, err
	case "/api/v1/home/summary":
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || handler.service.home.Scope != scope {
			return 0, nil, ErrInventoryNotFound
		}
		value, err := BuildHomeSummary(request.Context(), handler.service.home)
		return http.StatusOK, homeSummaryJSON(value), err
	case "/api/v1/search":
		if request.Method != http.MethodGet {
			return 0, nil, ErrInventoryNotFound
		}
		query := request.URL.Query()
		if len(query) != 2 || len(query["q"]) != 1 || len(query["limit"]) != 1 {
			return 0, nil, ErrInventoryInvalid
		}
		limit, err := strconv.Atoi(query.Get("limit"))
		if err != nil {
			return 0, nil, ErrInventoryInvalid
		}
		values, err := handler.service.search.Query(request.Context(), scope, query.Get("q"), limit)
		return http.StatusOK, map[string]any{"items": searchJSONs(values)}, err
	}
	if strings.HasPrefix(path, "/api/v1/findings/") {
		return handler.finding(request, scope, strings.TrimPrefix(path, "/api/v1/findings/"))
	}
	if strings.HasPrefix(path, "/api/v1/attack-paths/") {
		return handler.attackPath(request, scope, strings.TrimPrefix(path, "/api/v1/attack-paths/"))
	}
	return 0, nil, ErrInventoryNotFound
}

func (handler *RiskHTTPHandler) finding(request *http.Request, scope domain.Scope, tail string) (int, any, error) {
	if request.URL.RawQuery != "" {
		return 0, nil, ErrInventoryInvalid
	}
	parts := strings.Split(tail, "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return 0, nil, ErrInventoryNotFound
	}
	id, err := domain.ParseProductID(parts[0])
	if err != nil {
		return 0, nil, ErrInventoryInvalid
	}
	if len(parts) == 1 {
		switch request.Method {
		case http.MethodGet:
			value, err := handler.service.findings.Get(request.Context(), scope, id)
			return http.StatusOK, findingJSON(value), err
		case http.MethodPatch:
			var input struct {
				Status FindingStatus `json:"status"`
			}
			if err := decodeInventoryRequest(request, &input); err != nil {
				return 0, nil, err
			}
			value, err := handler.service.findings.Update(request.Context(), scope, id, input.Status)
			return http.StatusOK, findingJSON(value), err
		default:
			return 0, nil, ErrInventoryNotFound
		}
	}
	if request.Method != http.MethodPost {
		return 0, nil, ErrInventoryNotFound
	}
	switch parts[1] {
	case "accept-risk":
		var input struct {
			Reason string `json:"reason"`
		}
		if err := decodeInventoryRequest(request, &input); err != nil {
			return 0, nil, err
		}
		value, err := handler.service.findings.AcceptRisk(request.Context(), scope, id, input.Reason)
		return http.StatusOK, findingJSON(value), err
	case "ticket":
		var input struct{}
		if err := decodeInventoryRequest(request, &input); err != nil {
			return 0, nil, err
		}
		ticket, err := handler.service.findings.CreateTicket(request.Context(), scope, id, handler.service.secret, handler.service.webhook)
		return http.StatusCreated, map[string]any{"ticket_id": ticket}, err
	default:
		return 0, nil, ErrInventoryNotFound
	}
}

func (handler *RiskHTTPHandler) attackPath(request *http.Request, scope domain.Scope, tail string) (int, any, error) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		return 0, nil, ErrInventoryNotFound
	}
	parts := strings.Split(tail, "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return 0, nil, ErrInventoryNotFound
	}
	id, err := domain.ParseProductID(parts[0])
	if err != nil {
		return 0, nil, ErrInventoryInvalid
	}
	if len(parts) == 1 {
		value, err := handler.service.paths.Get(request.Context(), scope, id)
		return http.StatusOK, attackPathJSON(value), err
	}
	if parts[1] != "break-options" {
		return 0, nil, ErrInventoryNotFound
	}
	values, err := handler.service.paths.BreakOptions(request.Context(), scope, id)
	return http.StatusOK, map[string]any{"items": breakOptionJSONs(values)}, err
}

func findingJSON(value Finding) map[string]any {
	evidence := make([]string, len(value.EvidenceIDs))
	for i, id := range value.EvidenceIDs {
		evidence[i] = id.String()
	}
	factors := make([]map[string]any, len(value.Factors))
	for i, factor := range value.Factors {
		factors[i] = map[string]any{"name": factor.Name, "evidence_id": factor.EvidenceID.String()}
	}
	result := map[string]any{"id": value.ID.String(), "source": string(value.Source), "title": value.Title, "severity": string(value.Severity), "status": string(value.Status), "evidence_ids": evidence, "risk_factors": factors}
	if !value.AgentID.IsZero() {
		result["agent_id"] = value.AgentID.String()
	}
	if !value.PathID.IsZero() {
		result["path_id"] = value.PathID.String()
	}
	if value.Rule != "" {
		result["rule"] = string(value.Rule)
	}
	if value.ComplianceContext != "" {
		result["compliance_context"] = value.ComplianceContext
	}
	if value.AcceptanceReason != "" {
		result["acceptance_reason"] = value.AcceptanceReason
	}
	return result
}
func findingJSONs(values []Finding) []map[string]any {
	result := make([]map[string]any, len(values))
	for i, value := range values {
		result[i] = findingJSON(value)
	}
	return result
}
func attackPathJSON(value AttackPath) map[string]any {
	nodes := make([]string, len(value.NodeIDs))
	for i, id := range value.NodeIDs {
		nodes[i] = id.String()
	}
	evidence := make([]string, len(value.EvidenceIDs))
	for i, id := range value.EvidenceIDs {
		evidence[i] = id.String()
	}
	return map[string]any{"id": value.ID.String(), "entry_id": value.EntryID.String(), "sink_id": value.SinkID.String(), "node_ids": nodes, "state": string(value.State), "evidence_ids": evidence, "blocked_edge": value.BlockedEdge}
}
func attackPathJSONs(values []AttackPath) []map[string]any {
	result := make([]map[string]any, len(values))
	for i, value := range values {
		result[i] = attackPathJSON(value)
	}
	return result
}
func breakOptionJSONs(values []BreakOption) []map[string]any {
	result := make([]map[string]any, len(values))
	for i, value := range values {
		result[i] = map[string]any{"path_id": value.PathID.String(), "target_id": value.TargetID.String(), "evidence_id": value.EvidenceID.String(), "kind": value.Kind, "rank": value.Rank}
	}
	return result
}
func homeSummaryJSON(value HomeSummary) map[string]any {
	return map[string]any{"agent_count": value.AgentCount, "high_risk_paths": value.HighRiskPaths, "verified_changes": value.VerifiedChanges, "blocked_changes": value.BlockedChanges, "pending_approvals": value.PendingApprovals, "oldest_approval_age_seconds": value.OldestApprovalAgeSeconds, "needs_human_runs": value.NeedsHumanRuns, "failed_runs": value.FailedRuns, "inconclusive_runs": value.InconclusiveRuns, "recent_contained": value.RecentContained, "recent_remediated": value.RecentRemediated, "healthy": value.Healthy, "attention_required": value.AttentionRequired}
}
func searchJSONs(values []SearchRecord) []map[string]any {
	result := make([]map[string]any, len(values))
	for i, value := range values {
		result[i] = map[string]any{"id": value.ID.String(), "type": value.Type, "name": value.Name}
	}
	return result
}
