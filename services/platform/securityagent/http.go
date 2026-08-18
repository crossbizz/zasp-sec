package securityagent

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxAPIBody = 64 * 1024

type HTTPOptions struct {
	Repository          *MemoryRepository
	Registry            *Registry
	Plans               *PlanStore
	Templates           []Template
	Now                 func() time.Time
	NewID               func(string) string
	Permissions         func(context.Context, string, string) bool
	ReferenceAuthorized func(context.Context, string, string, string, string) bool
	Planner             func(context.Context, SecurityAgent, PlannerScope, []string) (Plan, error)
	FreshAuth           func(context.Context, string, time.Time) bool
	Enqueue             func(context.Context, RunJob) error
	ActionSupported     func(context.Context, ActionMetadata, string) bool
}

type HTTPHandler struct {
	options     HTTPOptions
	coordinator *ApprovalCoordinator
}

type requestScope struct{ organizationID, workspaceID, environmentID, principalID string }

type agentInput struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	TriggerKind            string   `json:"trigger_kind"`
	TriggerSource          string   `json:"trigger_source"`
	EnvironmentIDs         []string `json:"environment_ids"`
	Autonomy               Autonomy `json:"autonomy"`
	MaxSteps               int      `json:"max_steps"`
	MaxDurationSeconds     int      `json:"max_duration_seconds"`
	TemporaryPolicySeconds int      `json:"temporary_policy_seconds"`
	AITokenBudget          int      `json:"ai_token_budget"`
	ConcurrencyLimit       int      `json:"concurrency_limit"`
	AllowedActions         []string `json:"allowed_actions"`
	VerificationKind       string   `json:"verification_kind"`
	DefinitionVersion      int      `json:"definition_version"`
	Enabled                bool     `json:"enabled"`
}

type simulationInput struct {
	Goal          string   `json:"goal"`
	EnvironmentID string   `json:"environment_id"`
	EvidenceIDs   []string `json:"evidence_ids"`
}
type manualRunInput struct {
	EnvironmentID string `json:"environment_id"`
	TriggerKind   string `json:"trigger_kind"`
	TriggerID     string `json:"trigger_id"`
}
type decisionInput struct {
	Decision ApprovalState `json:"decision"`
}

func NewHTTPHandler(options HTTPOptions) (*HTTPHandler, error) {
	if options.Repository == nil || options.Registry == nil || options.Plans == nil || options.Now == nil || options.NewID == nil || options.Permissions == nil || options.ReferenceAuthorized == nil || options.Planner == nil || options.FreshAuth == nil || options.Enqueue == nil {
		return nil, ErrRejected
	}
	registry, err := NewTemplateRegistry(options.Templates)
	if err != nil || len(registry.IDs()) == 0 {
		return nil, ErrRejected
	}
	coordinator, err := NewApprovalCoordinator(options.Repository, options.FreshAuth, options.Enqueue)
	if err != nil {
		return nil, err
	}
	return &HTTPHandler{options: options, coordinator: coordinator}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || request.URL == nil {
		writeAPIError(writer, http.StatusInternalServerError, "security_agent_failed")
		return
	}
	scope, ok := parseRequestScope(request)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "security_agent_unauthorized")
		return
	}
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(segments) < 3 || segments[0] != "api" || segments[1] != "v1" {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	resource := segments[2]
	switch resource {
	case "security-agent-templates":
		if len(segments) == 3 && request.Method == http.MethodGet {
			handler.listTemplates(writer)
			return
		}
	case "security-actions":
		if len(segments) == 3 && request.Method == http.MethodGet {
			handler.listActions(writer, request, scope)
			return
		}
	case "security-agents":
		handler.agents(writer, request, scope, segments[3:])
		return
	case "security-agent-runs":
		handler.runs(writer, request, scope, segments[3:])
		return
	case "security-agent-approvals":
		handler.approvals(writer, request, scope, segments[3:])
		return
	}
	writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
}

func parseRequestScope(request *http.Request) (requestScope, bool) {
	value := requestScope{organizationID: request.Header.Get("X-Zasp-Organization"), workspaceID: request.Header.Get("X-Zasp-Workspace"), environmentID: request.Header.Get("X-Zasp-Environment"), principalID: request.Header.Get("X-Zasp-Principal")}
	return value, bounded(value.organizationID, 128) && bounded(value.workspaceID, 128) && bounded(value.environmentID, 128) && bounded(value.principalID, 128)
}

func (handler *HTTPHandler) listTemplates(writer http.ResponseWriter) {
	items := make([]templateOutput, 0, len(handler.options.Templates))
	for _, value := range handler.options.Templates {
		items = append(items, templateJSON(value))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	writeAPIJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (handler *HTTPHandler) listActions(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	target := request.URL.Query().Get("target")
	items := []actionOutput{}
	for _, metadata := range handler.options.Registry.AllMetadata() {
		if target != "" && !contains(metadata.TargetTypes, target) {
			continue
		}
		supported := metadata.Key != "revoke_integration_connection"
		if handler.options.ActionSupported != nil {
			supported = handler.options.ActionSupported(request.Context(), metadata, scope.environmentID)
		}
		if supported {
			items = append(items, actionJSON(metadata))
		}
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (handler *HTTPHandler) agents(writer http.ResponseWriter, request *http.Request, scope requestScope, tail []string) {
	if len(tail) == 0 {
		switch request.Method {
		case http.MethodGet:
			handler.listAgents(writer, request, scope)
		case http.MethodPost:
			handler.createAgent(writer, request, scope)
		default:
			writeAPIError(writer, http.StatusMethodNotAllowed, "security_agent_method_not_allowed")
		}
		return
	}
	if len(tail) == 1 {
		switch request.Method {
		case http.MethodGet:
			handler.getAgent(writer, request, scope, tail[0])
		case http.MethodPatch:
			handler.updateAgent(writer, request, scope, tail[0])
		case http.MethodDelete:
			handler.deleteAgent(writer, request, scope, tail[0])
		default:
			writeAPIError(writer, http.StatusMethodNotAllowed, "security_agent_method_not_allowed")
		}
		return
	}
	if len(tail) == 2 && request.Method == http.MethodPost {
		switch tail[1] {
		case "simulate":
			handler.simulate(writer, request, scope, tail[0])
			return
		case "runs":
			handler.createRun(writer, request, scope, tail[0])
			return
		}
	}
	writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
}

func (handler *HTTPHandler) listAgents(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	limit := parseLimit(request.URL.Query().Get("limit"))
	if limit == 0 {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	values, next, err := handler.options.Repository.ListAgents(request.Context(), scope.organizationID, request.URL.Query().Get("cursor"), 100)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	filtered := []SecurityAgent{}
	for _, value := range values {
		query := request.URL.Query()
		if trigger := query.Get("trigger"); trigger != "" && value.Trigger.Kind != trigger {
			continue
		}
		if environment := query.Get("environment_id"); environment != "" && !contains(value.Scope.EnvironmentIDs, environment) {
			continue
		}
		if status := query.Get("status"); status != "" && status != agentStatus(value) {
			continue
		}
		filtered = append(filtered, value)
	}
	if len(filtered) > limit {
		next = filtered[limit-1].ID
		filtered = filtered[:limit]
	}
	items := make([]agentOutput, 0, len(filtered))
	for _, value := range filtered {
		items = append(items, agentJSON(value))
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (handler *HTTPHandler) createAgent(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	var input agentInput
	if decodeAPIJSON(writer, request, &input) != nil {
		return
	}
	if input.ID == "" {
		input.ID = handler.options.NewID("agent")
	}
	agent := input.agent(scope.organizationID)
	if handler.validateAgentAccess(request.Context(), scope.principalID, agent) != nil || handler.options.Repository.CreateAgent(request.Context(), agent) != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	writeAPIJSON(writer, http.StatusCreated, agentJSON(agent))
}

func (handler *HTTPHandler) getAgent(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	value, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, id)
	if err != nil || !value.DeletedAt.IsZero() {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	writeAPIJSON(writer, http.StatusOK, agentJSON(value))
}

func (handler *HTTPHandler) updateAgent(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	current, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, id)
	if err != nil || !current.DeletedAt.IsZero() {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	var input agentInput
	if decodeAPIJSON(writer, request, &input) != nil {
		return
	}
	input.ID = id
	value := input.agent(scope.organizationID)
	value.Version = current.Version
	if handler.validateAgentAccess(request.Context(), scope.principalID, value) != nil || handler.options.Repository.UpdateAgent(request.Context(), value, current.Version) != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	value.Version++
	writeAPIJSON(writer, http.StatusOK, agentJSON(value))
}

func (handler *HTTPHandler) deleteAgent(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	value, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, id)
	if err != nil || !value.DeletedAt.IsZero() {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	if err := handler.options.Repository.SoftDeleteAgent(request.Context(), scope.organizationID, id, value.Version, handler.options.Now()); err != nil {
		writeAPIError(writer, http.StatusConflict, "security_agent_conflict")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *HTTPHandler) validateAgentAccess(ctx context.Context, principalID string, agent SecurityAgent) error {
	if ValidateAgent(agent) != nil {
		return ErrRejected
	}
	permissions := map[string]bool{}
	directVerification := true
	for _, action := range agent.AllowedActions {
		metadata, err := handler.options.Registry.Metadata(action)
		if err != nil {
			return ErrRejected
		}
		directVerification = directVerification && metadata.VerificationKind == agent.Verification.Kind
		permissions[action] = handler.options.Permissions(ctx, principalID, action)
	}
	if !directVerification && !handler.matchesTemplateVerification(agent) {
		return ErrRejected
	}
	if agent.Enabled {
		return ValidateEnablePermissions(agent, handler.options.Registry, permissions)
	}
	return nil
}

func (handler *HTTPHandler) matchesTemplateVerification(agent SecurityAgent) bool {
	selected := map[string]bool{}
	for _, action := range agent.AllowedActions {
		selected[action] = true
	}
	for _, template := range handler.options.Templates {
		if template.TriggerKind != agent.Trigger.Kind || template.VerificationCondition != agent.Verification.Kind || len(template.DefaultActions) != len(selected) {
			continue
		}
		matches := true
		for _, action := range template.DefaultActions {
			matches = matches && selected[action]
		}
		if matches {
			return true
		}
	}
	return false
}

func (handler *HTTPHandler) simulate(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	agent, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, id)
	if err != nil || !agent.DeletedAt.IsZero() {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	var input simulationInput
	if decodeAPIJSON(writer, request, &input) != nil {
		return
	}
	if !contains(agent.Scope.EnvironmentIDs, input.EnvironmentID) || !uniqueBounded(input.EvidenceIDs, 128) || !bounded(input.Goal, 1024) {
		writeAPIError(writer, http.StatusForbidden, "security_agent_scope_denied")
		return
	}
	allowed := map[string]bool{}
	for _, evidenceID := range input.EvidenceIDs {
		allowed[evidenceID] = true
	}
	plannerScope := PlannerScope{OrganizationID: scope.organizationID, WorkspaceID: scope.workspaceID, EnvironmentID: input.EnvironmentID, RunID: "simulation", AllowedReferences: allowed}
	plan, err := handler.options.Planner(request.Context(), agent, plannerScope, cloneStrings(input.EvidenceIDs))
	if err != nil || ValidatePlannerOutput(plan, agent, plannerScope, handler.options.Registry, 100) != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_simulation_failed")
		return
	}
	steps := []map[string]any{}
	for _, step := range plan.Steps {
		metadata, _ := handler.options.Registry.Metadata(step.ActionKey)
		steps = append(steps, map[string]any{"index": step.Index, "action": step.ActionKey, "authorization": AuthorizeAction(agent, metadata, plannerScope), "approval_required": metadata.ApprovalFloor != "none" || agent.Autonomy == AutonomySupervised})
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"matched_evidence_ids": input.EvidenceIDs, "summary": plan.Summary, "steps": steps, "side_effects": 0})
}

func (handler *HTTPHandler) createRun(writer http.ResponseWriter, request *http.Request, scope requestScope, agentID string) {
	agent, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, agentID)
	if err != nil || !agent.Enabled || !agent.DeletedAt.IsZero() {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	var input manualRunInput
	if decodeAPIJSON(writer, request, &input) != nil {
		return
	}
	if !contains([]string{"finding", "attack_path", "session"}, input.TriggerKind) || !contains(agent.Scope.EnvironmentIDs, input.EnvironmentID) || !handler.options.ReferenceAuthorized(request.Context(), scope.organizationID, input.EnvironmentID, input.TriggerKind, input.TriggerID) {
		writeAPIError(writer, http.StatusForbidden, "security_agent_scope_denied")
		return
	}
	run := SecurityAgentRun{ID: handler.options.NewID("run"), OrganizationID: scope.organizationID, AgentID: agent.ID, State: RunQueued, TriggerEvidenceIDs: []string{input.TriggerID}, DefinitionVersion: agent.DefinitionVersion, Version: 1}
	if err := handler.options.Repository.CreateRun(request.Context(), run); err != nil {
		writeAPIError(writer, http.StatusConflict, "security_agent_conflict")
		return
	}
	if err := handler.options.Enqueue(request.Context(), RunJob{Name: "security_agent.run", OrganizationID: scope.organizationID, RunID: run.ID, IdempotencyKey: "manual-" + run.ID}); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "security_agent_unavailable")
		return
	}
	writeAPIJSON(writer, http.StatusCreated, runJSON(run))
}

func (handler *HTTPHandler) runs(writer http.ResponseWriter, request *http.Request, scope requestScope, tail []string) {
	if len(tail) == 0 && request.Method == http.MethodGet {
		handler.listRuns(writer, request, scope)
		return
	}
	if len(tail) == 1 && request.Method == http.MethodGet {
		handler.getRun(writer, request, scope, tail[0])
		return
	}
	if len(tail) == 2 && tail[1] == "cancel" && request.Method == http.MethodPost {
		handler.cancelRun(writer, request, scope, tail[0])
		return
	}
	writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
}

func (handler *HTTPHandler) listRuns(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	limit := parseLimit(request.URL.Query().Get("limit"))
	if limit == 0 {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	values, err := handler.options.Repository.ListRuns(request.Context(), scope.organizationID)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	query, cursor := request.URL.Query(), request.URL.Query().Get("cursor")
	result := []SecurityAgentRun{}
	for _, value := range values {
		if cursor != "" && value.ID <= cursor {
			continue
		}
		if query.Get("agent_id") != "" && value.AgentID != query.Get("agent_id") {
			continue
		}
		if query.Get("status") != "" && string(value.State) != query.Get("status") {
			continue
		}
		agent, getErr := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, value.AgentID)
		if getErr != nil || query.Get("environment_id") != "" && !contains(agent.Scope.EnvironmentIDs, query.Get("environment_id")) {
			continue
		}
		result = append(result, value)
	}
	next := ""
	if len(result) > limit {
		next = result[limit-1].ID
		result = result[:limit]
	}
	items := make([]runOutput, 0, len(result))
	for _, value := range result {
		items = append(items, runJSON(value))
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (handler *HTTPHandler) getRun(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	run, err := handler.options.Repository.GetRun(request.Context(), scope.organizationID, id)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	plan, planErr := handler.optionsPlan(scope.organizationID, id)
	redacted := []map[string]any{}
	if planErr == nil {
		for _, step := range plan.Steps {
			parameters := map[string]string{}
			for key := range step.Parameters {
				parameters[key] = "[REDACTED]"
			}
			redacted = append(redacted, map[string]any{"index": step.Index, "action": step.ActionKey, "parameters": parameters})
		}
	}
	steps, _ := handler.options.Repository.ListSteps(request.Context(), scope.organizationID, id)
	approvals, _ := handler.options.Repository.ListApprovals(request.Context(), scope.organizationID, id)
	approvalItems := make([]approvalOutput, 0, len(approvals))
	for _, value := range approvals {
		approvalItems = append(approvalItems, approvalJSON(value))
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"run": runJSON(run), "evidence_ids": run.TriggerEvidenceIDs, "plan": map[string]any{"summary": plan.Summary, "steps": redacted}, "authorization": "recorded", "approvals": approvalItems, "execution": steps, "verification": string(run.State)})
}

func (handler *HTTPHandler) optionsPlan(organizationID, runID string) (Plan, error) {
	return handler.options.Plans.Get(organizationID, runID)
}

func (handler *HTTPHandler) cancelRun(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	run, err := handler.options.Repository.GetRun(request.Context(), scope.organizationID, id)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	if !CanTransition(run.State, RunCancelled) {
		writeAPIError(writer, http.StatusConflict, "security_agent_terminal")
		return
	}
	value, err := CancelRun(request.Context(), handler.options.Repository, scope.organizationID, id)
	if err != nil {
		writeAPIError(writer, http.StatusConflict, "security_agent_conflict")
		return
	}
	writeAPIJSON(writer, http.StatusOK, runJSON(value))
}

func (handler *HTTPHandler) approvals(writer http.ResponseWriter, request *http.Request, scope requestScope, tail []string) {
	if len(tail) == 0 && request.Method == http.MethodGet {
		handler.listApprovals(writer, request, scope)
		return
	}
	if len(tail) == 1 && request.Method == http.MethodGet {
		handler.getApproval(writer, request, scope, tail[0])
		return
	}
	if len(tail) == 2 && tail[1] == "decision" && request.Method == http.MethodPost {
		handler.decideApproval(writer, request, scope, tail[0])
		return
	}
	writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
}

func (handler *HTTPHandler) listApprovals(writer http.ResponseWriter, request *http.Request, scope requestScope) {
	values, err := handler.options.Repository.ListOrganizationApprovals(request.Context(), scope.organizationID)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	result := []Approval{}
	for _, value := range values {
		run, runErr := handler.options.Repository.GetRun(request.Context(), scope.organizationID, value.RunID)
		if runErr != nil {
			continue
		}
		agent, agentErr := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, run.AgentID)
		if agentErr == nil && contains(agent.Scope.EnvironmentIDs, scope.environmentID) {
			result = append(result, value)
		}
	}
	items := make([]approvalOutput, 0, len(result))
	for _, value := range result {
		items = append(items, approvalJSON(value))
	}
	writeAPIJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (handler *HTTPHandler) getApproval(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	approval, run, _, ok := handler.scopedApproval(request, scope, id)
	if !ok {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	metadata := ActionMetadata{}
	if steps, _ := handler.options.Repository.ListSteps(request.Context(), scope.organizationID, run.ID); len(steps) > 0 {
		for _, step := range steps {
			if step.ID == approval.StepID {
				metadata, _ = handler.options.Registry.Metadata(step.ActionKey)
			}
		}
	}
	output := approvalJSON(approval)
	output.ExpectedEffect = metadata.Key
	output.Reversible = metadata.Reversible
	output.TTLSeconds = max(0, int(approval.ExpiresAt.Sub(handler.options.Now()).Seconds()))
	output.EvidenceSummary = cloneStrings(run.TriggerEvidenceIDs)
	writeAPIJSON(writer, http.StatusOK, output)
}

func (handler *HTTPHandler) decideApproval(writer http.ResponseWriter, request *http.Request, scope requestScope, id string) {
	approval, run, _, ok := handler.scopedApproval(request, scope, id)
	if !ok {
		writeAPIError(writer, http.StatusNotFound, "security_agent_not_found")
		return
	}
	if scope.principalID == run.AgentID {
		writeAPIError(writer, http.StatusForbidden, "security_agent_self_approval_denied")
		return
	}
	var input decisionInput
	if decodeAPIJSON(writer, request, &input) != nil {
		return
	}
	if !contains([]ApprovalState{ApprovalApproved, ApprovalRejected, ApprovalCancelled}, input.Decision) {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return
	}
	value, err := handler.coordinator.Decide(request.Context(), scope.organizationID, approval.ID, scope.principalID, handler.options.Now(), input.Decision)
	if err != nil {
		writeAPIError(writer, http.StatusForbidden, "security_agent_fresh_auth_required")
		return
	}
	writeAPIJSON(writer, http.StatusOK, approvalJSON(value))
}

func (handler *HTTPHandler) scopedApproval(request *http.Request, scope requestScope, id string) (Approval, SecurityAgentRun, SecurityAgent, bool) {
	approval, err := handler.options.Repository.GetApproval(request.Context(), scope.organizationID, id)
	if err != nil {
		return Approval{}, SecurityAgentRun{}, SecurityAgent{}, false
	}
	run, err := handler.options.Repository.GetRun(request.Context(), scope.organizationID, approval.RunID)
	if err != nil {
		return Approval{}, SecurityAgentRun{}, SecurityAgent{}, false
	}
	agent, err := handler.options.Repository.GetAgent(request.Context(), scope.organizationID, run.AgentID)
	if err != nil || !contains(agent.Scope.EnvironmentIDs, scope.environmentID) {
		return Approval{}, SecurityAgentRun{}, SecurityAgent{}, false
	}
	return approval, run, agent, true
}

func (input agentInput) agent(organizationID string) SecurityAgent {
	return SecurityAgent{ID: input.ID, OrganizationID: organizationID, Name: input.Name, Trigger: Trigger{Kind: input.TriggerKind, Source: input.TriggerSource}, Scope: Scope{OrganizationID: organizationID, EnvironmentIDs: cloneStrings(input.EnvironmentIDs)}, Autonomy: input.Autonomy, Limits: RunLimits{MaxSteps: input.MaxSteps, MaxDuration: time.Duration(input.MaxDurationSeconds) * time.Second, TemporaryPolicyTTL: time.Duration(input.TemporaryPolicySeconds) * time.Second, MaxAITokens: input.AITokenBudget, MaxConcurrent: input.ConcurrencyLimit}, AllowedActions: cloneStrings(input.AllowedActions), Verification: Verification{Kind: input.VerificationKind}, DefinitionVersion: input.DefinitionVersion, Enabled: input.Enabled}
}
func agentStatus(value SecurityAgent) string {
	if !value.DeletedAt.IsZero() {
		return "deleted"
	}
	if value.Enabled {
		return "enabled"
	}
	return "disabled"
}
func parseLimit(raw string) int {
	if raw == "" {
		return 50
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 100 {
		return 0
	}
	return value
}
func decodeAPIJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxAPIBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) == nil {
		writeAPIError(writer, http.StatusBadRequest, "security_agent_invalid")
		return ErrRejected
	}
	return nil
}
func writeAPIJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func writeAPIError(writer http.ResponseWriter, status int, code string) {
	writeAPIJSON(writer, status, map[string]string{"code": code, "message": "Security Agent request rejected."})
}

type templateOutput struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Version               int      `json:"version"`
	TriggerKind           string   `json:"trigger_kind"`
	DefaultActions        []string `json:"default_actions"`
	VerificationCondition string   `json:"verification_condition"`
}
type actionOutput struct {
	Key              string   `json:"key"`
	RiskClass        string   `json:"risk_class"`
	ApprovalFloor    string   `json:"approval_floor"`
	VerificationKind string   `json:"verification_kind"`
	TargetTypes      []string `json:"target_types"`
	Reversible       bool     `json:"reversible"`
}
type agentOutput struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	TriggerKind            string   `json:"trigger_kind"`
	TriggerSource          string   `json:"trigger_source"`
	VerificationKind       string   `json:"verification_kind"`
	EnvironmentIDs         []string `json:"environment_ids"`
	AllowedActions         []string `json:"allowed_actions"`
	Autonomy               Autonomy `json:"autonomy"`
	MaxSteps               int      `json:"max_steps"`
	MaxDurationSeconds     int      `json:"max_duration_seconds"`
	TemporaryPolicySeconds int      `json:"temporary_policy_seconds"`
	AITokenBudget          int      `json:"ai_token_budget"`
	ConcurrencyLimit       int      `json:"concurrency_limit"`
	DefinitionVersion      int      `json:"definition_version"`
	Enabled                bool     `json:"enabled"`
}
type runOutput struct {
	ID                string   `json:"id"`
	AgentID           string   `json:"agent_id"`
	State             RunState `json:"state"`
	EvidenceIDs       []string `json:"evidence_ids"`
	DefinitionVersion int      `json:"definition_version"`
	Version           int64    `json:"version"`
}
type approvalOutput struct {
	ID              string        `json:"id"`
	RunID           string        `json:"run_id"`
	StepID          string        `json:"step_id"`
	State           ApprovalState `json:"state"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Version         int64         `json:"version"`
	ExpectedEffect  string        `json:"expected_effect,omitempty"`
	Reversible      bool          `json:"reversible"`
	TTLSeconds      int           `json:"ttl_seconds,omitempty"`
	EvidenceSummary []string      `json:"evidence_summary,omitempty"`
}

func templateJSON(value Template) templateOutput {
	return templateOutput{ID: value.ID, Name: value.Name, Version: value.Version, TriggerKind: value.TriggerKind, DefaultActions: cloneStrings(value.DefaultActions), VerificationCondition: value.VerificationCondition}
}
func actionJSON(value ActionMetadata) actionOutput {
	return actionOutput{Key: value.Key, RiskClass: value.RiskClass, TargetTypes: cloneStrings(value.TargetTypes), ApprovalFloor: value.ApprovalFloor, Reversible: value.Reversible, VerificationKind: value.VerificationKind}
}
func agentJSON(value SecurityAgent) agentOutput {
	return agentOutput{ID: value.ID, Name: value.Name, TriggerKind: value.Trigger.Kind, TriggerSource: value.Trigger.Source, EnvironmentIDs: cloneStrings(value.Scope.EnvironmentIDs), Autonomy: value.Autonomy, MaxSteps: value.Limits.MaxSteps, MaxDurationSeconds: int(value.Limits.MaxDuration.Seconds()), TemporaryPolicySeconds: int(value.Limits.TemporaryPolicyTTL.Seconds()), AITokenBudget: value.Limits.MaxAITokens, ConcurrencyLimit: value.Limits.MaxConcurrent, AllowedActions: cloneStrings(value.AllowedActions), VerificationKind: value.Verification.Kind, DefinitionVersion: value.DefinitionVersion, Enabled: value.Enabled}
}
func runJSON(value SecurityAgentRun) runOutput {
	return runOutput{ID: value.ID, AgentID: value.AgentID, State: value.State, EvidenceIDs: cloneStrings(value.TriggerEvidenceIDs), DefinitionVersion: value.DefinitionVersion, Version: value.Version}
}
func approvalJSON(value Approval) approvalOutput {
	return approvalOutput{ID: value.ID, RunID: value.RunID, StepID: value.StepID, State: value.State, ExpiresAt: value.ExpiresAt, Version: value.Version}
}
