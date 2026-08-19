package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformintegration "github.com/zasp-ai/zasp-sec/services/platform/integration"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

type workflowRepository interface {
	ListWorkflows(context.Context, domain.Scope, string, string, string) (json.RawMessage, error)
	GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error)
	MutateWorkflow(context.Context, RequestIdentity, WorkflowMutation) (WorkflowMutationResult, error)
}

type workflowHTTPHandler struct {
	repository workflowRepository
	signingKey []byte
	now        func() time.Time
	catalog    *platformintegration.Catalog
}

func newWorkflowHTTPHandler(repository workflowRepository, signingKey []byte, now func() time.Time) (*workflowHTTPHandler, error) {
	if nilInterface(repository) || len(signingKey) < 32 || len(signingKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	}
	instant := now()
	if instant.IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	catalog, err := platformintegration.NewCatalog(platformintegration.BuiltinManifests())
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &workflowHTTPHandler{repository: repository, signingKey: append([]byte(nil), signingKey...), now: now, catalog: catalog}, nil
}

func (handler *workflowHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if request.Method == http.MethodGet {
		handler.read(writer, request, identity, routed)
		return
	}
	handler.mutate(writer, request, identity, routed)
}

func (handler *workflowHTTPHandler) read(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	if routed.OperationID == "listIntegrationCatalog" {
		values, err := handler.catalog.SearchContext(request.Context(), platformintegration.CatalogFilter{
			Query: request.URL.Query().Get("q"), Category: request.URL.Query().Get("category"), DataType: request.URL.Query().Get("data_type"), Action: request.URL.Query().Get("action"), AuthMode: request.URL.Query().Get("auth_mode"),
		})
		payload, marshalErr := json.Marshal(map[string]any{"items": values})
		if err != nil || marshalErr != nil {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		writeProductionResponse(writer, request, http.StatusOK, payload, nil)
		return
	}
	if routed.OperationID == "listSecurityAgentTemplates" {
		writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": workflowTemplates()}, nil)
		return
	}
	if routed.OperationID == "listSecurityActions" {
		writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": workflowActions()}, nil)
		return
	}
	kind, list, parentField, parentID, ok := workflowReadTarget(routed)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	if list {
		payload, err := handler.repository.ListWorkflows(request.Context(), identity.Scope, kind, parentField, parentID)
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
		return
	}
	value, err := handler.repository.GetWorkflow(request.Context(), identity.Scope, kind, routed.PathParameters["id"])
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(value.Version))
	if routed.OperationID == "getSensorCoverage" {
		coverage, coverageErr := sensorCoverage(value.Body)
		writeJSONValue(writer, request, http.StatusOK, coverage, coverageErr)
		return
	}
	if routed.OperationID == "getSecurityAgentRun" {
		var run map[string]any
		if json.Unmarshal(value.Body, &run) != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		writeJSONValue(writer, request, http.StatusOK, map[string]any{"run": run, "evidence_ids": run["evidence_ids"], "plan": map[string]any{"summary": "Durable bounded plan", "steps": []any{}}, "authorization": "approval_required", "approvals": []any{}, "execution": []any{}, "verification": "pending"}, nil)
		return
	}
	writeProductionResponse(writer, request, http.StatusOK, value.Body, nil)
}

func (handler *workflowHTTPHandler) mutate(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		writeProductionStatusError(writer, request, http.StatusBadRequest, "operation_rejected", "Operation rejected", false)
		return
	}
	correlationID := correlationIDFromContext(request.Context())
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	mutation, status, responseKind, err := handler.buildMutation(request, identity, routed, idempotencyKey, auditID, correlationID)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	result, err := handler.repository.MutateWorkflow(request.Context(), identity, mutation)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if status == http.StatusNoContent {
		writer.WriteHeader(status)
		return
	}
	payload := result.Body
	if responseKind == "sensor_secret" {
		payload, err = handler.sensorEnrollment(result, identity.Scope, mutation.ID, idempotencyKey)
	} else if strings.HasPrefix(responseKind, "policy_rollout:") {
		parts := strings.SplitN(responseKind, ":", 3)
		payload, err = json.Marshal(map[string]any{"policy_id": mutation.ID, "state": parts[1], "target_id": parts[2]})
	}
	writeProductionResponse(writer, request, status, payload, err)
}

func (handler *workflowHTTPHandler) buildMutation(request *http.Request, identity RequestIdentity, routed RoutedOperation, idempotencyKey, auditID, correlationID string) (WorkflowMutation, int, string, error) {
	var err error
	kind, action, status, ok := workflowMutationTarget(routed.OperationID)
	if !ok {
		return WorkflowMutation{}, 0, "", ErrRepositoryNotFound
	}
	id := routed.PathParameters["id"]
	expected := int64(0)
	if action != "create" {
		var err error
		expected, err = parseVersion(request.Header.Get("If-Match"))
		if err != nil {
			return WorkflowMutation{}, 0, "", errPreconditionRequired
		}
	}
	var body json.RawMessage
	responseKind := "body"
	switch routed.OperationID {
	case "createPolicy", "updatePolicy":
		var value platformpolicy.Policy
		if decodeProductionJSON(request, &value) != nil || platformpolicy.Validate(value, workflowPolicyCapabilities()) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		if id == "" {
			id = value.ID
		}
		if id != value.ID {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		body, _ = json.Marshal(value)
	case "simulatePolicy":
		stored, err := handler.repository.GetWorkflow(request.Context(), identity.Scope, "policy", id)
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
		var input struct {
			Events []map[string]string `json:"events"`
		}
		if decodeProductionJSON(request, &input) != nil || len(input.Events) < 1 || len(input.Events) > 100 {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		var value platformpolicy.Policy
		if json.Unmarshal(stored.Body, &value) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryUnavailable
		}
		compiled, err := platformpolicy.Compile(value)
		if err != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		matches, blocks, examples := 0, 0, []string{}
		for _, event := range input.Events {
			decision, evaluateErr := platformpolicy.Evaluate(request.Context(), compiled, event)
			if evaluateErr != nil {
				return WorkflowMutation{}, 0, "", ErrRepositoryOperation
			}
			if decision.Matched {
				matches++
				if decision.Action == platformpolicy.ActionBlock {
					blocks++
				}
				if session := event["session_id"]; len(examples) < 5 && session != "" {
					examples = append(examples, session)
				}
			}
		}
		body, _ = json.Marshal(map[string]any{"matches": matches, "would_block": blocks, "example_session_ids": examples})
		action, expected, status = "audit", stored.Version, http.StatusOK
	case "rolloutPolicy", "disablePolicy":
		stored, err := handler.repository.GetWorkflow(request.Context(), identity.Scope, "policy", id)
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
		if stored.Version != expected {
			return WorkflowMutation{}, 0, "", ErrRepositoryConflict
		}
		var policyValue map[string]any
		if json.Unmarshal(stored.Body, &policyValue) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryUnavailable
		}
		target := identity.Scope.EnvironmentID().String()
		state := "disabled"
		if routed.OperationID == "rolloutPolicy" {
			var input struct {
				State    string `json:"state"`
				TargetID string `json:"target_id"`
			}
			if decodeProductionJSON(request, &input) != nil || (input.State != "monitor" && input.State != "enforced") || input.TargetID == "" {
				return WorkflowMutation{}, 0, "", ErrRepositoryOperation
			}
			state, target = input.State, input.TargetID
		} else if decodeEmptyInput(request) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		policyValue["rollout"] = state
		body, _ = json.Marshal(policyValue)
		responseKind = "policy_rollout:" + state + ":" + target
	case "deletePolicy", "deleteIntegration", "deleteSensor", "deleteSecurityAgent":
		body = json.RawMessage(`{}`)
	case "createIntegration", "updateIntegration":
		body, id, err = handler.integrationBody(request, identity.Scope, id, idempotencyKey, routed.OperationID == "createIntegration")
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
	case "createSensorEnrollment", "updateSensor":
		body, id, err = handler.sensorBody(request, identity.Scope, id, idempotencyKey, routed.OperationID == "createSensorEnrollment")
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
		if routed.OperationID == "createSensorEnrollment" {
			responseKind = "sensor_secret"
		}
	case "rotateSensorToken":
		if decodeEmptyInput(request) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		stored, getErr := handler.repository.GetWorkflow(request.Context(), identity.Scope, "sensor", id)
		if getErr != nil {
			return WorkflowMutation{}, 0, "", getErr
		}
		body, responseKind = stored.Body, "sensor_secret"
	case "createSecurityAgent", "updateSecurityAgent":
		if routed.OperationID == "createSecurityAgent" && id == "" {
			id = handler.idempotentProductID(identity.Scope, routed.OperationID, idempotencyKey)
		}
		body, id, err = securityAgentBody(request, identity.Scope, id, routed.OperationID == "createSecurityAgent")
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
	case "simulateSecurityAgent":
		body, expected, err = handler.securityAgentSimulation(request, identity.Scope, id)
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
		action, status = "audit", http.StatusOK
	case "runSecurityAgent":
		body, id, err = handler.securityAgentRun(request, identity.Scope, id, idempotencyKey)
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
		kind, action, expected, status = "security_agent_run", "create", 0, http.StatusCreated
	case "cancelSecurityAgentRun":
		stored, getErr := handler.repository.GetWorkflow(request.Context(), identity.Scope, "security_agent_run", id)
		if getErr != nil {
			return WorkflowMutation{}, 0, "", getErr
		}
		if stored.Version != expected {
			return WorkflowMutation{}, 0, "", ErrRepositoryConflict
		}
		var value map[string]any
		if json.Unmarshal(stored.Body, &value) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryUnavailable
		}
		value["state"], value["version"] = "cancelled", expected+1
		body, _ = json.Marshal(value)
	case "decideSecurityAgentApproval":
		if request.Header.Get("X-Zasp-Fresh-Auth") != "confirmed" {
			return WorkflowMutation{}, 0, "", ErrRepositoryAuthorization
		}
		stored, getErr := handler.repository.GetWorkflow(request.Context(), identity.Scope, "security_agent_approval", id)
		if getErr != nil {
			return WorkflowMutation{}, 0, "", getErr
		}
		if stored.Version != expected {
			return WorkflowMutation{}, 0, "", ErrRepositoryConflict
		}
		var input struct {
			Decision string `json:"decision"`
		}
		if decodeProductionJSON(request, &input) != nil || input.Decision != "approved" && input.Decision != "rejected" && input.Decision != "cancelled" {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		var value map[string]any
		if json.Unmarshal(stored.Body, &value) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryUnavailable
		}
		value["state"], value["version"] = input.Decision, expected+1
		body, _ = json.Marshal(value)
	default:
		return WorkflowMutation{}, 0, "", ErrRepositoryNotFound
	}
	mutation := WorkflowMutation{Action: action, Kind: kind, ID: id, Operation: routed.OperationID, IdempotencyKey: idempotencyKey, ExpectedVersion: expected, Body: body, AuditID: auditID, CorrelationID: correlationID}
	return mutation, status, responseKind, nil
}

var errPreconditionRequired = errors.New("precondition required")
var ErrRepositoryAuthorization = errors.New("repository authorization rejected")

func workflowReadTarget(routed RoutedOperation) (kind string, list bool, parentField, parentID string, ok bool) {
	switch routed.OperationID {
	case "listPolicies":
		return "policy", true, "", "", true
	case "getPolicy":
		return "policy", false, "", "", true
	case "listPolicyDecisions":
		return "policy_decision", true, "policy_id", routed.PathParameters["id"], true
	case "listIntegrations":
		return "integration", true, "", "", true
	case "getIntegration":
		return "integration", false, "", "", true
	case "listSensors":
		return "sensor", true, "", "", true
	case "getSensor", "getSensorCoverage":
		return "sensor", false, "", "", true
	case "listSecurityAgents":
		return "security_agent", true, "", "", true
	case "getSecurityAgent":
		return "security_agent", false, "", "", true
	case "listSecurityAgentRuns":
		return "security_agent_run", true, "", "", true
	case "getSecurityAgentRun":
		return "security_agent_run", false, "", "", true
	case "listSecurityAgentApprovals":
		return "security_agent_approval", true, "", "", true
	case "getSecurityAgentApproval":
		return "security_agent_approval", false, "", "", true
	default:
		return "", false, "", "", false
	}
}

func workflowMutationTarget(operation string) (kind, action string, status int, ok bool) {
	switch operation {
	case "createPolicy":
		return "policy", "create", http.StatusCreated, true
	case "updatePolicy":
		return "policy", "update", http.StatusOK, true
	case "deletePolicy":
		return "policy", "delete", http.StatusNoContent, true
	case "simulatePolicy", "rolloutPolicy", "disablePolicy":
		return "policy", "update", http.StatusOK, true
	case "createIntegration":
		return "integration", "create", http.StatusCreated, true
	case "updateIntegration":
		return "integration", "update", http.StatusOK, true
	case "deleteIntegration":
		return "integration", "delete", http.StatusNoContent, true
	case "createSensorEnrollment":
		return "sensor", "create", http.StatusCreated, true
	case "updateSensor":
		return "sensor", "update", http.StatusOK, true
	case "deleteSensor":
		return "sensor", "delete", http.StatusNoContent, true
	case "rotateSensorToken":
		return "sensor", "rotate_secret", http.StatusOK, true
	case "createSecurityAgent":
		return "security_agent", "create", http.StatusCreated, true
	case "updateSecurityAgent":
		return "security_agent", "update", http.StatusOK, true
	case "deleteSecurityAgent":
		return "security_agent", "delete", http.StatusNoContent, true
	case "simulateSecurityAgent":
		return "security_agent", "audit", http.StatusOK, true
	case "runSecurityAgent":
		return "security_agent_run", "create", http.StatusCreated, true
	case "cancelSecurityAgentRun":
		return "security_agent_run", "update", http.StatusOK, true
	case "decideSecurityAgentApproval":
		return "security_agent_approval", "update", http.StatusOK, true
	default:
		return "", "", 0, false
	}
}

func (handler *workflowHTTPHandler) integrationBody(request *http.Request, scope domain.Scope, id, idempotencyKey string, create bool) (json.RawMessage, string, error) {
	var input struct {
		ConnectorKey  string            `json:"connector_key"`
		Name          string            `json:"name"`
		Configuration map[string]string `json:"configuration"`
	}
	if decodeProductionJSON(request, &input) != nil || input.Name == "" || len(input.Name) > 128 {
		return nil, "", ErrRepositoryOperation
	}
	var current map[string]any
	if !create {
		stored, err := handler.repository.GetWorkflow(request.Context(), scope, "integration", id)
		if err != nil {
			return nil, "", err
		}
		if json.Unmarshal(stored.Body, &current) != nil {
			return nil, "", ErrRepositoryUnavailable
		}
		input.ConnectorKey, _ = current["connector_key"].(string)
	}
	if handler.catalog.ValidateSetup(input.ConnectorKey, input.Configuration) != nil {
		return nil, "", ErrRepositoryOperation
	}
	if create {
		id = handler.idempotentProductID(scope, "createIntegration", idempotencyKey)
	}
	now := handler.now().Format(time.RFC3339)
	if current == nil {
		current = map[string]any{"id": id, "connector_key": input.ConnectorKey, "status": "pending_authorization", "created_at": now}
	}
	current["name"], current["configuration"], current["updated_at"] = input.Name, input.Configuration, now
	body, _ := json.Marshal(current)
	return body, id, nil
}

func (handler *workflowHTTPHandler) sensorBody(request *http.Request, scope domain.Scope, id, idempotencyKey string, create bool) (json.RawMessage, string, error) {
	var input struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	}
	if decodeProductionJSON(request, &input) != nil || input.Name == "" || len(input.Name) > 128 || input.Mode != "metadata_only" && input.Mode != "full" {
		return nil, "", ErrRepositoryOperation
	}
	var current map[string]any
	if create {
		id = handler.idempotentProductID(scope, "createSensorEnrollment", idempotencyKey)
	} else {
		stored, err := handler.repository.GetWorkflow(request.Context(), scope, "sensor", id)
		if err != nil {
			return nil, "", err
		}
		if json.Unmarshal(stored.Body, &current) != nil {
			return nil, "", ErrRepositoryUnavailable
		}
	}
	now := handler.now().Format(time.RFC3339)
	if current == nil {
		current = map[string]any{"id": id, "capabilities": []string{}, "created_at": now}
	}
	current["name"], current["mode"], current["updated_at"] = input.Name, input.Mode, now
	body, _ := json.Marshal(current)
	return body, id, nil
}

func securityAgentBody(request *http.Request, scope domain.Scope, id string, create bool) (json.RawMessage, string, error) {
	var input struct {
		ID                     string   `json:"id"`
		Name                   string   `json:"name"`
		TriggerKind            string   `json:"trigger_kind"`
		TriggerSource          string   `json:"trigger_source"`
		EnvironmentIDs         []string `json:"environment_ids"`
		Autonomy               string   `json:"autonomy"`
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
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		return nil, "", ErrRepositoryOperation
	}
	if create && input.ID == "" {
		input.ID = id
	} else if id == "" {
		id = input.ID
	}
	value := securityagent.SecurityAgent{ID: id, OrganizationID: scope.OrganizationID().String(), Name: input.Name, Trigger: securityagent.Trigger{Kind: input.TriggerKind, Source: input.TriggerSource}, Scope: securityagent.Scope{OrganizationID: scope.OrganizationID().String(), EnvironmentIDs: input.EnvironmentIDs}, Autonomy: securityagent.Autonomy(input.Autonomy), Limits: securityagent.RunLimits{MaxSteps: input.MaxSteps, MaxDuration: time.Duration(input.MaxDurationSeconds) * time.Second, TemporaryPolicyTTL: time.Duration(input.TemporaryPolicySeconds) * time.Second, MaxAITokens: input.AITokenBudget, MaxConcurrent: input.ConcurrencyLimit}, AllowedActions: input.AllowedActions, Verification: securityagent.Verification{Kind: input.VerificationKind}, DefinitionVersion: input.DefinitionVersion, Enabled: input.Enabled}
	if securityagent.ValidateAgent(value) != nil || !exactWorkflowEnvironment(input.EnvironmentIDs, scope.EnvironmentID().String()) || !servedWorkflowActions(input.AllowedActions) {
		return nil, "", ErrRepositoryOperation
	}
	body, _ := json.Marshal(map[string]any{"id": id, "name": input.Name, "trigger_kind": input.TriggerKind, "trigger_source": input.TriggerSource, "environment_ids": input.EnvironmentIDs, "autonomy": input.Autonomy, "max_steps": input.MaxSteps, "max_duration_seconds": input.MaxDurationSeconds, "temporary_policy_seconds": input.TemporaryPolicySeconds, "ai_token_budget": input.AITokenBudget, "concurrency_limit": input.ConcurrencyLimit, "allowed_actions": input.AllowedActions, "verification_kind": input.VerificationKind, "definition_version": input.DefinitionVersion, "enabled": input.Enabled})
	return body, id, nil
}

func (handler *workflowHTTPHandler) securityAgentSimulation(request *http.Request, scope domain.Scope, id string) (json.RawMessage, int64, error) {
	stored, err := handler.repository.GetWorkflow(request.Context(), scope, "security_agent", id)
	if err != nil {
		return nil, 0, err
	}
	var input struct {
		Goal          string   `json:"goal"`
		EnvironmentID string   `json:"environment_id"`
		EvidenceIDs   []string `json:"evidence_ids"`
	}
	if decodeProductionJSON(request, &input) != nil || input.Goal == "" || len(input.Goal) > 1024 || input.EnvironmentID != scope.EnvironmentID().String() || len(input.EvidenceIDs) < 1 || len(input.EvidenceIDs) > 100 {
		return nil, 0, ErrRepositoryOperation
	}
	var agent struct {
		AllowedActions []string `json:"allowed_actions"`
	}
	if json.Unmarshal(stored.Body, &agent) != nil || len(agent.AllowedActions) == 0 {
		return nil, 0, ErrRepositoryUnavailable
	}
	steps := make([]map[string]any, len(agent.AllowedActions))
	for index, action := range agent.AllowedActions {
		steps[index] = map[string]any{"index": index, "action": action, "authorization": "approval_required", "approval_required": true}
	}
	payload, _ := json.Marshal(map[string]any{"matched_evidence_ids": input.EvidenceIDs, "summary": "Deterministic bounded plan requiring approval", "steps": steps, "side_effects": 0})
	return payload, stored.Version, nil
}

func (handler *workflowHTTPHandler) securityAgentRun(request *http.Request, scope domain.Scope, agentID, idempotencyKey string) (json.RawMessage, string, error) {
	stored, err := handler.repository.GetWorkflow(request.Context(), scope, "security_agent", agentID)
	if err != nil {
		return nil, "", err
	}
	var input struct {
		EnvironmentID string `json:"environment_id"`
		TriggerKind   string `json:"trigger_kind"`
		TriggerID     string `json:"trigger_id"`
	}
	if decodeProductionJSON(request, &input) != nil || input.EnvironmentID != scope.EnvironmentID().String() || input.TriggerKind != "finding" && input.TriggerKind != "attack_path" && input.TriggerKind != "session" {
		return nil, "", ErrRepositoryOperation
	}
	if _, err := domain.ParseProductID(input.TriggerID); err != nil {
		return nil, "", ErrRepositoryOperation
	}
	runID := handler.idempotentProductID(scope, "runSecurityAgent:"+agentID, idempotencyKey)
	payload, _ := json.Marshal(map[string]any{"id": runID, "agent_id": agentID, "state": "waiting_approval", "evidence_ids": []string{input.TriggerID}, "definition_version": stored.Version, "version": 1})
	return payload, runID, nil
}

func (handler *workflowHTTPHandler) sensorEnrollment(result WorkflowMutationResult, scope domain.Scope, id, idempotencyKey string) (json.RawMessage, error) {
	var body map[string]any
	if json.Unmarshal(result.Body, &body) != nil {
		return nil, ErrRepositoryUnavailable
	}
	storedID, ok := body["id"].(string)
	if !ok || storedID == "" {
		return nil, ErrRepositoryUnavailable
	}
	id = storedID
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write([]byte(scopeKey(scope) + "\x00" + id + "\x00" + strconv.FormatInt(result.SecretGeneration, 10) + "\x00" + idempotencyKey))
	body["token"] = "sen_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return json.Marshal(body)
}

func (handler *workflowHTTPHandler) idempotentProductID(scope domain.Scope, operation, idempotencyKey string) string {
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write([]byte(scopeKey(scope) + "\x00" + operation + "\x00" + idempotencyKey))
	value := mac.Sum(nil)[:16]
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return "pid_" + encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func sensorCoverage(payload json.RawMessage) (map[string]any, error) {
	var sensor struct {
		ID            string   `json:"id"`
		Capabilities  []string `json:"capabilities"`
		LastHeartbeat string   `json:"last_heartbeat"`
		Kernel        string   `json:"kernel"`
		BTF           bool     `json:"btf"`
		EventRate     int64    `json:"event_rate"`
		Drops         int64    `json:"drops"`
	}
	if json.Unmarshal(payload, &sensor) != nil {
		return nil, ErrRepositoryUnavailable
	}
	status := "awaiting_heartbeat"
	supported := false
	if sensor.LastHeartbeat != "" {
		status, supported = "supported", true
		if !sensor.BTF || sensor.Drops > 0 {
			status, supported = "degraded", false
		}
	}
	coverage := map[string]any{"sensor_id": sensor.ID, "supported": supported, "status": status, "kernel": sensor.Kernel, "btf": sensor.BTF, "capabilities": sensor.Capabilities, "event_rate": sensor.EventRate, "drops": sensor.Drops}
	if sensor.LastHeartbeat != "" {
		coverage["last_heartbeat"] = sensor.LastHeartbeat
	}
	return coverage, nil
}

func workflowPolicyCapabilities() platformpolicy.Capabilities {
	return platformpolicy.Capabilities{Triggers: []string{"tool", "runtime", "network", "file", "credential"}, Fields: []string{"action", "resource", "principal_id", "agent_id", "session_id", "environment_id"}, Actions: []platformpolicy.Action{platformpolicy.ActionMonitor, platformpolicy.ActionBlock}}
}

func workflowTemplates() []map[string]any {
	values := securityagent.BuiltInTemplates()
	result := make([]map[string]any, len(values))
	for index, value := range values {
		result[index] = map[string]any{"id": deterministicProductID(index + 1), "name": value.Name, "version": value.Version, "trigger_kind": value.TriggerKind, "default_actions": value.DefaultActions, "verification_condition": value.VerificationCondition}
	}
	return result
}

func workflowActions() []map[string]any {
	return []map[string]any{
		{"key": "create_temporary_policy", "risk_class": "containment", "target_types": []string{"environment"}, "approval_floor": "operator", "reversible": true, "verification_kind": "policy_state"},
		{"key": "create_evidence_export", "risk_class": "low", "target_types": []string{"evidence"}, "approval_floor": "none", "reversible": true, "verification_kind": "export"},
		{"key": "run_test", "risk_class": "low", "target_types": []string{"test_definition"}, "approval_floor": "none", "reversible": true, "verification_kind": "test_run"},
	}
}

func exactWorkflowEnvironment(values []string, environmentID string) bool {
	if len(values) != 1 || values[0] != environmentID {
		return false
	}
	return true
}

func servedWorkflowActions(values []string) bool {
	served := map[string]struct{}{"create_temporary_policy": {}, "create_evidence_export": {}, "run_test": {}}
	for _, value := range values {
		if _, ok := served[value]; !ok {
			return false
		}
	}
	return true
}

func deterministicProductID(index int) string {
	return "pid_7000000" + strconv.Itoa(index) + "-0000-4000-8000-00000000000" + strconv.Itoa(index)
}

func newWorkflowProductID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return "pid_" + encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func parseVersion(value string) (int64, error) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 1 {
		return 0, errPreconditionRequired
	}
	return version, nil
}

func quoteVersion(value int64) string { return `"` + strconv.FormatInt(value, 10) + `"` }
func decodeEmptyInput(request *http.Request) error {
	var value map[string]any
	if decodeProductionJSON(request, &value) != nil || len(value) != 0 {
		return ErrRepositoryOperation
	}
	return nil
}

func writeJSONValue(writer http.ResponseWriter, request *http.Request, status int, value any, valueErr error) {
	if valueErr != nil {
		writeProductionError(writer, request, valueErr)
		return
	}
	payload, err := json.Marshal(value)
	writeProductionResponse(writer, request, status, payload, err)
}

func writeWorkflowMutationError(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, errPreconditionRequired) {
		writeProductionStatusError(writer, request, http.StatusPreconditionRequired, "precondition_required", "A current resource version is required", false)
		return
	}
	if errors.Is(err, ErrRepositoryConflict) {
		writeProductionStatusError(writer, request, http.StatusConflict, "version_conflict", "Resource version conflict", false)
		return
	}
	if errors.Is(err, ErrRepositoryAuthorization) {
		writeProductionStatusError(writer, request, http.StatusForbidden, "authorization_rejected", "Authorization rejected", false)
		return
	}
	writeProductionError(writer, request, err)
}

func writeProductionStatusError(writer http.ResponseWriter, request *http.Request, status int, code, message string, retryable bool) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": correlationIDFromContext(request.Context()), "retryable": retryable})
}
