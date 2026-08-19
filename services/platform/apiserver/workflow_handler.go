package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
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
	ListWorkflowPage(context.Context, domain.Scope, string, string, int) (WorkflowListPage, error)
	GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error)
	ReplayWorkflow(context.Context, RequestIdentity, string, string, json.RawMessage) (WorkflowMutationResult, bool, error)
	MutateWorkflow(context.Context, RequestIdentity, WorkflowMutation) (WorkflowMutationResult, error)
	ListWorkflowMutationReceipts(context.Context, RequestIdentity, int) ([]WorkflowMutationReceipt, error)
	AcknowledgeWorkflowMutationReceipt(context.Context, RequestIdentity, string) error
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
	catalog, err := platformintegration.NewCatalog(locallyCompleteWorkflowManifests())
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
	if routed.OperationID == "listWorkflowMutationReceipts" {
		handler.readMutationReceipts(writer, request, identity)
		return
	}
	if routed.OperationID == "listIntegrationCatalog" {
		query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"q": 128, "category": 63, "data_type": 63, "action": 63, "auth_mode": 63})
		if !ok {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		values, err := handler.catalog.SearchContext(request.Context(), platformintegration.CatalogFilter{
			Query: query.Get("q"), Category: query.Get("category"), DataType: query.Get("data_type"), Action: query.Get("action"), AuthMode: query.Get("auth_mode"),
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
	kind, list, parentField, parentID, ok := workflowReadTarget(routed)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	if list {
		if parentField != "" || parentID != "" {
			payload, err := handler.repository.ListWorkflows(request.Context(), identity.Scope, kind, parentField, parentID)
			writeProductionResponse(writer, request, http.StatusOK, payload, err)
			return
		}
		handler.readWorkflowPage(writer, request, identity, kind)
		return
	}
	value, err := handler.repository.GetWorkflow(request.Context(), identity.Scope, kind, routed.PathParameters["id"])
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(value.Version))
	writeProductionResponse(writer, request, http.StatusOK, value.Body, nil)
}

func (handler *workflowHTTPHandler) readMutationReceipts(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"limit": 3})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit := 20
	if values, present := query["limit"]; present {
		var err error
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 50 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
	}
	receipts, err := handler.repository.ListWorkflowMutationReceipts(request.Context(), identity, limit)
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": receipts}, err)
}

type workflowCursorPayload struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	Kind           string `json:"k"`
	AfterID        string `json:"a"`
}

func (handler *workflowHTTPHandler) readWorkflowPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, kind string) {
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit, ok := workflowPageLimit(query)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	afterID := ""
	if values, present := query["cursor"]; present {
		if len(values) != 1 {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		var valid bool
		afterID, valid = handler.decodeWorkflowCursor(values[0], identity.Scope, kind)
		if !valid {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
	}
	page, err := handler.repository.ListWorkflowPage(request.Context(), identity.Scope, kind, afterID, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	pageInfo := map[string]any{"next_cursor": nil, "has_more": false}
	if page.NextID != "" {
		pageInfo["next_cursor"] = handler.encodeWorkflowCursor(identity.Scope, kind, page.NextID)
		pageInfo["has_more"] = true
	}
	payload, err := json.Marshal(map[string]any{"items": page.Items, "page_info": pageInfo})
	writeProductionResponse(writer, request, http.StatusOK, payload, err)
}

func exactWorkflowQuery(raw string, allowed map[string]int) (url.Values, bool) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, false
	}
	for key, values := range query {
		maximum, declared := allowed[key]
		if !declared || len(values) != 1 || len(values[0]) > maximum {
			return nil, false
		}
	}
	return query, true
}

func workflowPageLimit(query url.Values) (int, bool) {
	values, present := query["limit"]
	if !present {
		return 50, true
	}
	if len(values) != 1 {
		return 0, false
	}
	limit, err := strconv.Atoi(values[0])
	return limit, err == nil && limit >= 1 && limit <= 100
}

func (handler *workflowHTTPHandler) encodeWorkflowCursor(scope domain.Scope, kind, afterID string) string {
	payload, _ := json.Marshal(workflowCursorPayload{Version: 1, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), Kind: kind, AfterID: afterID})
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *workflowHTTPHandler) decodeWorkflowCursor(value string, scope domain.Scope, kind string) (string, bool) {
	if len(value) < 2 || len(value) > 512 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size {
		return "", false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", false
	}
	var raw map[string]json.RawMessage
	var cursor workflowCursorPayload
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 6 || json.Unmarshal(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != scope.OrganizationID().String() || cursor.WorkspaceID != scope.WorkspaceID().String() || cursor.EnvironmentID != scope.EnvironmentID().String() || cursor.Kind != kind || !validWorkflowID(kind, cursor.AfterID) {
		return "", false
	}
	return cursor.AfterID, true
}

func (handler *workflowHTTPHandler) mutate(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	if routed.OperationID == "acknowledgeWorkflowMutationReceipt" {
		if decodeEmptyInput(request) != nil {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		err := handler.repository.AcknowledgeWorkflowMutationReceipt(request.Context(), identity, routed.PathParameters["id"])
		if err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) {
		writeProductionStatusError(writer, request, http.StatusBadRequest, "operation_rejected", "Operation rejected", false)
		return
	}
	intent, _, err := canonicalWorkflowIntent(request, routed)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	result, replayed, err := handler.repository.ReplayWorkflow(request.Context(), identity, routed.OperationID, idempotencyKey, intent)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	if replayed {
		_, _, status, ok := workflowMutationTarget(routed.OperationID)
		if !ok {
			writeWorkflowMutationError(writer, request, ErrRepositoryNotFound)
			return
		}
		handler.writeMutationResult(writer, request, identity, routed, idempotencyKey, intent, result, status, workflowResponseKind(routed, identity.Scope, intent))
		return
	}
	correlationID := correlationIDFromContext(request.Context())
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	receiptID := ""
	if identity.CredentialKind == CredentialBrowserSession {
		receiptID, err = newWorkflowProductID()
		if err != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
	}
	mutation, status, responseKind, err := handler.buildMutation(request, identity, routed, idempotencyKey, auditID, correlationID)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	mutation.ReceiptID = receiptID
	mutation.Intent = intent
	result, err = handler.repository.MutateWorkflow(request.Context(), identity, mutation)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	handler.writeMutationResult(writer, request, identity, routed, idempotencyKey, intent, result, status, responseKind)
}

func (handler *workflowHTTPHandler) writeMutationResult(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation, idempotencyKey string, intent json.RawMessage, result WorkflowMutationResult, status int, responseKind string) {
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writer.Header().Set("X-Audit-ID", result.AuditID)
	if result.ReceiptID != "" {
		writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	}
	if status == http.StatusNoContent {
		writer.WriteHeader(status)
		return
	}
	payload := result.Body
	var err error
	if strings.HasPrefix(responseKind, "policy_rollout:") {
		parts := strings.SplitN(responseKind, ":", 3)
		payload, err = json.Marshal(map[string]any{"policy_id": routed.PathParameters["id"], "state": parts[1], "target_id": parts[2]})
	}
	writeProductionResponse(writer, request, status, payload, err)
}

func canonicalWorkflowIntent(request *http.Request, routed RoutedOperation) (json.RawMessage, int64, error) {
	_, action, _, ok := workflowMutationTarget(routed.OperationID)
	if !ok {
		return nil, 0, ErrRepositoryNotFound
	}
	expected := int64(0)
	if action != "create" {
		var err error
		expected, err = parseVersion(request.Header.Get("If-Match"))
		if err != nil {
			return nil, 0, errPreconditionRequired
		}
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		return nil, 0, ErrRepositoryOperation
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte(`{}`)
	}
	var decoded map[string]any
	if json.Unmarshal(body, &decoded) != nil || decoded == nil {
		return nil, 0, ErrRepositoryOperation
	}
	canonicalBody, err := json.Marshal(decoded)
	if err != nil {
		return nil, 0, ErrRepositoryOperation
	}
	request.Body = io.NopCloser(bytes.NewReader(canonicalBody))
	intent, err := json.Marshal(map[string]any{"resource_id": routed.PathParameters["id"], "expected_version": expected, "body": decoded})
	if err != nil {
		return nil, 0, ErrRepositoryOperation
	}
	return intent, expected, nil
}

func workflowResponseKind(routed RoutedOperation, scope domain.Scope, intent json.RawMessage) string {
	switch routed.OperationID {
	case "rolloutPolicy":
		var value struct {
			Body struct {
				State string `json:"state"`
			} `json:"body"`
		}
		if json.Unmarshal(intent, &value) != nil || value.Body.State != "monitor" && value.Body.State != "enforced" {
			return "body"
		}
		return "policy_rollout:" + value.Body.State + ":" + scope.EnvironmentID().String()
	case "disablePolicy":
		return "policy_rollout:disabled:" + scope.EnvironmentID().String()
	default:
		return "body"
	}
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
		if routed.OperationID == "createPolicy" && value.Rollout != string(platformpolicy.RolloutDraft) {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		if id == "" {
			id = value.ID
		}
		if id != value.ID {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		body, _ = json.Marshal(value)
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
			if decodeProductionJSON(request, &input) != nil || (input.State != "monitor" && input.State != "enforced") || input.TargetID != identity.Scope.EnvironmentID().String() {
				return WorkflowMutation{}, 0, "", ErrRepositoryOperation
			}
			state, target = input.State, input.TargetID
		} else if decodeEmptyInput(request) != nil {
			return WorkflowMutation{}, 0, "", ErrRepositoryOperation
		}
		current, currentOK := policyValue["rollout"].(string)
		validTransition := routed.OperationID == "rolloutPolicy" && (current == "draft" && state == "monitor" || current == "monitor" && state == "enforced") ||
			routed.OperationID == "disablePolicy" && (current == "monitor" || current == "enforced")
		if !currentOK || !validTransition {
			return WorkflowMutation{}, 0, "", ErrRepositoryConflict
		}
		policyValue["rollout"] = state
		policyValue["_target_environment_id"] = target
		body, _ = json.Marshal(policyValue)
		responseKind = "policy_rollout:" + state + ":" + target
	case "deletePolicy", "deleteIntegration", "deleteSecurityAgent":
		body = json.RawMessage(`{}`)
	case "createIntegration", "updateIntegration":
		body, id, err = handler.integrationBody(request, identity.Scope, id, idempotencyKey, routed.OperationID == "createIntegration")
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
	case "createSecurityAgent", "updateSecurityAgent":
		if routed.OperationID == "createSecurityAgent" && id == "" {
			id = handler.idempotentProductID(identity.Scope, routed.OperationID, idempotencyKey)
		}
		body, id, err = securityAgentBody(request, identity.Scope, id, routed.OperationID == "createSecurityAgent")
		if err != nil {
			return WorkflowMutation{}, 0, "", err
		}
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
	case "listIntegrations":
		return "integration", true, "", "", true
	case "getIntegration":
		return "integration", false, "", "", true
	case "listSecurityAgents":
		return "security_agent", true, "", "", true
	case "getSecurityAgent":
		return "security_agent", false, "", "", true
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
	case "rolloutPolicy", "disablePolicy":
		return "policy", "update", http.StatusOK, true
	case "createIntegration":
		return "integration", "create", http.StatusCreated, true
	case "updateIntegration":
		return "integration", "update", http.StatusOK, true
	case "deleteIntegration":
		return "integration", "delete", http.StatusNoContent, true
	case "createSecurityAgent":
		return "security_agent", "create", http.StatusCreated, true
	case "updateSecurityAgent":
		return "security_agent", "update", http.StatusOK, true
	case "deleteSecurityAgent":
		return "security_agent", "delete", http.StatusNoContent, true
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
		current = map[string]any{"id": id, "connector_key": input.ConnectorKey, "status": "configured", "created_at": now}
	}
	current["name"], current["configuration"], current["updated_at"] = input.Name, input.Configuration, now
	body, _ := json.Marshal(current)
	return body, id, nil
}

func securityAgentBody(request *http.Request, scope domain.Scope, id string, create bool) (json.RawMessage, string, error) {
	var input struct {
		ID                     *string  `json:"id"`
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
	if create {
		if input.ID != nil {
			return nil, "", ErrRepositoryOperation
		}
	} else if input.ID == nil || *input.ID != id {
		return nil, "", ErrRepositoryOperation
	}
	value := securityagent.SecurityAgent{ID: id, OrganizationID: scope.OrganizationID().String(), Name: input.Name, Trigger: securityagent.Trigger{Kind: input.TriggerKind, Source: input.TriggerSource}, Scope: securityagent.Scope{OrganizationID: scope.OrganizationID().String(), EnvironmentIDs: input.EnvironmentIDs}, Autonomy: securityagent.Autonomy(input.Autonomy), Limits: securityagent.RunLimits{MaxSteps: input.MaxSteps, MaxDuration: time.Duration(input.MaxDurationSeconds) * time.Second, TemporaryPolicyTTL: time.Duration(input.TemporaryPolicySeconds) * time.Second, MaxAITokens: input.AITokenBudget, MaxConcurrent: input.ConcurrencyLimit}, AllowedActions: input.AllowedActions, Verification: securityagent.Verification{Kind: input.VerificationKind}, DefinitionVersion: input.DefinitionVersion, Enabled: input.Enabled}
	if securityagent.ValidateAgent(value) != nil || !exactWorkflowEnvironment(input.EnvironmentIDs, scope.EnvironmentID().String()) || !servedWorkflowActions(input.AllowedActions) {
		return nil, "", ErrRepositoryOperation
	}
	body, _ := json.Marshal(map[string]any{"id": id, "name": input.Name, "trigger_kind": input.TriggerKind, "trigger_source": input.TriggerSource, "environment_ids": input.EnvironmentIDs, "autonomy": input.Autonomy, "max_steps": input.MaxSteps, "max_duration_seconds": input.MaxDurationSeconds, "temporary_policy_seconds": input.TemporaryPolicySeconds, "ai_token_budget": input.AITokenBudget, "concurrency_limit": input.ConcurrencyLimit, "allowed_actions": input.AllowedActions, "verification_kind": input.VerificationKind, "definition_version": input.DefinitionVersion, "enabled": input.Enabled})
	return body, id, nil
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

func workflowPolicyCapabilities() platformpolicy.Capabilities {
	return platformpolicy.Capabilities{Triggers: []string{"tool", "runtime", "network", "file", "credential"}, Fields: []string{"action", "resource", "principal_id", "agent_id", "session_id", "environment_id"}, Actions: []platformpolicy.Action{platformpolicy.ActionMonitor, platformpolicy.ActionBlock}}
}

func workflowTemplates() []map[string]any {
	values := securityagent.BuiltInTemplates()
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		if !servedWorkflowActions(value.DefaultActions) {
			continue
		}
		result = append(result, map[string]any{"id": deterministicProductID(index + 1), "name": value.Name, "version": value.Version, "trigger_kind": value.TriggerKind, "default_actions": value.DefaultActions, "verification_condition": value.VerificationCondition})
	}
	return result
}

func locallyCompleteWorkflowManifests() []platformintegration.ConnectorManifest {
	values := platformintegration.BuiltinManifests()
	result := make([]platformintegration.ConnectorManifest, 0, 1)
	for _, value := range values {
		if value.Key == "generic-webhook" {
			value.Description = "Store one scoped HTTPS webhook configuration for a future delivery adapter."
			value.DataTypes = []string{"configuration"}
			value.Actions = []string{"store_configuration"}
			value.AuthMode = "secret_reference"
			value.AccessGuidance = "Save only an HTTPS destination and an opaque product secret reference."
			value.TestSemantics = "Validate and durably persist the local configuration without contacting the destination."
			result = append(result, value)
		}
	}
	return result
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
