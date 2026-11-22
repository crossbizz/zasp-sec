package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var policyDecisionIDPattern = regexp.MustCompile(`^(?:pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|decision-[a-z0-9][a-z0-9-]{0,118})$`)

type PolicyActionHistory interface {
	SearchPolicyActions(context.Context, domain.Scope, string, int) ([]platformpolicy.ActionContext, error)
	Ready(context.Context) error
}

type PolicyDecisionHistory interface {
	ListPolicyDecisions(context.Context, domain.Scope, string, int) ([]platformpolicy.RuntimeDecision, error)
	Ready(context.Context) error
}

type PolicyPublicHTTPConfig struct {
	EvidenceDB JSONDatabase
	Workflows  workflowRepository
	History    PolicyActionHistory
	Decisions  PolicyDecisionHistory
}

type PolicyPublicHTTPHandler struct{ config PolicyPublicHTTPConfig }

func NewPolicyPublicHTTPHandler(config PolicyPublicHTTPConfig) (*PolicyPublicHTTPHandler, error) {
	if nilInterface(config.Workflows) || nilInterface(config.History) || nilInterface(config.Decisions) {
		return nil, ErrRepositoryConfiguration
	}
	return &PolicyPublicHTTPHandler{config: config}, nil
}

func (handler *PolicyPublicHTTPHandler) Ready(ctx context.Context) error {
	if handler == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	if err := handler.config.History.Ready(ctx); err != nil {
		return ErrRepositoryUnavailable
	}
	if err := handler.config.Decisions.Ready(ctx); err != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (handler *PolicyPublicHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if handler == nil || !identityOK || !routedOK || request == nil || request.URL == nil {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	if isSuggestionOperation(routed.OperationID) {
		handler.suggestions(writer, request, identity, routed)
		return
	}
	policyID := routed.PathParameters["id"]
	if !policyIDPattern.MatchString(policyID) {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	switch routed.OperationID {
	case "simulatePolicy":
		handler.simulate(writer, request, identity, policyID)
	case "listPolicyDecisions":
		handler.decisions(writer, request, identity, policyID)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *PolicyPublicHTTPHandler) simulate(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, policyID string) {
	var raw json.RawMessage
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || decodeProductionJSON(request, &raw) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	var input struct {
		SchemaVersion  int   `json:"schema_version"`
		PolicyRevision int64 `json:"policy_revision"`
		platformpolicy.ReplayWindow
	}
	legacy := len(raw) > 0 && raw[0] == '{' && exactJSONFields(raw)
	if !legacy && (!exactJSONFields(raw, "schema_version", "policy_revision", "agent_id", "from", "to") || json.Unmarshal(raw, &input) != nil || input.SchemaVersion != 2 || input.PolicyRevision <= 0 || !input.ReplayWindow.Valid() || input.To.After(time.Now())) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	value, err := handler.config.Workflows.GetWorkflow(request.Context(), identity.Scope, "policy", policyID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var policyValue platformpolicy.Policy
	if decodePolicyValue(value.Body, policyID, &policyValue) != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	var events []platformpolicy.ActionContext
	var truncated bool
	if legacy {
		events, err = handler.config.History.SearchPolicyActions(request.Context(), identity.Scope, policyValue.Trigger, 100)
	} else {
		if value.Version != input.PolicyRevision {
			writeProductionError(writer, request, ErrRepositoryConflict)
			return
		}
		reader, ok := handler.config.History.(interface {
			SearchReplayActions(context.Context, domain.Scope, string, platformpolicy.ReplayWindow) ([]platformpolicy.ActionContext, bool, error)
		})
		if !ok {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		events, truncated, err = reader.SearchReplayActions(request.Context(), identity.Scope, policyValue.Trigger, input.ReplayWindow)
	}
	if err != nil || len(events) > 100 || request.Context().Err() != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	for _, event := range events {
		normalized, normalizeErr := platformpolicy.NormalizeActionContext(event)
		if normalizeErr != nil || normalized.EnvironmentID != identity.Scope.EnvironmentID().String() || normalized.Action != policyValue.Trigger || !legacy && normalized.AgentID != input.AgentID {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
	}
	result := platformpolicy.SimulationResult{Examples: []string{}}
	if len(events) > 0 {
		store := platformpolicy.NewMemoryStore()
		if store.Create(request.Context(), policyValue, workflowPolicyCapabilities()) != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		result, err = store.Simulate(request.Context(), policyID, events)
		if err != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
	}
	response := map[string]any{"matches": result.Matches, "would_block": result.WouldBlock, "example_session_ids": result.Examples}
	if !legacy {
		response["replay"] = map[string]any{"policy_revision": value.Version, "from": input.From, "to": input.To, "agent_id": input.AgentID, "evaluated": len(events), "truncated": truncated, "coverage": "indexed_events_only"}
	}
	writeJSONValue(writer, request, http.StatusOK, response, nil)
}

func (handler *PolicyPublicHTTPHandler) decisions(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, policyID string) {
	if request.Method != http.MethodGet {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"limit": 3})
	if !ok {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	limit := 100
	if values, present := query["limit"]; present {
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > 100 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		limit = parsed
	}
	if _, err := handler.config.Workflows.GetWorkflow(request.Context(), identity.Scope, "policy", policyID); err != nil {
		writeProductionError(writer, request, err)
		return
	}
	values, err := handler.config.Decisions.ListPolicyDecisions(request.Context(), identity.Scope, policyID, limit)
	if err != nil || len(values) > limit || !validPolicyDecisions(values, identity.Scope, policyID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": values}, nil)
}

func decodePolicyValue(source json.RawMessage, policyID string, destination *platformpolicy.Policy) error {
	if len(source) < 2 || len(source) > 16*1024 || destination == nil {
		return ErrRepositoryUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF || destination.ID != policyID || platformpolicy.Validate(*destination, workflowPolicyCapabilities()) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func validPolicyDecisions(values []platformpolicy.RuntimeDecision, scope domain.Scope, policyID string) bool {
	previous := time.Time{}
	previousID := ""
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !policyDecisionIDPattern.MatchString(value.ID) || value.PolicyID != policyID || value.EnvironmentID != scope.EnvironmentID().String() || value.Result != "allow" && value.Result != "monitor" && value.Result != "block" || !boundedPolicyPublicText(value.CorrelationID, 128) || value.At.IsZero() || value.At.Location() != time.UTC || index > 0 && (value.At.After(previous) || value.At.Equal(previous) && value.ID <= previousID) {
			return false
		}
		if _, exists := seen[value.ID]; exists {
			return false
		}
		seen[value.ID] = struct{}{}
		previous = value.At
		previousID = value.ID
	}
	return true
}

func boundedPolicyPublicText(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
