package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

type OptionalEgressHTTPConfig struct {
	Repository *OptionalEgressRepository
	Authorizer RequestAuthorizer
	Sender     optionalegress.Sender
	Clock      func() time.Time
}

// WithOptionalEgressSurfaces keeps optional features unavailable until their
// registered SQL authority and production sender are explicitly configured.
// The retained risk and identity handlers remain the owners of other routes.
func WithOptionalEgressSurfaces(dependencies Dependencies, config *OptionalEgressHTTPConfig) (Dependencies, error) {
	if nilInterface(dependencies.Risk) || nilInterface(dependencies.Identity) {
		return Dependencies{}, ErrRepositoryConfiguration
	}
	if config != nil && (config.Repository == nil || nilInterface(config.Authorizer) || nilInterface(config.Sender) || config.Clock == nil) {
		return Dependencies{}, ErrRepositoryConfiguration
	}
	dependencies.Risk = &optionalEgressHTTPHandler{config: config, next: dependencies.Risk}
	dependencies.Identity = &optionalEgressHTTPHandler{config: config, next: dependencies.Identity}
	return dependencies, nil
}

type optionalEgressHTTPHandler struct {
	config *OptionalEgressHTTPConfig
	next   http.Handler
}

type optionalEgressScope struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
	Actor        string `json:"actor_id"`
}

type optionalExplanationInput struct {
	FindingID      string `json:"finding_id"`
	FindingVersion int64  `json:"finding_version"`
	IdempotencyKey string `json:"idempotency_key"`
}

type optionalFlowUpdate struct {
	FlowID          string `json:"flow_id"`
	Enabled         *bool  `json:"enabled"`
	ExpectedVersion int64  `json:"expected_version"`
	IdempotencyKey  string `json:"idempotency_key"`
}

var optionalIntentKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$`)

func decodeOptionalEgressJSON(request *http.Request, output any) error {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return ErrRepositoryOperation
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return ErrRepositoryOperation
	}
	// These DTOs are flat. Reject duplicate keys before unmarshalling so the
	// idempotency and finding identity cannot have two wire interpretations.
	keys := json.NewDecoder(bytes.NewReader(raw))
	first, err := keys.Token()
	if err != nil || first != json.Delim('{') {
		return ErrRepositoryOperation
	}
	seen := map[string]bool{}
	for keys.More() {
		key, err := keys.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return ErrRepositoryOperation
		}
		seen[name] = true
		var value json.RawMessage
		if keys.Decode(&value) != nil {
			return ErrRepositoryOperation
		}
	}
	if end, err := keys.Token(); err != nil || end != json.Delim('}') {
		return ErrRepositoryOperation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrRepositoryOperation
	}
	return nil
}

func (h *optionalEgressHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	route, ok := RoutedOperationFromRequest(request)
	if !ok || !stringIn(route.OperationID, "createAIExplanation", "getExternalDataFlows", "updateExternalDataFlows") || route.OperationID == "getExternalDataFlows" && h.config == nil {
		h.next.ServeHTTP(writer, request)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if h.config == nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	grant, ok := requestAuthorizationFromContext(request.Context())
	if !ok || grant.OperationID != route.OperationID || grant.Credential.Kind != CredentialBrowserSession || !validRequestIdentity(grant.Identity, false) || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrAuthorizationDenied)
		return
	}
	scope := optionalEgressScope{grant.Identity.Scope.OrganizationID().String(), grant.Identity.Scope.WorkspaceID().String(), grant.Identity.Scope.EnvironmentID().String(), grant.Identity.PrincipalID.String()}
	if route.OperationID == "getExternalDataFlows" {
		proof, err := authorizationProofJSON(grant)
		var result json.RawMessage
		if err == nil {
			err = h.config.Repository.query(request.Context(), proof, "catalog", scope, &result)
		}
		writeProductionResponse(writer, request, http.StatusOK, result, err)
		return
	}
	if route.OperationID == "updateExternalDataFlows" {
		var input optionalFlowUpdate
		if decodeOptionalEgressJSON(request, &input) != nil || input.Enabled == nil || !optionalIntentKey.MatchString(input.IdempotencyKey) || (len(request.Header.Values("Idempotency-Key")) != 1 || request.Header.Get("Idempotency-Key") != input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 100000000000000 || !stringIn(input.FlowID, "posthog", "openrouter", "remote-otlp") {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		proof, err := authorizationProofJSON(grant)
		command := struct {
			optionalEgressScope
			optionalFlowUpdate
		}{scope, input}
		var result json.RawMessage
		if err == nil {
			err = h.config.Repository.query(request.Context(), proof, "update", command, &result)
		}
		writeProductionResponse(writer, request, http.StatusOK, result, err)
		return
	}
	var input optionalExplanationInput
	if decodeOptionalEgressJSON(request, &input) != nil || !optionalIntentKey.MatchString(input.IdempotencyKey) || (len(request.Header.Values("Idempotency-Key")) != 1 || request.Header.Get("Idempotency-Key") != input.IdempotencyKey) || input.FindingVersion < 1 || input.FindingVersion > 1000000 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	if id, err := domain.ParseProductID(input.FindingID); err != nil || id.String() != input.FindingID {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	service, err := optionalegress.New(optionalegress.Config{Store: h.config.Repository, Authorizer: &optionalFindingAuthorizer{h.config.Authorizer, grant}, Sender: h.config.Sender, Now: h.config.Clock, NewRequestID: newWorkflowProductID})
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	intent := optionalegress.Intent{OrganizationID: scope.Organization, WorkspaceID: scope.Workspace, EnvironmentID: scope.Environment, ActorID: scope.Actor, FindingID: input.FindingID, FindingVersion: input.FindingVersion, IdempotencyKey: input.IdempotencyKey, Purpose: optionalegress.Purpose}
	result, err := service.Generate(request.Context(), intent)
	if err != nil {
		if errors.Is(err, optionalegress.ErrInvalid) {
			err = ErrRepositoryOperation
		}
		writeProductionError(writer, request, err)
		return
	}
	response := map[string]any{"request_id": result.Receipt.Binding.RequestID, "state": result.Receipt.State, "result_retained": false, "source": map[string]any{"finding_id": input.FindingID, "finding_version": input.FindingVersion}, "sent_fields": []string{"rule", "severity", "evidence_count"}}
	if result.Explanation != nil {
		response["explanation"], response["recommendation"] = result.Explanation.Explanation, result.Explanation.Recommendation
	}
	writeJSONValue(writer, request, http.StatusOK, response, nil)
}

type optionalFindingAuthorizer struct {
	authorizer RequestAuthorizer
	original   RequestAuthorization
}

func (a *optionalFindingAuthorizer) Authorize(ctx context.Context, intent optionalegress.Intent, phase optionalegress.Phase) (optionalegress.Proof, error) {
	if a == nil || !stringIn(string(phase), "replay", "source", "reserve", "dispatch") || intent.OrganizationID != a.original.Identity.Scope.OrganizationID().String() || intent.WorkspaceID != a.original.Identity.Scope.WorkspaceID().String() || intent.EnvironmentID != a.original.Identity.Scope.EnvironmentID().String() || intent.ActorID != a.original.Identity.PrincipalID.String() {
		return nil, ErrAuthorizationDenied
	}
	// A new current Check for the exact finding precedes EACH durable phase.
	// The initial environment permission never substitutes for finding access.
	grant, err := a.authorizer.Authorize(ctx, a.original.Identity, a.original.Credential, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": intent.FindingID}})
	if err != nil {
		return nil, err
	}
	if grant.Collection || len(grant.Allowed) != 1 || grant.Allowed[0].Kind != "finding" || grant.Allowed[0].ID != intent.FindingID || grant.Allowed[0].Version != intent.FindingVersion || grant.Allowed[0].Scope != a.original.Identity.Scope {
		return nil, ErrAuthorizationDenied
	}
	return authorizationProofJSON(grant)
}
