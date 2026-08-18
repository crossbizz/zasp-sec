package reconciliation

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const inventoryMaximumRequestBytes = 16 * 1024
const inventoryFallbackCorrelationID = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"

type InventoryAuthorizer func(*http.Request) (domain.Scope, error)

type InventoryHTTPHandler struct {
	service   *InventoryService
	authorize InventoryAuthorizer
	now       func() time.Time
}

func NewInventoryHTTPHandler(service *InventoryService, authorize InventoryAuthorizer, now func() time.Time) (*InventoryHTTPHandler, error) {
	if !service.usable() || authorize == nil || now == nil {
		return nil, ErrInventoryConfiguration
	}
	return &InventoryHTTPHandler{service: service, authorize: authorize, now: now}, nil
}

func (handler *InventoryHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || !handler.service.usable() || request == nil || request.URL == nil {
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

func (handler *InventoryHTTPHandler) dispatch(request *http.Request, scope domain.Scope) (int, any, error) {
	path := request.URL.EscapedPath()
	if path != request.URL.Path || strings.HasSuffix(path, "/") || len(request.URL.Query()) != 0 {
		return 0, nil, ErrInventoryInvalid
	}
	collections := map[string]Kind{"/api/v1/agents": KindAgent, "/api/v1/tools": KindTool, "/api/v1/identities": KindIdentity, "/api/v1/runtimes": KindRuntime}
	if kind, ok := collections[path]; ok {
		if request.Method != http.MethodGet {
			return 0, nil, ErrInventoryNotFound
		}
		values, err := handler.service.List(request.Context(), scope, kind)
		return http.StatusOK, map[string]any{"items": inventoryAssets(values)}, err
	}
	resources := []struct {
		prefix string
		kind   Kind
	}{{"/api/v1/agents/", KindAgent}, {"/api/v1/tools/", KindTool}, {"/api/v1/identities/", KindIdentity}, {"/api/v1/runtimes/", KindRuntime}, {"/api/v1/assets/", KindAsset}}
	for _, resource := range resources {
		if strings.HasPrefix(path, resource.prefix) {
			return handler.resource(request, scope, resource.kind, strings.TrimPrefix(path, resource.prefix))
		}
	}
	return 0, nil, ErrInventoryNotFound
}

func (handler *InventoryHTTPHandler) resource(request *http.Request, scope domain.Scope, kind Kind, tail string) (int, any, error) {
	parts := strings.Split(tail, "/")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return 0, nil, ErrInventoryNotFound
	}
	id, err := domain.ParseProductID(parts[0])
	if err != nil {
		return 0, nil, ErrInventoryInvalid
	}
	if len(parts) == 1 {
		if kind == KindAgent && request.Method == http.MethodPatch {
			var input ownershipJSON
			if err := decodeInventoryRequest(request, &input); err != nil {
				return 0, nil, err
			}
			value, audit, err := handler.service.UpdateAgent(request.Context(), scope, id, input.Owner, input.Team, input.Tags, handler.now())
			return http.StatusOK, map[string]any{"agent": inventoryAsset(value), "audit_id": audit.ID.String()}, err
		}
		if request.Method != http.MethodGet {
			return 0, nil, ErrInventoryNotFound
		}
		value, err := handler.service.Get(request.Context(), scope, id, kind)
		return http.StatusOK, inventoryAsset(value), err
	}
	if kind != KindAgent || request.Method != http.MethodGet {
		return 0, nil, ErrInventoryNotFound
	}
	switch parts[1] {
	case "capabilities":
		values, err := handler.service.Capabilities(request.Context(), scope, id)
		return http.StatusOK, map[string]any{"items": inventoryCapabilities(values)}, err
	case "relationships":
		values, err := handler.service.Relationships(request.Context(), scope, id)
		return http.StatusOK, map[string]any{"items": inventoryRelationships(values)}, err
	case "sessions":
		values, err := handler.service.Sessions(request.Context(), scope, id)
		return http.StatusOK, map[string]any{"items": inventorySessions(values)}, err
	default:
		return 0, nil, ErrInventoryNotFound
	}
}

type ownershipJSON struct {
	Owner string   `json:"owner"`
	Team  string   `json:"team"`
	Tags  []string `json:"tags"`
}

func inventoryAsset(value Asset) map[string]any {
	result := map[string]any{"id": value.ID.String(), "name": value.Name, "kind": string(value.Kind), "owner": value.Owner, "team": value.Team, "tags": append([]string(nil), value.Tags...), "evidence_id": value.EvidenceID.String(), "first_seen": value.FirstSeen.Format(time.RFC3339Nano), "last_seen": value.LastSeen.Format(time.RFC3339Nano)}
	if value.Kind == KindIdentity {
		result["credential_reference"], result["credential_fingerprint"] = value.CredentialReference, value.CredentialFingerprint
	}
	if value.Kind == KindRuntime {
		result["workload_id"], result["sandbox_id"], result["isolation"] = value.WorkloadID, value.SandboxID, value.Isolation
	}
	return result
}
func inventoryAssets(values []Asset) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		result[index] = inventoryAsset(value)
	}
	return result
}
func inventoryCapabilities(values []Capability) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		evidence := make([]string, len(value.EvidenceIDs))
		for evidenceIndex, id := range value.EvidenceIDs {
			evidence[evidenceIndex] = id.String()
		}
		result[index] = map[string]any{"agent_id": value.AgentID.String(), "target_id": value.TargetID.String(), "target_kind": string(value.TargetKind), "category": string(value.Category), "outcome": value.Outcome, "state": string(value.State), "reachable": value.Reachable, "evidence_ids": evidence}
	}
	return result
}
func inventoryRelationships(values []Relationship) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		result[index] = map[string]any{"from_id": value.From.String(), "to_id": value.To.String(), "type": value.Type, "evidence_id": value.EvidenceID.String()}
	}
	return result
}
func inventorySessions(values []AgentSession) []map[string]any {
	result := make([]map[string]any, len(values))
	for index, value := range values {
		result[index] = map[string]any{"id": value.ID.String(), "agent_id": value.AgentID.String(), "started_at": value.StartedAt.Format(time.RFC3339Nano)}
	}
	return result
}
func decodeInventoryRequest(request *http.Request, target any) error {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return ErrInventoryInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, inventoryMaximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInventoryInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInventoryInvalid
	}
	return nil
}
func inventoryAuthorize(authorize InventoryAuthorizer, request *http.Request) (scope domain.Scope, err error) {
	defer func() {
		if recover() != nil {
			scope, err = domain.Scope{}, ErrInventoryForbidden
		}
	}()
	return authorize(request)
}
func writeInventoryError(writer http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, "operation_rejected", "Operation rejected"
	switch {
	case errors.Is(err, ErrInventoryForbidden):
		status, code, message = http.StatusForbidden, "authorization_rejected", "Authorization rejected"
	case errors.Is(err, ErrInventoryNotFound):
		status, code, message = http.StatusNotFound, "not_found", "Inventory resource not found"
	case errors.Is(err, ErrInventoryInvalid):
		status, code, message = http.StatusBadRequest, "invalid_request", "Request rejected"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": inventoryFallbackCorrelationID, "retryable": false})
}
