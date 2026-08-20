package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type inventoryHTTPHandler struct {
	repository InventoryRepository
	signingKey []byte
}

type inventoryCursorPayload struct {
	Version        int           `json:"v"`
	OrganizationID string        `json:"o"`
	WorkspaceID    string        `json:"w"`
	EnvironmentID  string        `json:"e"`
	Operation      string        `json:"op"`
	Kind           InventoryKind `json:"k"`
	ParentID       string        `json:"p"`
	Limit          int           `json:"l"`
	AfterKey       string        `json:"a"`
}

func newInventoryHTTPHandler(repository InventoryRepository, signingKey []byte) (*inventoryHTTPHandler, error) {
	if nilInterface(repository) || len(signingKey) < 32 || len(signingKey) > 4096 {
		return nil, ErrRepositoryConfiguration
	}
	return &inventoryHTTPHandler{repository: repository, signingKey: append([]byte(nil), signingKey...)}, nil
}

func (handler *inventoryHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "listAgents":
		handler.inventoryPage(writer, request, identity, routed, InventoryKindAgent)
	case "listTools":
		handler.inventoryPage(writer, request, identity, routed, InventoryKindTool)
	case "listIdentities":
		handler.inventoryPage(writer, request, identity, routed, InventoryKindIdentity)
	case "listRuntimes":
		handler.inventoryPage(writer, request, identity, routed, InventoryKindRuntime)
	case "getAgent":
		handler.inventoryDetail(writer, request, identity, routed, InventoryKindAgent)
	case "getTool":
		handler.inventoryDetail(writer, request, identity, routed, InventoryKindTool)
	case "getIdentity":
		handler.inventoryDetail(writer, request, identity, routed, InventoryKindIdentity)
	case "getRuntime":
		handler.inventoryDetail(writer, request, identity, routed, InventoryKindRuntime)
	case "getAsset":
		handler.inventoryDetail(writer, request, identity, routed, InventoryKindAsset)
	case "getAgentCapabilities", "getAgentRelationships", "listAgentSessions":
		handler.agentSubresourcePage(writer, request, identity, routed)
	case "getHomeSummary":
		handler.home(writer, request, identity)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *inventoryHTTPHandler) inventoryPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation, kind InventoryKind) {
	after, limit, ok := handler.pageQuery(request, identity.Scope, routed.OperationID, kind, "")
	if !ok {
		handler.writePageQueryError(writer, request)
		return
	}
	page, err := handler.repository.ListInventoryPage(request.Context(), identity.Scope, kind, after, limit)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	handler.writePage(writer, request, identity.Scope, routed.OperationID, kind, "", limit, page.Items, page.NextKey)
}

func (handler *inventoryHTTPHandler) inventoryDetail(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation, kind InventoryKind) {
	id, err := domain.ParseProductID(routed.PathParameters["id"])
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || err != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	detail, err := handler.repository.GetInventory(request.Context(), identity.Scope, id, kind)
	writeJSONValue(writer, request, http.StatusOK, detail, err)
}

func (handler *inventoryHTTPHandler) agentSubresourcePage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	id, err := domain.ParseProductID(routed.PathParameters["id"])
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	after, limit, ok := handler.pageQuery(request, identity.Scope, routed.OperationID, InventoryKindAgent, id.String())
	if !ok {
		handler.writePageQueryError(writer, request)
		return
	}
	switch routed.OperationID {
	case "getAgentCapabilities":
		page, pageErr := handler.repository.ListAgentCapabilitiesPage(request.Context(), identity.Scope, id, after, limit)
		if pageErr != nil {
			writeProductionError(writer, request, pageErr)
			return
		}
		handler.writePage(writer, request, identity.Scope, routed.OperationID, InventoryKindAgent, id.String(), limit, page.Items, page.NextKey)
	case "getAgentRelationships":
		page, pageErr := handler.repository.ListAgentRelationshipsPage(request.Context(), identity.Scope, id, after, limit)
		if pageErr != nil {
			writeProductionError(writer, request, pageErr)
			return
		}
		handler.writePage(writer, request, identity.Scope, routed.OperationID, InventoryKindAgent, id.String(), limit, page.Items, page.NextKey)
	case "listAgentSessions":
		page, pageErr := handler.repository.ListAgentSessionsPage(request.Context(), identity.Scope, id, after, limit)
		if pageErr != nil {
			writeProductionError(writer, request, pageErr)
			return
		}
		handler.writePage(writer, request, identity.Scope, routed.OperationID, InventoryKindAgent, id.String(), limit, page.Items, page.NextKey)
	}
}

func (handler *inventoryHTTPHandler) home(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	summary, err := handler.repository.GetHomeSummary(request.Context(), identity.Scope)
	writeJSONValue(writer, request, http.StatusOK, summary, err)
}

func (handler *inventoryHTTPHandler) pageQuery(request *http.Request, scope domain.Scope, operation string, kind InventoryKind, parentID string) (string, int, bool) {
	if request.Method != http.MethodGet {
		return "", 0, false
	}
	query, ok := exactWorkflowQuery(request.URL.RawQuery, map[string]int{"cursor": 512, "limit": 3})
	if !ok {
		return "", 0, false
	}
	limit, ok := workflowPageLimit(query)
	if !ok {
		return "", 0, false
	}
	after := ""
	if values, exists := query["cursor"]; exists {
		if len(values) != 1 || values[0] == "" {
			return "", 0, false
		}
		after, ok = handler.decodeCursor(values[0], scope, operation, kind, parentID, limit)
		if !ok {
			return "", 0, false
		}
	}
	return after, limit, true
}

func (handler *inventoryHTTPHandler) writePage(writer http.ResponseWriter, request *http.Request, scope domain.Scope, operation string, kind InventoryKind, parentID string, limit int, items any, nextKey string) {
	pageInfo := map[string]any{"next_cursor": nil, "has_more": false}
	if nextKey != "" {
		pageInfo["next_cursor"] = handler.encodeCursor(scope, operation, kind, parentID, limit, nextKey)
		pageInfo["has_more"] = true
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": items, "page_info": pageInfo}, nil)
}

func (handler *inventoryHTTPHandler) encodeCursor(scope domain.Scope, operation string, kind InventoryKind, parentID string, limit int, after string) string {
	payload, _ := json.Marshal(inventoryCursorPayload{Version: 1, OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), Operation: operation, Kind: kind, ParentID: parentID, Limit: limit, AfterKey: after})
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *inventoryHTTPHandler) decodeCursor(value string, scope domain.Scope, operation string, kind InventoryKind, parentID string, limit int) (string, bool) {
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
	var cursor inventoryCursorPayload
	if decodeStrictInventory(payload, &cursor) != nil || cursor.Version != 1 || cursor.OrganizationID != scope.OrganizationID().String() || cursor.WorkspaceID != scope.WorkspaceID().String() || cursor.EnvironmentID != scope.EnvironmentID().String() || cursor.Operation != operation || cursor.Kind != kind || cursor.ParentID != parentID || cursor.Limit != limit || !printableInventoryString(cursor.AfterKey, 1, 512, false) {
		return "", false
	}
	if parentID == "" && !validProductID(cursor.AfterKey) {
		return "", false
	}
	return cursor.AfterKey, true
}

func (handler *inventoryHTTPHandler) writePageQueryError(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Query().Get("cursor") != "" {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	writeProductionError(writer, request, ErrRepositoryOperation)
}
