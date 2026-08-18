package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumIdentityRequestBytes = 16 * 1024

type RequestAuthenticator func(*http.Request) (Principal, error)
type FreshAuthorizer func(context.Context, Principal) error
type HTTPOption func(*HTTPHandler) error

type HTTPHandler struct {
	store        *MemoryStore
	authenticate RequestAuthenticator
	generate     IDGenerator
	fallbackID   domain.ProductID
	connections  *ConnectionService
	fresh        FreshAuthorizer
}

func NewHTTPHandler(store *MemoryStore, authenticate RequestAuthenticator, generate IDGenerator, options ...HTTPOption) (*HTTPHandler, error) {
	if store == nil || authenticate == nil || generate == nil {
		return nil, ErrConfiguration
	}
	fallback, err := generate()
	if err != nil || !validProductID(fallback) {
		return nil, ErrConfiguration
	}
	handler := &HTTPHandler{store: store, authenticate: authenticate, generate: generate, fallbackID: fallback}
	for _, option := range options {
		if option == nil || option(handler) != nil {
			return nil, ErrConfiguration
		}
	}
	return handler, nil
}

func WithConnectionService(service *ConnectionService, fresh FreshAuthorizer) HTTPOption {
	return func(handler *HTTPHandler) error {
		if handler == nil || service == nil || service.adapter == nil || fresh == nil || handler.connections != nil || handler.fresh != nil {
			return ErrConfiguration
		}
		handler.connections = service
		handler.fresh = fresh
		return nil
	}
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.store == nil || handler.authenticate == nil || request == nil || request.URL == nil {
		http.Error(writer, "", http.StatusInternalServerError)
		return
	}
	principal, err := authenticateRequest(handler.authenticate, request)
	if err != nil || !principal.valid() {
		handler.writeError(writer, http.StatusUnauthorized, "authentication_required", "Authentication required", false)
		return
	}
	status, payload, resultErr := handler.dispatch(request, principal)
	if resultErr != nil {
		handler.writeMappedError(writer, resultErr)
		return
	}
	handler.writeJSON(writer, status, payload)
}

func (handler *HTTPHandler) dispatch(request *http.Request, principal Principal) (int, any, error) {
	path := request.URL.EscapedPath()
	if path != request.URL.Path || strings.HasSuffix(path, "/") {
		return 0, nil, ErrNotFound
	}
	switch {
	case path == "/api/v1/organization" && request.Method == http.MethodGet:
		return handler.getOrganization(request.Context(), principal)
	case path == "/api/v1/workspaces" && request.Method == http.MethodGet:
		return handler.listWorkspaces(request, principal)
	case path == "/api/v1/workspaces" && request.Method == http.MethodPost:
		return handler.createWorkspace(request, principal)
	case strings.HasPrefix(path, "/api/v1/workspaces/"):
		return handler.workspaceByID(request, principal, strings.TrimPrefix(path, "/api/v1/workspaces/"))
	case path == "/api/v1/environments" && request.Method == http.MethodGet:
		return handler.listEnvironments(request, principal)
	case path == "/api/v1/environments" && request.Method == http.MethodPost:
		return handler.createEnvironment(request, principal)
	case strings.HasPrefix(path, "/api/v1/environments/"):
		return handler.environmentByID(request, principal, strings.TrimPrefix(path, "/api/v1/environments/"))
	case path == "/api/v1/me" && request.Method == http.MethodGet:
		return handler.getCurrentPrincipal(request.Context(), principal)
	case path == "/api/v1/admin/members" && request.Method == http.MethodGet:
		return handler.listMembers(request, principal)
	case path == "/api/v1/admin/roles" && request.Method == http.MethodGet:
		return handler.listBuiltInRoles(request, principal)
	case path == "/api/v1/admin/sso-connections":
		return handler.ssoCollection(request, principal)
	case strings.HasPrefix(path, "/api/v1/admin/sso-connections/"):
		return handler.ssoByID(request, principal, strings.TrimPrefix(path, "/api/v1/admin/sso-connections/"))
	case path == "/api/v1/admin/scim-connections":
		return handler.scimCollection(request, principal)
	case strings.HasPrefix(path, "/api/v1/admin/scim-connections/"):
		return handler.scimByID(request, principal, strings.TrimPrefix(path, "/api/v1/admin/scim-connections/"))
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) ssoCollection(request *http.Request, principal Principal) (int, any, error) {
	if handler.connections == nil || !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	switch request.Method {
	case http.MethodGet:
		limit, offset, err := parsePageQuery(request, nil)
		if err != nil {
			return 0, nil, err
		}
		values, err := handler.connections.ListSSO(request.Context(), principal.organizationReference)
		items := make([]ssoConnectionResponse, len(values))
		for index, value := range values {
			items[index] = ssoConnectionJSON(value)
		}
		items, pageInfo, pageErr := paginate(items, limit, offset)
		return http.StatusOK, pageResponse[ssoConnectionResponse]{Items: items, PageInfo: pageInfo}, errors.Join(err, pageErr)
	case http.MethodPost:
		if err := handler.requireFresh(request.Context(), principal); err != nil {
			return 0, nil, err
		}
		var input ssoConnectionRequest
		if err := decodeIdentityRequest(request, &input); err != nil {
			return 0, nil, err
		}
		value, err := handler.connections.CreateSSO(request.Context(), principal.organizationReference, SSOConfig(input))
		response := ssoConnectionJSON(value)
		response.AuditCorrelationID, err = handler.auditCorrelationID(err)
		return http.StatusCreated, response, err
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) ssoByID(request *http.Request, principal Principal, suffix string) (int, any, error) {
	if handler.connections == nil || !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	isTest := strings.HasSuffix(suffix, "/test")
	reference := strings.TrimSuffix(suffix, "/test")
	if strings.Contains(reference, "/") || !validSSOReference(reference) || (isTest && request.Method != http.MethodPost) || (!isTest && request.Method != http.MethodDelete) {
		return 0, nil, ErrNotFound
	}
	if err := handler.requireFresh(request.Context(), principal); err != nil {
		return 0, nil, err
	}
	if isTest {
		err := handler.connections.TestSSO(request.Context(), principal.organizationReference, reference)
		correlation, err := handler.auditCorrelationID(err)
		return http.StatusOK, connectionTestResponse{Healthy: true, AuditCorrelationID: correlation}, err
	}
	err := handler.connections.DeleteSSO(request.Context(), principal.organizationReference, reference)
	correlation, err := handler.auditCorrelationID(err)
	return http.StatusOK, deletionResponse{ID: reference, AuditCorrelationID: correlation}, err
}

func (handler *HTTPHandler) scimCollection(request *http.Request, principal Principal) (int, any, error) {
	if handler.connections == nil || !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	switch request.Method {
	case http.MethodGet:
		limit, offset, err := parsePageQuery(request, nil)
		if err != nil {
			return 0, nil, err
		}
		values, err := handler.connections.ListSCIM(request.Context(), principal.organizationReference)
		items := make([]scimConnectionResponse, len(values))
		for index, value := range values {
			items[index] = scimConnectionJSON(value)
		}
		items, pageInfo, pageErr := paginate(items, limit, offset)
		return http.StatusOK, pageResponse[scimConnectionResponse]{Items: items, PageInfo: pageInfo}, errors.Join(err, pageErr)
	case http.MethodPost:
		if err := handler.requireFresh(request.Context(), principal); err != nil {
			return 0, nil, err
		}
		var input scimConnectionRequest
		if err := decodeIdentityRequest(request, &input); err != nil {
			return 0, nil, err
		}
		value, err := handler.connections.CreateSCIM(request.Context(), principal.organizationReference, SCIMConfig(input))
		response := scimCredentialJSON(value)
		response.AuditCorrelationID, err = handler.auditCorrelationID(err)
		return http.StatusCreated, response, err
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) scimByID(request *http.Request, principal Principal, reference string) (int, any, error) {
	if handler.connections == nil || !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	if request.Method != http.MethodDelete || strings.Contains(reference, "/") || !validSCIMReference(reference) {
		return 0, nil, ErrNotFound
	}
	if err := handler.requireFresh(request.Context(), principal); err != nil {
		return 0, nil, err
	}
	err := handler.connections.DeleteSCIM(request.Context(), principal.organizationReference, reference)
	correlation, err := handler.auditCorrelationID(err)
	return http.StatusOK, deletionResponse{ID: reference, AuditCorrelationID: correlation}, err
}

func (handler *HTTPHandler) requireFresh(ctx context.Context, principal Principal) (resultErr error) {
	if handler.fresh == nil {
		return ErrFreshAuthentication
	}
	defer func() {
		if recover() != nil {
			resultErr = ErrFreshAuthentication
		}
	}()
	if err := handler.fresh(ctx, principal); err != nil || ctx.Err() != nil {
		return ErrFreshAuthentication
	}
	return nil
}

func (handler *HTTPHandler) getOrganization(ctx context.Context, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionView) {
		return 0, nil, ErrForbidden
	}
	value, err := handler.store.GetOrganization(ctx, principal.organizationID)
	return http.StatusOK, organizationJSON(value), err
}

func (handler *HTTPHandler) listWorkspaces(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionView) {
		return 0, nil, ErrForbidden
	}
	limit, offset, err := parsePageQuery(request, nil)
	if err != nil {
		return 0, nil, err
	}
	values, err := handler.store.ListWorkspaces(request.Context(), principal.organizationID)
	items := make([]workspaceResponse, len(values))
	for index, value := range values {
		items[index] = workspaceJSON(value)
	}
	items, pageInfo, pageErr := paginate(items, limit, offset)
	return http.StatusOK, pageResponse[workspaceResponse]{Items: items, PageInfo: pageInfo}, errors.Join(err, pageErr)
}

func (handler *HTTPHandler) createWorkspace(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	var input nameRequest
	if err := decodeIdentityRequest(request, &input); err != nil {
		return 0, nil, ErrInvalidRecord
	}
	value, err := handler.store.CreateWorkspace(request.Context(), principal.organizationID, input.Name)
	response := workspaceJSON(value)
	response.AuditCorrelationID, err = handler.auditCorrelationID(err)
	return http.StatusCreated, response, err
}

func (handler *HTTPHandler) workspaceByID(request *http.Request, principal Principal, textID string) (int, any, error) {
	if strings.Contains(textID, "/") {
		return 0, nil, ErrNotFound
	}
	id, err := domain.ParseProductID(textID)
	if err != nil {
		return 0, nil, ErrInvalidRecord
	}
	switch request.Method {
	case http.MethodGet:
		if !roleAllows(principal.role, PermissionView) {
			return 0, nil, ErrForbidden
		}
		value, resultErr := handler.store.GetWorkspace(request.Context(), principal.organizationID, id)
		return http.StatusOK, workspaceJSON(value), resultErr
	case http.MethodPatch:
		if !roleAllows(principal.role, PermissionManageIdentity) {
			return 0, nil, ErrForbidden
		}
		var input nameRequest
		if err := decodeIdentityRequest(request, &input); err != nil {
			return 0, nil, ErrInvalidRecord
		}
		value, resultErr := handler.store.UpdateWorkspace(request.Context(), principal.organizationID, id, input.Name)
		response := workspaceJSON(value)
		response.AuditCorrelationID, resultErr = handler.auditCorrelationID(resultErr)
		return http.StatusOK, response, resultErr
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) listEnvironments(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionView) {
		return 0, nil, ErrForbidden
	}
	limit, offset, err := parsePageQuery(request, map[string]bool{"workspace_id": true})
	if err != nil {
		return 0, nil, err
	}
	workspaceID, err := domain.ParseProductID(request.URL.Query().Get("workspace_id"))
	if err != nil {
		return 0, nil, ErrInvalidRecord
	}
	values, err := handler.store.ListEnvironments(request.Context(), principal.organizationID, workspaceID)
	items := make([]environmentResponse, len(values))
	for index, value := range values {
		items[index] = environmentJSON(value)
	}
	items, pageInfo, pageErr := paginate(items, limit, offset)
	return http.StatusOK, pageResponse[environmentResponse]{Items: items, PageInfo: pageInfo}, errors.Join(err, pageErr)
}

func (handler *HTTPHandler) createEnvironment(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	var input environmentRequest
	if err := decodeIdentityRequest(request, &input); err != nil {
		return 0, nil, ErrInvalidRecord
	}
	workspaceID, err := domain.ParseProductID(input.WorkspaceID)
	if err != nil {
		return 0, nil, ErrInvalidRecord
	}
	value, err := handler.store.CreateEnvironment(request.Context(), principal.organizationID, workspaceID, input.Name)
	response := environmentJSON(value)
	response.AuditCorrelationID, err = handler.auditCorrelationID(err)
	return http.StatusCreated, response, err
}

func (handler *HTTPHandler) environmentByID(request *http.Request, principal Principal, textID string) (int, any, error) {
	if strings.Contains(textID, "/") {
		return 0, nil, ErrNotFound
	}
	id, err := domain.ParseProductID(textID)
	if err != nil {
		return 0, nil, ErrInvalidRecord
	}
	switch request.Method {
	case http.MethodGet:
		if !roleAllows(principal.role, PermissionView) {
			return 0, nil, ErrForbidden
		}
		value, resultErr := handler.store.GetEnvironment(request.Context(), principal.organizationID, id)
		return http.StatusOK, environmentJSON(value), resultErr
	case http.MethodPatch:
		if !roleAllows(principal.role, PermissionManageIdentity) {
			return 0, nil, ErrForbidden
		}
		var input nameRequest
		if err := decodeIdentityRequest(request, &input); err != nil {
			return 0, nil, ErrInvalidRecord
		}
		value, resultErr := handler.store.UpdateEnvironment(request.Context(), principal.organizationID, id, input.Name)
		response := environmentJSON(value)
		response.AuditCorrelationID, resultErr = handler.auditCorrelationID(resultErr)
		return http.StatusOK, response, resultErr
	default:
		return 0, nil, ErrNotFound
	}
}

func (handler *HTTPHandler) getCurrentPrincipal(ctx context.Context, principal Principal) (int, any, error) {
	value, err := handler.store.GetPrincipal(ctx, principal.organizationID, principal.id)
	return http.StatusOK, principalJSON(value), err
}

func (handler *HTTPHandler) listMembers(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	limit, offset, err := parsePageQuery(request, nil)
	if err != nil {
		return 0, nil, err
	}
	values, err := handler.store.ListPrincipals(request.Context(), principal.organizationID)
	items := make([]principalResponse, len(values))
	for index, value := range values {
		items[index] = principalJSON(value)
	}
	items, pageInfo, pageErr := paginate(items, limit, offset)
	return http.StatusOK, pageResponse[principalResponse]{Items: items, PageInfo: pageInfo}, errors.Join(err, pageErr)
}

func (handler *HTTPHandler) listBuiltInRoles(request *http.Request, principal Principal) (int, any, error) {
	if !roleAllows(principal.role, PermissionManageIdentity) {
		return 0, nil, ErrForbidden
	}
	limit, offset, err := parsePageQuery(request, nil)
	if err != nil {
		return 0, nil, err
	}
	roles := BuiltInRoles()
	names := make([]string, 0, len(roles))
	for role := range roles {
		names = append(names, string(role))
	}
	sort.Strings(names)
	items := make([]roleResponse, 0, len(names))
	for _, name := range names {
		permissions := roles[Role(name)]
		items = append(items, roleResponse{Role: name, Permissions: permissions})
	}
	items, pageInfo, err := paginate(items, limit, offset)
	return http.StatusOK, pageResponse[roleResponse]{Items: items, PageInfo: pageInfo}, err
}

func parsePageQuery(request *http.Request, required map[string]bool) (int, int, error) {
	if request == nil || request.URL == nil {
		return 0, 0, ErrInvalidRecord
	}
	query := request.URL.Query()
	for key, values := range query {
		if key != "limit" && key != "cursor" && !required[key] || len(values) != 1 {
			return 0, 0, ErrInvalidRecord
		}
	}
	for key := range required {
		if len(query[key]) != 1 || query.Get(key) == "" {
			return 0, 0, ErrInvalidRecord
		}
	}
	limit := 50
	if text := query.Get("limit"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 100 || strconv.Itoa(value) != text {
			return 0, 0, ErrInvalidRecord
		}
		limit = value
	}
	offset := 0
	if cursor := query.Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != cursor {
			return 0, 0, ErrInvalidRecord
		}
		value, err := strconv.Atoi(string(decoded))
		if err != nil || value < 1 || strconv.Itoa(value) != string(decoded) {
			return 0, 0, ErrInvalidRecord
		}
		offset = value
	}
	return limit, offset, nil
}

func paginate[T any](values []T, limit, offset int) ([]T, pageInfoResponse, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > len(values) {
		return nil, pageInfoResponse{}, ErrInvalidRecord
	}
	end := min(offset+limit, len(values))
	page := append([]T(nil), values[offset:end]...)
	if end == len(values) {
		return page, terminalPage(), nil
	}
	cursor := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	return page, pageInfoResponse{NextCursor: &cursor, HasMore: true}, nil
}

func (handler *HTTPHandler) auditCorrelationID(prior error) (string, error) {
	if prior != nil {
		return "", prior
	}
	id, err := handler.generate()
	if err != nil || !validProductID(id) {
		return "", ErrInvalidRecord
	}
	return id.String(), nil
}

func decodeIdentityRequest(request *http.Request, target any) error {
	if request == nil || request.Body == nil || request.Header.Get("Content-Type") != "application/json" || request.ContentLength > maximumIdentityRequestBytes {
		return ErrInvalidRecord
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maximumIdentityRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidRecord
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidRecord
	}
	return nil
}

func authenticateRequest(authenticate RequestAuthenticator, request *http.Request) (result Principal, resultErr error) {
	defer func() {
		if recover() != nil {
			result = Principal{}
			resultErr = ErrAuthentication
		}
	}()
	return authenticate(request)
}

func (handler *HTTPHandler) writeMappedError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		handler.writeError(writer, http.StatusForbidden, "forbidden", "Access forbidden", false)
	case errors.Is(err, ErrFreshAuthentication):
		handler.writeError(writer, http.StatusForbidden, "fresh_authentication_required", "Fresh authentication required", false)
	case errors.Is(err, ErrNotFound):
		handler.writeError(writer, http.StatusNotFound, "not_found", "Resource not found", false)
	case errors.Is(err, ErrConflict):
		handler.writeError(writer, http.StatusConflict, "conflict", "Resource conflict", false)
	default:
		handler.writeError(writer, http.StatusBadRequest, "invalid_request", "Request rejected", false)
	}
}

func (handler *HTTPHandler) writeError(writer http.ResponseWriter, status int, code, message string, retryable bool) {
	id := handler.fallbackID
	if candidate, err := handler.generate(); err == nil && validProductID(candidate) {
		id = candidate
	}
	productCode, _ := domain.ParseProductErrorCode(code)
	correlation, _ := domain.NewCorrelationID(id)
	envelope, _ := domain.NewProductErrorEnvelope(productCode, message, correlation, retryable)
	handler.writeJSON(writer, status, envelope)
}

func (handler *HTTPHandler) writeJSON(writer http.ResponseWriter, status int, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		http.Error(writer, "", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

type organizationResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

type workspaceResponse struct {
	ID                 string `json:"id"`
	OrganizationID     string `json:"organization_id"`
	Name               string `json:"name"`
	AuditCorrelationID string `json:"audit_correlation_id,omitempty"`
}

type environmentResponse struct {
	ID                 string `json:"id"`
	OrganizationID     string `json:"organization_id"`
	WorkspaceID        string `json:"workspace_id"`
	Name               string `json:"name"`
	AuditCorrelationID string `json:"audit_correlation_id,omitempty"`
}

type ssoConnectionResponse struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	DisplayName        string `json:"display_name"`
	Protocol           string `json:"protocol"`
	IdentityProvider   string `json:"identity_provider"`
	AuditCorrelationID string `json:"audit_correlation_id,omitempty"`
}

type scimConnectionResponse struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	DisplayName        string `json:"display_name"`
	IdentityProvider   string `json:"identity_provider"`
	BaseURL            string `json:"base_url"`
	BearerToken        string `json:"bearer_token,omitempty"`
	AuditCorrelationID string `json:"audit_correlation_id,omitempty"`
}

type deletionResponse struct {
	ID                 string `json:"id"`
	AuditCorrelationID string `json:"audit_correlation_id"`
}

type connectionTestResponse struct {
	Healthy            bool   `json:"healthy"`
	AuditCorrelationID string `json:"audit_correlation_id"`
}

type principalResponse struct {
	ID                    string `json:"id"`
	OrganizationID        string `json:"organization_id"`
	OrganizationReference string `json:"organization_reference"`
	MemberReference       string `json:"member_reference"`
	Role                  Role   `json:"role"`
	Active                bool   `json:"active"`
}

type roleResponse struct {
	Role        string       `json:"role"`
	Permissions []Permission `json:"permissions"`
}

type pageInfoResponse struct {
	NextCursor *string `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

type pageResponse[T any] struct {
	Items    []T              `json:"items"`
	PageInfo pageInfoResponse `json:"page_info"`
}

type nameRequest struct {
	Name string `json:"name"`
}

type environmentRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
}

type ssoConnectionRequest struct {
	DisplayName      string `json:"display_name"`
	Protocol         string `json:"protocol"`
	IdentityProvider string `json:"identity_provider"`
}

type scimConnectionRequest struct {
	DisplayName      string `json:"display_name"`
	IdentityProvider string `json:"identity_provider"`
}

func organizationJSON(value Organization) organizationResponse {
	return organizationResponse{ID: value.id.String(), Name: value.name, Domain: value.domain}
}

func workspaceJSON(value Workspace) workspaceResponse {
	return workspaceResponse{ID: value.id.String(), OrganizationID: value.organizationID.String(), Name: value.name}
}

func environmentJSON(value Environment) environmentResponse {
	return environmentResponse{
		ID: value.id.String(), OrganizationID: value.organizationID.String(), WorkspaceID: value.workspaceID.String(), Name: value.name,
	}
}

func principalJSON(value Principal) principalResponse {
	return principalResponse{
		ID: value.id.String(), OrganizationID: value.organizationID.String(), OrganizationReference: value.organizationReference,
		MemberReference: value.memberReference, Role: value.role, Active: value.active,
	}
}

func ssoConnectionJSON(value SSOConnection) ssoConnectionResponse {
	return ssoConnectionResponse{ID: value.reference, Status: value.status, DisplayName: value.displayName,
		Protocol: value.protocol, IdentityProvider: value.identityProvider}
}

func scimConnectionJSON(value SCIMConnection) scimConnectionResponse {
	return scimConnectionResponse{ID: value.reference, Status: value.status, DisplayName: value.displayName,
		IdentityProvider: value.identityProvider, BaseURL: value.baseURL}
}

func scimCredentialJSON(value SCIMCredential) scimConnectionResponse {
	response := scimConnectionJSON(value.Connection)
	response.BearerToken = value.bearerToken
	return response
}

func terminalPage() pageInfoResponse { return pageInfoResponse{NextCursor: nil, HasMore: false} }
