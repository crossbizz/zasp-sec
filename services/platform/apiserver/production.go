package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type CallbackProvider interface {
	Complete(context.Context, string, string) (SessionGrant, error)
	Ready(context.Context) error
}

// IdentityLiveVerifier is deliberately separate from CallbackProvider.Ready:
// Ready validates local configuration, while VerifyIdentityProvider performs a
// bounded remote probe. A configured provider must not be reported healthy
// unless it implements this boundary and the probe succeeds.
type IdentityLiveVerifier interface {
	VerifyIdentityProvider(context.Context) error
}
type CallbackProviderFunc func(context.Context, string, string) (SessionGrant, error)

func (function CallbackProviderFunc) Complete(ctx context.Context, code, state string) (SessionGrant, error) {
	return function(ctx, code, state)
}

func (function CallbackProviderFunc) Ready(context.Context) error { return nil }

type SessionGrant struct {
	PrincipalID domain.ProductID
	Scope       domain.Scope
	Permissions []string
	ExpiresAt   time.Time
	ReturnTo    string
}

type CookiePolicy struct {
	Secure                 bool
	WorkflowSigningKey     []byte
	TokenRevealKey         []byte
	Clock                  func() time.Time
	BuildVersion           string
	DeploymentMode         string
	OrganizationID         string
	ConnectorCapabilities  ConnectorCapabilities
	DiscoveryParserVersion string
	DiscoveryToolVersion   string
}

type sessionRepository interface {
	Authenticate(context.Context, Credential) (RequestIdentity, error)
	Bootstrap(context.Context, RequestIdentity) (json.RawMessage, error)
	CreateSession(context.Context, SessionGrant) (string, error)
	Revoke(context.Context, RequestIdentity, string) error
	ListScopes(context.Context, RequestIdentity) (json.RawMessage, error)
	SwitchScope(context.Context, RequestIdentity, string, domain.Scope) (RequestIdentity, error)
}

type coreRepository interface {
	Read(context.Context, domain.Scope, string) (json.RawMessage, error)
}

func NewProductionHandlers(repository *PostgresRepository, provider CallbackProvider, connector http.Handler, cookie CookiePolicy) (Dependencies, Authenticator, error) {
	if repository == nil || nilInterface(repository.database) || nilInterface(provider) || nilInterface(connector) || len(cookie.TokenRevealKey) != 32 {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	now := cookie.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	cookie.Clock = now
	pinnedOrganization, err := deploymentOrganization(cookie.DeploymentMode, cookie.OrganizationID)
	if err != nil {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	workflowCapabilities := cookie.ConnectorCapabilities
	if nilInterface(workflowCapabilities) {
		workflowCapabilities = defaultWorkflowConnectorCapabilities()
	}
	workflow, err := newWorkflowHTTPHandler(repository, cookie.WorkflowSigningKey, cookie.Clock, workflowCapabilities)
	if err != nil {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	workflowSurface := http.Handler(workflow)
	if isDiscoveryExecutionSchema(repository.schema) {
		if !executionVersionPattern.MatchString(cookie.DiscoveryParserVersion) || !executionVersionPattern.MatchString(cookie.DiscoveryToolVersion) {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
		discoveryRepository, discoveryErr := NewDiscoveryRepositoryForAuthority(repository.database, DiscoveryDatabaseAuthorityAPI)
		if discoveryErr != nil {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
		discoveryHandler, discoveryErr := NewDiscoveryPublicHTTPHandler(discoveryRepository, cookie.WorkflowSigningKey, DiscoveryPublicHandlerConfig{ParserVersion: cookie.DiscoveryParserVersion, ToolVersion: cookie.DiscoveryToolVersion, NewProductID: newWorkflowProductID})
		if discoveryErr != nil {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
		workflowSurface, discoveryErr = NewDiscoveryWorkflowSurface(workflow, discoveryHandler)
		if discoveryErr != nil {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
	}
	inventorySurface := http.Handler(&coreHTTPHandler{repository: repository, boundary: inventoryDependency})
	if isTypedInventorySchema(repository.schema) {
		inventoryRepository, inventoryErr := NewPostgresInventoryRepository(repository.database)
		if inventoryErr != nil {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
		inventoryHandler, inventoryErr := newInventoryHTTPHandler(inventoryRepository, cookie.WorkflowSigningKey)
		if inventoryErr != nil {
			return Dependencies{}, nil, ErrRepositoryConfiguration
		}
		inventorySurface = inventoryHandler
	}
	risk, err := newRiskHTTPHandler(repository, cookie.WorkflowSigningKey, cookie.Clock)
	if err != nil {
		return Dependencies{}, nil, ErrRepositoryConfiguration
	}
	session := &sessionHTTPHandler{repository: repository, provider: provider, cookie: cookie, deploymentMode: cookie.DeploymentMode, organizationID: pinnedOrganization}
	version := cookie.BuildVersion
	if version == "" {
		version = "dev"
	}
	return Dependencies{
		Session:   session,
		Identity:  &identityHTTPHandler{repository: repository, administration: repository, provider: provider, signingKey: append([]byte(nil), cookie.WorkflowSigningKey...), tokenRevealKey: append([]byte(nil), cookie.TokenRevealKey...), now: cookie.Clock, version: version},
		Inventory: inventorySurface,
		Risk:      risk,
		Workflow:  workflowSurface,
		Connector: connector,
	}, mustDeploymentAuthenticator(repository.Authenticate, cookie.DeploymentMode, pinnedOrganization), nil
}

func deploymentOrganization(mode, value string) (domain.ProductID, error) {
	if mode == "saas" && value == "" {
		return domain.ProductID{}, nil
	}
	if mode != "single_tenant" {
		return domain.ProductID{}, ErrRepositoryConfiguration
	}
	organization, err := domain.ParseProductID(value)
	if err != nil {
		return domain.ProductID{}, ErrRepositoryConfiguration
	}
	return organization, nil
}

func deploymentAuthenticator(authenticate Authenticator, mode string, organization domain.ProductID) (Authenticator, error) {
	if authenticate == nil || mode != "saas" && mode != "single_tenant" || mode == "saas" && !organization.IsZero() || mode == "single_tenant" && organization.IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return func(ctx context.Context, credential Credential) (RequestIdentity, error) {
		identity, err := authenticate(ctx, credential)
		if err != nil || mode == "single_tenant" && identity.Scope.OrganizationID() != organization {
			return RequestIdentity{}, ErrRepositoryAuthentication
		}
		return identity, nil
	}, nil
}

func mustDeploymentAuthenticator(authenticate Authenticator, mode string, organization domain.ProductID) Authenticator {
	wrapped, _ := deploymentAuthenticator(authenticate, mode, organization)
	return wrapped
}

type sessionHTTPHandler struct {
	repository     sessionRepository
	provider       CallbackProvider
	cookie         CookiePolicy
	deploymentMode string
	organizationID domain.ProductID
}

func (handler *sessionHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/api/v1/session/start":
		starter, ok := handler.provider.(IdentityStarter)
		returnTo := request.URL.Query().Get("return_to")
		if !ok || !validReturnPath(returnTo) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		target, err := starter.Start(request.Context(), returnTo)
		if err != nil {
			writeProductionError(writer, request, err)
			return
		}
		http.Redirect(writer, request, target, http.StatusFound)
	case "/api/v1/session/bootstrap":
		identity, ok := IdentityFromRequest(request)
		if !ok || identity.CredentialKind != CredentialBrowserSession || !validRequestIdentity(identity, true) {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		payload, err := handler.repository.Bootstrap(request.Context(), identity)
		if err == nil {
			payload, err = authorizedBootstrap(payload, identity)
		}
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
	case "/api/v1/session/callback":
		var input struct {
			ProviderToken string `json:"provider_token"`
			State         string `json:"state"`
		}
		if decodeProductionJSON(request, &input) != nil || input.ProviderToken == "" || len(input.ProviderToken) > 4096 || len(input.State) < 32 || len(input.State) > 512 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		grant, err := handler.provider.Complete(request.Context(), input.ProviderToken, input.State)
		if err != nil || handler.deploymentMode == "single_tenant" && grant.Scope.OrganizationID() != handler.organizationID {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		if !validReturnPath(grant.ReturnTo) {
			grant.ReturnTo = "/"
		}
		token, err := handler.repository.CreateSession(request.Context(), grant)
		if err != nil || token == "" {
			writeProductionError(writer, request, err)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Value: token, Path: "/", Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		payload, marshalErr := json.Marshal(map[string]string{"return_to": grant.ReturnTo})
		if marshalErr != nil {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		writeProductionResponse(writer, request, http.StatusOK, payload, nil)
	case "/api/v1/session/sign-out":
		identity, ok := IdentityFromRequest(request)
		cookie, cookieErr := request.Cookie(browserSessionCookie)
		if !ok || cookieErr != nil || handler.repository.Revoke(request.Context(), identity, cookie.Value) != nil {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: browserSessionCookie, Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), Secure: handler.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		writer.WriteHeader(http.StatusNoContent)
	case "/api/v1/session/scopes":
		identity, ok := IdentityFromRequest(request)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryAuthentication)
			return
		}
		payload, err := handler.repository.ListScopes(request.Context(), identity)
		writeProductionResponse(writer, request, http.StatusOK, payload, err)
	case "/api/v1/session/scope":
		identity, ok := IdentityFromRequest(request)
		cookie, cookieErr := request.Cookie(browserSessionCookie)
		var input struct {
			WorkspaceID   string `json:"workspace_id"`
			EnvironmentID string `json:"environment_id"`
		}
		if !ok || cookieErr != nil || decodeProductionJSON(request, &input) != nil {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		workspace, workspaceErr := domain.ParseProductID(input.WorkspaceID)
		environment, environmentErr := domain.ParseProductID(input.EnvironmentID)
		scope, scopeErr := domain.NewScope(identity.Scope.OrganizationID(), workspace, environment)
		if workspaceErr != nil || environmentErr != nil || scopeErr != nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		if _, err := handler.repository.SwitchScope(request.Context(), identity, cookie.Value, scope); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func authorizedBootstrap(payload json.RawMessage, identity RequestIdentity) (json.RawMessage, error) {
	var value map[string]json.RawMessage
	if json.Unmarshal(payload, &value) != nil {
		return nil, ErrRepositoryUnavailable
	}
	capabilities := capabilitiesForPermissions(identity.Permissions)
	replacements := map[string]any{
		"organization_id": identity.Scope.OrganizationID().String(),
		"workspace_id":    identity.Scope.WorkspaceID().String(),
		"environment_id":  identity.Scope.EnvironmentID().String(),
		"permissions":     identity.Permissions,
		"capabilities":    capabilities,
		"csrf_token":      identity.CSRFToken,
		"fresh_auth_expires_at": func() any {
			if identity.FreshAuthExpiresAt.IsZero() {
				return nil
			}
			return identity.FreshAuthExpiresAt.UTC().Format(time.RFC3339Nano)
		}(),
	}
	for name, replacement := range replacements {
		encoded, err := json.Marshal(replacement)
		if err != nil {
			return nil, ErrRepositoryUnavailable
		}
		value[name] = encoded
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return result, nil
}

func capabilitiesForPermissions(permissions []string) []string {
	capabilities := []string{}
	for _, permission := range permissions {
		switch permission {
		case "view":
			capabilities = append(capabilities, "inventory.read", "scope.switch", "policies.read", "integrations.read", "security-agents.read", "findings.read", "attack-paths.read", "administration.read", "system.read")
		case "manage_workflows":
			capabilities = append(capabilities, "policies.write", "integrations.write", "security-agents.write")
		case "manage_findings":
			capabilities = append(capabilities, "findings.write")
		case "manage_identity":
			capabilities = append(capabilities, "identity.manage")
		case "manage_api_tokens":
			capabilities = append(capabilities, "api-access.manage")
		case "view_audit":
			capabilities = append(capabilities, "audit.read")
		case "investigate_sessions":
			capabilities = append(capabilities, "sessions.read")
		case "revoke_sessions":
			capabilities = append(capabilities, "sessions.revoke")
		case "view_compliance":
			capabilities = append(capabilities, "compliance.read")
		case "manage_data_controls":
			capabilities = append(capabilities, "data-controls.manage")
		}
	}
	return capabilities
}

type identityHTTPHandler struct {
	repository     sessionRepository
	administration administrationRepository
	provider       CallbackProvider
	signingKey     []byte
	tokenRevealKey []byte
	now            func() time.Time
	version        string
}

func (handler *identityHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	routed, routedOK := RoutedOperationFromRequest(request)
	if routedOK && routed.OperationID != "getCurrentPrincipal" {
		handler.serveAdministration(writer, request, identity, routed)
		return
	}
	payload, err := handler.repository.Bootstrap(request.Context(), identity)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var bootstrap struct {
		Principal json.RawMessage `json:"principal"`
	}
	if json.Unmarshal(payload, &bootstrap) != nil || !json.Valid(bootstrap.Principal) {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	writeProductionResponse(writer, request, http.StatusOK, bootstrap.Principal, nil)
}

type administrationCursor struct {
	Version        int    `json:"v"`
	OrganizationID string `json:"o"`
	WorkspaceID    string `json:"w"`
	EnvironmentID  string `json:"e"`
	Operation      string `json:"p"`
	QueryDigest    string `json:"q"`
	AfterID        string `json:"i"`
	AfterParentID  string `json:"a,omitempty"`
	AfterTime      string `json:"t,omitempty"`
}

func (handler *identityHTTPHandler) serveAdministration(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	if request.Method != http.MethodGet {
		handler.mutateAdministration(writer, request, identity, routed)
		return
	}
	if handler.serveLocalAdministration(writer, request, routed) {
		return
	}
	parameters := make(map[string]string, len(routed.PathParameters)+4)
	for key, value := range routed.PathParameters {
		parameters[key] = value
	}
	list := administrationPagedOperation(routed.OperationID)
	if list {
		allowed := map[string]int{"cursor": 512, "limit": 3}
		if routed.OperationID == "listEnvironments" {
			allowed["workspace_id"] = 40
		}
		if routed.OperationID == "listSessions" {
			for _, key := range []string{"agent_id", "principal_id", "from", "to"} {
				allowed[key] = 256
			}
		}
		query, ok := exactWorkflowQuery(request.URL.RawQuery, allowed)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		limit, ok := workflowPageLimit(query)
		if !ok {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		parameters["limit"] = strconv.Itoa(limit)
		parameters["cursor_binding"] = administrationCursorBinding(query)
		if routed.OperationID == "listEnvironments" {
			workspace := query.Get("workspace_id")
			if !validAdministrationProductID(workspace) {
				writeProductionError(writer, request, ErrRepositoryOperation)
				return
			}
			if workspace != identity.Scope.WorkspaceID().String() {
				writeProductionError(writer, request, ErrRepositoryNotFound)
				return
			}
			parameters["workspace_id"] = workspace
		}
		if routed.OperationID == "listSessions" {
			if !handler.validateSessionFilters(query, parameters) {
				writeProductionError(writer, request, ErrRepositoryOperation)
				return
			}
		}
		if cursor := query.Get("cursor"); cursor != "" {
			position, valid := handler.decodeAdministrationCursor(cursor, identity, routed.OperationID, parameters["cursor_binding"])
			if !valid {
				writeProductionError(writer, request, ErrRepositoryNotFound)
				return
			}
			parameters["after_id"] = position.AfterID
			parameters["after_parent_id"] = position.AfterParentID
			parameters["after_time"] = position.AfterTime
		}
	}
	if id := parameters["id"]; id != "" && routed.OperationID != "getSession" && routed.OperationID != "listSessionEvents" && !validAdministrationProductID(id) {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	if (routed.OperationID == "getWorkspace" && parameters["id"] != identity.Scope.WorkspaceID().String()) || (routed.OperationID == "getEnvironment" && parameters["id"] != identity.Scope.EnvironmentID().String()) {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	payload, err := handler.administration.ReadAdministration(request.Context(), identity, routed.OperationID, parameters)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if list {
		handler.writeAdministrationPage(writer, request, identity, routed.OperationID, parameters, payload)
		return
	}
	var versioned struct {
		Version int64 `json:"version"`
	}
	if json.Unmarshal(payload, &versioned) == nil && versioned.Version > 0 {
		writer.Header().Set("ETag", quoteVersion(versioned.Version))
	}
	writeProductionResponse(writer, request, http.StatusOK, payload, nil)
}

func (handler *identityHTTPHandler) mutateAdministration(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, routed RoutedOperation) {
	mutation := administrationMutation{Operation: routed.OperationID, ID: routed.PathParameters["id"]}
	if routed.OperationID == "revealAPIToken" {
		handler.revealAPIToken(writer, request, identity, mutation.ID)
		return
	}
	if routed.OperationID == "updateWorkspace" && mutation.ID != identity.Scope.WorkspaceID().String() {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	auditID, err := newWorkflowProductID()
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	mutation.AuditID = auditID
	status := http.StatusOK
	switch routed.OperationID {
	case "createWorkspace":
		var input struct {
			Name string `json:"name"`
		}
		if decodeProductionJSON(request, &input) != nil || !validAdministrationName(input.Name) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		mutation.ID, err = newWorkflowProductID()
		if err == nil {
			mutation.InitialEnvironmentID, err = newWorkflowProductID()
		}
		mutation.Name, status = input.Name, http.StatusCreated
	case "updateWorkspace", "updateEnvironment":
		var input struct {
			Name string `json:"name"`
		}
		mutation.ExpectedVersion, err = parseVersion(request.Header.Get("If-Match"))
		if err == nil {
			err = decodeProductionJSON(request, &input)
		}
		if err != nil || !validAdministrationProductID(mutation.ID) || !validAdministrationName(input.Name) {
			writeWorkflowMutationError(writer, request, errOrOperation(err))
			return
		}
		if routed.OperationID == "updateEnvironment" && mutation.ID != identity.Scope.EnvironmentID().String() {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		mutation.Name = input.Name
	case "createEnvironment":
		var input struct {
			WorkspaceID string `json:"workspace_id"`
			Name        string `json:"name"`
		}
		if decodeProductionJSON(request, &input) != nil || !validAdministrationProductID(input.WorkspaceID) || !validAdministrationName(input.Name) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		if input.WorkspaceID != identity.Scope.WorkspaceID().String() {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		mutation.ID, err = newWorkflowProductID()
		mutation.WorkspaceID, mutation.Name, status = input.WorkspaceID, input.Name, http.StatusCreated
	case "updateMemberRole":
		var input struct {
			Role string `json:"role"`
		}
		mutation.ExpectedVersion, err = parseVersion(request.Header.Get("If-Match"))
		if err == nil {
			err = decodeProductionJSON(request, &input)
		}
		if err != nil || !validAdministrationProductID(mutation.ID) || !validAdministrationRole(input.Role) {
			writeWorkflowMutationError(writer, request, errOrOperation(err))
			return
		}
		mutation.Role = input.Role
	case "updateGroupMappings":
		var input struct {
			GroupReference string `json:"group_reference"`
			Role           string `json:"role"`
			WorkspaceID    string `json:"workspace_id"`
			EnvironmentID  string `json:"environment_id"`
			Expected       int64  `json:"expected_version"`
		}
		if decodeProductionJSON(request, &input) != nil || len(input.GroupReference) < 11 || len(input.GroupReference) > 128 || !strings.HasPrefix(input.GroupReference, "idp-group-") || !validAdministrationRole(input.Role) || !validAdministrationProductID(input.WorkspaceID) || !validAdministrationProductID(input.EnvironmentID) || input.Expected < 0 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		mutation.ID, mutation.Role, mutation.WorkspaceID, mutation.EnvironmentID, mutation.ExpectedVersion = input.GroupReference, input.Role, input.WorkspaceID, input.EnvironmentID, input.Expected
	case "createAPIToken":
		var input struct {
			Name          string   `json:"name"`
			WorkspaceID   string   `json:"workspace_id"`
			EnvironmentID string   `json:"environment_id"`
			Permissions   []string `json:"permissions"`
			ExpiresAt     string   `json:"expires_at"`
		}
		err = decodeProductionJSON(request, &input)
		mutation.ExpiresAt, err = parseAdministrationExpiry(input.ExpiresAt, handler.now(), err)
		mutation.IdempotencyKey = request.Header.Get("Idempotency-Key")
		if err != nil || !validAdministrationName(input.Name) || !validAdministrationProductID(input.WorkspaceID) || !validAdministrationProductID(input.EnvironmentID) || !validPermissions(input.Permissions) || len(input.Permissions) == 0 || !validAdministrationIdempotencyKey(mutation.IdempotencyKey) {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		if input.WorkspaceID != identity.Scope.WorkspaceID().String() || input.EnvironmentID != identity.Scope.EnvironmentID().String() {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		mutation.ID, err = newWorkflowProductID()
		rawToken, tokenErr := newAdministrationToken(err)
		mutation.GrantID, err = newWorkflowProductID()
		mutation.Name, mutation.WorkspaceID, mutation.EnvironmentID = input.Name, input.WorkspaceID, input.EnvironmentID
		mutation.Permissions, _ = json.Marshal(input.Permissions)
		mutation.revealKey = handler.tokenRevealKey
		if tokenErr == nil && err == nil {
			err = prepareAPITokenReveal(identity, &mutation, routed.OperationID, rawToken, handler.now())
		} else if err == nil {
			err = tokenErr
		}
		status = http.StatusCreated
	case "rotateAPIToken":
		mutation.ExpectedVersion, err = parseVersion(request.Header.Get("If-Match"))
		mutation.IdempotencyKey = request.Header.Get("Idempotency-Key")
		if err == nil {
			err = decodeEmptyInput(request)
		}
		if err != nil || !validAdministrationProductID(mutation.ID) || !validAdministrationIdempotencyKey(mutation.IdempotencyKey) {
			writeWorkflowMutationError(writer, request, errOrOperation(err))
			return
		}
		mutation.ReplacementID, err = newWorkflowProductID()
		rawToken, tokenErr := newAdministrationToken(err)
		mutation.GrantID, err = newWorkflowProductID()
		mutation.revealKey = handler.tokenRevealKey
		if tokenErr == nil && err == nil {
			err = prepareAPITokenReveal(identity, &mutation, routed.OperationID, rawToken, handler.now())
		} else if err == nil {
			err = tokenErr
		}
		status = http.StatusCreated
	case "acknowledgeAPITokenRevealGrant":
		if !validAdministrationProductID(mutation.ID) || decodeEmptyInput(request) != nil {
			writeProductionError(writer, request, ErrRepositoryNotFound)
			return
		}
		status = http.StatusNoContent
	case "revokeAPIToken", "revokeSession":
		mutation.ExpectedVersion, err = parseVersion(request.Header.Get("If-Match"))
		if err == nil {
			err = requireZeroByteInput(request)
		}
		if err != nil || mutation.ID == "" || routed.OperationID == "revokeAPIToken" && !validAdministrationProductID(mutation.ID) {
			writeWorkflowMutationError(writer, request, errOrOperation(err))
			return
		}
		if routed.OperationID == "revokeSession" {
			status = http.StatusNoContent
		}
	case "updateDataControls":
		var input struct {
			EnvironmentID    string `json:"environment_id"`
			EnvironmentClass string `json:"environment_class"`
			CollectionMode   string `json:"collection_mode"`
			RetentionDays    int    `json:"retention_days"`
			DeletionEnabled  bool   `json:"deletion_enabled"`
		}
		mutation.ExpectedVersion, err = parseVersion(request.Header.Get("If-Match"))
		if err == nil {
			err = decodeProductionJSON(request, &input)
		}
		if err != nil || input.EnvironmentID != identity.Scope.EnvironmentID().String() || !validEnvironmentClass(input.EnvironmentClass) || input.CollectionMode != "metadata_only" && input.CollectionMode != "extended" || input.EnvironmentClass == "production" && input.CollectionMode != "metadata_only" || input.RetentionDays < 1 || input.RetentionDays > 3650 {
			writeWorkflowMutationError(writer, request, errOrOperation(err))
			return
		}
		mutation.EnvironmentID, mutation.EnvironmentClass, mutation.CollectionMode, mutation.RetentionDays, mutation.DeletionEnabled = input.EnvironmentID, input.EnvironmentClass, input.CollectionMode, input.RetentionDays, input.DeletionEnabled
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	payload, err := handler.administration.MutateAdministration(request.Context(), identity, mutation)
	if err != nil {
		writeWorkflowMutationError(writer, request, err)
		return
	}
	if status == http.StatusNoContent {
		writer.WriteHeader(status)
		return
	}
	var value map[string]any
	if json.Unmarshal(payload, &value) != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	if (routed.OperationID == "createAPIToken" || routed.OperationID == "rotateAPIToken") && value["grant_id"] == nil {
		value = map[string]any{"grant_id": mutation.GrantID, "expires_at": mutation.GrantExpiresAt, "token": value}
	}
	if version, ok := value["version"].(float64); ok && version >= 1 {
		writer.Header().Set("ETag", quoteVersion(int64(version)))
	}
	if routed.OperationID == "createAPIToken" || routed.OperationID == "rotateAPIToken" {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writeJSONValue(writer, request, status, value, nil)
}

func (handler *identityHTTPHandler) revealAPIToken(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, grantID string) {
	if !validAdministrationProductID(grantID) || decodeEmptyInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	payload, err := handler.administration.ReadAdministration(request.Context(), identity, "revealAPIToken", map[string]string{"id": grantID})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	var envelope apiTokenRevealEnvelope
	if json.Unmarshal(payload, &envelope) != nil || envelope.GrantID != grantID {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	raw, err := decryptAPITokenReveal(handler.tokenRevealKey, identity, envelope)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"grant_id": envelope.GrantID, "token_id": envelope.TokenID, "raw_token": raw, "expires_at": envelope.ExpiresAt}, nil)
}

func errOrOperation(err error) error {
	if err == nil {
		return ErrRepositoryOperation
	}
	return err
}

func validAdministrationName(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character >= 0x7f && character <= 0x9f {
			return false
		}
	}
	return true
}

func validAdministrationRole(value string) bool {
	switch value {
	case "organization_admin", "security_admin", "security_engineer", "developer_owner", "compliance_viewer", "read_only_viewer":
		return true
	default:
		return false
	}
}

func validEnvironmentClass(value string) bool {
	return value == "development" || value == "test" || value == "staging" || value == "production"
}

func validAdministrationIdempotencyKey(value string) bool {
	return len(value) >= 16 && len(value) <= 128 && workflowKeyPattern.MatchString(value)
}

func parseAdministrationExpiry(value string, now time.Time, previous error) (time.Time, error) {
	if previous != nil {
		return time.Time{}, previous
	}
	expires, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !expires.After(now) || expires.After(now.Add(365*24*time.Hour)) {
		return time.Time{}, ErrRepositoryOperation
	}
	return expires.UTC(), nil
}

func newAdministrationToken(previous error) (string, error) {
	if previous != nil {
		return "", previous
	}
	value, err := randomCredential()
	if err != nil {
		return "", err
	}
	return "zasp_pat_" + value, nil
}

func administrationPagedOperation(operation string) bool {
	switch operation {
	case "listWorkspaces", "listEnvironments", "listMembers", "listAPITokens", "listAPITokenRevealGrants", "listAuditEvents", "listSessions", "listSessionEvents", "listComplianceControls", "listComplianceEvidence":
		return true
	default:
		return false
	}
}

func (handler *identityHTTPHandler) writeAdministrationPage(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, operation string, parameters map[string]string, payload json.RawMessage) {
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	limit := adminLimit(parameters)
	if json.Unmarshal(payload, &page) != nil || len(page.Items) > limit+1 {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	hasMore := len(page.Items) > limit
	if hasMore {
		page.Items = page.Items[:limit]
	}
	var cursor any
	if hasMore {
		position, valid := administrationCursorPosition(operation, page.Items[len(page.Items)-1])
		if !valid {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		cursor = handler.encodeAdministrationCursor(identity, operation, parameters["cursor_binding"], position)
	}
	if operation == "listAPITokenRevealGrants" {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": page.Items, "page_info": map[string]any{"next_cursor": cursor, "has_more": hasMore}}, nil)
}

func (handler *identityHTTPHandler) encodeAdministrationCursor(identity RequestIdentity, operation, queryDigest string, position administrationCursor) string {
	position.Version = 2
	position.OrganizationID = identity.Scope.OrganizationID().String()
	position.WorkspaceID = identity.Scope.WorkspaceID().String()
	position.EnvironmentID = identity.Scope.EnvironmentID().String()
	position.Operation = operation
	position.QueryDigest = queryDigest
	payload, _ := json.Marshal(position)
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
}

func (handler *identityHTTPHandler) decodeAdministrationCursor(value string, identity RequestIdentity, operation, queryDigest string) (administrationCursor, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || len(decoded) <= sha256.Size || len(value) > 512 {
		return administrationCursor{}, false
	}
	payload, signature := decoded[:len(decoded)-sha256.Size], decoded[len(decoded)-sha256.Size:]
	mac := hmac.New(sha256.New, handler.signingKey)
	_, _ = mac.Write(payload)
	var cursor administrationCursor
	if !hmac.Equal(signature, mac.Sum(nil)) || json.Unmarshal(payload, &cursor) != nil {
		return administrationCursor{}, false
	}
	canonical, marshalErr := json.Marshal(cursor)
	if marshalErr != nil || !bytes.Equal(canonical, payload) || cursor.Version != 2 || cursor.OrganizationID != identity.Scope.OrganizationID().String() || cursor.WorkspaceID != identity.Scope.WorkspaceID().String() || cursor.EnvironmentID != identity.Scope.EnvironmentID().String() || cursor.Operation != operation || cursor.QueryDigest != queryDigest || !validAdministrationCursorPosition(operation, cursor) {
		return administrationCursor{}, false
	}
	return cursor, true
}

func administrationCursorPosition(operation string, item json.RawMessage) (administrationCursor, bool) {
	var value struct {
		ID         string `json:"id"`
		GrantID    string `json:"grant_id"`
		OccurredAt string `json:"occurred_at"`
		At         string `json:"at"`
		Control    struct {
			ID string `json:"id"`
		} `json:"control"`
		Evidence []struct {
			ID string `json:"id"`
		} `json:"evidence"`
	}
	if json.Unmarshal(item, &value) != nil {
		return administrationCursor{}, false
	}
	position := administrationCursor{AfterID: value.ID}
	switch operation {
	case "listAPITokenRevealGrants":
		position.AfterID = value.GrantID
	case "listComplianceEvidence":
		if len(value.Evidence) == 1 {
			position.AfterID = value.Evidence[0].ID
			position.AfterParentID = value.Control.ID
		} else {
			position.AfterID = ""
		}
	case "listAuditEvents":
		position.AfterTime, _ = canonicalAdministrationTime(value.OccurredAt)
	case "listSessionEvents":
		position.AfterTime, _ = canonicalAdministrationTime(value.At)
	}
	return position, validAdministrationCursorPosition(operation, position)
}

func validAdministrationCursorPosition(operation string, cursor administrationCursor) bool {
	if len(cursor.AfterID) < 1 || len(cursor.AfterID) > 256 || strings.TrimSpace(cursor.AfterID) != cursor.AfterID {
		return false
	}
	requiresTime := operation == "listAuditEvents" || operation == "listSessionEvents"
	requiresParent := operation == "listComplianceEvidence"
	if requiresParent != (cursor.AfterParentID != "") || cursor.AfterParentID != "" && (len(cursor.AfterParentID) > 256 || strings.TrimSpace(cursor.AfterParentID) != cursor.AfterParentID) {
		return false
	}
	if !requiresTime {
		return cursor.AfterTime == ""
	}
	parsed, err := time.Parse(time.RFC3339Nano, cursor.AfterTime)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == cursor.AfterTime
}

func canonicalAdministrationTime(value string) (string, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", false
	}
	return parsed.UTC().Format(time.RFC3339Nano), true
}

func administrationCursorBinding(query url.Values) string {
	copy := make(url.Values, len(query))
	for key, values := range query {
		copy[key] = append([]string(nil), values...)
	}
	copy.Del("cursor")
	digest := sha256.Sum256([]byte(copy.Encode()))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (handler *identityHTTPHandler) validateSessionFilters(query url.Values, parameters map[string]string) bool {
	for _, key := range []string{"agent_id", "principal_id"} {
		parameters[key] = query.Get(key)
	}
	if principal := parameters["principal_id"]; principal != "" && !validAdministrationProductID(principal) {
		return false
	}
	var from, to time.Time
	for _, key := range []string{"from", "to"} {
		value := query.Get(key)
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
			return false
		}
		parameters[key] = value
		if key == "from" {
			from = parsed
		} else {
			to = parsed
		}
	}
	return from.IsZero() || to.IsZero() || !from.After(to)
}

func (handler *identityHTTPHandler) serveLocalAdministration(writer http.ResponseWriter, request *http.Request, routed RoutedOperation) bool {
	if request.URL.RawQuery != "" && (routed.OperationID == "listBuiltInRoles" || routed.OperationID == "getExternalDataFlows" || routed.OperationID == "getSystemStatus" || routed.OperationID == "listSystemComponents" || routed.OperationID == "getSystemVersion") {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return true
	}
	switch routed.OperationID {
	case "listBuiltInRoles":
		writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": serverOwnedRoles(), "page_info": map[string]any{"next_cursor": nil, "has_more": false}}, nil)
	case "getExternalDataFlows":
		providerHealthy := handler.providerLiveVerified(request.Context())
		state := "degraded"
		if providerHealthy {
			state = "healthy"
		}
		writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": []any{map[string]any{"id": "identity-provider", "required": true, "categories": []string{"identity_metadata"}, "enabled": true, "health": state}}}, nil)
	case "getSystemStatus", "listSystemComponents":
		now := handler.now().UTC().Truncate(time.Second)
		databaseHealthy := false
		if repository, ok := handler.administration.(*PostgresRepository); ok {
			databaseHealthy = repository.Ready(request.Context()) == nil
		}
		providerHealthy := handler.providerLiveVerified(request.Context())
		if routed.OperationID == "getSystemStatus" {
			writeJSONValue(writer, request, http.StatusOK, map[string]any{"security_plane_healthy": databaseHealthy && providerHealthy, "optional_degraded": !providerHealthy, "fresh_at": now}, nil)
		} else {
			componentState := func(healthy bool) string {
				if healthy {
					return "healthy"
				}
				return "unavailable"
			}
			providerState := "degraded"
			if providerHealthy {
				providerState = "healthy"
			}
			writeJSONValue(writer, request, http.StatusOK, map[string]any{"items": []any{map[string]any{"id": "postgresql", "required": true, "state": componentState(databaseHealthy), "fresh_at": now}, map[string]any{"id": "identity-provider", "required": true, "state": providerState, "fresh_at": now}}}, nil)
		}
	case "getSystemVersion":
		writeJSONValue(writer, request, http.StatusOK, map[string]string{"version": handler.version}, nil)
	default:
		return false
	}
	return true
}

func (handler *identityHTTPHandler) providerLiveVerified(ctx context.Context) bool {
	verifier, ok := handler.provider.(IdentityLiveVerifier)
	return ok && verifier.VerifyIdentityProvider(ctx) == nil
}

func serverOwnedRoles() []map[string]any {
	admin := []string{"investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "view", "view_audit", "view_compliance"}
	return []map[string]any{
		{"role": "organization_admin", "permissions": admin},
		{"role": "security_admin", "permissions": admin},
		{"role": "security_engineer", "permissions": []string{"investigate_sessions", "manage_findings", "manage_workflows", "view"}},
		{"role": "developer_owner", "permissions": []string{"investigate_sessions", "view"}},
		{"role": "compliance_viewer", "permissions": []string{"view", "view_audit", "view_compliance"}},
		{"role": "read_only_viewer", "permissions": []string{"view"}},
	}
}

type coreHTTPHandler struct {
	repository coreRepository
	boundary   dependencyKind
}

func (handler *coreHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	identity, ok := IdentityFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	operation, _, status, err := productionOperation(request, handler.boundary)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	payload, err := handler.repository.Read(request.Context(), identity.Scope, operation)
	writeProductionResponse(writer, request, status, payload, err)
}

func productionOperation(request *http.Request, boundary dependencyKind) (string, bool, int, error) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		return "", false, 0, ErrRepositoryNotFound
	}
	id := routed.PathParameters["id"]
	if boundary == inventoryDependency {
		switch routed.OperationID {
		case "getHomeSummary":
			return "home", false, http.StatusOK, nil
		case "listAgents":
			return "agents", false, http.StatusOK, nil
		case "getAgent":
			return "agent:" + id, false, http.StatusOK, nil
		case "getAgentCapabilities":
			return "agent_capabilities:" + id, false, http.StatusOK, nil
		case "getAgentRelationships":
			return "agent_relationships:" + id, false, http.StatusOK, nil
		case "listAgentSessions":
			return "agent_sessions:" + id, false, http.StatusOK, nil
		case "listTools":
			return "tools", false, http.StatusOK, nil
		case "getTool":
			return "tool:" + id, false, http.StatusOK, nil
		case "listIdentities":
			return "identities", false, http.StatusOK, nil
		case "getIdentity":
			return "identity:" + id, false, http.StatusOK, nil
		case "listRuntimes":
			return "runtimes", false, http.StatusOK, nil
		case "getRuntime":
			return "runtime:" + id, false, http.StatusOK, nil
		case "getAsset":
			return "asset:" + id, false, http.StatusOK, nil
		}
	}
	return "", false, 0, ErrRepositoryNotFound
}

func decodeProductionJSON(request *http.Request, target any) error {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return ErrRepositoryOperation
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 16*1024+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrRepositoryOperation
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrRepositoryOperation
	}
	return nil
}

func writeProductionResponse(writer http.ResponseWriter, request *http.Request, status int, payload json.RawMessage, err error) {
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
	_, _ = writer.Write([]byte("\n"))
}

func writeProductionError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message, retryable := http.StatusServiceUnavailable, "provider_unavailable", "Provider unavailable", true
	if errors.Is(err, ErrRepositoryAuthentication) {
		status, code, message, retryable = http.StatusUnauthorized, "authentication_required", "Authentication required", false
	}
	if errors.Is(err, ErrRepositoryNotFound) {
		status, code, message, retryable = http.StatusNotFound, "not_found", "Resource not found", false
	}
	if errors.Is(err, ErrRepositoryOperation) {
		status, code, message, retryable = http.StatusBadRequest, "invalid_request", "Request rejected", false
	}
	if errors.Is(err, ErrRepositoryConflict) {
		status, code, message, retryable = http.StatusConflict, "operation_conflict", "Operation conflicted", false
	}
	correlation := fallbackCorrelationID
	if request != nil {
		correlation = correlationIDFromContext(request.Context())
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": code, "message": message, "correlation_id": correlation, "retryable": retryable})
}
