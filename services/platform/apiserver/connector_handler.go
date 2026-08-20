package apiserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var connectorOAuthValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,512}$`)

type OAuthSecretMaterial struct {
	State     string
	Verifier  []byte
	ExpiresAt time.Time
}

type ConnectorOAuthSecretStore interface {
	Acquire(context.Context, string, OAuthSecretMaterial, time.Time) (OAuthSecretMaterial, error)
	Consume(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type ConnectorOAuthGrant struct {
	ConnectionReference string
	ProviderSubject     string
	CredentialClass     string
	Metadata            json.RawMessage
}

type ConnectorOAuthProvider interface {
	AuthorizationURL(string, string) (string, error)
	Complete(context.Context, string, string, []byte) (ConnectorOAuthGrant, error)
	Recover(context.Context, string) (ConnectorOAuthGrant, error)
	Discard(context.Context, string, bool) error
	Revoke(context.Context, string) error
}

var ErrConnectorOutcomeNotFound = errors.New("connector outcome not found")

type ConnectorOAuthProviderFactory interface {
	Provider(map[string]string) (ConnectorOAuthProvider, error)
}

type ConnectorOAuthProviderDefinition struct {
	Provider        ConnectorOAuthProvider
	Factory         ConnectorOAuthProviderFactory
	RequestedScopes []string
	CredentialClass string
}

type connectorWorkflowReader interface {
	GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error)
}

type ConnectorHTTPConfig struct {
	Repository ConnectorAuthorizationRepository
	Workflows  connectorWorkflowReader
	Secrets    ConnectorOAuthSecretStore
	Providers  map[string]ConnectorOAuthProviderDefinition
	Registry   *ConnectorProviderRegistry
	Clock      func() time.Time
}

type connectorHTTPHandler struct {
	repository ConnectorAuthorizationRepository
	workflows  connectorWorkflowReader
	secrets    ConnectorOAuthSecretStore
	registry   *ConnectorProviderRegistry
	now        func() time.Time
}

func NewConnectorHTTPHandler(config ConnectorHTTPConfig) (http.Handler, error) {
	if nilInterface(config.Repository) || nilInterface(config.Workflows) || nilInterface(config.Secrets) || config.Registry != nil && len(config.Providers) != 0 {
		return nil, ErrRepositoryConfiguration
	}
	registry := config.Registry
	if registry == nil {
		var err error
		registry, err = NewConnectorProviderRegistry(config.Providers, nil)
		if err != nil {
			return nil, ErrRepositoryConfiguration
		}
	}
	now := config.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if instant := now(); instant.IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return &connectorHTTPHandler{repository: config.Repository, workflows: config.Workflows, secrets: config.Secrets, registry: registry, now: now}, nil
}

func (handler *connectorHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	identity, identityOK := IdentityFromRequest(request)
	routed, routedOK := RoutedOperationFromRequest(request)
	if !identityOK || !routedOK || identity.CredentialKind != CredentialBrowserSession {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "authorizeIntegration":
		handler.authorize(writer, request, identity, routed.PathParameters["id"])
	case "remediateIntegrationAuthorization":
		handler.remediateQuarantine(writer, request, identity, routed.PathParameters["id"])
	case "completeIntegrationOAuthCallback":
		handler.callback(writer, request, identity)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

func (handler *connectorHTTPHandler) remediateQuarantine(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	var input struct {
		Acknowledgement string `json:"acknowledgement"`
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	expectedVersion, versionErr := parseVersion(request.Header.Get("If-Match"))
	if request.Method != http.MethodPost || !identity.FreshAuthenticated || !validProductID(integrationID) || versionErr != nil || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) || decodeProductionJSON(request, &input) != nil || !stringIn(input.Acknowledgement, "provider_grant_revoked_manually", "provider_grant_verified_absent") {
		if !identity.FreshAuthenticated {
			writeWorkflowMutationError(writer, request, ErrRepositoryAuthorization)
		} else {
			writeProductionError(writer, request, ErrRepositoryOperation)
		}
		return
	}
	quarantine, err := handler.repository.GetConnectorQuarantine(request.Context(), identity.Scope, integrationID)
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	workflow, workflowErr := handler.workflows.GetWorkflow(request.Context(), identity.Scope, "integration", integrationID)
	providerKey, providerConfiguration, workflowOK := authorizedOAuthIntegrationStatus(workflow, integrationID, "degraded", "pending_authorization", "active", "revoking")
	definition, ready := handler.registry.Provider(request.Context(), providerKey)
	provider, providerErr := connectorOAuthProvider(definition, providerConfiguration)
	cleanupErr := providerErr
	if workflowErr == nil && workflowOK && ready && providerKey == quarantine.Provider && providerErr == nil {
		if quarantine.Operation == "pkce_cleanup" {
			cleanupErr = handler.secrets.Delete(request.Context(), quarantine.ConnectionReference)
		} else {
			cleanupErr = provider.Discard(request.Context(), quarantine.ID, false)
		}
	}
	if workflowErr != nil || !workflowOK || !ready || providerKey != quarantine.Provider || cleanupErr != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	intent, intentErr := json.Marshal(map[string]any{"resource_id": integrationID, "expected_version": expectedVersion, "body": map[string]any{"acknowledgement": input.Acknowledgement}})
	auditID, auditErr := newWorkflowProductID()
	receiptID, receiptErr := newWorkflowProductID()
	correlationID := correlationIDFromContext(request.Context())
	if intentErr != nil || auditErr != nil || receiptErr != nil || !validProductID(correlationID) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	result, err := handler.repository.RemediateConnectorQuarantine(request.Context(), identity, ConnectorQuarantineRemediation{EffectID: quarantine.ID, IntegrationID: integrationID, Acknowledgement: input.Acknowledgement, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, Intent: intent, Body: json.RawMessage(`{}`), AuditID: auditID, CorrelationID: correlationID, ReceiptID: receiptID})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", quoteVersion(result.Version))
	writer.Header().Set("X-Audit-ID", result.AuditID)
	writer.Header().Set("X-Mutation-Receipt-ID", result.ReceiptID)
	writeProductionResponse(writer, request, http.StatusOK, result.Body, nil)
}

func (handler *connectorHTTPHandler) authorize(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID string) {
	idempotencyKey := request.Header.Get("Idempotency-Key")
	cookie, cookieErr := request.Cookie(browserSessionCookie)
	if request.Method != http.MethodPost || !validProductID(integrationID) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 || !workflowKeyPattern.MatchString(idempotencyKey) || cookieErr != nil || len(cookie.Value) < 8 || len(cookie.Value) > 4096 || decodeEmptyInput(request) != nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	workflow, err := handler.workflows.GetWorkflow(request.Context(), identity.Scope, "integration", integrationID)
	providerKey, providerConfiguration, ok := authorizedOAuthIntegration(workflow, integrationID)
	definition, ready := handler.registry.Provider(request.Context(), providerKey)
	if err != nil || !ok || !ready {
		writeProductionError(writer, request, firstError(err, ErrRepositoryNotFound))
		return
	}
	provider, err := connectorOAuthProvider(definition, providerConfiguration)
	if err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	attemptID := connectorDeterministicID(identity.Scope, identity.PrincipalID.String(), integrationID, idempotencyKey, "oauth-attempt")
	state, stateErr := randomCredential()
	verifier, verifierErr := randomCredential()
	if stateErr != nil || verifierErr != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	expiresAt := handler.now().UTC().Add(10 * time.Minute)
	reference := "ref:oauth/pkce/" + strings.TrimPrefix(attemptID, "pid_")
	material, err := handler.secrets.Acquire(request.Context(), reference, OAuthSecretMaterial{State: state, Verifier: []byte(verifier), ExpiresAt: expiresAt}, expiresAt)
	if err != nil || !connectorOAuthValuePattern.MatchString(material.State) || !connectorPKCEVerifier(material.Verifier) || !material.ExpiresAt.After(handler.now()) || material.ExpiresAt.After(expiresAt.Add(time.Second)) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	sessionDigest := sha256.Sum256([]byte(cookie.Value))
	stateDigest := sha256.Sum256([]byte(material.State))
	requestDigest := connectorAuthorizationIntentDigest(identity, workflow, integrationID, attemptID, providerKey, providerConfiguration, definition.RequestedScopes)
	configurationJSON, configurationErr := json.Marshal(providerConfiguration)
	if configurationErr != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	attempt, err := handler.repository.StartOAuth(request.Context(), identity, OAuthStart{
		AttemptID: attemptID, IntegrationID: integrationID, Provider: providerKey, SessionDigest: sessionDigest[:], StateDigest: stateDigest[:], PKCEVerifierReference: reference,
		RequestDigest: requestDigest[:], RequestedScopes: definition.RequestedScopes, ExpiresAt: material.ExpiresAt.UTC(), IntegrationVersion: workflow.Version, Configuration: configurationJSON,
	})
	cleanupID := connectorDeterministicID(identity.Scope, attemptID, "pkce-cleanup")
	if err != nil {
		if cleanupErr := handler.secrets.Delete(request.Context(), reference); cleanupErr != nil {
			_, _ = handler.repository.StagePKCECleanup(request.Context(), identity.Scope, PKCECleanupStage{ID: cleanupID, IntegrationID: integrationID, Provider: providerKey, Reference: reference, RequestDigest: requestDigest[:], AvailableAt: handler.now().UTC(), Reason: "oauth_start_rejected"})
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		writeProductionError(writer, request, err)
		return
	}
	if _, err := handler.repository.StagePKCECleanup(request.Context(), identity.Scope, PKCECleanupStage{ID: cleanupID, IntegrationID: integrationID, OAuthAttemptID: attempt.ID, Provider: providerKey, Reference: reference, RequestDigest: requestDigest[:], AvailableAt: attempt.ExpiresAt.UTC(), Reason: "oauth_attempt_expiry"}); err != nil {
		_ = handler.secrets.Delete(request.Context(), reference)
		writeProductionError(writer, request, err)
		return
	}
	challengeDigest := sha256.Sum256(material.Verifier)
	challenge := rawURLBase64(challengeDigest[:])
	target, err := provider.AuthorizationURL(material.State, challenge)
	if err != nil || !validConnectorAuthorizationTarget(target, material.State) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	payload, err := json.Marshal(map[string]any{"authorization_attempt_id": attempt.ID, "authorization_url": target, "expires_at": attempt.ExpiresAt.UTC()})
	writeProductionResponse(writer, request, http.StatusOK, payload, err)
}

func (handler *connectorHTTPHandler) callback(writer http.ResponseWriter, request *http.Request, identity RequestIdentity) {
	query, providerDenial, valid := exactConnectorCallbackQuery(request.URL.RawQuery)
	cookie, cookieErr := request.Cookie(browserSessionCookie)
	if request.Method != http.MethodGet || !valid || cookieErr != nil || len(cookie.Value) < 8 || len(cookie.Value) > 4096 {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	state := query.Get("state")
	stateDigest := sha256.Sum256([]byte(state))
	sessionDigest := sha256.Sum256([]byte(cookie.Value))
	consumption, err := handler.repository.ConsumeOAuth(request.Context(), identity, stateDigest[:], sessionDigest[:])
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	requestDigest, decodeErr := hex.DecodeString(consumption.RequestDigest)
	effectID := connectorDeterministicID(identity.Scope, consumption.ID, "oauth-effect")
	pkceCleanupID := connectorDeterministicID(identity.Scope, consumption.ID, "pkce-cleanup")
	effect, err := handler.repository.BeginConnectorEffect(request.Context(), identity.Scope, ConnectorEffectStart{ID: effectID, IntegrationID: consumption.IntegrationID, OAuthAttemptID: consumption.ID, Provider: consumption.Provider, Operation: "authorize", IdempotencyKey: "oauth-authorize:" + consumption.ID, RequestDigest: requestDigest})
	if decodeErr != nil || len(requestDigest) != sha256.Size || err != nil || effect.Status != "pending" && effect.Status != "unknown" {
		writeProductionError(writer, request, firstError(err, ErrRepositoryConflict))
		return
	}
	rejectConsumed := func(reason string) error {
		_, activateErr := handler.repository.ActivatePKCECleanup(request.Context(), identity.Scope, pkceCleanupID)
		verifier, consumeErr := handler.secrets.Consume(request.Context(), consumption.PKCEVerifierReference)
		clear(verifier)
		_, cleanupErr := handler.repository.CompletePKCECleanup(request.Context(), identity.Scope, pkceCleanupID)
		_, resolveErr := handler.repository.ResolveConnectorEffect(request.Context(), identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "failed", ErrorCode: reason, Metadata: json.RawMessage(`{}`)})
		if activateErr != nil || consumeErr != nil || cleanupErr != nil || resolveErr != nil {
			return ErrRepositoryUnavailable
		}
		return nil
	}
	definition, ready := handler.registry.Provider(request.Context(), consumption.Provider)
	if !ready || !equalStringSet(consumption.RequestedScopes, definition.RequestedScopes) {
		if err := rejectConsumed("authorization_intent_changed"); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writeProductionError(writer, request, ErrRepositoryConflict)
		return
	}
	workflow, workflowErr := handler.workflows.GetWorkflow(request.Context(), identity.Scope, "integration", consumption.IntegrationID)
	providerKey, providerConfiguration, integrationOK := authorizedOAuthIntegration(workflow, consumption.IntegrationID)
	provider, providerConfigErr := connectorOAuthProvider(definition, providerConfiguration)
	if workflowErr != nil || !integrationOK || providerKey != consumption.Provider || providerConfigErr != nil {
		if err := rejectConsumed("authorization_intent_changed"); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writeProductionError(writer, request, ErrRepositoryConflict)
		return
	}
	expectedDigest := connectorAuthorizationIntentDigest(identity, workflow, consumption.IntegrationID, consumption.ID, providerKey, providerConfiguration, definition.RequestedScopes)
	if decodeErr != nil || len(requestDigest) != sha256.Size || subtle.ConstantTimeCompare(requestDigest, expectedDigest[:]) != 1 {
		if err := rejectConsumed("authorization_intent_changed"); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writeProductionError(writer, request, ErrRepositoryConflict)
		return
	}
	if providerDenial != "" {
		if err := rejectConsumed("provider_" + providerDenial); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		http.Redirect(writer, request, consumption.ReturnPath, http.StatusSeeOther)
		return
	}
	if _, err := handler.repository.ActivatePKCECleanup(request.Context(), identity.Scope, pkceCleanupID); err != nil {
		writeProductionError(writer, request, err)
		return
	}
	verifier, err := handler.secrets.Consume(request.Context(), consumption.PKCEVerifierReference)
	if err != nil || !connectorPKCEVerifier(verifier) {
		_, _ = handler.repository.ResolveConnectorEffect(request.Context(), identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "failed", ErrorCode: "verifier_unavailable", Metadata: json.RawMessage(`{}`)})
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	if _, err := handler.repository.CompletePKCECleanup(request.Context(), identity.Scope, pkceCleanupID); err != nil {
		clear(verifier)
		writeProductionError(writer, request, err)
		return
	}
	if _, err = handler.repository.ResolveConnectorEffect(request.Context(), identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "unknown", ErrorCode: "provider_effect_started", Metadata: json.RawMessage(`{}`)}); err != nil {
		clear(verifier)
		writeProductionError(writer, request, err)
		return
	}
	grant, providerErr := provider.Complete(request.Context(), effectID, query.Get("code"), verifier)
	clear(verifier)
	if providerErr != nil || !validConnectorOAuthGrant(grant, definition.CredentialClass) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	connectionID := connectorDeterministicID(identity.Scope, consumption.ID, "connection")
	credentialID := connectorDeterministicID(identity.Scope, consumption.ID, "credential")
	_, err = handler.repository.CompleteOAuth(request.Context(), identity.Scope, OAuthCompletion{
		AttemptID: consumption.ID, EffectID: effectID, ConnectionID: connectionID, ConnectionReference: grant.ConnectionReference, ProviderSubject: grant.ProviderSubject,
		CredentialID: credentialID, CredentialClass: grant.CredentialClass, Metadata: grant.Metadata,
	})
	if err != nil {
		writeProductionError(writer, request, err)
		return
	}
	if err := provider.Discard(request.Context(), effectID, false); err != nil {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return
	}
	if _, err := handler.repository.CompleteConnectorCleanup(request.Context(), identity.Scope, effectID); err != nil {
		writeProductionError(writer, request, err)
		return
	}
	http.Redirect(writer, request, consumption.ReturnPath, http.StatusSeeOther)
}

func connectorAuthorizationIntentDigest(identity RequestIdentity, workflow WorkflowValue, integrationID, attemptID, provider string, configuration map[string]string, scopes []string) [sha256.Size]byte {
	return connectorAuthorizationIntentDigestValues(identity.Scope, identity.PrincipalID.String(), workflow, integrationID, attemptID, provider, configuration, scopes)
}

func connectorAuthorizationIntentDigestValues(scope domain.Scope, principalID string, workflow WorkflowValue, integrationID, attemptID, provider string, configuration map[string]string, scopes []string) [sha256.Size]byte {
	configurationJSON, _ := json.Marshal(configuration)
	return sha256.Sum256([]byte(strings.Join([]string{scopeKey(scope), principalID, integrationID, strconv.FormatInt(workflow.Version, 10), attemptID, provider, string(configurationJSON), strings.Join(scopes, "\x1e")}, "\x1f")))
}

func authorizedOAuthIntegration(value WorkflowValue, expectedID string) (string, map[string]string, bool) {
	return authorizedOAuthIntegrationStatus(value, expectedID, "configured", "pending_authorization", "active")
}

func authorizedOAuthIntegrationStatus(value WorkflowValue, expectedID string, allowedStatuses ...string) (string, map[string]string, bool) {
	if value.Version < 1 || len(value.Body) < 2 || len(value.Body) > 16<<10 {
		return "", nil, false
	}
	var body map[string]any
	if json.Unmarshal(value.Body, &body) != nil || body["id"] != expectedID {
		return "", nil, false
	}
	provider, providerOK := body["connector_key"].(string)
	status, statusOK := body["status"].(string)
	configurationValue, configurationOK := body["configuration"].(map[string]any)
	configuration := make(map[string]string, len(configurationValue))
	for key, raw := range configurationValue {
		value, ok := raw.(string)
		if !ok || len(key) < 1 || len(key) > 64 || len(value) < 1 || len(value) > 2048 {
			return "", nil, false
		}
		configuration[key] = value
	}
	return provider, configuration, providerOK && statusOK && configurationOK && stringIn(provider, "github", "okta") && stringIn(status, allowedStatuses...)
}

func connectorOAuthProvider(definition ConnectorOAuthProviderDefinition, configuration map[string]string) (ConnectorOAuthProvider, error) {
	if !nilInterface(definition.Provider) {
		return definition.Provider, nil
	}
	if nilInterface(definition.Factory) {
		return nil, ErrRepositoryConfiguration
	}
	provider, err := definition.Factory.Provider(configuration)
	if err != nil || nilInterface(provider) {
		return nil, ErrRepositoryConfiguration
	}
	return provider, nil
}

func exactConnectorCallbackQuery(raw string) (url.Values, string, bool) {
	query, err := url.ParseQuery(raw)
	if err != nil || len(query) != 2 || len(query["state"]) != 1 || !connectorOAuthValuePattern.MatchString(query["state"][0]) {
		return nil, "", false
	}
	if len(query["code"]) == 1 && connectorOAuthValuePattern.MatchString(query["code"][0]) {
		return query, "", true
	}
	if len(query["error"]) == 1 && stringIn(query["error"][0], "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable") {
		return query, query["error"][0], true
	}
	return nil, "", false
}

func validConnectorAuthorizationTarget(value, state string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || net.ParseIP(parsed.Hostname()) != nil || strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".local") {
		return false
	}
	return parsed.Query().Get("state") == state && len(parsed.Query()["state"]) == 1
}

func validConnectorOAuthGrant(value ConnectorOAuthGrant, credentialClass string) bool {
	return validOpaqueReference(value.ConnectionReference) && value.CredentialClass == credentialClass && len(value.ProviderSubject) >= 1 && len(value.ProviderSubject) <= 256 && validConnectorMetadata(value.Metadata)
}

func connectorPKCEVerifier(value []byte) bool {
	return len(value) >= 43 && len(value) <= 128 && connectorOAuthValuePattern.Match(value)
}

func connectorDeterministicID(scope domain.Scope, parts ...string) string {
	joined := append([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, parts...)
	value := sha256.Sum256([]byte(strings.Join(joined, "\x1f")))
	bytes := append([]byte(nil), value[:16]...)
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	encoded := hex.EncodeToString(bytes)
	return "pid_" + encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func rawURLBase64(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(value)*8+5)/6)
	var accumulator uint32
	var bits uint
	for _, item := range value {
		accumulator = accumulator<<8 | uint32(item)
		bits += 8
		for bits >= 6 {
			bits -= 6
			result = append(result, alphabet[(accumulator>>bits)&63])
		}
	}
	if bits > 0 {
		result = append(result, alphabet[(accumulator<<(6-bits))&63])
	}
	return string(result)
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func firstError(value, fallback error) error {
	if value != nil {
		return value
	}
	return fallback
}
