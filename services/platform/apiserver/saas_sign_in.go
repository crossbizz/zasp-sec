package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Sign-in to a SaaS platform from the product.
//
// A saas integration that names no Nango connection yet (configuration
// platform and tenant_id) is connected by a person signing in to the
// platform. The two existing connector operations serve it:
//
//   - authorizeIntegration starts the sign-in and answers the provider's
//     authorization address, as it does for an OAuth connector;
//   - completeIntegrationOAuthCallback takes the provider's answer, lets
//     Nango finish the exchange, requires the connection to reach the tenant
//     the integration names, and sends the browser back to the Integrations
//     page with the reference of the connection Nango created.
//
// The sign-in ends in that reference and changes nothing else. The page
// stores it in the integration with an ordinary update, and the integration
// is then authorized by reference, which has the fresh authentication and
// the tenant check of every reference authorization. The product never
// receives a provider token.
//
// The statements are functions of completion.sql section ws6_saas_sign_in.
const (
	postgresSaaSSignInReadySQL       = `SELECT to_jsonb(to_regprocedure('zasp_authorization80.saas_sign_in_finish(text,text,text,text,text,text,text)') IS NOT NULL)`
	postgresSaaSSignInIntegrationSQL = `SELECT zasp_authorization80.saas_sign_in_integration($1,$2,$3,$4,$5)`
	postgresSaaSSignInStartSQL       = `SELECT zasp_authorization80.saas_sign_in_start($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresSaaSSignInConsumeSQL     = `SELECT zasp_authorization80.saas_sign_in_consume($1,$2,$3,$4,$5,$6)`
	postgresSaaSSignInFinishSQL      = `SELECT zasp_authorization80.saas_sign_in_finish($1,$2,$3,$4,$5,$6,$7)`

	// saasSignInReturnPath is where the browser is sent after the callback.
	saasSignInReturnPath = "/integrations"
)

// ErrSaaSSignInTenantMismatch: the person signed in to another tenant than
// the one the integration names.
var ErrSaaSSignInTenantMismatch = errors.New("saas sign-in reached another tenant")

// SaaSSignInIntegration is a saas integration that waits for its sign-in.
type SaaSSignInIntegration struct {
	Platform string `json:"platform"`
	TenantID string `json:"tenant_id"`
	Version  int64  `json:"version"`
	Status   string `json:"status"`
}

// SaaSSignInAttempt is the sign-in a callback belongs to.
type SaaSSignInAttempt struct {
	ID            string `json:"id"`
	IntegrationID string `json:"integration_id"`
	Platform      string `json:"platform"`
	TenantID      string `json:"tenant_id"`
	// Accepted is false when the state was presented late, a second time,
	// or by another person or browser session than the one that started.
	Accepted bool `json:"accepted"`
}

type SaaSSignInStart struct {
	IntegrationID, AttemptID   string
	SessionDigest, StateDigest []byte
	ExpiresAt                  time.Time
	IntegrationVersion         int64
}

// SaaSSignInStore records sign-ins. found is false when the integration or
// the state is not one of a saas sign-in; the connector handler then serves
// the request as before.
type SaaSSignInStore interface {
	Integration(ctx context.Context, identity RequestIdentity, integrationID string) (value SaaSSignInIntegration, found bool, err error)
	Start(ctx context.Context, identity RequestIdentity, input SaaSSignInStart) error
	Consume(ctx context.Context, identity RequestIdentity, stateDigest, sessionDigest []byte) (attempt SaaSSignInAttempt, found bool, err error)
	Finish(ctx context.Context, identity RequestIdentity, attemptID, outcome, connectionReference string) error
}

type SaaSSignInRequest struct {
	Scope                                 domain.Scope
	PrincipalID, IntegrationID, AttemptID string
	Platform, TenantID                    string
}

type SaaSSignInCompletion struct {
	SaaSSignInRequest
	State, Code string
}

// SaaSSignInProvider runs the sign-in at Nango.
type SaaSSignInProvider interface {
	// Available reports whether a person can sign in to the platform here.
	Available(ctx context.Context, platform string) bool
	// Start asks Nango for the provider's authorization address.
	Start(ctx context.Context, request SaaSSignInRequest) (ConnectorAuthorizationTarget, error)
	// Complete lets Nango finish the exchange and returns the reference of
	// the connection it created. It returns ErrSaaSSignInTenantMismatch when
	// that connection reaches another tenant than request.TenantID; the
	// connection is then removed.
	Complete(ctx context.Context, request SaaSSignInCompletion) (connectionReference string, err error)
}

// SaaSSignIn is the optional sign-in capability of the connector handler.
type SaaSSignIn struct {
	Store    SaaSSignInStore
	Provider SaaSSignInProvider
}

type SaaSSignInRepository struct{ database JSONDatabase }

// NewSaaSSignInRepository returns the repository, or ErrRepositoryNotFound
// when the database does not have the sign-in section yet. It is called at
// startup, before requests exist.
func NewSaaSSignInRepository(ctx context.Context, database JSONDatabase) (*SaaSSignInRepository, error) {
	if nilInterface(database) || ctx == nil {
		return nil, ErrRepositoryConfiguration
	}
	payload, err := database.QueryJSON(ctx, postgresSaaSSignInReadySQL)
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if !ready {
		return nil, ErrRepositoryNotFound
	}
	return &SaaSSignInRepository{database: database}, nil
}

func (repository *SaaSSignInRepository) scopeArguments(identity RequestIdentity) []any {
	return []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
}

func (repository *SaaSSignInRepository) Integration(ctx context.Context, identity RequestIdentity, integrationID string) (SaaSSignInIntegration, bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validProductID(integrationID) {
		return SaaSSignInIntegration{}, false, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSSignInIntegrationSQL, append(repository.scopeArguments(identity), integrationID)...)
	if err != nil {
		return SaaSSignInIntegration{}, false, discoveryProviderError(err)
	}
	var envelope struct {
		Found bool `json:"found"`
		SaaSSignInIntegration
	}
	if decodeStrictDiscovery(payload, &envelope) != nil {
		return SaaSSignInIntegration{}, false, ErrRepositoryUnavailable
	}
	if !envelope.Found {
		return SaaSSignInIntegration{}, false, nil
	}
	value := envelope.SaaSSignInIntegration
	if !saasPlatformPattern.MatchString(value.Platform) || !saasTenantPattern.MatchString(value.TenantID) || strings.Contains(value.TenantID, "..") || value.Version < 1 {
		return SaaSSignInIntegration{}, false, ErrRepositoryUnavailable
	}
	return value, true, nil
}

func (repository *SaaSSignInRepository) Start(ctx context.Context, identity RequestIdentity, input SaaSSignInStart) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validProductID(input.IntegrationID) || !validProductID(input.AttemptID) ||
		len(input.SessionDigest) != 32 || len(input.StateDigest) != 32 || input.ExpiresAt.IsZero() || input.IntegrationVersion < 1 {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSSignInStartSQL, append(repository.scopeArguments(identity), input.IntegrationID, input.AttemptID, input.SessionDigest, input.StateDigest, input.ExpiresAt.UTC(), input.IntegrationVersion)...)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		ID            string    `json:"id"`
		IntegrationID string    `json:"integration_id"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != input.AttemptID || result.IntegrationID != input.IntegrationID {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SaaSSignInRepository) Consume(ctx context.Context, identity RequestIdentity, stateDigest, sessionDigest []byte) (SaaSSignInAttempt, bool, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || len(stateDigest) != 32 || len(sessionDigest) != 32 {
		return SaaSSignInAttempt{}, false, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSSignInConsumeSQL, append(repository.scopeArguments(identity), stateDigest, sessionDigest)...)
	if err != nil {
		return SaaSSignInAttempt{}, false, discoveryProviderError(err)
	}
	var envelope struct {
		Found bool `json:"found"`
		SaaSSignInAttempt
	}
	if decodeStrictDiscovery(payload, &envelope) != nil {
		return SaaSSignInAttempt{}, false, ErrRepositoryUnavailable
	}
	if !envelope.Found {
		return SaaSSignInAttempt{}, false, nil
	}
	attempt := envelope.SaaSSignInAttempt
	if !validProductID(attempt.ID) || !validProductID(attempt.IntegrationID) || attempt.Accepted && (!saasPlatformPattern.MatchString(attempt.Platform) || !saasTenantPattern.MatchString(attempt.TenantID) || strings.Contains(attempt.TenantID, "..")) {
		return SaaSSignInAttempt{}, false, ErrRepositoryUnavailable
	}
	return attempt, true, nil
}

func (repository *SaaSSignInRepository) Finish(ctx context.Context, identity RequestIdentity, attemptID, outcome, connectionReference string) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !validProductID(attemptID) ||
		(outcome == "completed") != saasConnectionReferencePattern.MatchString(connectionReference) || outcome != "completed" && connectionReference != "" {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSaaSSignInFinishSQL, append(repository.scopeArguments(identity), attemptID, outcome, connectionReference)...)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		ID            string `json:"id"`
		IntegrationID string `json:"integration_id"`
		Status        string `json:"status"`
	}
	wantStatus := "failed"
	if outcome == "completed" {
		wantStatus = "completed"
	}
	if decodeStrictDiscovery(payload, &result) != nil || result.ID != attemptID || result.Status != wantStatus {
		return ErrRepositoryUnavailable
	}
	return nil
}

var _ SaaSSignInStore = (*SaaSSignInRepository)(nil)

// authorizeSaaS starts a sign-in when the integration is a saas integration
// that waits for one. It reports whether it served the request.
func (handler *connectorHTTPHandler) authorizeSaaS(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, integrationID, idempotencyKey string, sessionDigest []byte) bool {
	if handler.saasSignIn == nil {
		return false
	}
	integration, found, err := handler.saasSignIn.Store.Integration(request.Context(), identity, integrationID)
	if err != nil {
		writeProductionError(writer, request, err)
		return true
	}
	if !found {
		return false
	}
	if !stringIn(integration.Status, "configured", "pending_authorization") {
		writeProductionError(writer, request, ErrRepositoryConflict)
		return true
	}
	if !handler.saasSignIn.Provider.Available(request.Context(), integration.Platform) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return true
	}
	now := handler.now().UTC()
	limit := now.Add(10 * time.Minute)
	attemptID := connectorDeterministicID(identity.Scope, identity.PrincipalID.String(), integrationID, idempotencyKey, "saas-sign-in")
	target, err := handler.saasSignIn.Provider.Start(request.Context(), SaaSSignInRequest{Scope: identity.Scope, PrincipalID: identity.PrincipalID.String(), IntegrationID: integrationID, AttemptID: attemptID, Platform: integration.Platform, TenantID: integration.TenantID})
	if err != nil || !connectorOAuthValuePattern.MatchString(target.State) || !target.ExpiresAt.After(now) || target.ExpiresAt.After(limit) || !validConnectorAuthorizationTarget(target.URL, target.State) {
		writeProductionError(writer, request, ErrRepositoryUnavailable)
		return true
	}
	stateDigest := connectorDigest(target.State)
	if err := handler.saasSignIn.Store.Start(request.Context(), identity, SaaSSignInStart{IntegrationID: integrationID, AttemptID: attemptID, SessionDigest: sessionDigest, StateDigest: stateDigest, ExpiresAt: target.ExpiresAt.UTC(), IntegrationVersion: integration.Version}); err != nil {
		writeProductionError(writer, request, err)
		return true
	}
	payload, err := json.Marshal(map[string]any{"authorization_attempt_id": attemptID, "authorization_url": target.URL, "expires_at": target.ExpiresAt.UTC()})
	writeProductionResponse(writer, request, http.StatusOK, payload, err)
	return true
}

// callbackSaaS finishes a sign-in when the state belongs to one. It reports
// whether it served the request.
func (handler *connectorHTTPHandler) callbackSaaS(writer http.ResponseWriter, request *http.Request, identity RequestIdentity, query url.Values, providerDenial string, stateDigest, sessionDigest []byte) bool {
	if handler.saasSignIn == nil {
		return false
	}
	attempt, found, err := handler.saasSignIn.Store.Consume(request.Context(), identity, stateDigest, sessionDigest)
	if err != nil {
		writeProductionError(writer, request, err)
		return true
	}
	if !found {
		return false
	}
	if !attempt.Accepted {
		writeProductionError(writer, request, ErrRepositoryConflict)
		return true
	}
	fail := func(code string) {
		if err := handler.saasSignIn.Store.Finish(request.Context(), identity, attempt.ID, code, ""); err != nil {
			writeProductionError(writer, request, err)
			return
		}
		http.Redirect(writer, request, saasSignInReturn(attempt.IntegrationID, "saas_sign_in_error", code), http.StatusSeeOther)
	}
	if providerDenial != "" {
		fail("provider_" + providerDenial)
		return true
	}
	reference, err := handler.saasSignIn.Provider.Complete(request.Context(), SaaSSignInCompletion{
		SaaSSignInRequest: SaaSSignInRequest{Scope: identity.Scope, PrincipalID: identity.PrincipalID.String(), IntegrationID: attempt.IntegrationID, AttemptID: attempt.ID, Platform: attempt.Platform, TenantID: attempt.TenantID},
		State:             query.Get("state"), Code: query.Get("code"),
	})
	switch {
	case errors.Is(err, ErrSaaSSignInTenantMismatch):
		fail("tenant_mismatch")
		return true
	case err != nil || !saasConnectionReferencePattern.MatchString(reference):
		fail("provider_unavailable")
		return true
	}
	if err := handler.saasSignIn.Store.Finish(request.Context(), identity, attempt.ID, "completed", reference); err != nil {
		writeProductionError(writer, request, err)
		return true
	}
	// The reference names a connection; it is not a credential. The page
	// stores it in the integration with an ordinary update.
	http.Redirect(writer, request, saasSignInReturn(attempt.IntegrationID, "saas_connection", strings.TrimPrefix(reference, "ref:nango/connection/")), http.StatusSeeOther)
	return true
}

func saasSignInReturn(integrationID, key, value string) string {
	return saasSignInReturnPath + "?" + url.Values{"saas_sign_in": {integrationID}, key: {value}}.Encode()
}
