package apiserver

import (
	"encoding/json"
	"net/http"
	"time"
)

// How long an API token may live (completion.sql, section WS10c).
//
//	GET /api/v1/admin/api-token-policy   getAPITokenPolicy
//	PUT /api/v1/admin/api-token-policy   putAPITokenPolicy
//
// A token's expiry is chosen when it is created. Without a choice it is 24
// hours, as before. The longest lifetime depends on what the token may do:
//
//   - a token that holds decide_guardrails and nothing else can ask for
//     guardrail decisions and can read nothing. It lives in a gateway's
//     configuration and may live a year;
//   - every other token reads the Environment, and with a manage permission
//     changes it, so a leaked one is worth more for longer. It may live 90
//     days.
//
// The administrators of an Environment may lower both limits with one number
// of days. PostgreSQL enforces the limits where the token is written; the
// handler refuses a request above the fixed limits before it gets there.
const (
	currentAPITokenPolicySQL    = `SELECT zasp_authorization80.api_token_policy($1,$2,$3)`
	currentAPITokenSetPolicySQL = `SELECT zasp_authorization80.api_token_set_policy($1,$2,$3,$4,$5,$6,$7,$8)`

	// APITokenDefaultLifetime is the lifetime of a token created without an
	// expiry.
	APITokenDefaultLifetime = 24 * time.Hour
	// APITokenDecisionMaxLifetimeDays is the longest lifetime of a token that
	// holds decide_guardrails only; APITokenMaxLifetimeDays of any other.
	APITokenDecisionMaxLifetimeDays = 365
	APITokenMaxLifetimeDays         = 90

	// apiTokenExpiryTolerance is the clock difference allowed between the
	// caller that computed an expiry and the server that checks it.
	apiTokenExpiryTolerance = 5 * time.Minute
)

// apiTokenLifetimeCeilingDays is the fixed limit for a token with these
// permissions, before the Environment's own limit.
func apiTokenLifetimeCeilingDays(permissions []string) int {
	if len(permissions) == 1 && permissions[0] == PermissionDecideGuardrails {
		return APITokenDecisionMaxLifetimeDays
	}
	return APITokenMaxLifetimeDays
}

// APITokenPolicy is the API token lifetime setting of an Environment.
// Version is 0 while no limit was saved; MaxLifetimeDays is then 365, which
// lowers nothing. The two effective limits are what a new token may ask for.
type APITokenPolicy struct {
	EnvironmentID                string     `json:"environment_id"`
	MaxLifetimeDays              int        `json:"max_lifetime_days"`
	Version                      int64      `json:"version"`
	UpdatedAt                    *time.Time `json:"updated_at"`
	DefaultLifetimeDays          int        `json:"default_lifetime_days"`
	DecisionTokenMaxLifetimeDays int        `json:"decision_token_max_lifetime_days"`
	TokenMaxLifetimeDays         int        `json:"token_max_lifetime_days"`
}

func decodeAPITokenPolicy(raw json.RawMessage, environment string, extra ...string) (APITokenPolicy, error) {
	fields := append([]string{"decision_token_max_lifetime_days", "default_lifetime_days", "environment_id", "max_lifetime_days", "token_max_lifetime_days", "updated_at", "version"}, extra...)
	var policy APITokenPolicy
	if !exactJSONFields(raw, fields...) || json.Unmarshal(raw, &policy) != nil || policy.EnvironmentID != environment || policy.Version < 0 || policy.Version > 1000000 || (policy.Version == 0) != (policy.UpdatedAt == nil) ||
		policy.MaxLifetimeDays < 1 || policy.MaxLifetimeDays > 365 || policy.Version == 0 && policy.MaxLifetimeDays != 365 || policy.DefaultLifetimeDays != 1 ||
		policy.DecisionTokenMaxLifetimeDays != min(APITokenDecisionMaxLifetimeDays, policy.MaxLifetimeDays) || policy.TokenMaxLifetimeDays != min(APITokenMaxLifetimeDays, policy.MaxLifetimeDays) {
		return APITokenPolicy{}, ErrRepositoryUnavailable
	}
	if policy.UpdatedAt != nil {
		value := policy.UpdatedAt.UTC()
		policy.UpdatedAt = &value
	}
	return policy, nil
}

type apiTokenPolicyHTTPHandler struct {
	database     JSONDatabase
	newProductID func() (string, error)
}

func (handler *apiTokenPolicyHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request, operation string) {
	writer.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(request)
	if !ok || identity.CredentialKind != CredentialBrowserSession {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	scope := identity.Scope
	organization, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	switch operation {
	case "getAPITokenPolicy":
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		raw, err := handler.database.QueryJSON(request.Context(), currentAPITokenPolicySQL, organization, workspace, environment)
		if err != nil {
			writeProductionError(writer, request, discoveryProviderError(err))
			return
		}
		policy, err := decodeAPITokenPolicy(raw, environment)
		if err != nil {
			writeProductionError(writer, request, err)
			return
		}
		writer.Header().Set("ETag", quoteVersion(policy.Version))
		writeJSONValue(writer, request, http.StatusOK, policy, nil)
	case "putAPITokenPolicy":
		// The optimistic version makes a repeated request safe: the second one
		// names a version that is no longer current and is refused.
		_, expectedVersion, valid := discoveryMutationHeaders(request, true)
		var input struct {
			MaxLifetimeDays *int `json:"max_lifetime_days"`
		}
		if !identity.FreshAuthenticated {
			writeWorkflowMutationError(writer, request, ErrRepositoryAuthorization)
			return
		}
		if request.Method != http.MethodPut || request.URL.RawQuery != "" || !valid || decodeProductionJSON(request, &input) != nil || input.MaxLifetimeDays == nil || *input.MaxLifetimeDays < 1 || *input.MaxLifetimeDays > 365 {
			writeProductionError(writer, request, ErrRepositoryOperation)
			return
		}
		auditID, idErr := handler.newProductID()
		correlationID := correlationIDFromContext(request.Context())
		if idErr != nil || !validProductID(auditID) || !validProductID(correlationID) || auditID == correlationID {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		raw, err := handler.database.QueryJSON(request.Context(), currentAPITokenSetPolicySQL, organization, workspace, environment, identity.PrincipalID.String(), *input.MaxLifetimeDays, expectedVersion, auditID, correlationID)
		if err != nil {
			writeProductionError(writer, request, discoveryProviderError(err))
			return
		}
		policy, err := decodeAPITokenPolicy(raw, environment, "audit_id", "correlation_id")
		if err != nil || policy.Version != expectedVersion+1 || policy.MaxLifetimeDays != *input.MaxLifetimeDays {
			writeProductionError(writer, request, ErrRepositoryUnavailable)
			return
		}
		writeDiscoveryMutationHeaders(writer, policy.Version, auditID, "")
		writeJSONValue(writer, request, http.StatusOK, policy, nil)
	default:
		writeProductionError(writer, request, ErrRepositoryNotFound)
	}
}

// The two policy statements belong to a browser session's request on its own
// Environment; the write also to a freshly authenticated one.
func apiTokenPolicyEnvironmentAllowed(g RequestAuthorization, _ []any) bool {
	return g.PathParameters["id"] == "" && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
}

func apiTokenSetPolicyAllowed(g RequestAuthorization, args []any) bool {
	days, daysOK := args[4].(int)
	version, versionOK := args[5].(int64)
	audit, auditOK := args[6].(string)
	correlation, correlationOK := args[7].(string)
	return daysOK && versionOK && auditOK && correlationOK && days >= 1 && days <= 365 && version >= 0 && version <= 1000000 && validProductID(audit) && validProductID(correlation) && apiTokenPolicyEnvironmentAllowed(g, args)
}

func init() {
	productStatementRules[currentAPITokenPolicySQL] = productStatementRule{operations: []string{"getAPITokenPolicy"}, arguments: 3, scope: 1, browserOnly: true, check: apiTokenPolicyEnvironmentAllowed}
	productStatementRules[currentAPITokenSetPolicySQL] = productStatementRule{operations: []string{"putAPITokenPolicy"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, fresh: true, check: apiTokenSetPolicyAllowed}
}
