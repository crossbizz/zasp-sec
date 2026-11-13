package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// The administrator's approval of the planner's provider account and price
// ceiling for one Environment (PUT /security-agent-planner-pricing). The
// planner is never called without one; the worker reads its pins at use time
// (zasp_authorization80.security_agent_pricing_binding). The statement is the
// authorized form of the release's pricing_admin
// (migrations/baseline/completion.sql, section X8): a browser session with
// fresh authentication and manage_identity on the current Environment. The
// time of fresh authentication is read from the verified session in
// PostgreSQL, never sent by the API.
const currentSecurityAgentPricingAdminSQL = `SELECT zasp_authorization80.security_agent_pricing_admin($1,$2,$3,$4,$5::jsonb)`

// SecurityAgentPlannerPricingPolicy is the closed policy of the release. It
// names a credential by reference and digest only.
type SecurityAgentPlannerPricingPolicy struct {
	Provider               string `json:"provider"`
	Model                  string `json:"model"`
	AccountProfile         string `json:"account_profile"`
	CostUnit               string `json:"cost_unit"`
	MaximumTokens          int64  `json:"maximum_tokens"`
	MaximumCostNanoCredits int64  `json:"maximum_cost_nano_credits"`
	RequestPolicyVersion   string `json:"request_policy_version"`
	RequestTokenLimit      int64  `json:"request_token_limit"`
	CredentialReference    string `json:"credential_reference"`
	CredentialDigest       string `json:"credential_digest"`
	EffectiveAt            string `json:"effective_at"`
	ExpiresAt              string `json:"expires_at"`
}

type SecurityAgentPlannerPricingMutation struct {
	Operation              string
	IdempotencyKey         string
	ExpectedVersion        int64
	ExpectedAccountVersion int64
	Policy                 SecurityAgentPlannerPricingPolicy
}

type SecurityAgentPlannerPricingResult struct {
	PolicyID       string                            `json:"policy_id"`
	Version        int64                             `json:"version"`
	PolicyDigest   string                            `json:"policy_digest"`
	AccountID      string                            `json:"account_id"`
	AccountVersion int64                             `json:"account_version"`
	Disabled       bool                              `json:"disabled"`
	Policy         SecurityAgentPlannerPricingPolicy `json:"policy"`
	MutationID     string                            `json:"mutation_id"`
}

// securityAgentPricingRequest is the closed request of the statement. It has
// no time of fresh authentication: PostgreSQL adds the session's own.
type securityAgentPricingRequest struct {
	OrganizationID         string                            `json:"organization_id"`
	WorkspaceID            string                            `json:"workspace_id"`
	EnvironmentID          string                            `json:"environment_id"`
	ActorID                string                            `json:"actor_id"`
	Operation              string                            `json:"operation"`
	IdempotencyKey         string                            `json:"idempotency_key"`
	ExpectedVersion        int64                             `json:"expected_version"`
	ExpectedAccountVersion int64                             `json:"expected_account_version"`
	Policy                 SecurityAgentPlannerPricingPolicy `json:"policy"`
}

var (
	securityAgentPricingModelPattern     = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
	securityAgentPricingProfilePattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	securityAgentPricingPolicyPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)
	securityAgentPricingReferencePattern = regexp.MustCompile(`^secret_ref_planner/[A-Za-z0-9_/-]{1,220}$`)
	securityAgentPricingDigestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

const securityAgentPricingTimeLayout = "2006-01-02T15:04:05.000000Z"

// validSecurityAgentPricingPolicy states the release's policy rules
// (zasp_sa_multistep_prior.pricing_policy_valid) plus the credential scope:
// the reference must lie below the request's own Environment.
func validSecurityAgentPricingPolicy(policy SecurityAgentPlannerPricingPolicy, organization, workspace, environment string) bool {
	effective, effectiveErr := time.Parse(securityAgentPricingTimeLayout, policy.EffectiveAt)
	expires, expiresErr := time.Parse(securityAgentPricingTimeLayout, policy.ExpiresAt)
	prefix := "secret_ref_planner/" + organization + "/" + workspace + "/" + environment + "/"
	return policy.Provider == "openrouter" && policy.CostUnit == "openrouter_credit" &&
		len(policy.Model) >= 1 && len(policy.Model) <= 128 && securityAgentPricingModelPattern.MatchString(policy.Model) &&
		securityAgentPricingProfilePattern.MatchString(policy.AccountProfile) && securityAgentPricingPolicyPattern.MatchString(policy.RequestPolicyVersion) &&
		securityAgentPricingReferencePattern.MatchString(policy.CredentialReference) && !bytes.Contains([]byte(policy.CredentialReference), []byte("..")) && !bytes.Contains([]byte(policy.CredentialReference), []byte("//")) &&
		len(policy.CredentialReference) > len(prefix) && policy.CredentialReference[:len(prefix)] == prefix &&
		securityAgentPricingDigestPattern.MatchString(policy.CredentialDigest) &&
		policy.MaximumTokens >= 1 && policy.MaximumTokens <= 12000 && policy.MaximumCostNanoCredits >= 1 && policy.MaximumCostNanoCredits <= 1000000000000 &&
		policy.RequestTokenLimit >= 1 && policy.RequestTokenLimit <= 4096 && policy.RequestTokenLimit <= policy.MaximumTokens &&
		effectiveErr == nil && expiresErr == nil && expires.After(effective) && !expires.After(effective.Add(720*time.Hour))
}

func validSecurityAgentPricingRequest(request securityAgentPricingRequest) bool {
	return stringIn(request.Operation, "create", "version", "disable") && validPublicIdempotency(request.IdempotencyKey) &&
		request.ExpectedVersion >= 0 && request.ExpectedVersion <= 999999 && (request.Operation == "create") == (request.ExpectedVersion == 0) &&
		request.ExpectedAccountVersion >= 0 && request.ExpectedAccountVersion <= 1000000 &&
		validSecurityAgentPricingPolicy(request.Policy, request.OrganizationID, request.WorkspaceID, request.EnvironmentID)
}

// securityAgentPricingStatementAllowed admits the pricing approval. It
// reports handled for the statement, so it cannot reach the generic rule
// table. Operation, scope, actor, browser session, fresh authentication and
// the Environment as the allowed target are compared with the checked
// request here; PostgreSQL compares them again with the attested proof.
func securityAgentPricingStatementAllowed(g RequestAuthorization, q string, args []any) (handled, allowed bool) {
	if q != currentSecurityAgentPricingAdminSQL {
		return false, false
	}
	if g.OperationID != "setSecurityAgentPlannerPricing" || g.Collection || len(args) != 5 || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated || g.Identity.FreshAuthExpiresAt.IsZero() {
		return true, false
	}
	o, w, e, actor := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	values, ok := securityAgentWriteStrings(args, 0, 1, 2, 3)
	raw, rawOK := args[4].(json.RawMessage)
	if !ok || !rawOK || len(raw) > 8192 || values[0] != o || values[1] != w || values[2] != e || values[3] != actor || !authorizationNativeTargetAllowed(g, "environment", e) {
		return true, false
	}
	var request securityAgentPricingRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.More() {
		return true, false
	}
	return true, request.OrganizationID == o && request.WorkspaceID == w && request.EnvironmentID == e && request.ActorID == actor && validSecurityAgentPricingRequest(request)
}

// SetSecurityAgentPlannerPricing writes one pricing approval with one
// authorized statement.
func (repository *PostgresRepository) SetSecurityAgentPlannerPricing(ctx context.Context, identity RequestIdentity, input SecurityAgentPlannerPricingMutation) (SecurityAgentPlannerPricingResult, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, false) || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() {
		return SecurityAgentPlannerPricingResult{}, ErrRepositoryOperation
	}
	o, w, e, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	request := securityAgentPricingRequest{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ActorID: actor, Operation: input.Operation, IdempotencyKey: input.IdempotencyKey, ExpectedVersion: input.ExpectedVersion, ExpectedAccountVersion: input.ExpectedAccountVersion, Policy: input.Policy}
	if !validSecurityAgentPricingRequest(request) {
		return SecurityAgentPlannerPricingResult{}, ErrRepositoryOperation
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return SecurityAgentPlannerPricingResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentPricingAdminSQL, o, w, e, actor, json.RawMessage(raw))
	if err != nil {
		return SecurityAgentPlannerPricingResult{}, discoveryProviderError(err)
	}
	var wire struct {
		ContractVersion int    `json:"contract_version"`
		OrganizationID  string `json:"organization_id"`
		WorkspaceID     string `json:"workspace_id"`
		EnvironmentID   string `json:"environment_id"`
		SecurityAgentPlannerPricingResult
	}
	if !exactJSONFields(payload, "account_id", "account_version", "contract_version", "disabled", "environment_id", "mutation_id", "organization_id", "policy", "policy_digest", "policy_id", "version", "workspace_id") || decodeStrictDiscovery(payload, &wire) != nil {
		return SecurityAgentPlannerPricingResult{}, ErrRepositoryUnavailable
	}
	result := wire.SecurityAgentPlannerPricingResult
	if wire.ContractVersion != 61 || wire.OrganizationID != o || wire.WorkspaceID != w || wire.EnvironmentID != e ||
		!validProductID(result.PolicyID) || !validProductID(result.AccountID) || !validProductID(result.MutationID) || !securityAgentPricingDigestPattern.MatchString(result.PolicyDigest) ||
		result.Version != input.ExpectedVersion+1 || result.AccountVersion < 1 || result.AccountVersion > 1000000 || result.Disabled != (input.Operation == "disable") || result.Policy != input.Policy {
		return SecurityAgentPlannerPricingResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

// SecurityAgentPricingAuthority writes the pricing approval.
type SecurityAgentPricingAuthority interface {
	SetSecurityAgentPlannerPricing(context.Context, RequestIdentity, SecurityAgentPlannerPricingMutation) (SecurityAgentPlannerPricingResult, error)
}

type securityAgentPricingHTTPHandler struct {
	authority SecurityAgentPricingAuthority
	clock     func() time.Time
}

func NewSecurityAgentPricingHTTPHandler(authority SecurityAgentPricingAuthority, clock func() time.Time) (http.Handler, error) {
	if nilInterface(authority) || clock == nil || clock().IsZero() {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentPricingHTTPHandler{authority: authority, clock: clock}, nil
}

func (handler *securityAgentPricingHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	routed, routedOK := RoutedOperationFromRequest(request)
	identity, ok := IdentityFromRequest(request)
	if !routedOK || routed.OperationID != "setSecurityAgentPlannerPricing" {
		writeProductionError(writer, request, ErrRepositoryNotFound)
		return
	}
	now := handler.clock().UTC()
	if !ok || identity.CredentialKind != CredentialBrowserSession || !identity.FreshAuthenticated || identity.FreshAuthExpiresAt.IsZero() || !identity.FreshAuthExpiresAt.After(now) {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	idempotencyKey, expectedVersion, headersOK := discoveryMutationHeaders(request, true)
	var input struct {
		EnvironmentID          string                            `json:"environment_id"`
		Operation              string                            `json:"operation"`
		ExpectedAccountVersion *int64                            `json:"expected_account_version"`
		Policy                 SecurityAgentPlannerPricingPolicy `json:"policy"`
	}
	if request.Method != http.MethodPut || request.URL.RawQuery != "" || !validSecurityAgentFreshAuthentication(now, identity.FreshAuthExpiresAt) || !exactHeaderValue(request.Header.Values("X-Zasp-Fresh-Auth"), "confirmed") || !headersOK ||
		decodeProductionJSON(request, &input) != nil || input.EnvironmentID != identity.Scope.EnvironmentID().String() || input.ExpectedAccountVersion == nil {
		writeProductionError(writer, request, ErrRepositoryOperation)
		return
	}
	result, err := handler.authority.SetSecurityAgentPlannerPricing(request.Context(), identity, SecurityAgentPlannerPricingMutation{Operation: input.Operation, IdempotencyKey: idempotencyKey, ExpectedVersion: expectedVersion, ExpectedAccountVersion: *input.ExpectedAccountVersion, Policy: input.Policy})
	if err != nil {
		writeSecurityAgentDefinitionError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(result.Version, 10)+`"`)
	writer.Header().Set("X-Audit-ID", result.MutationID)
	writeJSONValue(writer, request, http.StatusOK, result, nil)
}

// NewSecurityAgentPricingWorkflowSurface routes the pricing approval to its
// handler and everything else to the surface it wraps.
func NewSecurityAgentPricingWorkflowSurface(workflow, pricing http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(pricing) {
		return nil, ErrRepositoryConfiguration
	}
	return &securityAgentPricingWorkflowSurface{workflow: workflow, pricing: pricing}, nil
}

type securityAgentPricingWorkflowSurface struct {
	workflow http.Handler
	pricing  http.Handler
}

func (surface *securityAgentPricingWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if routed, ok := RoutedOperationFromRequest(request); ok && routed.OperationID == "setSecurityAgentPlannerPricing" {
		surface.pricing.ServeHTTP(writer, request)
		return
	}
	surface.workflow.ServeHTTP(writer, request)
}
