package apiserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

// Provider token types accepted by the session callback. The value names the
// Stytch redirect token type, never a product credential.
const (
	ProviderTokenTypeOAuth     = "oauth"
	ProviderTokenTypeMagicLink = "multi_tenant_magic_links"
)

type providerTokenTypeKey struct{}

// WithProviderTokenType records which provider exchange a callback token
// belongs to. An unknown value is kept so the authenticator refuses it; the
// absence of a value means the original OAuth exchange.
func WithProviderTokenType(ctx context.Context, tokenType string) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, providerTokenTypeKey{}, tokenType)
}

// ProviderTokenTypeFromContext returns the recorded callback token type, or
// OAuth when the caller recorded none.
func ProviderTokenTypeFromContext(ctx context.Context) string {
	if ctx == nil {
		return ProviderTokenTypeOAuth
	}
	if value, ok := ctx.Value(providerTokenTypeKey{}).(string); ok {
		return value
	}
	return ProviderTokenTypeOAuth
}

// ValidProviderTokenType reports whether the callback may name this type.
func ValidProviderTokenType(tokenType string) bool {
	_, ok := stytchTokenExchanges[tokenType]
	return ok
}

type stytchTokenExchange struct{ path, field string }

// Each accepted redirect token type has exactly one provider exchange. Both
// return a session JWT that is then verified through the unchanged session
// authentication call, so every type resolves the same provider principal.
var stytchTokenExchanges = map[string]stytchTokenExchange{
	ProviderTokenTypeOAuth:     {path: "/v1/b2b/oauth/authenticate", field: "oauth_token"},
	ProviderTokenTypeMagicLink: {path: "/v1/b2b/magic_links/authenticate", field: "magic_links_token"},
}

// NewStytchDirectory builds the provider adapter used by the operator
// bootstrap. inviteRedirectURL must be the product callback of the deployment
// the invited administrator will sign in to.
func NewStytchDirectory(baseURL, project, secret, inviteRedirectURL string, timeout time.Duration, now func() time.Time) (*platformidentity.Adapter, error) {
	parsed, err := url.Parse(baseURL)
	redirect, redirectErr := url.Parse(inviteRedirectURL)
	if err != nil || !validProviderBaseURL(parsed) || !boundedSecret(project) || !boundedSecret(secret) || timeout <= 0 || timeout > 30*time.Second || now == nil ||
		redirectErr != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.User != nil || redirect.Path != "/auth/callback" || redirect.RawQuery != "" || redirect.Fragment != "" {
		return nil, ErrRepositoryConfiguration
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("identity redirect rejected") }}
	adapter, err := platformidentity.NewAdapter(&stytchSessionDriver{baseURL: parsed, client: client, project: project, secret: secret, inviteRedirectURL: redirect.String()}, now)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return adapter, nil
}

type stytchOrganization struct {
	Reference      string   `json:"organization_id"`
	Name           string   `json:"organization_name"`
	Slug           string   `json:"organization_slug"`
	AllowedDomains []string `json:"email_allowed_domains"`
}

type stytchMember struct {
	Reference             string `json:"member_id"`
	OrganizationReference string `json:"organization_id"`
	Email                 string `json:"email_address"`
	Status                string `json:"status"`
}

type stytchSearchQuery struct {
	Operator string                `json:"operator"`
	Operands []stytchSearchOperand `json:"operands"`
}

type stytchSearchOperand struct {
	Name  string   `json:"filter_name"`
	Value []string `json:"filter_value"`
}

// stytchOrganizationSlug derives the one provider slug for a customer domain,
// so repeated bootstraps of the same domain resolve the same Organization.
func stytchOrganizationSlug(domainName string) string {
	return strings.ReplaceAll(domainName, ".", "-")
}

func (organization stytchOrganization) driverOrganization(domainName string) (platformidentity.DriverOrganization, error) {
	if !validExactStytchReference(organization.Reference, "organization-") || !validStytchName(organization.Name) || domainName == "" {
		return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
	}
	for _, allowed := range organization.AllowedDomains {
		if allowed == domainName {
			return platformidentity.DriverOrganization{Reference: organization.Reference, Name: organization.Name, Domain: domainName}, nil
		}
	}
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}

// GetOrganization has no production caller: sign-in resolves the Organization
// from the verified session, and the bootstrap resolves it by customer domain.
func (*stytchSessionDriver) GetOrganization(context.Context, string) (platformidentity.DriverOrganization, error) {
	return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
}

// EnsureOrganization resolves the provider Organization for a customer domain
// or creates it. An existing Organization with the derived slug must carry the
// requested name and allow the requested domain; a mismatch is refused rather
// than adopted or rewritten.
func (driver *stytchSessionDriver) EnsureOrganization(ctx context.Context, name, domainName string) (platformidentity.DriverOrganization, error) {
	if !validStytchName(name) || domainName == "" || len(domainName) > 253 {
		return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
	}
	slug := stytchOrganizationSlug(domainName)
	var found struct {
		StatusCode    int                  `json:"status_code"`
		Organizations []stytchOrganization `json:"organizations"`
	}
	search := map[string]any{"limit": 2, "query": stytchSearchQuery{Operator: "AND", Operands: []stytchSearchOperand{{Name: "organization_slugs", Value: []string{slug}}}}}
	if err := driver.doJSON(ctx, http.MethodPost, "/v1/b2b/organizations/search", search, &found); err != nil || found.StatusCode != http.StatusOK || len(found.Organizations) > 1 {
		return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
	}
	if len(found.Organizations) == 1 {
		existing := found.Organizations[0]
		if existing.Slug != slug || existing.Name != name {
			return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
		}
		return existing.driverOrganization(domainName)
	}
	var created struct {
		StatusCode   int                `json:"status_code"`
		Organization stytchOrganization `json:"organization"`
	}
	// Invitations are operator or administrator initiated; nobody joins by
	// merely holding an address in the allowed domain.
	body := map[string]any{
		"organization_name": name, "organization_slug": slug, "email_allowed_domains": []string{domainName},
		"email_invites": "ALL_ALLOWED", "email_jit_provisioning": "NOT_ALLOWED",
	}
	if err := driver.doJSON(ctx, http.MethodPost, "/v1/b2b/organizations", body, &created); err != nil || created.StatusCode != http.StatusOK || created.Organization.Slug != slug || created.Organization.Name != name {
		return platformidentity.DriverOrganization{}, platformidentity.ErrProvider
	}
	return created.Organization.driverOrganization(domainName)
}

// InviteAdmin returns the provider member for the designated first
// administrator. An existing member is returned without sending another
// invitation, which keeps repeated bootstraps idempotent; otherwise the
// provider sends its invitation and no password is ever created.
func (driver *stytchSessionDriver) InviteAdmin(ctx context.Context, organization, email string) (platformidentity.DriverInvitation, error) {
	if driver == nil || !validExactStytchReference(organization, "organization-") || email == "" || len(email) > 254 || driver.inviteRedirectURL == "" {
		return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
	}
	var found struct {
		StatusCode int            `json:"status_code"`
		Members    []stytchMember `json:"members"`
	}
	search := map[string]any{"organization_ids": []string{organization}, "limit": 2, "query": stytchSearchQuery{Operator: "AND", Operands: []stytchSearchOperand{{Name: "member_emails", Value: []string{email}}}}}
	if err := driver.doJSON(ctx, http.MethodPost, "/v1/b2b/organizations/members/search", search, &found); err != nil || found.StatusCode != http.StatusOK || len(found.Members) > 1 {
		return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
	}
	if len(found.Members) == 1 {
		return found.Members[0].driverInvitation(organization, email)
	}
	var invited struct {
		StatusCode int          `json:"status_code"`
		Member     stytchMember `json:"member"`
	}
	body := map[string]string{"organization_id": organization, "email_address": email, "invite_redirect_url": driver.inviteRedirectURL}
	if err := driver.doJSON(ctx, http.MethodPost, "/v1/b2b/magic_links/email/invite", body, &invited); err != nil || invited.StatusCode != http.StatusOK {
		return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
	}
	return invited.Member.driverInvitation(organization, email)
}

func (member stytchMember) driverInvitation(organization, email string) (platformidentity.DriverInvitation, error) {
	if !validExactStytchReference(member.Reference, "member-") || member.OrganizationReference != organization || member.Email != email ||
		member.Status != "active" && member.Status != "invited" && member.Status != "pending" {
		return platformidentity.DriverInvitation{}, platformidentity.ErrProvider
	}
	return platformidentity.DriverInvitation{MemberReference: member.Reference, OrganizationReference: organization, Email: email}, nil
}
