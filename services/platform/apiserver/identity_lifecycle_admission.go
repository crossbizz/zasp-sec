package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type identityAttempt struct {
	AttemptID   string `json:"attempt_id"`
	StateDigest string `json:"state_digest"`
	ReturnPath  string `json:"return_path"`
}

func (r *PostgresRepository) authenticateNativePAT(ctx context.Context, credential Credential) (RequestIdentity, error) {
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	var result RequestIdentity
	_, err = d.identityTransaction(ctx, identityPAT, []any{credential.Value}, func(b json.RawMessage) error {
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || len(fields) != 7 {
			return ErrRepositoryAuthentication
		}
		v, err := identityFromJSON(b, false)
		if err != nil || len(v.Permissions) != 0 || v.CSRFToken != "" || v.FreshAuthenticated || !v.FreshAuthExpiresAt.IsZero() {
			return ErrRepositoryAuthentication
		}
		v.CredentialKind = CredentialBearerToken
		if err := bindAuthorizationCredential(&v, credential, b); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return RequestIdentity{}, ErrRepositoryAuthentication
	}
	return result, nil
}

type identityRuntimeMetadata struct {
	Session authorization.IdentityRegistration `json:"session"`
	Webhook authorization.IdentityRegistration `json:"webhook"`
}
type identitySessionIssuer struct {
	key            *authorization.IdentitySessionKey
	webhookVersion string
	deployment     authorization.IdentityDeployment
	repository     *PostgresRepository
}
type identityAdmissionContextKey struct{}
type preparedIdentitySession struct {
	repository      *PostgresRepository
	external        platformidentity.ExternalPrincipal
	envelope        []byte
	token, csrf     string
	grant           SessionGrant
	organizationPin string
}

func (*preparedIdentitySession) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[prepared identity session]"))
}
func (g SessionGrant) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "SessionGrant{principal:%s, scope:%s, prepared:%t}", g.PrincipalID.String(), g.Scope.OrganizationID().String(), g.nativeAdmission != nil)
}

func (p *RepositoryIdentityProvider) RequireNativeIdentity(seed []byte, deployment authorization.IdentityDeployment) error {
	if p == nil {
		return ErrRepositoryConfiguration
	}
	auth, ok := p.authenticator.(*StytchOAuthAuthenticator)
	if !ok || auth.project != deployment.ProjectID || auth.baseURL.String() != deployment.ProviderBaseURL || p.organizationReference != deployment.ConfiguredOrganization {
		return ErrRepositoryConfiguration
	}
	repo, ok := p.resolver.(*PostgresRepository)
	if !ok || !repo.currentAuthorization || p.states != repo {
		return ErrRepositoryConfiguration
	}
	if _, err := deployment.Audience(); err != nil {
		return ErrRepositoryConfiguration
	}
	key, err := authorization.NewIdentitySessionKey(seed)
	if err != nil {
		return ErrRepositoryConfiguration
	}
	webhook, err := authorization.NewIdentityWebhookKey(seed)
	if err != nil {
		return ErrRepositoryConfiguration
	}
	p.identityIssuer = &identitySessionIssuer{key: key, webhookVersion: webhook.Version(), deployment: deployment, repository: repo}
	return nil
}

func (r *PostgresRepository) identityMetadata(ctx context.Context) (identityRuntimeMetadata, error) {
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return identityRuntimeMetadata{}, err
	}
	var m identityRuntimeMetadata
	_, err = d.identityTransaction(ctx, identityMetadata, nil, func(b json.RawMessage) error { return decodeStrictIdentityAdministration(b, &m) })
	return m, err
}
func (i *identitySessionIssuer) ready(ctx context.Context) (identityRuntimeMetadata, error) {
	if i == nil {
		return identityRuntimeMetadata{}, ErrRepositoryUnavailable
	}
	return readyIdentityRegistrations(ctx, i.repository, i.deployment, i.key.Version(), i.webhookVersion)
}
func readyIdentityRegistrations(ctx context.Context, repository *PostgresRepository, deployment authorization.IdentityDeployment, sessionVersion, webhookVersion string) (identityRuntimeMetadata, error) {
	m, err := repository.identityMetadata(ctx)
	audience, aerr := deployment.Audience()
	valid := func(r authorization.IdentityRegistration, version string) bool {
		return r.Version == version && r.Epoch > 0 && r.Audience == audience && r.Project == deployment.ProjectID && r.APIPrincipal != "" && r.OrganizationPin == deployment.OrganizationPin()
	}
	if err != nil || aerr != nil || !valid(m.Session, sessionVersion) || !valid(m.Webhook, webhookVersion) || m.Session.APIPrincipal != m.Webhook.APIPrincipal {
		return identityRuntimeMetadata{}, ErrRepositoryUnavailable
	}
	return m, nil
}
func (r *PostgresRepository) consumeIdentityAttempt(ctx context.Context, state string) (identityAttempt, error) {
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return identityAttempt{}, err
	}
	var a identityAttempt
	_, err = d.identityTransaction(ctx, identityConsume, []any{state}, func(b json.RawMessage) error {
		if decodeStrictIdentityAdministration(b, &a) != nil || !validReturnPath(a.ReturnPath) || len(a.AttemptID) != 64 {
			return ErrRepositoryAuthentication
		}
		h := sha256.Sum256([]byte(state))
		if a.StateDigest != hex.EncodeToString(h[:]) {
			return ErrRepositoryAuthentication
		}
		return nil
	})
	return a, err
}
func (i *identitySessionIssuer) prepare(ctx context.Context, e platformidentity.ExternalPrincipal, a identityAttempt) (*preparedIdentitySession, error) {
	m, err := i.ready(ctx)
	if err != nil {
		return nil, err
	}
	token, err := randomCredential()
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	csrf, err := randomCredential()
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	tokenDigest, csrfDigest := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(csrf))
	envelope, err := i.key.SignSession(e, authorization.IdentitySessionAdmission{Registration: m.Session, Profile: migrations.AuthorizationIdentityProfileChecksum(), StateDigest: a.StateDigest, AttemptID: a.AttemptID, TokenDigest: hex.EncodeToString(tokenDigest[:]), CSRFDigest: hex.EncodeToString(csrfDigest[:]), VerifiedAt: time.Now().UTC()})
	if err != nil {
		return nil, ErrRepositoryAuthentication
	}
	return &preparedIdentitySession{repository: i.repository, external: e, envelope: envelope, token: token, csrf: csrf, organizationPin: i.deployment.OrganizationID}, nil
}

type nativeIdentitySnapshot struct {
	PrincipalID           string   `json:"principal_id"`
	OrganizationID        string   `json:"organization_id"`
	OrganizationReference string   `json:"organization_reference"`
	MemberReference       string   `json:"member_reference"`
	Role                  string   `json:"role"`
	Active                bool     `json:"active"`
	Version               int64    `json:"version"`
	WorkspaceID           string   `json:"workspace_id"`
	EnvironmentID         string   `json:"environment_id"`
	Permissions           []string `json:"permissions"`
	Groups                []string `json:"groups"`
	Desired               int64    `json:"desired"`
	Generation            int64    `json:"generation"`
}

func (r *PostgresRepository) resolveNativeIdentity(ctx context.Context, e platformidentity.ExternalPrincipal) (SessionGrant, error) {
	prepared, ok := ctx.Value(identityAdmissionContextKey{}).(*preparedIdentitySession)
	if !ok || prepared == nil || prepared.repository != r || prepared.external != e {
		return SessionGrant{}, ErrRepositoryAuthentication
	}
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return SessionGrant{}, err
	}
	var grant SessionGrant
	_, err = d.identityTransaction(ctx, identityResolve, []any{string(prepared.envelope)}, func(b json.RawMessage) error {
		var snap nativeIdentitySnapshot
		if prepared.organizationPin != "" {
			if json.Unmarshal(b, &snap) != nil || snap.OrganizationID != prepared.organizationPin {
				return ErrRepositoryAuthentication
			}
		}
		if decodeStrictIdentityAdministration(b, &snap) != nil || !snap.Active || snap.Version < 1 || snap.Desired < 1 || snap.Generation < 0 || snap.OrganizationReference != e.OrganizationReference() || snap.MemberReference != e.MemberReference() || !slices.Equal(snap.Groups, e.GroupReferences()) {
			return ErrRepositoryAuthentication
		}
		native, _, active, err := membershipIdentityFromJSON(b)
		if err != nil || !active {
			return ErrRepositoryAuthentication
		}
		grant = SessionGrant{PrincipalID: native.PrincipalID, Scope: native.Scope, Permissions: append([]string{}, native.Permissions...), ExpiresAt: e.ExpiresAt().Truncate(time.Millisecond)}
		if !validSessionGrant(grant) {
			return ErrRepositoryAuthentication
		}
		return nil
	})
	if err != nil {
		return SessionGrant{}, err
	}
	prepared.grant = grant
	prepared.grant.Permissions = append([]string{}, grant.Permissions...)
	grant.nativeAdmission = prepared
	return grant, nil
}
func (r *PostgresRepository) createNativeSession(ctx context.Context, g SessionGrant) (string, error) {
	a := g.nativeAdmission
	if a == nil || a.repository == nil || g.PrincipalID != a.grant.PrincipalID || g.Scope != a.grant.Scope || !g.ExpiresAt.Equal(a.grant.ExpiresAt) || !slices.Equal(g.Permissions, a.grant.Permissions) {
		return "", ErrRepositoryAuthentication
	}
	d, err := r.nativeIdentityDatabase()
	if err != nil {
		return "", err
	}
	preparedDatabase, err := a.repository.nativeIdentityDatabase()
	if err != nil || preparedDatabase != d {
		return "", ErrRepositoryAuthentication
	}
	_, err = d.identityTransaction(ctx, identityIssue, []any{string(a.envelope), a.token, a.csrf}, func(b json.RawMessage) error {
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || len(fields) != 8 {
			return ErrRepositoryAuthentication
		}
		for _, k := range []string{"principal_id", "organization_id", "workspace_id", "environment_id", "permissions", "csrf_token", "fresh_authenticated", "fresh_auth_expires_at"} {
			if fields[k] == nil {
				return ErrRepositoryAuthentication
			}
		}
		v, err := identityFromJSON(b, true)
		if err != nil || v.PrincipalID != g.PrincipalID || v.Scope != g.Scope || v.CSRFToken != a.csrf || !equalPermissionSets(v.Permissions, g.Permissions) || !v.FreshAuthenticated || !v.FreshAuthExpiresAt.After(time.Now()) || v.FreshAuthExpiresAt.After(time.Now().Add(5*time.Minute+5*time.Second)) {
			return ErrRepositoryAuthentication
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	token := a.token
	a.token = ""
	a.csrf = ""
	return token, nil
}
