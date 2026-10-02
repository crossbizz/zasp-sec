package main

import (
	"context"
	"fmt"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationIdentityProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	next, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationIdentityProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return next.UpProductionAuthorizationIdentityProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionAuthorizationTemporalIdentityProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	next, ok := r.releaseMigrationRunner.(interface{ UpProductionAuthorizationTemporalIdentityProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return next.UpProductionAuthorizationTemporalIdentityProfile(ctx)
}

type identityVerifierRegistration struct {
	purpose, principal, api, version, audience, project, pin string
	key                                                      []byte
}

func (*identityVerifierRegistration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[identity verifier registration]"))
}

// Only fixed, purpose-specific commands accept verifier material, exclusively
// from configuration. Validate every public binding before opening PostgreSQL.
func loadIdentityVerifierRegistration(args []string, getenv func(string) string) (*identityVerifierRegistration, error) {
	if len(args) != 1 || getenv == nil {
		return nil, errInvalidMigrationCommand
	}
	purpose := ""
	switch args[0] {
	case "register-identity-session-verifier":
		purpose = "session"
	case "register-identity-webhook-verifier":
		purpose = "webhook"
	default:
		return nil, errInvalidMigrationCommand
	}
	d := authorization.IdentityDeployment{PublicOrigin: getenv("ZASP_PUBLIC_ORIGIN"), ProviderBaseURL: getenv("ZASP_STYTCH_BASE_URL"), ProjectID: getenv("ZASP_STYTCH_PROJECT_ID"), ConfiguredOrganization: getenv("ZASP_STYTCH_ORGANIZATION_ID"), Mode: getenv("ZASP_DEPLOYMENT_MODE"), OrganizationID: getenv("ZASP_ORGANIZATION_ID")}
	a, err := d.Audience()
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	r := &identityVerifierRegistration{purpose: purpose, principal: getenv(migrationPrincipalEnvironment), api: getenv(discoveryAPIPrincipalEnvironment), audience: a, project: d.ProjectID, pin: d.OrganizationPin()}
	if !databasePrincipalPattern.MatchString(r.principal) || !databasePrincipalPattern.MatchString(r.api) || r.principal == r.api {
		return nil, errInvalidMigrationCommand
	}
	seed := []byte(getenv("ZASP_WORKFLOW_SIGNING_KEY"))
	if purpose == "session" {
		k, e := authorization.NewIdentitySessionKey(seed)
		if e != nil {
			return nil, errInvalidMigrationCommand
		}
		r.key, r.version = k.Verifier(), k.Version()
	} else {
		k, e := authorization.NewIdentityWebhookKey(seed)
		if e != nil {
			return nil, errInvalidMigrationCommand
		}
		r.key, r.version = k.Verifier(), k.Version()
	}
	return r, nil
}
func registerIdentityVerifier(ctx context.Context, q principalQueryer, r *identityVerifierRegistration) error {
	if ctx == nil || ctx.Err() != nil || q == nil || r == nil {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_authorization80_identity.structural_ready($2)`, r.principal, migrations.AuthorizationIdentityProfileChecksum()).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	statement := ""
	switch r.purpose {
	case "session":
		statement = `SELECT zasp_authorization80_identity.register_session($1,$2,$3,$4,$5,$6)`
	case "webhook":
		statement = `SELECT zasp_authorization80_identity.register_webhook($1,$2,$3,$4,$5,$6)`
	default:
		return errReleasePrincipalRegistration
	}
	var epoch int64
	if err := q.QueryRow(ctx, statement, r.version, r.key, r.audience, r.project, r.api, r.pin).Scan(&epoch); err != nil || epoch < 1 {
		return errReleasePrincipalRegistration
	}
	return nil
}
