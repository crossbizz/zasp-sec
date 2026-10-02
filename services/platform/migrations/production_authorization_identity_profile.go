package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/identitysql"
)

//go:embed sql/0080_authorization_identity_profile.sql
var authorizationIdentityProfileSQL string

//go:embed sql/0080_identity_catalog_gate.sql
var authorizationIdentityCatalogGateSQL string

//go:embed sql/0080_identity_deprovision_wrapper.sql
var authorizationIdentityDeprovisionSQL string

//go:embed sql/0080_identity_administration.sql
var authorizationIdentityAdministrationSQL string

//go:embed sql/0080_identity_pat_reads.sql
var authorizationIdentityPATReadsSQL string

//go:embed sql/0080_identity_write_guards.sql
var authorizationIdentityWriteGuardsSQL string

//go:embed sql/0080_identity_post_login.sql
var authorizationIdentityPostLoginSQL string

const AuthorizationIdentityProfileName = "source19-canonical61-identity-v1"

func identityRetainedConsumers() string {
	source := authorizationIdentityAdministrationSQL + "\n" + authorizationIdentityPATReadsSQL
	for _, body := range []struct{ name, statement string }{
		{"UpdateMemberRole", identitysql.UpdateMemberRole},
		{"UpsertGroupMapping", identitysql.UpsertGroupMapping},
		{"CreateAPIToken", identitysql.CreateAPIToken},
		{"RotateAPIToken", identitysql.RotateAPIToken},
		{"RevokeAPIToken", identitysql.RevokeAPIToken},
		{"AcknowledgeAPITokenReveal", identitysql.AcknowledgeAPITokenReveal},
		{"RevokeInvestigatedSession", identitysql.RevokeInvestigatedSession},
		{"ListAPITokens", identitysql.ListAPITokens},
		{"ListAPITokenRevealGrants", identitysql.ListAPITokenRevealGrants},
		{"RevealAPIToken", identitysql.RevealAPIToken},
	} {
		marker := "-- retained identity " + body.name
		if strings.Count(source, marker) != 1 {
			panic("compiled identity retained source shape")
		}
		source = strings.Replace(source, marker, body.statement, 1)
	}
	// Preserve the pre-extraction separator after the PAT read functions.
	return source + "\n"
}

func identityCatalogBody() string {
	return strings.ReplaceAll(strings.TrimSpace(authorizationIdentityCatalogGateSQL), "-- identity19 fingerprint", ProductionIdentityAdministrationSemanticFingerprint())
}

func identity19CatalogQuery() string {
	const begin = "CREATE FUNCTION public.zasp_identity_administration_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$"
	_, tail, ok := strings.Cut(identityAdministrationUpSQL, begin)
	query, _, end := strings.Cut(tail, "$fingerprint$;")
	if !ok || !end || strings.Count(query, "pg_get_functiondef(procedure.oid)") != 1 {
		panic("compiled source19 catalog shape")
	}
	return strings.TrimSpace(query)
}

func identityDeprovisionSource() string {
	const begin = "CREATE FUNCTION public.zasp_identity_admin_reconcile_deprovision("
	_, tail, ok := strings.Cut(identityAdministrationUpSQL, begin)
	body, _, end := strings.Cut(tail, "$deprovision$;")
	if !ok || !end {
		panic("compiled source19 deprovision shape")
	}
	retained := "CREATE FUNCTION zasp_authorization80_identity.retained_deprovision(" + body + "$deprovision$;"
	projected := strings.Replace(identity19CatalogQuery(), "pg_get_functiondef(procedure.oid)", `CASE WHEN procedure.oid='public.zasp_identity_admin_reconcile_deprovision(text,text,text,text,bytea,text)'::regprocedure THEN(SELECT definition FROM zasp_authorization80_identity.predecessor) ELSE pg_get_functiondef(procedure.oid) END`, 1)
	return strings.NewReplacer("-- identity retained deprovision", retained, "-- identity projected19 query", projected, "-- identity19 fingerprint", ProductionIdentityAdministrationSemanticFingerprint()).Replace(authorizationIdentityDeprovisionSQL)
}

// This graph is intentionally one-way: main80 pins the checksum-free catalog
// gate body; identity pins assembled80, audit and composed profile checksums.
func authorizationIdentityProfileSource() (string, string) {
	_, audit := authorizationAuditProfileSource()
	_, composed := authorizationTemporalProfileSource()
	s := strings.NewReplacer("-- identity administration consumers", identityRetainedConsumers()+"\n"+authorizationIdentityWriteGuardsSQL, "-- identity deprovision wrapper", identityDeprovisionSource(), "-- identity catalog body", identityCatalogBody(), "-- identity80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- identity audit checksum", audit, "-- identity composed checksum", composed).Replace(authorizationIdentityProfileSQL)
	s = strings.Replace(s, "-- identity post-login reads", authorizationIdentityPostLoginSQL, 1)
	inputs := []string{ProductionCore().Checksum(), ProductionWorkflows().Checksum(), ProductionAdministration().Checksum(), ProductionIdentityAdministration().Checksum(), ProductionIdentityAdministrationSemanticFingerprint(), ProductionAuthorizationProjection().Checksum(), composed}
	// Pin historical dependencies even when a particular consumer needs only a
	// subset. The comment is part of this compiled installer's immutable identity.
	s = "-- identity predecessors " + strings.Join(inputs, " ") + "\n" + s
	digest := sha256.Sum256([]byte(s))
	checksum := hex.EncodeToString(digest[:])
	return strings.ReplaceAll(s, "-- identity checksum", checksum), checksum
}

func AuthorizationIdentityProfileChecksum() string {
	_, c := authorizationIdentityProfileSource()
	return c
}

func installAuthorizationIdentity(ctx context.Context, tx Transaction) error {
	var valid bool
	// Evaluate the compiled query directly. A replaced public fingerprint body
	// cannot bless the predecessor that this installer retains.
	// The caller has verified canonical61 before installing audit, and audit's
	// installer has compared its projected57 with that same predecessor. Final
	// public ancestry is intentionally unavailable until registrations exist.
	if err := scanRow(ctx, tx, `SELECT (`+identity19CatalogQuery()+`)=$1 AND public.zasp_identity_admin_security_ready() AND zasp_authorization80_audit.guard_ready()`, []any{ProductionIdentityAdministrationSemanticFingerprint()}, &valid); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !valid {
		return ErrInvalidState
	}
	const ancestry = `SELECT jsonb_build_array(zasp_authorization80_audit.projected57(),public.zasp_sa_multistep_registered_live_fingerprint(),zasp_authorization79.fingerprint(),zasp_authorization80.fingerprint(),zasp_authorization80_audit.fingerprint())::text`
	var before, after string
	if err := scanRow(ctx, tx, ancestry, nil, &before); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	source, _ := authorizationIdentityProfileSource()
	if err := tx.Exec(ctx, source); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if err := scanRow(ctx, tx, ancestry, nil, &after); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if before != after {
		return ErrInvalidState
	}
	if err := scanRow(ctx, tx, `SELECT zasp_authorization80_identity.projected19()=$1 AND public.zasp_identity_admin_security_ready()`, []any{ProductionIdentityAdministrationSemanticFingerprint()}, &valid); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !valid {
		return ErrInvalidState
	}
	return nil
}

func registerAuthorizationIdentity(ctx context.Context, tx Transaction) error {
	body := identityCatalogBody()
	const marker = "r.catalog=("
	if strings.Count(body, marker) != 1 || !strings.HasSuffix(body, ")),false)") {
		return ErrInvalidState
	}
	_, query, _ := strings.Cut(body, marker)
	query = strings.TrimSuffix(query, ")),false)")
	_, checksum := authorizationIdentityProfileSource()
	return fixedDatabaseError(ctx, tx.Exec(ctx, `INSERT INTO zasp_authorization80_identity.registration(checksum,catalog) SELECT $1,(`+query+`)`, checksum))
}

func (r *Runner) UpProductionAuthorizationIdentityProfile(ctx context.Context) error {
	return r.upProductionAuthorizationAuditProfile(ctx, true)
}

func (r *Runner) UpProductionAuthorizationTemporalIdentityProfile(ctx context.Context) error {
	return r.upProductionAuthorizationTemporalProfile(ctx, true, true)
}
