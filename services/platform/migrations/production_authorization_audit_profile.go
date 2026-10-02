package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
	"sync"
)

//go:embed sql/0080_authorization_audit_profile.sql
var authorizationAuditProfileSQL string

const AuthorizationAuditProfileName = "source52-canonical61-audit-v1"

var authorizationAuditChecksum = sync.OnceValue(func() string {
	_, checksum := authorizationAuditProfileSource()
	return checksum
})

// AuthorizationAuditProfileChecksum is the exact immutable compiled installer
// identity. It does not cache any database readiness or registration result.
func AuthorizationAuditProfileChecksum() string { return authorizationAuditChecksum() }

func authorizationAuditProfileSource() (string, string) {
	s := strings.NewReplacer("-- audit80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- audit52 checksum", ProductionAuditExports().Checksum(), "-- audit52 fingerprint", ProductionAuditExportsSemanticFingerprint(), "-- audit57 checksum", ProductionSecurityAgentAttackLab().Checksum(), "-- audit57 fingerprint", SecurityAgentAttackLabFingerprint()).Replace(authorizationAuditProfileSQL)
	h := sha256.Sum256([]byte(s))
	c := hex.EncodeToString(h[:])
	return strings.ReplaceAll(s, "-- audit profile checksum", c), c
}

// The six-query comparison is evaluated at the same bootstrap phase on either
// side of the single trigger delta. Final full ancestry is mandatory after all
// catalog registrations, including the composed72 precision handoff, are live.
func installAuthorizationAudit(ctx context.Context, tx Transaction) error {
	var before string
	if err := scanRow(ctx, tx, `SELECT public.zasp_sa_attack_lab_live_fingerprint()`, nil, &before); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	source, _ := authorizationAuditProfileSource()
	parts := strings.Split(source, "-- audit profile activate")
	if len(parts) != 2 {
		return ErrInvalidState
	}
	if err := tx.Exec(ctx, parts[0]); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	var valid bool
	if err := scanRow(ctx, tx, `SELECT zasp_authorization80_audit.guard_ready() AND zasp_authorization80_audit.projected57()=$1`, []any{before}, &valid); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !valid {
		return ErrInvalidState
	}
	if err := tx.Exec(ctx, parts[1]); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	return nil
}
func registerAuthorizationAudit(ctx context.Context, tx Transaction) error {
	_, checksum := authorizationAuditProfileSource()
	return fixedDatabaseError(ctx, tx.Exec(ctx, `INSERT INTO zasp_authorization80_audit.registration(checksum,fingerprint) VALUES($1,zasp_authorization80_audit.fingerprint())`, checksum))
}

func (r *Runner) UpProductionAuthorizationAuditProfile(ctx context.Context) error {
	return r.upProductionAuthorizationAuditProfile(ctx, false)
}

func (r *Runner) upProductionAuthorizationAuditProfile(ctx context.Context, identity bool) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(q string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, q, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if err := check(`SELECT (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1) AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND to_regnamespace('zasp_temporal78') IS NULL AND to_regnamespace('zasp_authorization80_temporal') IS NULL`, ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization80_audit') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		_, checksum := authorizationAuditProfileSource()
		identityMode := "none"
		if identity {
			identityMode = AuthorizationIdentityProfileName
		}
		if present {
			if identity {
				if err := check(`SELECT zasp_authorization80_identity.structural_ready($1)`, AuthorizationIdentityProfileChecksum()); err != nil {
					return err
				}
			}
			return check(`SELECT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum=$1) AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE name='canonical61-authorization79-80-v1' AND audit_mode=$2 AND identity_mode=$4) AND zasp_authorization80.ready($3)`, checksum, AuthorizationAuditProfileName, ProductionAuthorizationEnforcement().Checksum(), identityMode)
		}
		if err := check(`SELECT to_regnamespace('zasp_authorization80') IS NULL AND public.zasp_sa_multistep_readiness($1,$2)`, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization79') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, ProductionAuthorizationProjection().UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_authorization79.registration(checksum,fingerprint) VALUES($1,zasp_authorization79.fingerprint())`, ProductionAuthorizationProjection().Checksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_authorization79.ready($1)`, ProductionAuthorizationProjection().Checksum()); err != nil {
			return err
		}
		if err := tx.Exec(ctx, ProductionAuthorizationEnforcement().UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := tx.Exec(ctx, `UPDATE zasp_authorization80.runtime_profile SET audit_mode=$1,identity_mode=$2 WHERE singleton`, AuthorizationAuditProfileName, identityMode); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := installAuthorizationAudit(ctx, tx); err != nil {
			return err
		}
		if identity {
			if err := installAuthorizationIdentity(ctx, tx); err != nil {
				return err
			}
		}
		if err := tx.Exec(ctx, `INSERT INTO zasp_authorization80.registration(checksum,fingerprint) VALUES($1,zasp_authorization80.fingerprint())`, ProductionAuthorizationEnforcement().Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := registerAuthorizationAudit(ctx, tx); err != nil {
			return err
		}
		if identity {
			if err := registerAuthorizationIdentity(ctx, tx); err != nil {
				return err
			}
			if err := check(`SELECT zasp_authorization80_identity.structural_ready($1)`, AuthorizationIdentityProfileChecksum()); err != nil {
				return err
			}
		}
		return check(`SELECT zasp_authorization80.ready($1) AND zasp_authorization80_audit.catalog_ready() AND public.zasp_sa_multistep_readiness($2,$3)`, ProductionAuthorizationEnforcement().Checksum(), ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint())
	})
}
