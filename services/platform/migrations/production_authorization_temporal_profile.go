package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0080_authorization_temporal_profile.sql
var authorizationTemporalProfileSQL string

// This named private80 profile does not add a canonical migration number.
const AuthorizationTemporalProfileName = "canonical61-temporal78-authorization79-80-v1"

func authorizationTemporalProfileSource() (string, string) {
	s := strings.NewReplacer("-- profile79 checksum", ProductionAuthorizationProjection().Checksum(), "-- profile80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- profile78 checksum", TemporalFindingResponseChecksum(), "-- profile78 fingerprint", TemporalFindingResponseFingerprint()).Replace(authorizationTemporalProfileSQL)
	h := sha256.Sum256([]byte(s))
	c := hex.EncodeToString(h[:])
	return strings.ReplaceAll(s, "-- profile checksum", c), c
}

func (r *Runner) UpProductionAuthorizationTemporalProfile(ctx context.Context) error {
	return r.upProductionAuthorizationTemporalProfile(ctx, false, false)
}

func (r *Runner) UpProductionAuthorizationTemporalAuditProfile(ctx context.Context) error {
	return r.upProductionAuthorizationTemporalProfile(ctx, true, false)
}

func (r *Runner) upProductionAuthorizationTemporalProfile(ctx context.Context, audit, identity bool) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(q string, args ...any) error {
			var v bool
			if err := scanRow(ctx, tx, q, args, &v); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !v {
				return ErrInvalidState
			}
			return nil
		}
		present := func(n string) (bool, error) {
			var v bool
			err := scanRow(ctx, tx, `SELECT to_regnamespace($1) IS NOT NULL`, []any{n}, &v)
			return v, err
		}
		if err := check(`SELECT (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND name=$1 AND checksum=$2) AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, ProductionSecurityAgentMultistep().Name(), ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		if err := check(`SELECT to_regnamespace('zasp_temporal78') IS NOT NULL`); err != nil {
			return err
		}
		source, checksum := authorizationTemporalProfileSource()
		auditMode := "none"
		identityMode := "none"
		if identity {
			identityMode = AuthorizationIdentityProfileName
		}
		if audit {
			auditMode = AuthorizationAuditProfileName
		}
		profile, err := present("zasp_authorization80_temporal")
		if err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if profile {
			if identity {
				if err := check(`SELECT zasp_authorization80_identity.structural_ready($1)`, AuthorizationIdentityProfileChecksum()); err != nil {
					return err
				}
			}
			if audit {
				_, auditChecksum := authorizationAuditProfileSource()
				if err := check(`SELECT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE checksum=$1)`, auditChecksum); err != nil {
					return err
				}
			}
			return check(`SELECT EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE checksum=$1) AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE audit_mode=$2 AND identity_mode=$3) AND zasp_authorization80_temporal.ready()`, checksum, auditMode, identityMode)
		}
		if err = check(`SELECT to_regnamespace('zasp_authorization80') IS NULL`); err != nil {
			return err
		}
		if err = check(`SELECT to_regnamespace('zasp_authorization80_audit') IS NULL`); err != nil {
			return err
		}
		projection, err := present("zasp_authorization79")
		if err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !projection {
			if err = check(`SELECT zasp_temporal78.ready($1,$2)`, TemporalFindingResponseChecksum(), TemporalFindingResponseFingerprint()); err != nil {
				return err
			}
			if err = tx.Exec(ctx, ProductionAuthorizationProjection().UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err = tx.Exec(ctx, `INSERT INTO zasp_authorization79.registration(checksum,fingerprint) VALUES($1,zasp_authorization79.fingerprint())`, ProductionAuthorizationProjection().Checksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err = check(`SELECT zasp_authorization79.ready($1) AND zasp_temporal78.catalog_ready()`, ProductionAuthorizationProjection().Checksum()); err != nil {
			return err
		}
		stages := strings.Split(source, "-- profile catalogs")
		if len(stages) != 2 {
			return ErrInvalidState
		}
		if err = tx.Exec(ctx, stages[0]); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err = check(`SELECT zasp_authorization80_temporal.triggers_ready(false) AND zasp_authorization80_temporal.projected72()=$1 AND zasp_authorization80_temporal.projected68()=$2`, TemporalDiscoveryFingerprint(), TemporalExecutorFingerprint()); err != nil {
			return err
		}
		// Bind the explicit mode before registration. No intermediate readiness
		// is exposed: selectors, wrappers and both catalogs commit atomically.
		if err = tx.Exec(ctx, ProductionAuthorizationEnforcement().UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err = tx.Exec(ctx, `UPDATE zasp_authorization80.runtime_profile SET name=$1,audit_mode=$2,identity_mode=$3 WHERE singleton`, AuthorizationTemporalProfileName, auditMode, identityMode); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		parts := strings.Split(stages[1], "-- profile activate")
		if len(parts) != 2 {
			return ErrInvalidState
		}
		if err = tx.Exec(ctx, parts[0]); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err = check(`SELECT zasp_authorization80_temporal.triggers_ready(true) AND zasp_authorization80_temporal.projected72()=$1`, TemporalDiscoveryFingerprint()); err != nil {
			return err
		}
		if audit {
			if err = installAuthorizationAudit(ctx, tx); err != nil {
				return err
			}
		}
		if err = tx.Exec(ctx, parts[1]); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if identity {
			if err = installAuthorizationIdentity(ctx, tx); err != nil {
				return err
			}
		}
		if err = check(`SELECT zasp_authorization80_temporal.projected68()=$1 AND zasp_authorization80_temporal.projected72()=$2`, TemporalExecutorFingerprint(), TemporalDiscoveryFingerprint()); err != nil {
			return err
		}
		if err = tx.Exec(ctx, `INSERT INTO zasp_authorization80.registration(checksum,fingerprint) VALUES($1,zasp_authorization80.fingerprint())`, ProductionAuthorizationEnforcement().Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if audit {
			if err = registerAuthorizationAudit(ctx, tx); err != nil {
				return err
			}
		}
		if err = tx.Exec(ctx, `INSERT INTO zasp_authorization80_temporal.registration(checksum,fingerprint) VALUES($1,zasp_authorization80_temporal.fingerprint())`, checksum); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if identity {
			if err = registerAuthorizationIdentity(ctx, tx); err != nil {
				return err
			}
			if err = check(`SELECT zasp_authorization80_identity.structural_ready($1)`, AuthorizationIdentityProfileChecksum()); err != nil {
				return err
			}
		}
		return check(`SELECT zasp_authorization80_temporal.ready() AND public.zasp_sa_multistep_readiness($1,$2)`, ProductionSecurityAgentMultistep().Checksum(), SecurityAgentMultistepRegisteredFingerprint())
	})
}
