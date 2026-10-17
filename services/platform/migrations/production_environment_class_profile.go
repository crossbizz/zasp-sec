package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

const EnvironmentClassProfileName = "canonical61-temporal78-authorization79-80-environment-class-v1"
const EnvironmentClassAuditProfileName = "canonical61-temporal78-authorization79-80-audit-environment-class-v1"

//go:embed sql/environment_class_profile.sql
var environmentClassProfileSQL string

func environmentClassProfileSource(audit bool) (string, string) {
	_, worker := authorizationWorkerProfileSource()
	if audit {
		_, worker = authorizationWorkerAuditProfileSource()
	}
	source := strings.NewReplacer(
		"-- environment class worker checksum", worker,
		"-- environment class runtime checksum", AuthorizationRuntimeProfileChecksum(),
		"-- environment class authorization79 checksum", ProductionAuthorizationProjection().Checksum(),
		"-- environment class authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(),
		"-- environment class temporal78 checksum", TemporalFindingResponseChecksum(),
		"-- environment class temporal78 fingerprint", TemporalFindingResponseFingerprint(),
	).Replace(environmentClassProfileSQL)
	sum := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(sum[:])
	return strings.ReplaceAll(source, "-- environment class checksum", pin), pin
}
func EnvironmentClassProfileChecksum() string { _, p := environmentClassProfileSource(false); return p }
func EnvironmentClassAuditProfileChecksum() string {
	_, p := environmentClassProfileSource(true)
	return p
}
func IsEnvironmentClassProfileChecksum(pin string) bool {
	return len(pin) == 64 && (pin == EnvironmentClassProfileChecksum() || pin == EnvironmentClassAuditProfileChecksum())
}
func (r *Runner) UpProductionEnvironmentClassProfile(ctx context.Context) error {
	return r.upProductionEnvironmentClassProfile(ctx, false)
}
func (r *Runner) UpProductionEnvironmentClassAuditProfile(ctx context.Context) error {
	return r.upProductionEnvironmentClassProfile(ctx, true)
}

func (r *Runner) upProductionEnvironmentClassProfile(ctx context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := environmentClassProfileSource(audit)
	bootstrap, authority, writers, err := environmentClassDefinitions(source)
	if err != nil {
		return err
	}
	_, worker := authorizationWorkerProfileSource()
	if audit {
		_, worker = authorizationWorkerAuditProfileSource()
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(query string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, query, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		// The operator MUST be the original LOGIN table owner, not a delegated API
		// or merely a member of the nonlogin authority. No predecessor ACL changes.
		if err := check(`SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b JOIN pg_roles p ON p.rolname=b.principal_name JOIN pg_class e ON e.oid='public.zasp_environments'::regclass JOIN pg_class d ON d.oid='public.zasp_data_controls'::regclass WHERE b.principal_name=session_user AND b.authority_role='zasp_discovery_authority' AND e.relowner=p.oid AND d.relowner=p.oid AND p.rolcanlogin AND NOT(p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolcreatedb) AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')) AND (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1)`, ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_environment_class_v1') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, bootstrap); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		predecessor := func() error {
			return check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_temporal78.ready($3,$4) AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=$5) AND zasp_authorization80_runtime.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=$6) AND zasp_authorization80.hierarchy_create_source_ready()`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), TemporalFindingResponseChecksum(), TemporalFindingResponseFingerprint(), worker, AuthorizationRuntimeProfileChecksum())
		}
		if err := predecessor(); err != nil {
			return err
		}
		if !present {
			if err := tx.Exec(ctx, authority); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			// Temporary CREATE is confined to the NEW namespace and revoked before the
			// registration fingerprint. USAGE and read-only proof helper remain narrow.
			if err := tx.Exec(ctx, `DO $grant$ BEGIN EXECUTE format('GRANT USAGE,CREATE ON SCHEMA zasp_environment_class_v1 TO %I',session_user);EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_environment_class_v1.require_api(text,text,text,text,text,text) TO %I',session_user);END $grant$;SET LOCAL ROLE NONE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, writers); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority;DO $revoke$ BEGIN EXECUTE format('REVOKE CREATE ON SCHEMA zasp_environment_class_v1 FROM %I',session_user);END $revoke$`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_environment_class_v1.registration VALUES(true,$1,$2,$3,session_user::regrole::oid,zasp_environment_class_v1.fingerprint())`, pin, worker, AuthorizationRuntimeProfileChecksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_environment_class_v1.catalog_ready($1)`, pin); err != nil {
			return err
		}
		return predecessor()
	})
}

func environmentClassDefinitions(source string) (string, string, string, error) {
	const ddl = "CREATE SCHEMA zasp_environment_class_v1 AUTHORIZATION zasp_discovery_authority;"
	const marker = "-- environment class source LOGIN writers"
	before, rest, ok := strings.Cut(source, ddl)
	if !ok || strings.Count(source, ddl) != 1 || strings.Count(rest, marker) != 1 {
		return "", "", "", ErrInvalidState
	}
	for _, line := range strings.Split(before, "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "--") {
			return "", "", "", ErrInvalidState
		}
	}
	authority, writers, _ := strings.Cut(rest, marker)
	if strings.TrimSpace(authority) == "" || strings.TrimSpace(writers) == "" {
		return "", "", "", ErrInvalidState
	}
	return before + ddl, authority, writers, nil
}
