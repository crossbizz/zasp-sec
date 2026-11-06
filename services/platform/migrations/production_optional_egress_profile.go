package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

// OptionalEgressProfileName is supplementary; canonical migrations stay immutable.
const OptionalEgressProfileName = "canonical61-temporal78-authorization79-80-optional-egress-v1"

const OptionalEgressAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-optional-egress-v1"

//go:embed sql/optional_egress_profile.sql
var optionalEgressProfileSQL string

func optionalEgressProfileSource() (string, string) {
	_, workerPin := authorizationWorkerProfileSource()
	source := strings.NewReplacer("-- authorization79 checksum", ProductionAuthorizationProjection().Checksum(), "-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- optional worker checksum", workerPin, "-- optional runtime checksum", AuthorizationRuntimeProfileChecksum(), "-- optional temporal78 checksum", TemporalFindingResponseChecksum(), "-- optional temporal78 fingerprint", TemporalFindingResponseFingerprint()).Replace(optionalEgressProfileSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- optional egress checksum", pin), pin
}

func OptionalEgressProfileChecksum() string { _, pin := optionalEgressProfileSource(); return pin }

// The production audit/identity parent is a distinct compiled recipe. It never
// probes an installed catalog or falls back to the standalone parent.
func optionalEgressAuditProfileSource() (string, string) {
	_, workerPin := authorizationWorkerAuditProfileSource()
	source := strings.NewReplacer("-- authorization79 checksum", ProductionAuthorizationProjection().Checksum(), "-- authorization80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- optional worker checksum", workerPin, "-- optional runtime checksum", AuthorizationRuntimeProfileChecksum(), "-- optional temporal78 checksum", TemporalFindingResponseChecksum(), "-- optional temporal78 fingerprint", TemporalFindingResponseFingerprint()).Replace(optionalEgressProfileSQL)
	h := sha256.Sum256([]byte(source))
	pin := hex.EncodeToString(h[:])
	return strings.ReplaceAll(source, "-- optional egress checksum", pin), pin
}
func OptionalEgressAuditProfileChecksum() string {
	_, pin := optionalEgressAuditProfileSource()
	return pin
}

// IsOptionalEgressProfileChecksum validates explicit deployment selection only.
// Consumers must pass that selected checksum to the installed catalog gate.
func IsOptionalEgressProfileChecksum(pin string) bool {
	return len(pin) == 64 && (pin == OptionalEgressProfileChecksum() || pin == OptionalEgressAuditProfileChecksum())
}

// UpProductionOptionalEgressProfile installs an unavailable-by-default authority.
// It neither registers runtime logins nor approves a destination/profile.
func (r *Runner) UpProductionOptionalEgressProfile(ctx context.Context) error {
	return r.upProductionOptionalEgressProfile(ctx, false)
}

func (r *Runner) UpProductionOptionalEgressAuditProfile(ctx context.Context) error {
	return r.upProductionOptionalEgressProfile(ctx, true)
}

func (r *Runner) upProductionOptionalEgressProfile(ctx context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := optionalEgressProfileSource()
	if audit {
		source, pin = optionalEgressAuditProfileSource()
	}
	bootstrap, definitions, err := optionalEgressDefinitions(source)
	if err != nil {
		return err
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
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
		if err := check(`SELECT pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1)`, ProductionSecurityAgentMultistep().Checksum()); err != nil {
			return err
		}
		if err := requireMaintenanceAuthorizationReady(ctx, tx); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_optional_egress_v1') IS NOT NULL`, nil, &present); err != nil {
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
			_, wp := authorizationWorkerProfileSource()
			if audit {
				_, wp = authorizationWorkerAuditProfileSource()
			}
			return check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_temporal78.ready($3,$4) AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=$5) AND zasp_authorization80_runtime.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=$6)`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), TemporalFindingResponseChecksum(), TemporalFindingResponseFingerprint(), wp, AuthorizationRuntimeProfileChecksum())
		}
		if err := predecessor(); err != nil {
			return err
		}
		if !present {
			if err := tx.Exec(ctx, definitions); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_optional_egress_v1.registration VALUES(true,$1,zasp_optional_egress_v1.fingerprint())`, pin); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(`SELECT zasp_optional_egress_v1.catalog_ready($1)`, pin); err != nil {
			return err
		}
		return predecessor()
	})
}

func optionalEgressDefinitions(source string) (string, string, error) {
	const ddl = "CREATE SCHEMA zasp_optional_egress_v1 AUTHORIZATION zasp_discovery_authority;"
	before, rest, found := strings.Cut(source, ddl)
	if !found || strings.Count(source, ddl) != 1 {
		return "", "", ErrInvalidState
	}
	for _, line := range strings.Split(before, "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "--") {
			return "", "", ErrInvalidState
		}
	}
	return before + ddl, rest, nil
}
