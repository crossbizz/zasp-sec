package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
	"sync"
)

// RetentionProfileName is a supplementary exact Audit-parent recipe. It never
// replaces canonical versions or silently selects a different parent family.
const RetentionProfileName = "canonical61-temporal78-authorization79-80-audit-identity-retention-v1"

//go:embed sql/retention_profile.sql
var retentionProfileSQL string

//go:embed sql/retention_successor.sql
var retentionSuccessorSQL string

//go:embed sql/retention_index.sql
var retentionIndexSQL string

//go:embed sql/retention_partition.sql
var retentionPartitionSQL string

//go:embed sql/retention_cleanup.sql
var retentionCleanupSQL string

type RetentionProfileMetadata struct{}

func ProductionRetentionProfile() RetentionProfileMetadata { return RetentionProfileMetadata{} }
func (RetentionProfileMetadata) Name() string              { return RetentionProfileName }
func (RetentionProfileMetadata) Checksum() string          { return RetentionAuditProfileChecksum() }

// Only immutable compiled source is cached. Live catalog, identity, policy and
// readiness checks are evaluated by PostgreSQL on each consuming operation.
var retentionSourceOnce sync.Once
var retentionCompiledSource, retentionCompiledPin string

func retentionProfileSource() (string, string) {
	retentionSourceOnce.Do(func() {
		_, worker := authorizationWorkerAuditProfileSource()
		source := strings.NewReplacer("-- retention worker checksum", worker, "-- retention runtime checksum", AuthorizationRuntimeProfileChecksum()).Replace(strings.ReplaceAll(retentionProfileSQL, "-- retention successor definitions", retentionSuccessorSQL+"\n"+retentionIndexSQL+"\n"+retentionPartitionSQL+"\n"+retentionCleanupSQL))
		sum := sha256.Sum256([]byte(source))
		retentionCompiledPin = hex.EncodeToString(sum[:])
		retentionCompiledSource = strings.ReplaceAll(source, "-- retention checksum", retentionCompiledPin)
	})
	return retentionCompiledSource, retentionCompiledPin
}

func RetentionAuditProfileChecksum() string { _, pin := retentionProfileSource(); return pin }
func IsRetentionProfileChecksum(pin string) bool {
	return len(pin) == 64 && pin == RetentionAuditProfileChecksum()
}

// UpProductionRetentionAuditProfile prepares a dormant authority only. No
// activation/cutover evidence, runtime principals, or target scopes are seeded.
// The complete separately sealed successor is required before caller_ready can
// admit any runtime operation.
func (r *Runner) UpProductionRetentionAuditProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := retentionProfileSource()
	const boundary = "-- retention authority definitions"
	bridges, authority, found := strings.Cut(source, boundary)
	if !found || strings.Count(source, boundary) != 1 {
		return ErrInvalidState
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
		if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		_, worker := authorizationWorkerAuditProfileSource()
		if err := check(`SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER') AND (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1) AND (SELECT count(*)=2 FROM pg_class WHERE oid IN('public.zasp_data_controls'::regclass,'public.zasp_session_events'::regclass) AND relowner=session_user::regrole) AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=$2) AND zasp_authorization80_runtime.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=$3) AND zasp_authorization80.ready($4)`, ProductionSecurityAgentMultistep().Checksum(), worker, AuthorizationRuntimeProfileChecksum(), ProductionAuthorizationEnforcement().Checksum()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_retention_v1') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			// Provisioning is a separate genuine schema-owner operation. The
			// ordinary NOINHERIT source installer never grants itself privileges.
			var ddlReady bool
			if err := scanRow(ctx, tx, retentionPublicDDLReadySQL, nil, &ddlReady); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ddlReady {
				return ErrRetentionPublicDDLPrerequisite
			}
			if err := tx.Exec(ctx, `SET LOCAL ROLE NONE`); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, bridges); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, authority); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_retention_v1.registration VALUES(true,$1,$2,$3,zasp_retention_v1.fingerprint())`, pin, worker, AuthorizationRuntimeProfileChecksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		return check(`SELECT (zasp_retention_v1.prepared_ready($1) OR zasp_retention_v1.effective_catalog_ready($1)) AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_runtime.catalog_ready()`, pin)
	})
}
