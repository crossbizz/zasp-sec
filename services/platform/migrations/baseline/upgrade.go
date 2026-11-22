package baseline

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5"
)

// Both supported predecessors have immutable, recorded catalog seals.
const precedingV2Artifact = "eb705a3d269f2a632327d49514f5a790c29c3595c3a6e67d2f3d6ddd1dcddff9"

const precedingFrameworkArtifact = "44af7b31b098ad0a87dce6db8c3ab09e9204c321f1419140014575a0111e4b8d"

//go:embed feature_v2.sql
var featureV2DDL string

//go:embed framework_context.sql
var frameworkContextDDL string

//go:embed framework_addon.sql
var frameworkAddonDDL string

//go:embed framework_reporting.sql
var frameworkReportingDDL string

//go:embed framework_provider_hooks.sql
var frameworkProviderHooksDDL string

//go:embed framework_endpoint.sql
var frameworkEndpointDDL string

//go:embed intent_classifier.sql
var intentClassifierDDL string

//go:embed policy_replay.sql
var policyReplayDDL string

//go:embed provider_readiness.sql
var providerReadinessDDL string

// UpgradeToV2 applies the same DDL used by the fresh-install generator. The
// transaction includes temporary privileges, all new objects, the new catalog
// seal and caller-supplied readiness checks. Preserve preexisting privileges.
func UpgradeToV2(ctx context.Context, conn *pgx.Conn, checks ...Check) error {
	if ctx == nil || conn == nil {
		return refuse(StagePreconditions, "no connection", nil)
	}
	if _, err := loadArtifact(); err != nil {
		return refuse(StageArtifact, "invalid release artifact", err)
	}
	if Checksum() == precedingV2Artifact {
		return refuse(StageArtifact, "V2 artifact required", nil)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return refuse(StagePreconditions, "transaction did not start", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err = tx.Exec(ctx, "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('zasp-baseline-seal',0))"); err != nil {
		return refuse(StagePreconditions, "upgrade lock", err)
	}
	var operator bool
	err = tx.QueryRow(ctx, `SELECT current_user='zasp_operator' AND session_user=current_user AND d.datdba=current_user::regrole FROM pg_catalog.pg_database d WHERE d.datname=current_database()`).Scan(&operator)
	if err != nil || !operator {
		return refuse(StagePreconditions, "connect as the database owner zasp_operator", err)
	}
	var artifact string
	var intact bool
	err = tx.QueryRow(ctx, `SELECT coalesce(state->>'artifact',''), coalesce((state->>'intact')::boolean AND (state->>'sealed')::boolean,false) FROM zasp_baseline.state() AS state`).Scan(&artifact, &intact)
	if err != nil || !intact || (artifact != precedingV2Artifact && artifact != precedingFrameworkArtifact && artifact != Checksum()) {
		return refuse(StagePreconditions, "an intact supported baseline is required", err)
	}
	if artifact != Checksum() {
		var alreadyGranted bool
		err = tx.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege('zasp_discovery_authority','public','CREATE')`).Scan(&alreadyGranted)
		if err != nil {
			return refuse(StageOwnership, "schema grant", err)
		}
		if !alreadyGranted {
			if _, err = tx.Exec(ctx, `GRANT CREATE ON SCHEMA public TO zasp_discovery_authority`); err != nil {
				return refuse(StageOwnership, "temporary schema grant", err)
			}
		}
		// The operator is a member of the discovery authority and owns the
		// registry of private scan grants. Running as that principal permits
		// the explicit owner transitions for both kinds of object.
		if artifact == precedingV2Artifact {
			if err = execScript(ctx, conn, featureV2DDL); err != nil {
				return refuse(StageObjects, "V2 upgrade", err)
			}
		}
		for _, ddl := range []string{frameworkContextDDL, frameworkAddonDDL, frameworkReportingDDL, frameworkProviderHooksDDL, frameworkEndpointDDL, intentClassifierDDL, policyReplayDDL, providerReadinessDDL} {
			if err = execScript(ctx, conn, ddl); err != nil {
				return refuse(StageObjects, "framework coverage upgrade", err)
			}
		}
		if !alreadyGranted {
			if _, err = tx.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM zasp_discovery_authority`); err != nil {
				return refuse(StageOwnership, "restore schema grant", err)
			}
		}
		var sealed bool
		if err = tx.QueryRow(ctx, `SELECT zasp_baseline.accept($1)`, Checksum()).Scan(&sealed); err != nil || !sealed {
			return refuse(StageSeal, "catalog was not accepted", err)
		}
	}
	for _, check := range checks {
		if ok, err := queryBool(ctx, conn, check.SQL, check.Args...); err != nil || !ok {
			return refuse(StageVerification, check.Name, err)
		}
	}
	if ok, err := queryBool(ctx, conn, `SELECT zasp_baseline.intact()`); err != nil || !ok {
		return refuse(StageVerification, "catalog integrity", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return refuse(StageCommit, "upgrade", err)
	}
	return nil
}
