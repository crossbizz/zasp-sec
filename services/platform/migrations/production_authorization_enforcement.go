package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sql/0080_production_authorization_enforcement.up.sql
var authorizationEnforcementSQL string

//go:embed sql/0080_authorization_parent_reads.sql
var authorizationParentReadsSQL string

//go:embed sql/0080_authorization_sessions.sql
var authorizationSessionReadsSQL string

//go:embed sql/0080_authorization_session_search.sql
var authorizationSessionSearchSQL string

//go:embed sql/0080_authorization_sensors.sql
var authorizationSensorsSQL string

//go:embed sql/0080_authorization_recovery.sql
var authorizationRecoverySQL string

//go:embed sql/0080_authorization_home.sql
var authorizationHomeSQL string

//go:embed sql/0080_authorization_attestation.sql
var authorizationAttestationSQL string

//go:embed sql/0080_authorization_risk_isolation.sql
var authorizationRiskIsolationSQL string

//go:embed sql/0080_authorization_data_controls.sql
var authorizationDataControlsSQL string

//go:embed sql/0080_authorization_hierarchy_create.sql
var authorizationHierarchyCreateSQL string

//go:embed sql/0080_authorization_integration_rejection.sql
var authorizationIntegrationRejectionSQL string

//go:embed sql/0080_authorization_integration_mutations.sql
var authorizationIntegrationMutationsSQL string

//go:embed sql/0080_authorization_integration_reference.sql
var authorizationIntegrationReferenceSQL string

func ProductionAuthorizationEnforcement() Metadata {
	source := strings.ReplaceAll(authorizationEnforcementSQL, "-- authorization80 parent reads", authorizationParentReadsSQL)
	source = strings.ReplaceAll(source, "-- authorization80 session reads", authorizationSessionReadsSQL)
	source = strings.ReplaceAll(source, "-- authorization80 session search", authorizationSessionSearchSQL)
	source = strings.ReplaceAll(source, "-- authorization80 sensors", authorizationSensorsSQL)
	source = strings.ReplaceAll(source, "-- authorization80 recovery", authorizationRecoverySQL)
	source = strings.ReplaceAll(source, "-- authorization80 home", authorizationHomeSQL)
	source = strings.ReplaceAll(source, "-- authorization80 attestation", authorizationAttestationSQL)
	source = strings.ReplaceAll(source, "-- authorization80 risk isolation", authorizationRiskIsolationSQL)
	source = strings.ReplaceAll(source, "-- authorization80 data controls", authorizationDataControlsSQL)
	source = strings.ReplaceAll(source, "-- authorization80 hierarchy create", authorizationHierarchyCreateSQL)
	source = strings.ReplaceAll(source, "-- authorization80 integration rejection", authorizationIntegrationRejectionSQL)
	source = strings.ReplaceAll(source, "-- authorization80 integration mutations", authorizationIntegrationMutationsSQL)
	source = strings.ReplaceAll(source, "-- authorization80 integration reference", authorizationIntegrationReferenceSQL)
	source = strings.NewReplacer(
		"-- authorization80 identity catalog body", strings.ReplaceAll(identityCatalogBody(), "'", "''"),
		"-- authorization80 canonical checksum", ProductionSecurityAgentMultistep().Checksum(),
		"-- authorization80 canonical fingerprint", SecurityAgentMultistepRegisteredFingerprint(),
		"-- authorization80 projection checksum", ProductionAuthorizationProjection().Checksum(),
		"-- authorization80 session41 checksum", ProductionRuntimeSessionReads().Checksum(),
		"-- authorization80 session41 fingerprint", ProductionRuntimeSessionReadsSemanticFingerprint(),
		"-- authorization80 session50 checksum", ProductionRuntimeSandboxBinding().Checksum(),
		"-- authorization80 session50 fingerprint", ProductionRuntimeSandboxBindingSemanticFingerprint(),
		"-- authorization80 session43 checksum", ProductionRuntimeSessionQuery().Checksum(),
		"-- authorization80 session43 fingerprint", ProductionRuntimeSessionQuerySemanticFingerprint(),
		"-- authorization80 sensor45 checksum", ProductionRuntimeEnrollmentPairing().Checksum(),
		"-- authorization80 sensor45 fingerprint", ProductionRuntimeEnrollmentPairingSemanticFingerprint(),
		"-- authorization80 recovery27 checksum", ProductionRecovery().Checksum(),
		"-- authorization80 recovery27 fingerprint", ProductionRecoverySemanticFingerprint(),
		"-- authorization80 administration7 checksum", ProductionAdministration().Checksum(),
		"-- authorization80 administration7 fingerprint", ProductionAdministrationSemanticFingerprint(),
		"-- authorization80 home29 checksum", ProductionHomeAttention().Checksum(),
		"-- authorization80 home29 fingerprint", ProductionHomeAttentionSemanticFingerprint(),
		"-- authorization80 audit52 checksum", ProductionAuditExports().Checksum(),
		"-- authorization80 audit52 fingerprint", ProductionAuditExportsSemanticFingerprint(),
		"-- authorization80 compliance56 checksum", ProductionCompliance().Checksum(),
		"-- authorization80 compliance56 fingerprint", ComplianceFingerprint(),
	).Replace(source)
	digest := sha256.Sum256([]byte(source))
	checksum := hex.EncodeToString(digest[:])
	return Metadata{version: 80, name: "production_authorization_enforcement_extension", checksum: checksum, up: strings.ReplaceAll(source, "-- authorization80 checksum", checksum)}
}
func (r *Runner) UpProductionAuthorizationEnforcement(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var count int64
		if err := scanRow(ctx, tx, countRowsSQL, nil, &count); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if count != 61 {
			return ErrInvalidState
		}
		predecessor := ProductionSecurityAgentMultistep()
		var predecessorReady bool
		if err := scanRow(ctx, tx, `SELECT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=$1 AND name=$2 AND checksum=$3)`, []any{predecessor.Version(), predecessor.Name(), predecessor.Checksum()}, &predecessorReady); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !predecessorReady {
			return ErrInvalidState
		}
		var ready bool
		if err := scanRow(ctx, tx, `SELECT zasp_authorization79.ready($1)`, []any{ProductionAuthorizationProjection().Checksum()}, &ready); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !ready {
			return ErrInvalidState
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization80') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		metadata := ProductionAuthorizationEnforcement()
		if !present {
			if err := tx.Exec(ctx, metadata.UpSQL()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if err := tx.Exec(ctx, `INSERT INTO zasp_authorization80.registration(checksum,fingerprint) VALUES($1,zasp_authorization80.fingerprint())`, metadata.Checksum()); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := scanRow(ctx, tx, `SELECT zasp_authorization80.ready($1) AND EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE audit_mode='none')`, []any{metadata.Checksum()}, &ready); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !ready {
			return ErrInvalidState
		}
		return nil
	})
}
